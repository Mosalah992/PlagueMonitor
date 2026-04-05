from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
import uuid
from datetime import datetime

from backend.app.db.session import get_db
from backend.app.db.models import Run as DBRun, AgentState as DBAgentState, InfectionEvent as DBInfectionEvent, RunStateSnapshot as DBRunStateSnapshot
from backend.app.schemas import schemas
from backend.app.run_manager import manager
from backend.app.api.ws import manager as ws_manager

router = APIRouter()

@router.get("/health")
def read_health():
    return {"status": "ok"}

@router.post("/runs/start", response_model=schemas.Run)
def start_run(run_in: schemas.RunCreate, db: Session = Depends(get_db)):
    run_id = str(uuid.uuid4())
    db_run = DBRun(
        id=run_id,
        name=run_in.name,
        topology=run_in.topology,
        notes=run_in.notes,
        status="running"
    )
    db.add(db_run)
    db.commit()
    db.refresh(db_run)
    
    # Start the actual simulator process
    manager.start_runtime_process(run_id, run_in.topology)
    
    return db_run

@router.post("/runs/{run_id}/stop")
def stop_run(run_id: str, db: Session = Depends(get_db)):
    # Stop background process
    stopped = manager.stop_runtime_process(run_id)
    
    db_run = db.query(DBRun).filter(DBRun.id == run_id).first()
    if db_run:
        db_run.status = "stopped"
        db_run.ended_at = datetime.utcnow()
        db.commit()
    
    return {"status": "stopped", "run_id": run_id, "process_killed": stopped}

@router.get("/runs", response_model=List[schemas.Run])
def get_runs(db: Session = Depends(get_db)):
    return db.query(DBRun).order_by(DBRun.started_at.desc()).all()

@router.get("/runs/{run_id}", response_model=schemas.Run)
def get_run(run_id: str, db: Session = Depends(get_db)):
    db_run = db.query(DBRun).filter(DBRun.id == run_id).first()
    if not db_run:
        raise HTTPException(status_code=404, detail="Run not found")
    # update status dynamically if process died
    if db_run.status == "running" and not manager.is_running(run_id):
        db_run.status = "completed"
        db_run.ended_at = datetime.utcnow()
        db.commit()
    return db_run

@router.get("/runs/{run_id}/events", response_model=List[schemas.InfectionEvent])
def get_run_events(run_id: str, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(DBInfectionEvent).filter(DBInfectionEvent.run_id == run_id).order_by(DBInfectionEvent.timestamp.desc()).limit(limit).all()

@router.get("/runs/{run_id}/agents", response_model=List[schemas.AgentState])
def get_run_agents(run_id: str, db: Session = Depends(get_db)):
    return db.query(DBAgentState).filter(DBAgentState.run_id == run_id).all()

@router.get("/runs/{run_id}/snapshots", response_model=List[schemas.RunStateSnapshot])
def get_run_snapshots(run_id: str, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(DBRunStateSnapshot).filter(DBRunStateSnapshot.run_id == run_id).order_by(DBRunStateSnapshot.timestamp.desc()).limit(limit).all()

# --- Internal Endpoints for the Runtime to Push Events ---

@router.post("/internal/events/infection")
async def register_infection_event(event_in: schemas.InfectionEventCreate, db: Session = Depends(get_db)):
    event_id = str(uuid.uuid4())
    db_event = DBInfectionEvent(**event_in.model_dump(), event_id=event_id)
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    
    # Broadcast to WS
    event_dict = schemas.InfectionEvent.model_validate(db_event).model_dump()
    # convert datetime to isoformat
    event_dict['timestamp'] = event_dict['timestamp'].isoformat()
    await ws_manager.broadcast_json({"type": "infection_event", "data": event_dict})
    
    return {"status": "ok", "event_id": event_id}

@router.post("/internal/events/agent_state")
async def update_agent_state(state_in: schemas.AgentState, db: Session = Depends(get_db)):
    # Upsert logic
    db_state = db.query(DBAgentState).filter(
        DBAgentState.run_id == state_in.run_id, 
        DBAgentState.agent_id == state_in.agent_id
    ).first()
    
    if db_state:
        for k, v in state_in.model_dump().items():
            setattr(db_state, k, v)
    else:
        db_state = DBAgentState(**state_in.model_dump())
        db.add(db_state)
        
    db.commit()
    
    # Broadcast
    state_dict = state_in.model_dump()
    state_dict['last_event_at'] = state_dict['last_event_at'].isoformat()
    await ws_manager.broadcast_json({"type": "agent_state_update", "data": state_dict})
    return {"status": "ok"}

@router.post("/internal/events/snapshot")
async def register_snapshot(snapshot_in: schemas.RunStateSnapshot, db: Session = Depends(get_db)):
    db_snap = DBRunStateSnapshot(**snapshot_in.model_dump(exclude={'id'}))
    db.add(db_snap)
    
    # Also update run meta
    db_run = db.query(DBRun).filter(DBRun.id == snapshot_in.run_id).first()
    if db_run:
        db_run.total_agents = snapshot_in.total_agents
        db_run.infected_agents = snapshot_in.infected_count
    
    db.commit()
    db.refresh(db_snap)
    
    # Broadcast
    snap_dict = schemas.RunStateSnapshot.model_validate(db_snap).model_dump()
    snap_dict['timestamp'] = snap_dict['timestamp'].isoformat()
    await ws_manager.broadcast_json({"type": "snapshot", "data": snap_dict})
    return {"status": "ok"}
