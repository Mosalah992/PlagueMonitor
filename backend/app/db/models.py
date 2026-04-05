from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean, MetaData
from sqlalchemy.orm import declarative_base
from datetime import datetime

metadata = MetaData()
Base = declarative_base(metadata=metadata)

class Run(Base):
    __tablename__ = "runs"
    
    id = Column(String, primary_key=True, index=True)
    name = Column(String, index=True)
    status = Column(String, default="idle") # idle, running, stopped, completed, error
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    topology = Column(String)
    total_agents = Column(Integer, default=0)
    infected_agents = Column(Integer, default=0)
    notes = Column(String, nullable=True)

class AgentState(Base):
    __tablename__ = "agent_states"
    
    agent_id = Column(String, primary_key=True, index=True)
    run_id = Column(String, ForeignKey("runs.id"), primary_key=True)
    name = Column(String)
    role = Column(String) # courier, analyst, guardian, etc
    cognition_tier = Column(Integer, default=1)
    status = Column(String) # healthy, exposed, infected, c2_active, exfil_active, quarantined, recovered, persistent
    infection_score = Column(Float, default=0.0)
    last_event_at = Column(DateTime, default=datetime.utcnow)
    position_x = Column(Float, default=0.0)
    position_y = Column(Float, default=0.0)
    metadata_json = Column(String, nullable=True)

class InfectionEvent(Base):
    __tablename__ = "infection_events"
    
    event_id = Column(String, primary_key=True, index=True)
    run_id = Column(String, ForeignKey("runs.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_agent = Column(String, nullable=True)
    target_agent = Column(String)
    vector = Column(String)
    payload_hash = Column(String, nullable=True)
    parent_payload_hash = Column(String, nullable=True)
    mutation = Column(String, nullable=True)
    confidence = Column(Float, default=1.0)
    outcome = Column(String)
    severity = Column(String)
    notes = Column(String, nullable=True)
    raw_metadata = Column(String, nullable=True)

class RunStateSnapshot(Base):
    __tablename__ = "run_state_snapshots"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String, ForeignKey("runs.id"))
    current_tick = Column(Integer)
    total_agents = Column(Integer)
    healthy_count = Column(Integer)
    exposed_count = Column(Integer)
    infected_count = Column(Integer)
    c2_active_count = Column(Integer)
    exfil_active_count = Column(Integer)
    quarantined_count = Column(Integer)
    recovered_count = Column(Integer)
    persistent_count = Column(Integer)
    event_count = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)
