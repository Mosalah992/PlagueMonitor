from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class RunBase(BaseModel):
    name: str
    topology: str
    notes: Optional[str] = None

class RunCreate(RunBase):
    pass

class Run(RunBase):
    id: str
    status: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    total_agents: int
    infected_agents: int
    
    class Config:
        from_attributes = True

class AgentState(BaseModel):
    agent_id: str
    run_id: str
    name: str
    role: str
    cognition_tier: int
    status: str
    infection_score: float
    last_event_at: datetime
    position_x: float
    position_y: float
    metadata_json: Optional[str] = None
    
    class Config:
        from_attributes = True

class InfectionEventBase(BaseModel):
    run_id: str
    source_agent: Optional[str] = None
    target_agent: str
    vector: str
    payload_hash: Optional[str] = None
    parent_payload_hash: Optional[str] = None
    mutation: Optional[str] = None
    confidence: float = 1.0
    outcome: str
    severity: str
    notes: Optional[str] = None
    raw_metadata: Optional[str] = None

class InfectionEventCreate(InfectionEventBase):
    pass

class InfectionEvent(InfectionEventBase):
    event_id: str
    timestamp: datetime
    
    class Config:
        from_attributes = True

class RunStateSnapshot(BaseModel):
    id: int
    run_id: str
    current_tick: int
    total_agents: int
    healthy_count: int
    exposed_count: int
    infected_count: int
    c2_active_count: int
    exfil_active_count: int
    quarantined_count: int
    recovered_count: int
    persistent_count: int
    event_count: int
    timestamp: datetime
    
    class Config:
        from_attributes = True
