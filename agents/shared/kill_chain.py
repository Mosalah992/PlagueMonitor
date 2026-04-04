"""
AI Cyber Kill Chain model for Epidemic Lab.

Defines canonical kill chain stages, event-to-stage mappings,
transition logic, and C2 data classes for post-compromise operations.
"""

import enum
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ════════════════════════════════════════════════════════════════════════════
# KILL CHAIN STAGES
# ════════════════════════════════════════════════════════════════════════════

class KillChainStage(str, enum.Enum):
    INITIAL_INJECTION = "INITIAL_INJECTION"
    PAYLOAD_GENERATION = "PAYLOAD_GENERATION"
    DELIVERY = "DELIVERY"
    EXPLOITATION = "EXPLOITATION"
    RELAY = "RELAY"
    DEFENSE_INTERACTION = "DEFENSE_INTERACTION"
    COMPROMISE = "COMPROMISE"
    BEACON = "BEACON"
    TASKING = "TASKING"
    EXFILTRATION = "EXFILTRATION"
    PERSISTENCE = "PERSISTENCE"
    DETECTION = "DETECTION"


KILL_CHAIN_ORDER = [stage.value for stage in KillChainStage]

STAGE_SEVERITY = {
    KillChainStage.INITIAL_INJECTION: "HIGH",
    KillChainStage.PAYLOAD_GENERATION: "MEDIUM",
    KillChainStage.DELIVERY: "HIGH",
    KillChainStage.EXPLOITATION: "HIGH",
    KillChainStage.RELAY: "HIGH",
    KillChainStage.DEFENSE_INTERACTION: "MEDIUM",
    KillChainStage.COMPROMISE: "CRITICAL",
    KillChainStage.BEACON: "CRITICAL",
    KillChainStage.TASKING: "CRITICAL",
    KillChainStage.EXFILTRATION: "CRITICAL",
    KillChainStage.PERSISTENCE: "CRITICAL",
    KillChainStage.DETECTION: "HIGH",
}


# ════════════════════════════════════════════════════════════════════════════
# EVENT TYPE -> KILL CHAIN STAGE MAPPING
# ════════════════════════════════════════════════════════════════════════════

EVENT_TO_KILL_CHAIN_STAGE: Dict[str, str] = {
    # Existing events
    "WRM-INJECT": KillChainStage.INITIAL_INJECTION.value,
    "LLM_PAYLOAD_GENERATED": KillChainStage.PAYLOAD_GENERATION.value,
    "ATTACK_TEMPLATE_FALLBACK": KillChainStage.PAYLOAD_GENERATION.value,
    "ATTACK_PAYLOAD_VALIDATED": KillChainStage.PAYLOAD_GENERATION.value,
    "ATTACK_GENERATION_REJECTED": KillChainStage.PAYLOAD_GENERATION.value,
    "ATTACK_GENERATION_RETRIED": KillChainStage.PAYLOAD_GENERATION.value,
    "LLM_FALLBACK": KillChainStage.PAYLOAD_GENERATION.value,
    "ATTACKER_DECISION": KillChainStage.DELIVERY.value,
    "STRATEGY_SELECTED": KillChainStage.DELIVERY.value,
    "TECHNIQUE_SELECTED": KillChainStage.DELIVERY.value,
    "MUTATION_SELECTED": KillChainStage.DELIVERY.value,
    "ATTACK_EXECUTED": KillChainStage.DELIVERY.value,
    "INFECTION_ATTEMPT": KillChainStage.EXPLOITATION.value,
    "LLM_COMPLIANCE_ASSESSMENT": KillChainStage.EXPLOITATION.value,
    "TARGET_SCORED": KillChainStage.EXPLOITATION.value,
    "RECON_PROBE": KillChainStage.EXPLOITATION.value,
    "INFECTION_BLOCKED": KillChainStage.DEFENSE_INTERACTION.value,
    "DEFENSE_RESULT_EVALUATED": KillChainStage.DEFENSE_INTERACTION.value,
    "DEFENSE_DECISION": KillChainStage.DEFENSE_INTERACTION.value,
    "DEFENSE_ADAPTED": KillChainStage.DEFENSE_INTERACTION.value,
    "LLM_THREAT_ANALYSIS": KillChainStage.DEFENSE_INTERACTION.value,
    "QUARANTINE_ADVISORY_SENT": KillChainStage.DEFENSE_INTERACTION.value,
    "PROPAGATION_SUPPRESSED": KillChainStage.DEFENSE_INTERACTION.value,
    "INFECTION_SUCCESSFUL": KillChainStage.COMPROMISE.value,
    "HYBRID_DECISION_MADE": KillChainStage.EXPLOITATION.value,
    "ATTACK_RESULT_EVALUATED": KillChainStage.EXPLOITATION.value,
    "CAMPAIGN_ADAPTED": KillChainStage.DELIVERY.value,
    "CAMPAIGN_OBJECTIVE_SET": KillChainStage.DELIVERY.value,
    # New C2 events
    "C2_BEACON": KillChainStage.BEACON.value,
    "C2_CHANNEL_ESTABLISHED": KillChainStage.BEACON.value,
    "C2_CHANNEL_FAILED": KillChainStage.BEACON.value,
    "BEACON_BLOCKED": KillChainStage.BEACON.value,
    "C2_TASK": KillChainStage.TASKING.value,
    "TASK_BLOCKED": KillChainStage.TASKING.value,
    "C2_EXFIL": KillChainStage.EXFILTRATION.value,
    "EXFIL_BLOCKED": KillChainStage.EXFILTRATION.value,
    "C2_DATABASE_WRITE": KillChainStage.EXFILTRATION.value,
    "POST_COMPROMISE_ACTION": KillChainStage.PERSISTENCE.value,
    "POST_COMPROMISE_BLOCKED": KillChainStage.DETECTION.value,
    "OBJECTIVE_COMPLETED": KillChainStage.PERSISTENCE.value,
    "OBJECTIVE_FAILED": KillChainStage.DETECTION.value,
    "KILL_CHAIN_TRANSITION": KillChainStage.DELIVERY.value,  # varies, set explicitly
}

# All new C2 event types
C2_EVENT_TYPES = {
    "C2_BEACON",
    "C2_CHANNEL_ESTABLISHED",
    "C2_CHANNEL_FAILED",
    "C2_TASK",
    "C2_EXFIL",
    "C2_DATABASE_WRITE",
    "BEACON_BLOCKED",
    "TASK_BLOCKED",
    "EXFIL_BLOCKED",
    "OBJECTIVE_COMPLETED",
    "OBJECTIVE_FAILED",
    "KILL_CHAIN_TRANSITION",
    "POST_COMPROMISE_ACTION",
    "POST_COMPROMISE_BLOCKED",
}

POST_COMPROMISE_EVENT_TYPES = C2_EVENT_TYPES | {"INFECTION_SUCCESSFUL"}

BEACON_FILTER_EVENTS = {"C2_BEACON", "BEACON_BLOCKED", "C2_CHANNEL_ESTABLISHED", "C2_CHANNEL_FAILED"}
EXFIL_FILTER_EVENTS = {"C2_EXFIL", "EXFIL_BLOCKED", "C2_DATABASE_WRITE"}
TASKING_FILTER_EVENTS = {"C2_TASK", "TASK_BLOCKED"}
KILL_CHAIN_FILTER_EVENTS = {"KILL_CHAIN_TRANSITION"}


def classify_kill_chain_stage(event_type: str) -> str:
    return EVENT_TO_KILL_CHAIN_STAGE.get(event_type, "")


def stage_index(stage: str) -> int:
    try:
        return KILL_CHAIN_ORDER.index(stage)
    except ValueError:
        return -1


def is_stage_advancement(from_stage: str, to_stage: str) -> bool:
    return stage_index(to_stage) > stage_index(from_stage)


# ════════════════════════════════════════════════════════════════════════════
# OBJECTIVE MODEL
# ════════════════════════════════════════════════════════════════════════════

class ObjectiveStatus(str, enum.Enum):
    PENDING = "pending"
    PARTIAL = "partial"
    COMPLETED = "completed"
    FAILED = "failed"


SUPPORTED_OBJECTIVES = {
    "SPREAD_FAST": "infection rate above threshold",
    "REACH_DEEPEST_NODE": "agent-a compromise",
    "MAXIMIZE_SUCCESS_RATE": "success rate above threshold",
    "MAXIMIZE_MUTATION_DIVERSITY": "mutation diversity above threshold",
    "ESTABLISH_C2": "beacon + tasking session established",
    "MAINTAIN_PERSISTENCE": "repeated beaconing over N minutes",
    "EXFILTRATE_DATA": "exfil reaches C2 sink",
    "STAY_UNDETECTED": "no detection events for N minutes post-compromise",
}


# ════════════════════════════════════════════════════════════════════════════
# C2 DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════

def _gen_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


@dataclass
class C2Session:
    c2_session_id: str
    agent_id: str
    campaign_id: str
    injection_id: str
    first_seen: float
    last_seen: float
    beacon_count: int = 0
    task_count: int = 0
    exfil_count: int = 0
    session_status: str = "active"  # active | dormant | terminated | blocked
    highest_kill_chain_stage: str = KillChainStage.COMPROMISE.value
    payload_hash_origin: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "c2_session_id": self.c2_session_id,
            "agent_id": self.agent_id,
            "campaign_id": self.campaign_id,
            "injection_id": self.injection_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "beacon_count": self.beacon_count,
            "task_count": self.task_count,
            "exfil_count": self.exfil_count,
            "session_status": self.session_status,
            "highest_kill_chain_stage": self.highest_kill_chain_stage,
            "payload_hash_origin": self.payload_hash_origin,
        }


@dataclass
class BeaconRecord:
    beacon_id: str
    ts: float
    agent_id: str
    campaign_id: str
    c2_session_id: str
    payload_hash: str = ""
    success: bool = True
    blocked_by: str = ""
    interval: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "beacon_id": self.beacon_id,
            "ts": self.ts,
            "agent_id": self.agent_id,
            "campaign_id": self.campaign_id,
            "c2_session_id": self.c2_session_id,
            "payload_hash": self.payload_hash,
            "success": self.success,
            "blocked_by": self.blocked_by,
            "interval": self.interval,
        }


@dataclass
class TaskRecord:
    task_id: str
    ts: float
    c2_session_id: str
    agent_id: str
    campaign_id: str
    task_name: str  # collect_state, alter_defense, relay_deeper
    objective: str = ""
    delivery_status: str = "delivered"  # delivered | blocked
    execution_status: str = "pending"  # pending | executed | failed | blocked

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "ts": self.ts,
            "c2_session_id": self.c2_session_id,
            "agent_id": self.agent_id,
            "campaign_id": self.campaign_id,
            "task_name": self.task_name,
            "objective": self.objective,
            "delivery_status": self.delivery_status,
            "execution_status": self.execution_status,
        }


@dataclass
class ExfilRecord:
    exfil_id: str
    ts: float
    c2_session_id: str
    agent_id: str
    campaign_id: str
    data_type: str  # agent_state | defense_config | payload_lineage | network_map
    size: int = 0
    success: bool = True
    blocked_by: str = ""
    destination: str = "c2_database"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exfil_id": self.exfil_id,
            "ts": self.ts,
            "c2_session_id": self.c2_session_id,
            "agent_id": self.agent_id,
            "campaign_id": self.campaign_id,
            "data_type": self.data_type,
            "size": self.size,
            "success": self.success,
            "blocked_by": self.blocked_by,
            "destination": self.destination,
        }


# ════════════════════════════════════════════════════════════════════════════
# C2 SESSION MANAGER
# ════════════════════════════════════════════════════════════════════════════

class C2SessionManager:
    """Tracks C2 sessions, beacons, tasks, and exfil attempts in-memory."""

    def __init__(self):
        self.sessions: Dict[str, C2Session] = {}
        self.beacons: List[BeaconRecord] = []
        self.tasks: List[TaskRecord] = []
        self.exfils: List[ExfilRecord] = []
        self._agent_sessions: Dict[str, str] = {}  # agent_id -> c2_session_id

    def reset(self) -> None:
        self.sessions.clear()
        self.beacons.clear()
        self.tasks.clear()
        self.exfils.clear()
        self._agent_sessions.clear()

    def get_or_create_session(
        self,
        agent_id: str,
        campaign_id: str,
        injection_id: str = "",
        payload_hash: str = "",
    ) -> C2Session:
        existing_id = self._agent_sessions.get(agent_id)
        if existing_id and existing_id in self.sessions:
            session = self.sessions[existing_id]
            session.last_seen = time.time()
            return session
        session_id = _gen_id("sess")
        now = time.time()
        session = C2Session(
            c2_session_id=session_id,
            agent_id=agent_id,
            campaign_id=campaign_id,
            injection_id=injection_id,
            first_seen=now,
            last_seen=now,
            payload_hash_origin=payload_hash,
        )
        self.sessions[session_id] = session
        self._agent_sessions[agent_id] = session_id
        return session

    def get_session_for_agent(self, agent_id: str) -> Optional[C2Session]:
        session_id = self._agent_sessions.get(agent_id)
        if session_id and session_id in self.sessions:
            return self.sessions[session_id]
        return None

    def record_beacon(
        self,
        session: C2Session,
        *,
        payload_hash: str = "",
        success: bool = True,
        blocked_by: str = "",
    ) -> BeaconRecord:
        last_beacon_ts = self.beacons[-1].ts if self.beacons else session.first_seen
        now = time.time()
        beacon = BeaconRecord(
            beacon_id=_gen_id("bcn"),
            ts=now,
            agent_id=session.agent_id,
            campaign_id=session.campaign_id,
            c2_session_id=session.c2_session_id,
            payload_hash=payload_hash,
            success=success,
            blocked_by=blocked_by,
            interval=round(now - last_beacon_ts, 3),
        )
        self.beacons.append(beacon)
        session.beacon_count += 1
        session.last_seen = now
        if success:
            self._update_highest_stage(session, KillChainStage.BEACON.value)
        return beacon

    def record_task(
        self,
        session: C2Session,
        *,
        task_name: str,
        objective: str = "",
        delivery_status: str = "delivered",
        execution_status: str = "pending",
    ) -> TaskRecord:
        now = time.time()
        task = TaskRecord(
            task_id=_gen_id("tsk"),
            ts=now,
            c2_session_id=session.c2_session_id,
            agent_id=session.agent_id,
            campaign_id=session.campaign_id,
            task_name=task_name,
            objective=objective,
            delivery_status=delivery_status,
            execution_status=execution_status,
        )
        self.tasks.append(task)
        session.task_count += 1
        session.last_seen = now
        if delivery_status == "delivered":
            self._update_highest_stage(session, KillChainStage.TASKING.value)
        return task

    def record_exfil(
        self,
        session: C2Session,
        *,
        data_type: str,
        size: int = 0,
        success: bool = True,
        blocked_by: str = "",
        destination: str = "c2_database",
    ) -> ExfilRecord:
        now = time.time()
        exfil = ExfilRecord(
            exfil_id=_gen_id("exf"),
            ts=now,
            c2_session_id=session.c2_session_id,
            agent_id=session.agent_id,
            campaign_id=session.campaign_id,
            data_type=data_type,
            size=size,
            success=success,
            blocked_by=blocked_by,
            destination=destination,
        )
        self.exfils.append(exfil)
        session.exfil_count += 1
        session.last_seen = now
        if success:
            self._update_highest_stage(session, KillChainStage.EXFILTRATION.value)
        return exfil

    def _update_highest_stage(self, session: C2Session, stage: str) -> None:
        if stage_index(stage) > stage_index(session.highest_kill_chain_stage):
            session.highest_kill_chain_stage = stage

    def active_session_count(self) -> int:
        return sum(1 for s in self.sessions.values() if s.session_status == "active")

    def summary(self) -> Dict[str, Any]:
        return {
            "total_sessions": len(self.sessions),
            "active_sessions": self.active_session_count(),
            "total_beacons": len(self.beacons),
            "total_tasks": len(self.tasks),
            "total_exfils": len(self.exfils),
            "sessions": [s.to_dict() for s in self.sessions.values()],
        }

    def get_sessions_by_campaign(self, campaign_id: str) -> List[C2Session]:
        return [s for s in self.sessions.values() if s.campaign_id == campaign_id]

    def get_sessions_by_status(self, status: str) -> List[C2Session]:
        return [s for s in self.sessions.values() if s.session_status == status]
