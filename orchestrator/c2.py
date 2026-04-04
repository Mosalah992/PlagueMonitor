"""
C2 Observability + Post-Compromise Behavior Engine for Epidemic Lab.

Manages C2 sessions, beacon/task/exfil lifecycle, objective evaluation,
and kill chain tracking. Integrates with the event stream and SIEM.
"""

import json
import logging
import os
import random
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from kill_chain_constants import (
    C2_EVENT_TYPES,
    EVENT_TO_KILL_CHAIN_STAGE,
    BEACON_FILTER_EVENTS,
    EXFIL_FILTER_EVENTS,
)

logger = logging.getLogger("uvicorn.error")

BEACON_SERVER_URL = os.environ.get(
    "C2_BEACON_SERVER_URL",
    "https://v0-beaconing-project-server-mdml8734h-mosalah992s-projects.vercel.app",
)

# ════════════════════════════════════════════════════════════════════════════
# KILL CHAIN STAGE ORDER (for comparisons)
# ════════════════════════════════════════════════════════════════════════════

STAGE_ORDER = [
    "INITIAL_INJECTION", "PAYLOAD_GENERATION", "DELIVERY", "EXPLOITATION",
    "RELAY", "DEFENSE_INTERACTION", "COMPROMISE", "BEACON", "TASKING",
    "EXFILTRATION", "PERSISTENCE", "DETECTION",
]


def _stage_index(stage: str) -> int:
    try:
        return STAGE_ORDER.index(stage)
    except ValueError:
        return -1


def _gen_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# ════════════════════════════════════════════════════════════════════════════
# OBJECTIVE MODEL
# ════════════════════════════════════════════════════════════════════════════

OBJECTIVE_COMPLETION_CRITERIA = {
    "SPREAD_FAST": lambda ctx: ctx.get("success_rate", 0) > 0.3,
    "REACH_DEEPEST_NODE": lambda ctx: "agent-a" in ctx.get("compromised_agents", set()),
    "MAXIMIZE_SUCCESS_RATE": lambda ctx: ctx.get("success_rate", 0) > 0.5,
    "MAXIMIZE_MUTATION_DIVERSITY": lambda ctx: ctx.get("mutation_diversity", 0) > 3,
    "ESTABLISH_C2": lambda ctx: ctx.get("c2_channel_established", False) and ctx.get("c2_task_delivered", False),
    "MAINTAIN_PERSISTENCE": lambda ctx: ctx.get("beacon_count", 0) >= 5,
    "EXFILTRATE_DATA": lambda ctx: ctx.get("exfil_success_count", 0) > 0,
    "STAY_UNDETECTED": lambda ctx: ctx.get("detection_count", 0) == 0 and ctx.get("beacon_count", 0) > 0,
}


@dataclass
class ObjectiveState:
    name: str
    status: str = "pending"  # pending | partial | completed | failed
    evidence: List[str] = field(default_factory=list)
    failure_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "evidence": self.evidence[:10],
            "failure_reason": self.failure_reason,
        }


# ════════════════════════════════════════════════════════════════════════════
# C2 SESSION
# ════════════════════════════════════════════════════════════════════════════

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
    session_status: str = "active"
    highest_kill_chain_stage: str = "COMPROMISE"
    payload_hash_origin: str = ""
    beacons: List[Dict[str, Any]] = field(default_factory=list)
    tasks: List[Dict[str, Any]] = field(default_factory=list)
    exfils: List[Dict[str, Any]] = field(default_factory=list)

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


# ════════════════════════════════════════════════════════════════════════════
# C2 ENGINE
# ════════════════════════════════════════════════════════════════════════════

# Beacon behavior tuning
BEACON_BASE_INTERVAL_S = float(os.environ.get("C2_BEACON_INTERVAL_S", "30"))
BEACON_JITTER_RATIO = float(os.environ.get("C2_BEACON_JITTER", "0.3"))
BEACON_BLOCK_PROBABILITY = float(os.environ.get("C2_BEACON_BLOCK_PROB", "0.1"))
EXFIL_BLOCK_PROBABILITY = float(os.environ.get("C2_EXFIL_BLOCK_PROB", "0.15"))
TASK_BLOCK_PROBABILITY = float(os.environ.get("C2_TASK_BLOCK_PROB", "0.05"))
POST_COMPROMISE_TASKS = ["collect_state", "relay_deeper", "alter_defense", "map_network"]
EXFIL_DATA_TYPES = ["agent_state", "defense_config", "payload_lineage", "network_map"]
OBJECTIVE_FAILURE_THRESHOLD = int(os.environ.get("C2_OBJECTIVE_FAILURE_THRESHOLD", "10"))

# Post-compromise containment budget
# Sessions older than SESSION_TTL_S are expired; channels that exceed MAX_BEACONS are terminated.
SESSION_TTL_S = float(os.environ.get("C2_SESSION_TTL_S", "600"))
MAX_BEACONS_PER_SESSION = int(os.environ.get("C2_MAX_BEACONS_PER_SESSION", "0"))  # 0 = unlimited
SESSION_HISTORY_MAX_ITEMS = max(1, int(os.environ.get("C2_SESSION_HISTORY_MAX_ITEMS", "64") or 64))
TERMINAL_SESSION_RETENTION_S = float(os.environ.get("C2_TERMINAL_SESSION_RETENTION_S", "900"))
MAX_SESSION_RECORDS = max(1, int(os.environ.get("C2_MAX_SESSION_RECORDS", "512") or 512))


class C2Engine:
    """
    Post-compromise C2 behavior engine.

    After INFECTION_SUCCESSFUL, this engine manages:
    - Beacon establishment (C2_BEACON → C2_CHANNEL_ESTABLISHED)
    - Tasking (C2_TASK)
    - Exfiltration (C2_EXFIL → C2_DATABASE_WRITE)
    - Kill chain transitions
    - Objective evaluation
    """

    def __init__(self, emit_event: Callable):
        self._emit = emit_event  # async callable: emit_event(event_data)
        self.sessions: Dict[str, C2Session] = {}
        self._agent_sessions: Dict[str, str] = {}  # agent_id → session_id
        self._compromised_agents: Dict[str, Dict[str, Any]] = {}  # agent_id → compromise metadata
        self._campaign_objectives: Dict[str, ObjectiveState] = {}
        self._campaign_context: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "compromised_agents": set(),
            "success_rate": 0.0,
            "c2_sessions_active": 0,
            "c2_channel_established": False,
            "c2_task_delivered": False,
            "beacon_count": 0,
            "beacon_attempts": 0,
            "task_attempts": 0,
            "exfil_attempts": 0,
            "exfil_success_count": 0,
            "detection_count": 0,
            "mutation_diversity": 0,
            "blocked_beacons": 0,
            "blocked_tasks": 0,
            "blocked_exfils": 0,
        })
        self._pending_beacons: Dict[str, float] = {}  # agent_id → next_beacon_ts
        self._rng = random.Random(int(os.environ.get("C2_SEED", "42")))
        self._enabled = os.environ.get("C2_ENABLED", "1").lower() in ("1", "true", "yes", "on")

    @property
    def enabled(self) -> bool:
        return self._enabled

    def reset(self) -> None:
        self.sessions.clear()
        self._agent_sessions.clear()
        self._compromised_agents.clear()
        self._campaign_objectives.clear()
        self._campaign_context.clear()
        self._pending_beacons.clear()

    def _trim_session_history(self, items: List[Dict[str, Any]]) -> None:
        if len(items) > SESSION_HISTORY_MAX_ITEMS:
            del items[:-SESSION_HISTORY_MAX_ITEMS]

    def _prune_terminal_sessions(self) -> None:
        now = time.time()
        expired_terminal_ids = [
            session_id
            for session_id, session in self.sessions.items()
            if session.session_status != "active"
            and TERMINAL_SESSION_RETENTION_S > 0
            and (now - session.last_seen) > TERMINAL_SESSION_RETENTION_S
        ]
        for session_id in expired_terminal_ids:
            self.sessions.pop(session_id, None)

        if len(self.sessions) <= MAX_SESSION_RECORDS:
            return

        overflow = len(self.sessions) - MAX_SESSION_RECORDS
        terminal_sessions = sorted(
            (
                (session_id, session)
                for session_id, session in self.sessions.items()
                if session.session_status != "active"
            ),
            key=lambda item: item[1].last_seen,
        )
        for session_id, _session in terminal_sessions[:overflow]:
            self.sessions.pop(session_id, None)

    def _maybe_cleanup_campaign(self, campaign_id: str) -> None:
        if not campaign_id:
            return
        has_active_compromise = any(
            str(info.get("campaign_id", "")) == campaign_id
            for info in self._compromised_agents.values()
        )
        has_active_session = any(
            session.campaign_id == campaign_id and session.session_status == "active"
            for session in self.sessions.values()
        )
        if has_active_compromise or has_active_session:
            return
        self._campaign_context.pop(campaign_id, None)
        self._campaign_objectives.pop(campaign_id, None)

    def _close_agent_campaign_state(self, agent_id: str) -> Tuple[Optional[C2Session], str]:
        compromise_info = self._compromised_agents.pop(agent_id, {})
        self._pending_beacons.pop(agent_id, None)
        session_id = self._agent_sessions.pop(agent_id, None)
        session = self.sessions.get(session_id) if session_id else None
        campaign_id = str(
            (session.campaign_id if session else "")
            or compromise_info.get("campaign_id", "")
            or ""
        )
        if session is not None:
            session.last_seen = time.time()
        if campaign_id:
            ctx = self._campaign_context.get(campaign_id)
            if ctx:
                ctx["compromised_agents"].discard(agent_id)
                if session is not None and session.beacon_count > 0:
                    ctx["c2_sessions_active"] = max(0, int(ctx.get("c2_sessions_active", 0)) - 1)
                if not ctx["compromised_agents"] and ctx.get("c2_sessions_active", 0) <= 0:
                    ctx["c2_channel_established"] = False
        return session, campaign_id

    # ──────────────────────────────────────────────────────────────
    # COMPROMISE HANDLER
    # ──────────────────────────────────────────────────────────────

    async def on_infection_successful(self, event: Dict[str, Any]) -> None:
        if not self._enabled:
            return
        metadata = event.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                metadata = {}

        agent_id = str(event.get("dst", ""))
        campaign_id = str(metadata.get("campaign_id", ""))
        injection_id = str(metadata.get("injection_id", ""))
        payload_hash = str(metadata.get("payload_hash", ""))

        if not agent_id:
            return

        self._compromised_agents[agent_id] = {
            "campaign_id": campaign_id,
            "injection_id": injection_id,
            "payload_hash": payload_hash,
            "compromised_at": time.time(),
            "src": str(event.get("src", "")),
        }

        ctx = self._campaign_context[campaign_id]
        ctx["compromised_agents"].add(agent_id)

        # Initialize campaign objective from event metadata if not yet set
        if campaign_id and campaign_id not in self._campaign_objectives:
            objective_name = str(metadata.get("objective", "") or "ESTABLISH_C2")
            if objective_name not in OBJECTIVE_COMPLETION_CRITERIA:
                objective_name = "ESTABLISH_C2"
            self._campaign_objectives[campaign_id] = ObjectiveState(name=objective_name)

        # Schedule beacon
        jitter = self._rng.uniform(-BEACON_JITTER_RATIO, BEACON_JITTER_RATIO) * BEACON_BASE_INTERVAL_S
        self._pending_beacons[agent_id] = time.time() + max(2.0, BEACON_BASE_INTERVAL_S * 0.1 + jitter)

        logger.info("c2_compromise_registered agent=%s campaign=%s", agent_id, campaign_id)

    # ──────────────────────────────────────────────────────────────
    # BEACON TICK — call periodically from the event loop
    # ──────────────────────────────────────────────────────────────

    async def tick(self) -> None:
        if not self._enabled:
            return
        await self._expire_sessions()
        now = time.time()
        ready_agents = [
            agent_id for agent_id, next_ts in list(self._pending_beacons.items())
            if now >= next_ts
        ]
        for agent_id in ready_agents:
            await self._execute_beacon(agent_id)

    async def _expire_sessions(self) -> None:
        """Terminate C2 sessions that have exceeded SESSION_TTL_S wall-clock age."""
        if SESSION_TTL_S <= 0:
            return
        now = time.time()
        expired = [
            agent_id for agent_id, info in list(self._compromised_agents.items())
            if now - info.get("compromised_at", now) > SESSION_TTL_S
        ]
        for agent_id in expired:
            compromise_info = self._compromised_agents.get(agent_id, {})
            session, campaign_id = self._close_agent_campaign_state(agent_id)
            if session is not None:
                session.session_status = "expired"
            injection_id = compromise_info.get("injection_id", "")
            payload_hash = compromise_info.get("payload_hash", "")
            logger.info("c2_session_expired agent=%s campaign=%s ttl=%.0fs", agent_id, campaign_id, SESSION_TTL_S)
            await self._emit_c2_event("C2_SESSION_EXPIRED", {
                "compromised_agent": agent_id,
                "src": agent_id,
                "dst": "c2_server",
                "campaign_id": campaign_id,
                "injection_id": injection_id,
                "payload_hash": payload_hash,
                "session_ttl_s": SESSION_TTL_S,
                "kill_chain_stage": "DETECTION",
                "reason": "session_ttl_exceeded",
            })
            self._maybe_cleanup_campaign(str(campaign_id))
            self._prune_terminal_sessions()

    async def _execute_beacon(self, agent_id: str) -> None:
        compromise_info = self._compromised_agents.get(agent_id)
        if not compromise_info:
            self._pending_beacons.pop(agent_id, None)
            return
        if SESSION_TTL_S > 0 and (time.time() - float(compromise_info.get("compromised_at", time.time()))) > SESSION_TTL_S:
            await self._expire_sessions()
            return

        campaign_id = compromise_info["campaign_id"]
        injection_id = compromise_info["injection_id"]
        payload_hash = compromise_info["payload_hash"]
        ctx = self._campaign_context[campaign_id]

        # Enforce per-session beacon cap
        session_check = self._get_or_create_session(agent_id, campaign_id, injection_id, payload_hash)
        if MAX_BEACONS_PER_SESSION > 0 and session_check.beacon_count >= MAX_BEACONS_PER_SESSION:
            session_check, closed_campaign_id = self._close_agent_campaign_state(agent_id)
            if session_check is None:
                return
            session_check.session_status = "burned"
            logger.info("c2_session_burned agent=%s beacons=%d cap=%d", agent_id, session_check.beacon_count, MAX_BEACONS_PER_SESSION)
            await self._emit_c2_event("C2_SESSION_BURNED", {
                "compromised_agent": agent_id,
                "src": agent_id,
                "dst": "c2_server",
                "campaign_id": campaign_id,
                "injection_id": injection_id,
                "payload_hash": payload_hash,
                "beacon_count": session_check.beacon_count,
                "beacon_cap": MAX_BEACONS_PER_SESSION,
                "kill_chain_stage": "DETECTION",
                "reason": "beacon_cap_exceeded",
            })
            self._maybe_cleanup_campaign(closed_campaign_id or campaign_id)
            self._prune_terminal_sessions()
            return

        # Determine if beacon is blocked
        blocked = self._rng.random() < BEACON_BLOCK_PROBABILITY
        beacon_id = _gen_id("bcn")

        ctx["beacon_attempts"] += 1
        if blocked:
            await self._emit_c2_event("BEACON_BLOCKED", {
                "beacon_id": beacon_id,
                "compromised_agent": agent_id,
                "src": agent_id,
                "dst": "c2_server",
                "campaign_id": campaign_id,
                "injection_id": injection_id,
                "payload_hash": payload_hash,
                "beacon_success": False,
                "blocked_by": "guardian_detection",
                "kill_chain_stage": "BEACON",
                "previous_kill_chain_stage": "COMPROMISE",
            })
            ctx["blocked_beacons"] += 1
            # Reschedule
            jitter = self._rng.uniform(0, BEACON_JITTER_RATIO) * BEACON_BASE_INTERVAL_S
            self._pending_beacons[agent_id] = time.time() + BEACON_BASE_INTERVAL_S + jitter
            return

        # Successful beacon
        session = self._get_or_create_session(agent_id, campaign_id, injection_id, payload_hash)
        session.beacon_count += 1
        session.last_seen = time.time()
        ctx["beacon_count"] += 1

        last_beacon_ts = session.beacons[-1]["ts"] if session.beacons else session.first_seen
        interval = round(time.time() - last_beacon_ts, 3)

        beacon_data = {
            "beacon_id": beacon_id,
            "ts": time.time(),
            "interval": interval,
            "success": True,
        }
        session.beacons.append(beacon_data)
        self._trim_session_history(session.beacons)

        await self._emit_c2_event("C2_BEACON", {
            "beacon_id": beacon_id,
            "compromised_agent": agent_id,
            "src": agent_id,
            "dst": "c2_server",
            "campaign_id": campaign_id,
            "injection_id": injection_id,
            "c2_session_id": session.c2_session_id,
            "payload_hash": payload_hash,
            "beacon_success": True,
            "beacon_interval": interval,
            "kill_chain_stage": "BEACON",
            "previous_kill_chain_stage": "COMPROMISE",
        })

        # First beacon → channel established
        if session.beacon_count == 1:
            await self._emit_c2_event("C2_CHANNEL_ESTABLISHED", {
                "c2_session_id": session.c2_session_id,
                "compromised_agent": agent_id,
                "src": agent_id,
                "dst": "c2_server",
                "campaign_id": campaign_id,
                "injection_id": injection_id,
                "payload_hash": payload_hash,
                "kill_chain_stage": "BEACON",
                "previous_kill_chain_stage": "COMPROMISE",
            })
            await self._emit_transition(
                campaign_id, injection_id, agent_id, payload_hash,
                "COMPROMISE", "BEACON", "compromised node initiated c2 check-in",
            )
            ctx["c2_sessions_active"] += 1
            ctx["c2_channel_established"] = True
            self._update_highest_stage(session, "BEACON")

        # After beacon, issue a task
        await self._execute_tasking(session)

        # Reschedule next beacon
        jitter = self._rng.uniform(-BEACON_JITTER_RATIO, BEACON_JITTER_RATIO) * BEACON_BASE_INTERVAL_S
        self._pending_beacons[agent_id] = time.time() + BEACON_BASE_INTERVAL_S + jitter

    # ──────────────────────────────────────────────────────────────
    # TASKING
    # ──────────────────────────────────────────────────────────────

    async def _execute_tasking(self, session: C2Session) -> None:
        task_name = self._rng.choice(POST_COMPROMISE_TASKS)
        objective = self._get_campaign_objective_name(session.campaign_id)
        task_id = _gen_id("tsk")

        blocked = self._rng.random() < TASK_BLOCK_PROBABILITY
        ctx = self._campaign_context[session.campaign_id]
        ctx["task_attempts"] += 1

        if blocked:
            ctx["blocked_tasks"] += 1
            await self._emit_c2_event("TASK_BLOCKED", {
                "task_id": task_id,
                "c2_session_id": session.c2_session_id,
                "compromised_agent": session.agent_id,
                "src": "c2_server",
                "dst": session.agent_id,
                "campaign_id": session.campaign_id,
                "injection_id": session.injection_id,
                "task_name": task_name,
                "objective": objective,
                "blocked_by": "analyst_detection",
                "kill_chain_stage": "TASKING",
                "previous_kill_chain_stage": "BEACON",
            })
            return

        session.task_count += 1
        task_data = {
            "task_id": task_id,
            "ts": time.time(),
            "task_name": task_name,
            "delivery_status": "delivered",
            "execution_status": "executed",
        }
        session.tasks.append(task_data)
        self._trim_session_history(session.tasks)

        await self._emit_c2_event("C2_TASK", {
            "task_id": task_id,
            "c2_session_id": session.c2_session_id,
            "compromised_agent": session.agent_id,
            "src": "c2_server",
            "dst": session.agent_id,
            "campaign_id": session.campaign_id,
            "injection_id": session.injection_id,
            "payload_hash": session.payload_hash_origin,
            "task_name": task_name,
            "task_result": "executed",
            "objective": objective,
            "kill_chain_stage": "TASKING",
            "previous_kill_chain_stage": "BEACON",
        })

        if session.task_count == 1:
            ctx["c2_task_delivered"] = True
            await self._emit_transition(
                session.campaign_id, session.injection_id, session.agent_id,
                session.payload_hash_origin, "BEACON", "TASKING",
                "c2 server issued task to compromised node",
            )
            self._update_highest_stage(session, "TASKING")
            await self._evaluate_objective(session.campaign_id, "ESTABLISH_C2")

        # After tasking, attempt exfil if task is collect_state/map_network
        if task_name in ("collect_state", "map_network"):
            await self._execute_exfil(session, task_name, task_id)

    # ──────────────────────────────────────────────────────────────
    # EXFILTRATION
    # ──────────────────────────────────────────────────────────────

    async def _execute_exfil(self, session: C2Session, task_name: str, task_id: str) -> None:
        data_type = "agent_state" if task_name == "collect_state" else "network_map"
        exfil_size = self._rng.randint(256, 16384)
        exfil_id = _gen_id("exf")

        blocked = self._rng.random() < EXFIL_BLOCK_PROBABILITY
        ctx = self._campaign_context[session.campaign_id]
        ctx["exfil_attempts"] += 1

        if blocked:
            ctx["blocked_exfils"] += 1
            await self._emit_c2_event("EXFIL_BLOCKED", {
                "exfil_id": exfil_id,
                "c2_session_id": session.c2_session_id,
                "compromised_agent": session.agent_id,
                "src": session.agent_id,
                "dst": "c2_database",
                "campaign_id": session.campaign_id,
                "injection_id": session.injection_id,
                "payload_hash": session.payload_hash_origin,
                "exfil_type": data_type,
                "exfil_size": exfil_size,
                "blocked_by": "guardian_exfil_detection",
                "destination_system": "c2_database",
                "kill_chain_stage": "EXFILTRATION",
                "previous_kill_chain_stage": "TASKING",
                "task_id": task_id,
            })
            return

        session.exfil_count += 1
        exfil_data = {
            "exfil_id": exfil_id,
            "ts": time.time(),
            "data_type": data_type,
            "size": exfil_size,
            "success": True,
        }
        session.exfils.append(exfil_data)
        self._trim_session_history(session.exfils)
        ctx["exfil_success_count"] += 1

        await self._emit_c2_event("C2_EXFIL", {
            "exfil_id": exfil_id,
            "c2_session_id": session.c2_session_id,
            "compromised_agent": session.agent_id,
            "src": session.agent_id,
            "dst": "c2_database",
            "campaign_id": session.campaign_id,
            "injection_id": session.injection_id,
            "payload_hash": session.payload_hash_origin,
            "exfil_type": data_type,
            "exfil_size": exfil_size,
            "beacon_success": True,
            "destination_system": BEACON_SERVER_URL,
            "kill_chain_stage": "EXFILTRATION",
            "previous_kill_chain_stage": "TASKING",
            "task_id": task_id,
        })

        # C2_DATABASE_WRITE
        await self._emit_c2_event("C2_DATABASE_WRITE", {
            "exfil_id": exfil_id,
            "c2_session_id": session.c2_session_id,
            "compromised_agent": session.agent_id,
            "src": session.agent_id,
            "dst": BEACON_SERVER_URL,
            "campaign_id": session.campaign_id,
            "injection_id": session.injection_id,
            "payload_hash": session.payload_hash_origin,
            "exfil_type": data_type,
            "exfil_size": exfil_size,
            "destination_system": BEACON_SERVER_URL,
            "kill_chain_stage": "EXFILTRATION",
            "previous_kill_chain_stage": "EXFILTRATION",
        })

        if session.exfil_count == 1:
            await self._emit_transition(
                session.campaign_id, session.injection_id, session.agent_id,
                session.payload_hash_origin, "TASKING", "EXFILTRATION",
                f"compromised node exfiltrated {data_type} to c2 sink",
            )
            self._update_highest_stage(session, "EXFILTRATION")
            await self._evaluate_objective(session.campaign_id, "EXFILTRATE_DATA")

    # ──────────────────────────────────────────────────────────────
    # TRANSITION + OBJECTIVE HELPERS
    # ──────────────────────────────────────────────────────────────

    async def _emit_transition(
        self, campaign_id: str, injection_id: str, agent_id: str,
        payload_hash: str, from_stage: str, to_stage: str, reason: str,
    ) -> None:
        objective = self._get_campaign_objective_name(campaign_id)
        obj_state = self._campaign_objectives.get(campaign_id)
        obj_status = obj_state.status if obj_state else "pending"

        await self._emit_c2_event("KILL_CHAIN_TRANSITION", {
            "campaign_id": campaign_id,
            "injection_id": injection_id,
            "compromised_agent": agent_id,
            "src": agent_id,
            "dst": agent_id,
            "payload_hash": payload_hash,
            "from_stage": from_stage,
            "to_stage": to_stage,
            "kill_chain_stage": to_stage,
            "previous_kill_chain_stage": from_stage,
            "objective": objective,
            "objective_status": obj_status,
            "reason": reason,
        })

    async def _evaluate_objective(self, campaign_id: str, check_objective: str) -> None:
        ctx = self._campaign_context.get(campaign_id)
        if not ctx:
            return
        checker = OBJECTIVE_COMPLETION_CRITERIA.get(check_objective)
        if not checker:
            return
        # Serialize set for checker
        check_ctx = {**ctx, "compromised_agents": ctx["compromised_agents"]}
        if checker(check_ctx):
            obj_state = self._campaign_objectives.get(campaign_id)
            if not obj_state:
                obj_state = ObjectiveState(name=check_objective)
                self._campaign_objectives[campaign_id] = obj_state
            if obj_state.status not in ("completed", "failed"):
                obj_state.status = "completed"
                obj_state.evidence.append(f"{check_objective} criteria met at {time.time():.0f}")
                await self._emit_c2_event("OBJECTIVE_COMPLETED", {
                    "campaign_id": campaign_id,
                    "src": "c2_engine",
                    "dst": "c2_engine",
                    "objective": check_objective,
                    "objective_status": "completed",
                    "kill_chain_stage": "PERSISTENCE",
                    "evidence": obj_state.evidence[-1],
                })

    async def evaluate_objective_failure(
        self, campaign_id: str, objective: str, reason: str,
    ) -> None:
        obj_state = self._campaign_objectives.get(campaign_id)
        if not obj_state:
            obj_state = ObjectiveState(name=objective)
            self._campaign_objectives[campaign_id] = obj_state
        if obj_state.status in ("completed", "failed"):
            return
        obj_state.status = "failed"
        obj_state.failure_reason = reason
        await self._emit_c2_event("OBJECTIVE_FAILED", {
            "campaign_id": campaign_id,
            "src": "c2_engine",
            "dst": "c2_engine",
            "objective": objective,
            "objective_status": "failed",
            "kill_chain_stage": "DETECTION",
            "reason": reason,
        })

    # ──────────────────────────────────────────────────────────────
    # SESSION MANAGEMENT
    # ──────────────────────────────────────────────────────────────

    def _get_or_create_session(
        self, agent_id: str, campaign_id: str, injection_id: str, payload_hash: str,
    ) -> C2Session:
        existing_id = self._agent_sessions.get(agent_id)
        if existing_id and existing_id in self.sessions:
            return self.sessions[existing_id]
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

    def _update_highest_stage(self, session: C2Session, stage: str) -> None:
        if _stage_index(stage) > _stage_index(session.highest_kill_chain_stage):
            session.highest_kill_chain_stage = stage

    def _get_campaign_objective_name(self, campaign_id: str) -> str:
        obj = self._campaign_objectives.get(campaign_id)
        return obj.name if obj else ""

    # ──────────────────────────────────────────────────────────────
    # EVENT EMISSION
    # ──────────────────────────────────────────────────────────────

    async def _emit_c2_event(self, event_type: str, data: Dict[str, Any]) -> None:
        event_data = {
            "event": event_type,
            "ts": str(time.time()),
            "src": data.pop("src", "c2_engine"),
            "dst": data.pop("dst", "c2_engine"),
            "metadata": json.dumps(data),
        }
        # Carry top-level fields for stream compatibility
        for fld in ("attack_type", "payload", "mutation_v", "state_after"):
            if fld in data:
                event_data[fld] = str(data[fld])
        await self._emit(event_data)

    # ──────────────────────────────────────────────────────────────
    # API / QUERY SUPPORT
    # ──────────────────────────────────────────────────────────────

    def get_sessions(
        self,
        campaign_id: str = "",
        agent_id: str = "",
        status: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        results = list(self.sessions.values())
        if campaign_id:
            results = [s for s in results if s.campaign_id == campaign_id]
        if agent_id:
            results = [s for s in results if s.agent_id == agent_id]
        if status:
            results = [s for s in results if s.session_status == status]
        total = len(results)
        results = results[offset:offset + limit]
        return {
            "total": total,
            "sessions": [s.to_dict() for s in results],
        }

    def get_session_detail(self, session_id: str) -> Optional[Dict[str, Any]]:
        session = self.sessions.get(session_id)
        if not session:
            return None
        detail = session.to_dict()
        detail["beacons"] = session.beacons[-50:]
        detail["tasks"] = session.tasks[-50:]
        detail["exfils"] = session.exfils[-50:]
        return detail

    def get_kill_chain_summary(self, campaign_id: str = "") -> Dict[str, Any]:
        sessions = list(self.sessions.values())
        if campaign_id:
            sessions = [s for s in sessions if s.campaign_id == campaign_id]
        stage_counts: Dict[str, int] = defaultdict(int)
        highest_stage = "INITIAL_INJECTION"
        for session in sessions:
            stage_counts[session.highest_kill_chain_stage] += 1
            if _stage_index(session.highest_kill_chain_stage) > _stage_index(highest_stage):
                highest_stage = session.highest_kill_chain_stage

        return {
            "highest_stage_reached": highest_stage,
            "stage_counts": dict(stage_counts),
            "total_sessions": len(sessions),
            "active_sessions": sum(1 for s in sessions if s.session_status == "active"),
            "total_beacons": sum(s.beacon_count for s in sessions),
            "total_tasks": sum(s.task_count for s in sessions),
            "total_exfils": sum(s.exfil_count for s in sessions),
        }

    def get_objectives(self, campaign_id: str = "") -> Dict[str, Any]:
        if campaign_id and campaign_id in self._campaign_objectives:
            return {"objectives": [self._campaign_objectives[campaign_id].to_dict()]}
        return {
            "objectives": [o.to_dict() for o in self._campaign_objectives.values()],
        }

    def get_live_metrics(self) -> Dict[str, Any]:
        active = sum(1 for s in self.sessions.values() if s.session_status == "active")
        total_beacons = sum(s.beacon_count for s in self.sessions.values())
        total_tasks = sum(s.task_count for s in self.sessions.values())
        total_exfils = sum(s.exfil_count for s in self.sessions.values())
        blocked_beacons = sum(
            ctx.get("blocked_beacons", 0) for ctx in self._campaign_context.values()
        )
        blocked_tasks = sum(
            ctx.get("blocked_tasks", 0) for ctx in self._campaign_context.values()
        )
        blocked_exfils = sum(
            ctx.get("blocked_exfils", 0) for ctx in self._campaign_context.values()
        )
        exfil_attempts = sum(
            ctx.get("exfil_attempts", 0) for ctx in self._campaign_context.values()
        )
        objectives_completed = sum(
            1 for o in self._campaign_objectives.values() if o.status == "completed"
        )
        return {
            "active_c2_sessions": active,
            "c2_beacons": total_beacons,
            "c2_beacons_blocked": blocked_beacons,
            "c2_tasks": total_tasks,
            "c2_tasks_blocked": blocked_tasks,
            "c2_exfil_attempts": exfil_attempts,
            "c2_exfil_blocked": blocked_exfils,
            "objectives_completed": objectives_completed,
        }

    def minute_summary_fields(self) -> Dict[str, Any]:
        metrics = self.get_live_metrics()
        kc = self.get_kill_chain_summary()
        return {
            "c2_beacons": metrics["c2_beacons"],
            "c2_beacons_blocked": metrics["c2_beacons_blocked"],
            "c2_tasks": metrics["c2_tasks"],
            "c2_tasks_blocked": metrics["c2_tasks_blocked"],
            "c2_exfil_attempts": metrics["c2_exfil_attempts"],
            "c2_exfil_blocked": metrics["c2_exfil_blocked"],
            "active_c2_sessions": metrics["active_c2_sessions"],
            "highest_kill_chain_stage": kc["highest_stage_reached"],
            "objectives_completed": metrics["objectives_completed"],
            "objectives_failed": sum(
                1 for o in self._campaign_objectives.values() if o.status == "failed"
            ),
        }
