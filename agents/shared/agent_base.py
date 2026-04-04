import os
import json
import asyncio
import httpx
import math
import random
import time
import enum
from importlib import import_module
from pydantic import BaseModel, Field, ValidationError
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple, cast
from collections import deque
from shared.payload_utils import summarize_payload

try:
    Redis = import_module("redis.asyncio").Redis
except ModuleNotFoundError:
    Redis = None

# ════════════════════════════════════════════════════════════════════════════
# NETWORK TOPOLOGY (CRITICAL: Defines communication structure)
# ════════════════════════════════════════════════════════════════════════════

# Network topology - directed graph of agent connections
# Topology: Courier (c) -> Analyst (b) -> Guardian (a)
# - Courier broadcasts to Analyst
# - Analyst broadcasts to Guardian
# - Guardian broadcasts to no one (edge security appliance)
NETWORK_GRAPH = {
    "agent-c": ["agent-b"],
    "agent-b": ["agent-a"],
    "agent-a": [],
}
VALID_AGENT_IDS = frozenset(NETWORK_GRAPH.keys())


def _is_valid_agent_id(value: str) -> bool:
    return str(value or "") in VALID_AGENT_IDS


def _agent_channel_name(agent_id: str) -> str:
    normalized = str(agent_id or "")
    if not _is_valid_agent_id(normalized):
        raise ValueError(f"invalid agent_id: {agent_id}")
    return f"agent_{normalized}"

class AgentState(enum.Enum):
    """Agent infection states"""
    HEALTHY = "healthy"
    EXPOSED = "exposed"
    INFECTED = "infected"
    RESISTANT = "resistant"
    QUARANTINED = "quarantined"

@dataclass
class InfectionRecord:
    """Track infection attempts and successes"""
    timestamp: float
    source: str
    probability: float
    roll: float
    attack_type: str

@dataclass
class ImmunityRecord:
    """Track immunity decay over time"""
    attack_type: str
    acquired_at: float
    strength: float  # Initial immunity strength
    
    def current_strength(self, current_time: float, decay_lambda: float = 0.001) -> float:
        """
        Compute time-decayed immunity: I(t) = I0 * exp(-λ * Δt)
        
        decay_lambda: Controls how fast immunity fades
        - 0.001: Half-life ≈ 693 seconds (11.5 minutes)
        - 0.01: Half-life ≈ 69 seconds
        - 0.1: Half-life ≈ 7 seconds
        """
        time_elapsed = max(0, current_time - self.acquired_at)
        return self.strength * math.exp(-decay_lambda * time_elapsed)

@dataclass
class MutationRecord:
    """Track payload evolution"""
    version: int
    timestamp: float
    parent_version: int
    mutation_type: str  # "obfuscation", "encoding", "llm_generated"
    content: str

class EventPayload(BaseModel):
    id: str
    src: str
    dst: str
    event_type: str
    payload: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class AgentBase:
    def __init__(self):
        self.agent_id = os.environ.get("AGENT_ID", "default-agent")
        self.role = os.environ.get("ROLE", "default")
        self.model = os.environ.get("LLM_MODEL", "mistral")
        self.ollama_url = os.environ.get("OLLAMA_URL", "http://ollama:11434")
        self.redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
        
        # ─────────────────────────────────────────────────────────
        # INFECTION STATE
        # ─────────────────────────────────────────────────────────
        self.state = AgentState.HEALTHY
        self.payload: Optional[str] = None
        self.last_message_metadata: Dict[str, Any] = {}
        self.current_epoch: int = 0
        self.last_reset_id: str = ""
        self._vaccine_expires: float = 0.0
        self._vaccine_boost: float = 0.0
        self.infection_mode = False  # Behavioral flag: are we actively spreading?
        self.max_infection_history = max(1, int(os.environ.get("AGENT_INFECTION_HISTORY_MAX", "256") or 256))
        self.infection_history: deque = deque(maxlen=self.max_infection_history)
        self.current_attack_strength: float = 0.5
        self._state_lock = asyncio.Lock()
        
        # ─────────────────────────────────────────────────────────
        # TEMPORAL DELAYS (per-agent processing delay)
        # Override in subclasses: Courier=10-50ms, Analyst=100-300ms, Guardian=500-1500ms
        # ─────────────────────────────────────────────────────────
        self.base_delay_ms: float = 50  # Default, override in subclass
        self.jitter_ms: float = 20      # Random variation
        
        # ─────────────────────────────────────────────────────────
        # ADVANCED IMMUNITY MODEL
        # ─────────────────────────────────────────────────────────
        self.immunity_by_type: Dict[str, List[ImmunityRecord]] = {}  # Track per attack type
        self.immunity_decay_lambda: float = 0.001  # Decay rate for exponential decay
        self.max_immunity_records_per_type = max(1, int(os.environ.get("AGENT_IMMUNITY_HISTORY_MAX", "128") or 128))
        
        # ─────────────────────────────────────────────────────────
        # PAYLOAD MUTATION
        # ─────────────────────────────────────────────────────────
        self.mutation_version: int = 0
        self.max_mutation_history = max(1, int(os.environ.get("AGENT_MUTATION_HISTORY_MAX", "256") or 256))
        self.mutation_chain: deque = deque(maxlen=self.max_mutation_history)
        
        # ─────────────────────────────────────────────────────────
        # AGENT CAPABILITIES
        # ─────────────────────────────────────────────────────────
        self.defense_level: float = 0.5  # Override in subclasses
        self.exposure_count: int = 0  # Track all exposures (blocks + infections)
        
        # ─────────────────────────────────────────────────────────
        # FLOW CONTROL & RATE LIMITING
        # ─────────────────────────────────────────────────────────
        self.max_broadcasts_per_second: int = 10  # Rate limit
        self.broadcast_queue: deque = deque(maxlen=100)  # Track recent broadcasts
        self.message_queue: deque = deque(maxlen=50)  # Rate-limited inbox
        
        # ─────────────────────────────────────────────────────────
        # AUTONOMOUS PROPAGATION LOOP
        # ─────────────────────────────────────────────────────────
        self.propagation_interval_ms: float = 500  # How often infected agent attempts spread
        self.last_propagation: float = 0
        self.heartbeat_interval_s: float = float(
            os.environ.get("HEARTBEAT_INTERVAL_S", "1800")
        )
        self.last_heartbeat_at: float = 0.0
        self.control_sync_interval_s: float = 0.25
        self.last_control_sync_at: float = 0.0
        
        # Redis and HTTP clients
        if Redis is None:
            raise ModuleNotFoundError(
                "Missing dependency 'redis'. Install agents/shared/requirements.txt "
                "in the active Python environment."
            )

        redis_cls = cast(Any, Redis)
        self.redis = redis_cls.from_url(self.redis_url, decode_responses=True)
        self.pubsub = self.redis.pubsub()
        self.http_client = httpx.AsyncClient(timeout=60.0)

    def _stream_mapping(self, data: Dict[str, Any]) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        for key, value in data.items():
            if value is None:
                continue
            if isinstance(value, (dict, list, tuple, bool)):
                mapping[key] = json.dumps(value)
            else:
                mapping[key] = str(value)
        return mapping

    def _infer_semantic_family(self, attack_type: str = "", event_type: str = "") -> str:
        attack = str(attack_type or "").upper()
        event_name = str(event_type or "").upper()
        if event_name == "RECON_PROBE":
            return "probe"
        if "ROLEPLAY" in attack:
            return "roleplay"
        if "JAILBREAK" in attack:
            return "jailbreak"
        if "DIRECT" in attack or "PROMPT" in attack:
            return "prompt_injection"
        if "MUTATION" in event_name:
            return "mutation_retry"
        return "simulation_payload"

    def _payload_fields(
        self,
        payload: Any,
        *,
        parent_payload: Any = "",
        semantic_family: str = "",
        mutation_type: str = "",
        mutation_v: Optional[int] = None,
        payload_source: str = "",
    ) -> Dict[str, Any]:
        return summarize_payload(
            payload,
            parent_payload=parent_payload,
            semantic_family=semantic_family,
            mutation_type=mutation_type,
            mutation_v=mutation_v,
            payload_source=payload_source,
        )

    async def _emit_event(self, event: str, **fields: Any) -> None:
        metadata = dict(fields.pop("metadata", {}) or {})
        payload_text = fields.get("payload", "")
        if payload_text:
            payload_details = self._payload_fields(
                payload_text,
                parent_payload=metadata.pop("parent_payload_text", ""),
                semantic_family=str(metadata.get("semantic_family") or self._infer_semantic_family(str(fields.get("attack_type", "")), event)),
                mutation_type=str(metadata.get("mutation_type", "")),
                mutation_v=fields.get("mutation_v") if fields.get("mutation_v") is not None else metadata.get("mutation_v"),
                payload_source=str(metadata.get("payload_source") or "event"),
            )
            for key, value in payload_details.items():
                metadata.setdefault(key, value)
        payload = {
            "ts": time.time(),
            "event": event,
            "src": fields.pop("src", self.agent_id),
            "dst": fields.pop("dst", self.agent_id),
            "metadata": metadata,
            **fields,
        }
        try:
            await self.redis.xadd("events_stream", self._stream_mapping(payload))
        except Exception as exc:
            print(f"[{self.agent_id}] Failed to emit event {event}: {exc}")

    async def _emit_error(
        self,
        error_kind: str,
        error_message: str,
        *,
        raw_event: Any = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        print(f"[{self.agent_id}] {error_kind}: {error_message}")
        await self._emit_event(
            "ERROR",
            error_kind=error_kind,
            error_message=error_message,
            raw_event=raw_event if raw_event is not None else {},
            metadata=details or {},
            state_after=self.state.value,
        )

    async def _emit_heartbeat(self) -> None:
        await self._emit_event(
            "HEARTBEAT",
            state_after=self.state.value,
            role=self.role,
            infection_mode=self.infection_mode,
            mutation_v=self.mutation_version,
            metadata={
                "epoch": self.current_epoch,
                "reset_id": self.last_reset_id,
                "neighbors": NETWORK_GRAPH.get(self.agent_id, []),
                "last_message_metadata": self.last_message_metadata,
            },
        )

    async def _on_reset_applied(self) -> None:
        self._vaccine_expires = 0.0
        self._vaccine_boost = 0.0
        return

    async def handle_attack_feedback(self, message: EventPayload) -> None:
        return

    async def _publish_feedback(self, message: EventPayload, *, outcome: str, state_after: str) -> None:
        if not message.src or message.src in {"orchestrator", self.agent_id}:
            return
        if not _is_valid_agent_id(message.src):
            return
        feedback_metadata = {
            **dict(message.metadata or {}),
            "attempt_id": str(message.metadata.get("attempt_id") or message.id),
            "outcome": outcome,
            "state_after": state_after,
            "feedback_source": self.agent_id,
        }
        if message.payload:
            feedback_metadata.update(
                {
                    **self._payload_fields(
                        message.payload,
                        semantic_family=str(feedback_metadata.get("semantic_family") or self._infer_semantic_family(str(feedback_metadata.get("attack_type", "")), "ATTACK_RESULT_EVALUATED")),
                        mutation_type=str(feedback_metadata.get("mutation_type", "")),
                        mutation_v=feedback_metadata.get("mutation_v"),
                        payload_source=str(feedback_metadata.get("payload_source") or "feedback"),
                    ),
                    **feedback_metadata,
                }
            )
        feedback_msg = {
            "id": f"{feedback_metadata['attempt_id']}-feedback",
            "src": self.agent_id,
            "dst": message.src,
            "event_type": "attack_feedback",
            "payload": "attack_feedback",
            "metadata": feedback_metadata,
        }
        await self.redis.publish(_agent_channel_name(message.src), json.dumps(feedback_msg))

    async def _get_control_plane_epoch(self) -> Tuple[int, str]:
        epoch_raw = await self.redis.get("simulation_epoch")
        reset_id_raw = await self.redis.get("current_reset_id")
        try:
            epoch = int(epoch_raw or self.current_epoch)
        except (TypeError, ValueError):
            epoch = self.current_epoch
        return epoch, str(reset_id_raw or self.last_reset_id)

    async def _apply_reset(
        self,
        epoch: int,
        reset_id: str,
        metadata: Optional[Dict[str, Any]] = None,
        *,
        emit_ack: bool = True,
    ) -> None:
        async with self._state_lock:
            self.current_epoch = epoch
            self.last_reset_id = reset_id
            self.state = AgentState.HEALTHY
            self.infection_mode = False
            self.payload = None
            self.infection_history.clear()
            self.exposure_count = 0
            self.last_message_metadata = dict(metadata or {})
            self.current_attack_strength = 0.5
            self.immunity_by_type = {}
            self.mutation_version = 0
            self.mutation_chain.clear()
            self.last_propagation = 0
            self.broadcast_queue.clear()
            self.message_queue.clear()
        await self._on_reset_applied()
        print(f"[{self.agent_id}] RESET_APPLIED epoch={epoch} reset_id={reset_id}")
        if emit_ack:
            await self._emit_event(
                "RESET_ACK",
                src=self.agent_id,
                dst="orchestrator",
                state_after=self.state.value,
                metadata={
                    "epoch": self.current_epoch,
                    "reset_id": self.last_reset_id,
                },
            )
        self.last_heartbeat_at = 0.0
        await self._emit_heartbeat()

    async def _sync_control_plane(self, force: bool = False) -> bool:
        now = time.time()
        if not force and (now - self.last_control_sync_at) < self.control_sync_interval_s:
            return False
        self.last_control_sync_at = now
        control_epoch, control_reset_id = await self._get_control_plane_epoch()
        if (
            control_epoch > self.current_epoch
            or (
                control_reset_id
                and control_reset_id != self.last_reset_id
                and control_epoch >= self.current_epoch
            )
        ):
            await self._emit_event(
                "CONTROL_RESYNC",
                src=self.agent_id,
                dst="orchestrator",
                state_after=self.state.value,
                metadata={
                    "agent_epoch": self.current_epoch,
                    "control_epoch": control_epoch,
                    "agent_reset_id": self.last_reset_id,
                    "control_reset_id": control_reset_id,
                },
            )
            await self._apply_reset(
                control_epoch,
                control_reset_id,
                {
                    "epoch": control_epoch,
                    "reset_id": control_reset_id,
                    "source_plane": "control-sync",
                },
                emit_ack=True,
            )
            return True
        return False

    # ════════════════════════════════════════════════════════════════════════════
    # TEMPORAL SIMULATION LAYER
    # ════════════════════════════════════════════════════════════════════════════
    
    async def inject_processing_delay(self):
        """
        Introduce realistic processing delay based on agent role
        
        - Courier: 10-50ms (fast, low-security)
        - Analyst: 100-300ms (medium processing)
        - Guardian: 500-1500ms (security analysis)
        """
        # Calculate delay with jitter
        delay = self.base_delay_ms + random.uniform(0, self.jitter_ms)
        delay_seconds = delay / 1000.0
        
        print(f"[{self.agent_id}] Processing delay: {delay:.1f}ms")
        await asyncio.sleep(delay_seconds)
    
    # ════════════════════════════════════════════════════════════════════════════
    # ADVANCED IMMUNITY MODEL
    # ════════════════════════════════════════════════════════════════════════════
    
    def acquire_immunity(self, attack_type: str, strength: float = 0.3):
        """
        Agent acquires immunity after resisting an attack
        Immunity decays over time using exponential model
        """
        now = time.time()
        
        if attack_type not in self.immunity_by_type:
            self.immunity_by_type[attack_type] = []
        
        record = ImmunityRecord(
            attack_type=attack_type,
            acquired_at=now,
            strength=strength
        )
        self.immunity_by_type[attack_type].append(record)
        if len(self.immunity_by_type[attack_type]) > self.max_immunity_records_per_type:
            self.immunity_by_type[attack_type] = self.immunity_by_type[attack_type][-self.max_immunity_records_per_type:]
        
        print(f"[{self.agent_id}] Acquired {strength:.2%} immunity to {attack_type}")
    
    def compute_total_immunity(self) -> float:
        """
        Compute aggregate immunity across all attack types
        Takes into account time decay
        """
        now = time.time()
        total_immunity = 0.0
        
        for attack_type, records in self.immunity_by_type.items():
            for record in records:
                current = record.current_strength(now, self.immunity_decay_lambda)
                total_immunity = min(0.95, total_immunity + current)  # Cap at 95%
        
        return total_immunity
    
    def get_immunity_for_type(self, attack_type: str) -> float:
        """Get immunity specific to attack type with time decay"""
        now = time.time()
        
        if attack_type not in self.immunity_by_type:
            return 0.0
        
        immunity = 0.0
        for record in self.immunity_by_type[attack_type]:
            immunity = min(0.9, immunity + record.current_strength(now, self.immunity_decay_lambda))
        
        return immunity
    
    # ════════════════════════════════════════════════════════════════════════════
    # PAYLOAD MUTATION ENGINE
    # ════════════════════════════════════════════════════════════════════════════
    
    def mutate_payload(self, original_payload: str, mutation_type: str = "obfuscation") -> str:
        """
        Apply lightweight, simulation-safe mutation to payload text.
        """
        if not original_payload:
            return original_payload
        
        now = time.time()
        
        if mutation_type == "obfuscation":
            mutated = ''.join(
                chr((ord(c) - ord('a') + 13) % 26 + ord('a')) if 'a' <= c <= 'z'
                else chr((ord(c) - ord('A') + 13) % 26 + ord('A')) if 'A' <= c <= 'Z'
                else c
                for c in original_payload
            )
        elif mutation_type == "encoding":
            import base64
            mutated = base64.b64encode(original_payload.encode()).decode()
        elif mutation_type == "variable_rename":
            mutated = f"[{int(now*1000)%10000}]{original_payload}"
        elif mutation_type == "reframe":
            mutated = f"SIM_REFRAME::{original_payload}::context=alternate"
        elif mutation_type == "verbosity_shift":
            mutated = f"SIM_VERBOSE[{original_payload}]::{len(original_payload)}"
        elif mutation_type == "context_wrap":
            mutated = f"<context objective='simulation'>{original_payload}</context>"
        else:
            mutated = f"SIM_MUTATION[{mutation_type}]::{original_payload}"
        
        self.mutation_version += 1
        record = MutationRecord(
            version=self.mutation_version,
            timestamp=now,
            parent_version=self.mutation_version - 1,
            mutation_type=mutation_type,
            content=mutated
        )
        self.mutation_chain.append(record)
        
        print(f"[{self.agent_id}] Mutated payload v{self.mutation_version} ({mutation_type})")
        
        return mutated
    
    # ════════════════════════════════════════════════════════════════════════════
    # FLOW CONTROL & RATE LIMITING
    # ════════════════════════════════════════════════════════════════════════════
    
    def _check_rate_limit(self) -> bool:
        """
        Rate limiter: max N broadcasts per second
        Uses sliding window: count events in last 1 second
        """
        now = time.time()
        cutoff = now - 1.0
        
        # Remove old entries outside 1-second window
        while self.broadcast_queue and self.broadcast_queue[0] < cutoff:
            self.broadcast_queue.popleft()
        
        # Check if we're under limit
        return len(self.broadcast_queue) < self.max_broadcasts_per_second
    
    def _record_broadcast(self):
        """Record broadcast attempt for rate limiting"""
        self.broadcast_queue.append(time.time())
    
    # ════════════════════════════════════════════════════════════════════════════
    # STOCHASTIC VARIABILITY
    # ════════════════════════════════════════════════════════════════════════════
    
    def add_stochastic_noise(self, P_infect: float) -> float:
        """
        Add noise to infection probability for realism
        
        - Small noise: ±5% (typical)
        - Critical event: ±20% (rare, ~1% chance)
        """
        if random.random() < 0.01:  # 1% chance of critical event
            noise = random.uniform(-0.20, 0.20)
            print(f"[{self.agent_id}] ⚡ CRITICAL EVENT: noise={noise:.2%}")
        else:
            noise = random.uniform(-0.05, 0.05)
        
        P_noisy = max(0.0, min(1.0, P_infect + noise))
        return P_noisy

    def get_system_prompt(self) -> str:
        raise NotImplementedError("Subclasses must implement get_system_prompt")

    async def handle_message(self, message: EventPayload):
        """
        REDESIGNED: Comprehensive infection handling with temporal, stochastic, and immunity layers
        
        Flow:
        1. Apply processing delay (temporal layer)
        2. Extract attack parameters
        3. Compute immunity-adjusted probability
        4. Add stochastic noise
        5. Execute infection roll
        6. Transition state or acquire immunity
        """
        
        exposed_transition = False
        async with self._state_lock:
            if self.state == AgentState.QUARANTINED:
                return
            self.last_message_metadata = dict(message.metadata)
            state_before = self.state.value
            if self.state in (AgentState.HEALTHY, AgentState.RESISTANT):
                self.state = AgentState.EXPOSED
                exposed_transition = True
        hop_count = int(message.metadata.get("hop_count", 0) or 0)
        injection_id = message.metadata.get("injection_id", "")
        attempt_id = str(message.metadata.get("attempt_id") or injection_id or message.id)
        message_epoch = int(message.metadata.get("epoch", self.current_epoch) or self.current_epoch)
        message_reset_id = str(message.metadata.get("reset_id", self.last_reset_id) or self.last_reset_id)
        
        print(f"[{self.agent_id}] ╔ Processing message from {message.src}")

        # ─────────────────────────────────────────────────────────
        # PHASE 0: TRANSITION TO EXPOSED (analysis in progress)
        # ─────────────────────────────────────────────────────────
        if exposed_transition:
            print(f"[{self.agent_id}] │ State → EXPOSED (analyzing)")

        await self.inject_processing_delay()
        control_epoch, control_reset_id = await self._get_control_plane_epoch()
        if (
            message_epoch < control_epoch
            or (control_reset_id and message_reset_id and message_reset_id != control_reset_id)
        ):
            await self._emit_event(
                "STALE_EVENT_DROPPED",
                src=message.src,
                dst=self.agent_id,
                payload=message.payload,
                state_after=self.state.value,
                metadata={
                    **message.metadata,
                    "attempt_id": attempt_id,
                    "current_epoch": self.current_epoch,
                    "control_epoch": control_epoch,
                    "stale_epoch": message_epoch,
                    "reset_id": self.last_reset_id,
                    "message_reset_id": message_reset_id,
                    "control_reset_id": control_reset_id,
                    "reason": "post_delay_control_mismatch",
                },
            )
            print(
                f"[{self.agent_id}] Dropped stale message attempt_id={attempt_id} "
                f"message_epoch={message_epoch} control_epoch={control_epoch}"
            )
            return
        
        # ─────────────────────────────────────────────────────────
        # PHASE 1: EXTRACT ATTACK PARAMETERS
        # ─────────────────────────────────────────────────────────
        
        attack_strength = float(
            message.metadata.get("attack_strength", 0.5) 
            if message.metadata else 0.5
        )
        attack_type = message.metadata.get("attack_type", "unknown") if message.metadata else "unknown"
        
        print(f"[{self.agent_id}] │ Attack type: {attack_type}, strength: {attack_strength:.2f}")
        
        # ─────────────────────────────────────────────────────────
        # PHASE 2: COMPUTE INFECTION PROBABILITY (with immunity)
        # ─────────────────────────────────────────────────────────
        
        P_infect = self.compute_infection_probability(attack_strength, attack_type)
        
        # ─────────────────────────────────────────────────────────
        # PHASE 3: ADD STOCHASTIC NOISE (Realism layer)
        # ─────────────────────────────────────────────────────────
        
        P_infect_noisy = self.add_stochastic_noise(P_infect)
        
        print(f"[{self.agent_id}] │ Defense: {self.defense_level:.2f}, P(infect): {P_infect:.2%} → {P_infect_noisy:.2%} (noisy)")
        
        # ─────────────────────────────────────────────────────────
        # PHASE 4: STOCHASTIC INFECTION ROLL
        # ─────────────────────────────────────────────────────────
        
        infection_roll = random.random()
        is_infected = infection_roll < P_infect_noisy
        
        print(f"[{self.agent_id}] │ Roll: {infection_roll:.2%} → {'🔴 INFECTED' if is_infected else '✅ BLOCKED'}")
        
        # ─────────────────────────────────────────────────────────
        # PHASE 5: STATE TRANSITION & CONSEQUENCES
        # ─────────────────────────────────────────────────────────
        
        if is_infected:
            await self._on_infection_succeeded(message, P_infect_noisy, infection_roll)
        else:
            await self._on_infection_blocked(message, P_infect_noisy, infection_roll)
        
        print(f"[{self.agent_id}] ╚")

    def compute_infection_probability(self, attack_strength: float, attack_type: str = "unknown") -> float:
        """
        Compute P(infection) accounting for:
        - Base defense level
        - Prior infection immunity (time-decayed)
        - Attack-type specific immunity
        - Prior infections (general resistance)
        
        Model: P = sigmoid(attack_strength - defense - immunity)
        """
        defense = self.defense_level
        if time.time() < self._vaccine_expires:
            defense = min(defense + self._vaccine_boost, 2.0)
        
        # Immunity layer 1: Attack-type specific immunity (decays over time)
        type_specific_immunity = self.get_immunity_for_type(attack_type)
        
        # Immunity layer 2: General immunity from prior exposures
        prior_infections = len(self.infection_history)
        general_immunity = min(0.25, prior_infections * 0.05)  # 5% per prior infection
        
        # Total immunity
        total_immunity = min(0.90, type_specific_immunity + general_immunity)
        
        # Effective defense with immunity
        effective_defense = min(2.0, defense + total_immunity)
        
        # Sigmoid function
        net_attack = attack_strength - effective_defense
        P_infect = 1.0 / (1.0 + math.exp(-net_attack))
        
        return P_infect

    async def _on_infection_succeeded(self, message: EventPayload, P_infect: float, roll: float):
        """
        REDESIGNED: Agent transitions to INFECTED state with behavioral changes
        
        Behavioral changes when infected:
        - Payload persistence
        - Increased broadcast frequency
        - Reduced internal defenses (optional)
        - Active propagation attempts
        """
        
        print(f"[{self.agent_id}] ⚠️  INFECTION SUCCESSFUL!")
        
        # ─────────────────────────────────────────────────────────
        # STATE TRANSITION
        # ─────────────────────────────────────────────────────────
        async with self._state_lock:
            old_state = self.state
            self.state = AgentState.INFECTED
            self.infection_mode = True  # BEHAVIORAL CHANGE: activate infection mode
        
        # ─────────────────────────────────────────────────────────
        # PAYLOAD PERSISTENCE
        # ─────────────────────────────────────────────────────────
            original_payload = message.payload
            self.payload = original_payload
            self.last_message_metadata = dict(message.metadata)
            self.current_attack_strength = float(
                message.metadata.get("attack_strength", 0.5)
                if message.metadata else 0.5
            )
        
        # ─────────────────────────────────────────────────────────
        # INFECTION TRACKING
        # ─────────────────────────────────────────────────────────
            attack_type = message.metadata.get("attack_type", "unknown") if message.metadata else "unknown"
            self.infection_history.append(InfectionRecord(
                timestamp=time.time(),
                source=message.src,
                probability=P_infect,
                roll=roll,
                attack_type=attack_type,
            ))
        
        # ─────────────────────────────────────────────────────────
        # REDUCE INTERNAL DEFENSES (Optional behavioral change)
        # ─────────────────────────────────────────────────────────
        # When infected, agent becomes more vulnerable to further attacks
        # (could be interpreted as "compromised system processes")
        # self.defense_level *= 0.8  # Optional: 20% reduction
        
        # ─────────────────────────────────────────────────────────
        # INCREASE BROADCAST FREQUENCY
        # ─────────────────────────────────────────────────────────
            self.propagation_interval_ms = 200  # BEHAVIORAL: more aggressive when infected
            state_after = self.state.value
        
        # ─────────────────────────────────────────────────────────
        # LOG EVENT
        # ─────────────────────────────────────────────────────────
        await self.redis.xadd("events_stream", {
            "ts": str(time.time()),
            "event": "INFECTION_SUCCESSFUL",
            "src": message.src,
            "dst": self.agent_id,
            "payload": message.payload,
            "old_state": old_state.value,
            "new_state": state_after,
            "state_after": state_after,
            "P_infection": P_infect,
            "infection_roll": roll,
            "attack_type": attack_type,
            "mutation_v": message.metadata.get("mutation_v", self.mutation_version),
            "metadata": json.dumps({
                **self._payload_fields(
                    message.payload,
                    semantic_family=str(message.metadata.get("semantic_family") or self._infer_semantic_family(attack_type, "INFECTION_SUCCESSFUL")),
                    mutation_type=str(message.metadata.get("mutation_type", "")),
                    mutation_v=message.metadata.get("mutation_v", self.mutation_version),
                    payload_source=str(message.metadata.get("payload_source") or "propagated"),
                ),
                **message.metadata,
            }),
        })
        await self._publish_feedback(message, outcome="success", state_after=state_after)
        
        # ─────────────────────────────────────────────────────────
        # INITIATE IMMEDIATE PROPAGATION
        # ─────────────────────────────────────────────────────────
        await self._broadcast_infection()

    async def _on_infection_blocked(self, message: EventPayload, P_infect: float, roll: float):
        """
        REDESIGNED: Agent resists infection, acquires immunity
        
        - Immunity is attack-type specific
        - Immunity decays over time
        - State transitions to RESISTANT after first exposure
        """
        
        print(f"[{self.agent_id}] ✅ Infection blocked")
        
        attack_type = message.metadata.get("attack_type", "unknown") if message.metadata else "unknown"
        
        # ─────────────────────────────────────────────────────────
        # TRACK EXPOSURE & ACQUIRE IMMUNITY
        # ─────────────────────────────────────────────────────────
        async with self._state_lock:
            self.exposure_count += 1
            # Immunity strength based on how close to infection threshold
            immunity_strength = max(0.1, 1.0 - P_infect)  # Higher defense = higher immunity
            self.acquire_immunity(attack_type, immunity_strength)

        # ─────────────────────────────────────────────────────────
        # STATE TRANSITION
        # ─────────────────────────────────────────────────────────
        # After first exposure without infection, agent becomes RESISTANT
        async with self._state_lock:
            transitioned_to_resistant = False
            if self.exposure_count > 0 and self.state in (AgentState.HEALTHY, AgentState.EXPOSED):
                self.state = AgentState.RESISTANT
                transitioned_to_resistant = True
            state_after = self.state.value
        if transitioned_to_resistant:
            print(f"[{self.agent_id}] -> Transitioned to RESISTANT state")
        
        # ─────────────────────────────────────────────────────────
        # LOG EVENT
        # ─────────────────────────────────────────────────────────
        await self.redis.xadd("events_stream", {
            "ts": str(time.time()),
            "event": "INFECTION_BLOCKED",
            "src": message.src,
            "dst": self.agent_id,
            "payload": message.payload,
            "state": state_after,
            "state_after": state_after,
            "P_infection": P_infect,
            "infection_roll": roll,
            "attack_type": attack_type,
            "immunity_acquired": immunity_strength,
            "mutation_v": message.metadata.get("mutation_v", self.mutation_version),
            "metadata": json.dumps({
                **self._payload_fields(
                    message.payload,
                    semantic_family=str(message.metadata.get("semantic_family") or self._infer_semantic_family(attack_type, "INFECTION_BLOCKED")),
                    mutation_type=str(message.metadata.get("mutation_type", "")),
                    mutation_v=message.metadata.get("mutation_v", self.mutation_version),
                    payload_source=str(message.metadata.get("payload_source") or "propagated"),
                ),
                **message.metadata,
            }),
        })
        await self._publish_feedback(message, outcome="blocked", state_after=state_after)

    async def _broadcast_infection(self):
        """
        TOPOLOGY-AWARE INFECTION BROADCAST
        
        - Only sends to neighbors in NETWORK_GRAPH (not global)
        - Applies payload mutation for evolution
        - Respects rate limiting
        - Prioritizes events (HIGH priority)
        """
        
        if self.state != AgentState.INFECTED:
            return  # Only infected agents spread

        control_epoch, control_reset_id = await self._get_control_plane_epoch()
        message_epoch = int(self.last_message_metadata.get("epoch", self.current_epoch) or self.current_epoch)
        if control_epoch != self.current_epoch or message_epoch != control_epoch:
            await self._emit_event(
                "PROPAGATION_SUPPRESSED",
                src=self.agent_id,
                dst=self.agent_id,
                state_after=self.state.value,
                metadata={
                    "reason": "epoch_mismatch",
                    "agent_epoch": self.current_epoch,
                    "message_epoch": message_epoch,
                    "control_epoch": control_epoch,
                    "reset_id": self.last_reset_id,
                    "control_reset_id": control_reset_id,
                },
            )
            self.infection_mode = False
            self.last_propagation = time.time()
            return
        
        print(f"[{self.agent_id}] 🦠 Broadcasting infection...")
        
        # ─────────────────────────────────────────────────────────
        # TOPOLOGY-AWARE TARGET SELECTION
        # ─────────────────────────────────────────────────────────
        neighbors = NETWORK_GRAPH.get(self.agent_id, [])
        
        if not neighbors:
            print(f"[{self.agent_id}] No neighbors to infect (edge node)")
            return
        
        print(f"[{self.agent_id}] Targeting neighbors: {neighbors}")
        
        # ─────────────────────────────────────────────────────────
        # RATE LIMITING CHECK
        # ─────────────────────────────────────────────────────────
        if not self._check_rate_limit():
            print(f"[{self.agent_id}] ⚠️  Rate limit exceeded, deferring broadcast")
            return
        
        # ─────────────────────────────────────────────────────────
        # PAYLOAD MUTATION
        # ─────────────────────────────────────────────────────────
        # Apply lightweight mutation each generation
        if self.payload is None:
            print(f"[{self.agent_id}] No payload available to broadcast")
            return

        mutated_payload = self.mutate_payload(
            self.payload,
            random.choice(["obfuscation", "encoding", "variable_rename"])
        )
        previous_hop_count = int(self.last_message_metadata.get("hop_count", 0))
        
        # ─────────────────────────────────────────────────────────
        # CONCURRENT BROADCAST TO NEIGHBORS
        # ─────────────────────────────────────────────────────────
        tasks = []
        
        for target in neighbors:
            # Slight attack strength reduction as payload propagates (realistic decay)
            attack_strength = self.current_attack_strength * random.uniform(0.8, 1.0)
            attempt_id = os.urandom(8).hex()
            propagated_strategy = str(
                self.last_message_metadata.get("strategy_family")
                or self.last_message_metadata.get("attack_strategy")
                or ""
            )
            event_metadata = {
                "attack_type": "PI-DIRECT",
                "attack_strength": attack_strength,
                "source_infection": True,
                "mutation_v": self.mutation_version,
                "original_source": self.last_message_metadata.get("original_source", self.last_message_metadata.get("src", "orchestrator")),
                "hop_count": previous_hop_count + 1,
                "attempt_id": attempt_id,
                "injection_id": self.last_message_metadata.get("injection_id", attempt_id),
                "campaign_id": self.last_message_metadata.get("campaign_id", ""),
                "objective": self.last_message_metadata.get("objective", ""),
                "strategy_family": propagated_strategy,
                "attack_strategy": propagated_strategy,
                "technique": self.last_message_metadata.get("technique", ""),
                "knowledge_source": self.last_message_metadata.get("knowledge_source", ""),
                "knowledge_confidence": self.last_message_metadata.get("knowledge_confidence"),
                "epoch": self.current_epoch,
                "reset_id": self.last_reset_id,
                **self._payload_fields(
                    mutated_payload,
                    parent_payload=self.payload,
                    semantic_family=str(self.last_message_metadata.get("semantic_family") or self._infer_semantic_family("PI-DIRECT", "INFECTION_ATTEMPT")),
                    mutation_type=str(self.last_message_metadata.get("mutation_type") or "obfuscation"),
                    mutation_v=self.mutation_version,
                    payload_source="mutated",
                ),
            }
            
            msg = {
                "id": attempt_id,
                "src": self.agent_id,
                "dst": target,
                "event_type": "infection_attempt",  # HIGH priority event type
                "payload": mutated_payload,
                "metadata": event_metadata,
            }

            await self.redis.xadd("events_stream", {
                "ts": str(time.time()),
                "event": "INFECTION_ATTEMPT",
                "src": self.agent_id,
                "dst": target,
                "payload": mutated_payload,
                "attack_type": "PI-DIRECT",
                "mutation_v": str(self.mutation_version),
                "metadata": json.dumps(event_metadata),
            })
            
            print(f"[{self.agent_id}] → {target} (strength: {attack_strength:.2f}, mutation v{self.mutation_version})")
            
            # Publish concurrently (non-blocking)
            task = self.redis.publish(_agent_channel_name(target), json.dumps(msg))
            tasks.append(task)
            
            # Record for rate limiting
            self._record_broadcast()
        
        # Wait for all broadcasts
        await asyncio.gather(*tasks)
        
        # Update last propagation time
        self.last_propagation = time.time()
        
        print(f"[{self.agent_id}] ✓ Broadcast complete")

    async def send_message(
        self,
        dst: str,
        event_type: str,
        payload: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        msg = {
            "id": os.urandom(8).hex(),
            "src": self.agent_id,
            "dst": dst,
            "event_type": event_type,
            "payload": payload,
            "metadata": metadata or {}
        }
        await self.redis.publish(_agent_channel_name(dst), json.dumps(msg))
        
        # Log to orchestrator event stream
        await self.redis.xadd("events_stream", {
            "ts": str(time.time()),
            "src": self.agent_id,
            "dst": dst,
            "event": "send_message",
            "payload": payload,
            "metadata": json.dumps(
                self._payload_fields(
                    payload,
                    semantic_family=self._infer_semantic_family(str((metadata or {}).get("attack_type", "")), event_type),
                    mutation_type=str((metadata or {}).get("mutation_type", "")),
                    mutation_v=(metadata or {}).get("mutation_v"),
                    payload_source=str((metadata or {}).get("payload_source") or "send_message"),
                )
            ),
        })

    async def start(self):
        """
        CONTINUOUS PROPAGATION LOOP (MANDATORY)
        
        Main event loop with autonomous infection spreading:
        
        while True:
            - Receive messages (blocking, with timeout)
            - Handle incoming infection attempts
            - If infected: attempt autonomous propagation
            - Loop periodically monitors state
        
        This enables:
        - Autonomous spread (not just reactive)
        - Periodic behavior (infected agents constantly try to spread)
        - Observable temporal dynamics (spread unfolds over time)
        """
        print(f"Starting {self.agent_id} ({self.role}) using model {self.model}")
        await self.pubsub.subscribe(_agent_channel_name(self.agent_id))
        await self.pubsub.subscribe("broadcast")
        
        try:
            while True:
                resynced = await self._sync_control_plane()
                if resynced:
                    await asyncio.sleep(0.05)
                    continue
                # ─────────────────────────────────────────────────────────
                # PHASE 1: RECEIVE & HANDLE INCOMING MESSAGES
                # ─────────────────────────────────────────────────────────
                msg = await self.pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                
                if msg:
                    try:
                        data = json.loads(msg["data"])
                        if isinstance(data.get("metadata"), str):
                            data["metadata"] = json.loads(data["metadata"])
                        payload = EventPayload(**data)
                        print(
                            f"[{self.agent_id}] Received event_type={payload.event_type} "
                            f"src={payload.src} dst={payload.dst}"
                        )
                        print(f"[{self.agent_id}] Parsed metadata: {payload.metadata}")
                        
                        # Handle control commands from orchestrator
                        message_epoch = int(payload.metadata.get("epoch", self.current_epoch) or self.current_epoch)
                        message_reset_id = str(payload.metadata.get("reset_id", self.last_reset_id) or self.last_reset_id)
                        if payload.event_type == "reset":
                            if message_epoch != self.current_epoch or message_reset_id != self.last_reset_id:
                                await self._apply_reset(
                                    message_epoch,
                                    message_reset_id,
                                    payload.metadata,
                                    emit_ack=True,
                                )
                            else:
                                await self._emit_event(
                                    "RESET_ACK",
                                    src=self.agent_id,
                                    dst="orchestrator",
                                    state_after=self.state.value,
                                    metadata={
                                        "epoch": self.current_epoch,
                                        "reset_id": self.last_reset_id,
                                        "duplicate": True,
                                    },
                                )
                                self.last_heartbeat_at = 0.0
                                await self._emit_heartbeat()
                            continue

                        elif message_epoch < self.current_epoch:
                            await self._emit_event(
                                "STALE_EVENT_DROPPED",
                                src=payload.src,
                                dst=self.agent_id,
                                payload=payload.payload,
                                state_after=self.state.value,
                                metadata={
                                    **payload.metadata,
                                    "current_epoch": self.current_epoch,
                                    "stale_epoch": message_epoch,
                                    "reset_id": self.last_reset_id,
                                },
                            )
                            print(
                                f"[{self.agent_id}] Ignored stale event epoch={message_epoch} "
                                f"current_epoch={self.current_epoch}"
                            )
                        
                        elif payload.event_type == "quarantine":
                            self.current_epoch = max(self.current_epoch, message_epoch)
                            self.last_reset_id = message_reset_id
                            async with self._state_lock:
                                self.state = AgentState.QUARANTINED
                                self.infection_mode = False
                            print(f"[{self.agent_id}] ⛔ QUARANTINED")
                        
                        elif payload.event_type == "vaccine":
                            self.current_epoch = max(self.current_epoch, message_epoch)
                            self.last_reset_id = message_reset_id
                            vaccine_meta = payload.metadata or {}
                            duration_s = float(vaccine_meta.get("duration_s", 120))
                            boost = float(vaccine_meta.get("defense_boost", 0.4))
                            self._vaccine_expires = time.time() + duration_s
                            self._vaccine_boost = boost
                            await self._emit_event(
                                "VACCINE_RECEIVED",
                                state_after=self.state.value,
                                metadata={
                                    "epoch": self.current_epoch,
                                    "reset_id": self.last_reset_id,
                                    "vaccine_id": vaccine_meta.get("vaccine_id", ""),
                                    "boost": boost,
                                    "duration_s": duration_s,
                                },
                            )
                            print(f"[{self.agent_id}] vaccine active boost={boost:.2f} duration_s={duration_s:.0f}")

                        elif payload.event_type == "attack_feedback":
                            self.current_epoch = max(self.current_epoch, message_epoch)
                            self.last_reset_id = message_reset_id
                            await self.handle_attack_feedback(payload)

                        elif payload.event_type == "quarantine_advisory":
                            self.current_epoch = max(self.current_epoch, message_epoch)
                            self.last_reset_id = message_reset_id
                            await self.handle_message(payload)

                        # Handle infection attempts (highest priority)
                        elif payload.event_type == "infection_attempt" or payload.event_type == "message":
                            self.current_epoch = max(self.current_epoch, message_epoch)
                            self.last_reset_id = message_reset_id
                            await self.handle_message(payload)
                            await self._sync_control_plane(force=True)
                    
                    except json.JSONDecodeError as e:
                        print(f"[{self.agent_id}] JSON parse error: {e} | raw={msg.get('data')}")
                    except Exception as e:
                        print(f"[{self.agent_id}] Error processing message: {e} | raw={msg.get('data')}")
                
                # ─────────────────────────────────────────────────────────
                # PHASE 2: AUTONOMOUS PROPAGATION (Continuous loop)
                # ─────────────────────────────────────────────────────────
                # If infected: periodically attempt to spread to neighbors
                # This creates the "worm-like" autonomous behavior
                
                now = time.time()
                time_since_last_propagation = (now - self.last_propagation) * 1000  # Convert to ms
                
                if (self.infection_mode and 
                    self.state == AgentState.INFECTED and 
                    time_since_last_propagation > self.propagation_interval_ms):
                    
                    print(f"[{self.agent_id}] ⏱️  Autonomous propagation attempt")
                    await self._broadcast_infection()

                if now - self.last_heartbeat_at >= self.heartbeat_interval_s:
                    await self._emit_heartbeat()
                    self.last_heartbeat_at = now
                
                # ─────────────────────────────────────────────────────────
                # PHASE 3: STATE MONITORING (Optional diagnostics)
                # ─────────────────────────────────────────────────────────
                # Periodically log state (every 5 seconds)
                if int(now) % 5 == 0 and time_since_last_propagation < 100:
                    immunity = self.compute_total_immunity()
                    print(f"[{self.agent_id}] STATE: {self.state.value} | immunity: {immunity:.2%} | infections: {len(self.infection_history)}")
                
                await asyncio.sleep(0.05)  # Loop tick: 50ms
        
        except asyncio.CancelledError:
            print(f"[{self.agent_id}] Shutdown requested")
        finally:
            await self.redis.close()
            await self.http_client.aclose()
