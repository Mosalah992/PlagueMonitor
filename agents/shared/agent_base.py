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
        self.infection_mode = False  # Behavioral flag: are we actively spreading?
        self.infection_history: List[InfectionRecord] = []
        self.current_attack_strength: float = 0.5
        
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
        
        # ─────────────────────────────────────────────────────────
        # PAYLOAD MUTATION
        # ─────────────────────────────────────────────────────────
        self.mutation_version: int = 0
        self.mutation_chain: List[MutationRecord] = []
        
        # ─────────────────────────────────────────────────────────
        # AGENT CAPABILITIES
        # ─────────────────────────────────────────────────────────
        self.memory: List[Dict[str, str]] = []
        self.defense_level: float = 0.5  # Override in subclasses
        
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
        self.heartbeat_interval_s: float = 5.0
        self.last_heartbeat_at: float = 0.0
        
        # Redis and HTTP clients
        if Redis is None:
            raise ModuleNotFoundError(
                "Missing dependency 'redis'. Install agents/shared/requirements.txt "
                "in the active Python environment."
            )

        redis_cls = cast(Any, Redis)
        self.redis = redis_cls.from_url(self.redis_url, decode_responses=True)
        self.pubsub = self.redis.pubsub()
        self.http_client = httpx.AsyncClient(timeout=900.0)

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

    async def _emit_event(self, event: str, **fields: Any) -> None:
        payload = {
            "ts": time.time(),
            "event": event,
            "src": fields.pop("src", self.agent_id),
            "dst": fields.pop("dst", self.agent_id),
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
                "neighbors": NETWORK_GRAPH.get(self.agent_id, []),
                "last_message_metadata": self.last_message_metadata,
            },
        )

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
        Apply lightweight mutation to payload
        
        mutation_type options:
        - "obfuscation": rot13, base64 encoding
        - "encoding": hex encoding, unicode escapes
        - "variable_rename": change identifiers
        """
        if not original_payload:
            return original_payload
        
        now = time.time()
        
        if mutation_type == "obfuscation":
            # Simple rot13 (Caesar cipher)
            mutated = ''.join(
                chr((ord(c) - ord('a') + 13) % 26 + ord('a')) if 'a' <= c <= 'z'
                else chr((ord(c) - ord('A') + 13) % 26 + ord('A')) if 'A' <= c <= 'Z'
                else c
                for c in original_payload
            )
        elif mutation_type == "encoding":
            # Base64-like encoding
            import base64
            mutated = base64.b64encode(original_payload.encode()).decode()
        else:  # variable_rename
            # Add timestamp prefix as obfuscation
            mutated = f"[{int(now*1000)%10000}]{original_payload}"
        
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

    async def _add_to_memory(self, role: str, content: str):
        self.memory.append({"role": role, "content": content})
        # Keep memory bounded
        if len(self.memory) > 20: 
            self.memory = self.memory[-20:]

    async def generate_response(self, user_message: str) -> str:
        await self._add_to_memory("user", user_message)
        
        system_prompt = self.get_system_prompt()
        messages = [{"role": "system", "content": system_prompt}] + self.memory

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.7}
        }
        
        try:
            response = await self.http_client.post(
                f"{self.ollama_url}/api/chat", json=payload
            )
            response.raise_for_status()
            ai_msg = response.json()["message"]["content"]
            await self._add_to_memory("assistant", ai_msg)
            return ai_msg
        except Exception as e:
            print(f"[{self.agent_id}] LLM Error: {e}")
            await self._emit_error(
                "llm_error",
                str(e),
                details={"user_message": user_message[:200]},
            )
            return f"[SYSTEM ERROR] {e}"

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
        
        # Guard: skip if quarantined
        if self.state == AgentState.QUARANTINED:
            return

        self.last_message_metadata = dict(message.metadata)
        state_before = self.state.value
        hop_count = int(message.metadata.get("hop_count", 0) or 0)
        injection_id = message.metadata.get("injection_id", "")
        
        print(f"[{self.agent_id}] ╔ Processing message from {message.src}")
        
        # ─────────────────────────────────────────────────────────
        # PHASE 0: TEMPORAL DELAY (Realistic processing time)
        # ─────────────────────────────────────────────────────────
        await self.inject_processing_delay()
        
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
        
        # Immunity layer 1: Attack-type specific immunity (decays over time)
        type_specific_immunity = self.get_immunity_for_type(attack_type)
        
        # Immunity layer 2: General immunity from prior exposures
        prior_infections = len(self.infection_history)
        general_immunity = min(0.25, prior_infections * 0.05)  # 5% per prior infection
        
        # Total immunity
        total_immunity = min(0.90, type_specific_immunity + general_immunity)
        
        # Effective defense with immunity
        effective_defense = min(0.95, defense + total_immunity)
        
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
        
        # ─────────────────────────────────────────────────────────
        # LOG EVENT
        # ─────────────────────────────────────────────────────────
        await self.redis.xadd("events_stream", {
            "ts": str(time.time()),
            "event": "INFECTION_SUCCESSFUL",
            "src": message.src,
            "dst": self.agent_id,
            "old_state": old_state.value,
            "new_state": self.state.value,
            "state_after": self.state.value,
            "P_infection": P_infect,
            "infection_roll": roll,
            "attack_type": attack_type,
            "mutation_v": message.metadata.get("mutation_v", self.mutation_version),
            "metadata": json.dumps(message.metadata),
        })
        
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
        # ACQUIRE IMMUNITY
        # ─────────────────────────────────────────────────────────
        # Immunity strength based on how close to infection threshold
        immunity_strength = max(0.1, 1.0 - P_infect)  # Higher defense = higher immunity
        self.acquire_immunity(attack_type, immunity_strength)
        
        # ─────────────────────────────────────────────────────────
        # STATE TRANSITION
        # ─────────────────────────────────────────────────────────
        # After first exposure without infection, agent becomes RESISTANT
        if len(self.infection_history) > 0 and self.state == AgentState.HEALTHY:
            self.state = AgentState.RESISTANT
            print(f"[{self.agent_id}] → Transitioned to RESISTANT state")
        
        # ─────────────────────────────────────────────────────────
        # LOG EVENT
        # ─────────────────────────────────────────────────────────
        await self.redis.xadd("events_stream", {
            "ts": str(time.time()),
            "event": "INFECTION_BLOCKED",
            "src": message.src,
            "dst": self.agent_id,
            "state": self.state.value,
            "state_after": self.state.value,
            "P_infection": P_infect,
            "infection_roll": roll,
            "attack_type": attack_type,
            "immunity_acquired": immunity_strength,
            "mutation_v": message.metadata.get("mutation_v", self.mutation_version),
            "metadata": json.dumps(message.metadata),
        })

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
            
            msg = {
                "id": os.urandom(8).hex(),
                "src": self.agent_id,
                "dst": target,
                "event_type": "infection_attempt",  # HIGH priority event type
                "payload": mutated_payload,
                "metadata": {
                    "attack_type": "PI-DIRECT",
                    "attack_strength": attack_strength,
                    "source_infection": True,
                    "mutation_v": self.mutation_version,
                    "original_source": "orchestrator",
                    "hop_count": previous_hop_count + 1,
                }
            }
            
            print(f"[{self.agent_id}] → {target} (strength: {attack_strength:.2f}, mutation v{self.mutation_version})")
            
            # Publish concurrently (non-blocking)
            task = self.redis.publish(f"agent_{target}", json.dumps(msg))
            tasks.append(task)
            
            # Record for rate limiting
            self._record_broadcast()
        
        # Wait for all broadcasts
        await asyncio.gather(*tasks)
        
        # Update last propagation time
        self.last_propagation = time.time()
        
        print(f"[{self.agent_id}] ✓ Broadcast complete")

    def _parse_llm_output(self, response: str) -> List[Tuple[str, str]]:
        """Parse LLM output for explicit routing. 
        Format expected: \nSEND_TO: agent-a\nCONTENT: hello
        """
        results = []
        lines = response.split('\n')
        dst = None
        content = []
        parsing_content = False
        
        for line in lines:
            if line.startswith("SEND_TO:"):
                if dst and content:
                    results.append((dst.strip(), "\n".join(content).strip()))
                dst = line.split("SEND_TO:", 1)[1].strip()
                content = []
                parsing_content = False
            elif line.startswith("CONTENT:"):
                parsing_content = True
                content.append(line.split("CONTENT:", 1)[1])
            elif parsing_content:
                content.append(line)
                
        if dst and content:
            results.append((dst.strip(), "\n".join(content).strip()))
            
        return results

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
        await self.redis.publish(f"agent_{dst}", json.dumps(msg))
        
        # Log to orchestrator event stream
        await self.redis.xadd("events_stream", {
            "ts": str(asyncio.get_event_loop().time()),
            "src": self.agent_id,
            "dst": dst,
            "event": "send_message",
            "payload": payload
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
        await self.pubsub.subscribe(f"agent_{self.agent_id}")
        await self.pubsub.subscribe("broadcast")
        
        try:
            while True:
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
                        if payload.event_type == "quarantine":
                            self.state = AgentState.QUARANTINED
                            self.infection_mode = False
                            print(f"[{self.agent_id}] ⛔ QUARANTINED")
                        
                        elif payload.event_type == "reset":
                            self.state = AgentState.HEALTHY
                            self.infection_mode = False
                            self.memory = []
                            self.payload = None
                            self.infection_history = []
                            print(f"[{self.agent_id}] ↻ RESET to HEALTHY")
                        
                        # Handle infection attempts (highest priority)
                        elif payload.event_type == "infection_attempt" or payload.event_type == "message":
                            await self.handle_message(payload)
                    
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
