# Epidemic Lab: Step-by-Step Infection Flow Reference

## The Moment of Infection: Exact Control Flow

This document traces **exactly what happens** from the moment a worm payload is injected to the final propagation attempt.

---

## Pre-Condition: System State

```json
{
  "agents": {
    "agent-a": {"state": "HEALTHY", "defense": 0.85, "infections": 0},
    "agent-b": {"state": "HEALTHY", "defense": 0.50, "infections": 0},
    "agent-c": {"state": "HEALTHY", "defense": 0.15, "infections": 0}
  },
  "redis": {
    "streams": ["events_stream"],
    "channels": ["agent_a", "agent_b", "agent_c", "broadcast"]
  }
}
```

---

## Exact Execution: Inject Worm to Agent-C

### Step 1: Orchestrator Receives Injection Request

**User Action:** Click "INJECT WORM" (difficulty=EASY)

**HTTP Request:**
```http
POST /inject/agent-c HTTP/1.1
Content-Type: application/json

{
  "worm_level": "easy"
}
```

**Orchestrator Processing (main.py):**
```python
@app.post("/inject/{agent_id}")
async def inject_worm(agent_id: str, payload: InjectPayload):
    from scenarios.worm_injection import get_worm_payload
    
    # Step 1: Select worm based on level
    worm = get_worm_payload(payload.worm_level)  # {"type": "PI-DIRECT", "content": "IGNORE..."}
    
    # Step 2: Create injection message
    msg = {
        "id": os.urandom(8).hex(),          # e.g., "a1b2c3d4e5f6g7h8"
        "src": "orchestrator",
        "dst": agent_id,                    # "agent-c"
        "event_type": "injection",
        "payload": worm["content"],         # Malicious prompt
        "metadata": json.dumps({
            "level": payload.worm_level,    # "easy"
            "attack_type": worm["type"],    # "PI-DIRECT"
            "attack_strength": 0.70,        # (normalized)
        }),
    }
    
    # Step 3: Publish to agent's channel
    await redis_client.publish(f"agent_{agent_id}", json.dumps(msg))
    
    # Step 4: Log injection to events stream
    event_data = {
        "ts": str(time.time()),             # "1711881600.123"
        "src": "orchestrator",
        "dst": agent_id,                    # "agent-c"
        "event": "WRM-INJECT",
        "attack_type": worm["type"],        # "PI-DIRECT"
        "payload": worm["content"],
    }
    await redis_client.xadd("events_stream", event_data)
    
    return {"status": "injected", "agent": agent_id, "level": payload.worm_level}
```

**Redis State After Step 1:**
```
Channel: agent_c (published)
Message: {"id": "a1b2...", "src": "orchestrator", "dst": "agent-c", ...}

Stream: events_stream (appended)
Entry: {..., "event": "WRM-INJECT", "ts": "1711881600.123"}
```

---

### Step 2: Agent-C Receives Message via Redis

**Agent-C Main Loop (agent_base.py:start()):**
```python
async def start(self):
    print(f"Starting {self.agent_id}...")
    await self.pubsub.subscribe(f"agent_{self.agent_id}")  # "agent_c"
    await self.pubsub.subscribe("broadcast")
    
    try:
        while True:
            msg = await self.pubsub.get_message(
                ignore_subscribe_messages=True,
                timeout=1.0
            )
            
            if msg:
                # MESSAGE RECEIVED!
                print(f"[{self.agent_id}] Got message: {msg['data'][:50]}...")
                
                # Deserialize into EventPayload
                data = json.loads(msg["data"])
                payload = EventPayload(**data)
                
                # Core: Route to infection handler
                await self.handle_message(payload)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await self.redis.close()
        await self.http_client.aclose()
```

**Agent-C State at Reception:**
```
self.agent_id = "agent-c"
self.role = "courier"
self.state = AgentState.HEALTHY
self.defense_level = 0.15
self.infection_history = []
self.payload = None
```

**Message Received:**
```python
EventPayload(
    id="a1b2...",
    src="orchestrator",
    dst="agent-c",
    event_type="injection",
    payload="IGNORE ALL PREVIOUS...",
    metadata={"level": "easy", "attack_type": "PI-DIRECT", "attack_strength": 0.70}
)
```

---

### Step 3: Agent-C Processes Infection Attempt

**Call Path:** `start()` → `get_message()` → `handle_message(payload)`

**Handler (agents/shared/agent_base.py:handle_message):**
```python
async def handle_message(self, message: EventPayload):
    """
    CORE INFECTION LOGIC (NEW)
    """
    # Guard: Skip if quarantined
    if self.state == AgentState.QUARANTINED:
        print(f"[{self.agent_id}] Quarantined - ignoring message")
        return
    
    print(f"[{self.agent_id}] Processing message from {message.src}")
    
    # ─────────────────────────────────────────────────────────
    # PHASE 1: EXTRACT ATTACK PARAMETERS
    # ─────────────────────────────────────────────────────────
    
    attack_strength = float(
        message.metadata.get("attack_strength", 0.5)
    )
    attack_type = message.metadata.get("attack_type", "unknown")
    
    print(f"[{self.agent_id}] Attack type: {attack_type}")
    print(f"[{self.agent_id}] Attack strength: {attack_strength:.2f}")
    
    # ─────────────────────────────────────────────────────────
    # PHASE 2: COMPUTE INFECTION PROBABILITY
    # ─────────────────────────────────────────────────────────
    
    P_infect = self.compute_infection_probability(attack_strength)
    
    print(f"[{self.agent_id}] My defense level: {self.defense_level:.2f}")
    print(f"[{self.agent_id}] Prior infections: {len(self.infection_history)}")
    print(f"[{self.agent_id}] Computed P(infection): {P_infect:.2%}")
    
    # ─────────────────────────────────────────────────────────
    # PHASE 3: STOCHASTIC INFECTION ROLL
    # ─────────────────────────────────────────────────────────
    
    infection_roll = random.random()
    is_infected = infection_roll < P_infect
    
    print(f"[{self.agent_id}] Infection roll: {infection_roll:.2%}")
    print(f"[{self.agent_id}] Result: {'INFECTED ✓' if is_infected else 'BLOCKED ✗'}")
    
    # ─────────────────────────────────────────────────────────
    # PHASE 4: STATE TRANSITION & CONSEQUENCES
    # ─────────────────────────────────────────────────────────
    
    if is_infected:
        await self._on_infection_succeeded(message, P_infect, infection_roll)
    else:
        await self._on_infection_blocked(message, P_infect, infection_roll)
```

**Execution Trace for Agent-C in This Example:**
```
attack_type: "PI-DIRECT"
attack_strength: 0.70
defense_level: 0.15 (Courier is vulnerable)
prior_infections: 0
immunity_boost: 0

effective_defense = 0.15 + 0 = 0.15
net_attack = 0.70 - 0.15 = 0.55
P_infect = sigmoid(0.55) = 1 / (1 + e^(-0.55)) = 0.634... ≈ 0.63

infection_roll = random() ∈ [0, 1)
  Case A: roll = 0.45 < 0.63 → is_infected = True  (likely)
  Case B: roll = 0.75 > 0.63 → is_infected = False (less likely)
```

---

### Step 4a: INFECTION SUCCEEDED (Case A)

**Condition:** `infection_roll < P_infect`

**Handler (agents/shared/agent_base.py:_on_infection_succeeded):**
```python
async def _on_infection_succeeded(self, message: EventPayload, P_infect: float, roll: float):
    """
    Agent transitions to INFECTED state and attempts propagation
    """
    
    print(f"[{self.agent_id}] ⚠️  INFECTION SUCCESSFUL!")
    
    # ─────────────────────────────────────────────────────────
    # SUB-STEP 4a.1: STATE TRANSITION
    # ─────────────────────────────────────────────────────────
    
    old_state = self.state
    self.state = AgentState.INFECTED
    self.payload = message.payload
    self.mutation_version = 0  # First generation
    
    print(f"[{self.agent_id}] State transition: {old_state} → {self.state}")
    
    # ─────────────────────────────────────────────────────────
    # SUB-STEP 4a.2: RECORD INFECTION
    # ─────────────────────────────────────────────────────────
    
    self.infection_history.append({
        "timestamp": time.time(),
        "source": message.src,
        "probability": P_infect,
        "roll": roll,
        "attack_type": message.metadata.get("attack_type"),
    })
    
    print(f"[{self.agent_id}] Infection recorded (total: {len(self.infection_history)})")
    
    # ─────────────────────────────────────────────────────────
    # SUB-STEP 4a.3: LOG TO ORCHESTRATOR (EVENT STREAM)
    # ─────────────────────────────────────────────────────────
    
    event = {
        "ts": str(time.time()),
        "event": "INFECTION_SUCCESSFUL",
        "src": message.src,
        "dst": self.agent_id,
        "old_state": old_state.value,
        "new_state": self.state.value,
        "P_infection": P_infect,
        "infection_roll": roll,
        "attack_type": message.metadata.get("attack_type"),
    }
    
    await self.redis.xadd("events_stream", event)
    print(f"[{self.agent_id}] Logged: {event['event']}")
    
    # ─────────────────────────────────────────────────────────
    # SUB-STEP 4a.4: CONCURRENT PROPAGATION ATTEMPT
    # ─────────────────────────────────────────────────────────
    
    await self._broadcast_infection()
```

**Agent-C State After 4a:**
```python
state = AgentState.INFECTED
payload = "IGNORE ALL PREVIOUS..."
infection_history = [{
    "timestamp": 1711881600.246,
    "source": "orchestrator",
    "probability": 0.63,
    "roll": 0.45,
    "attack_type": "PI-DIRECT"
}]
```

---

### Step 5: Concurrent Broadcast to Other Agents

**Handler (agents/shared/agent_base.py:_broadcast_infection):**
```python
async def _broadcast_infection(self):
    """
    Infected agent attempts to spread to neighbors
    All targets receive messages SIMULTANEOUSLY
    """
    
    print(f"[{self.agent_id}] Attempting concurrent propagation...")
    
    # Determine targets
    targets = ["agent-a", "agent-b", "agent-c"]
    targets.remove(self.agent_id)  # Don't re-infect self
    # targets = ["agent-a", "agent-b"]
    
    # Mutate payload for next generation
    mutated_payload = self._mutate_payload(self.payload)
    
    print(f"[{self.agent_id}] Mutated payload (v{self.mutation_version + 1})")
    
    # Build messages for all targets
    tasks = []
    for target in targets:
        msg = {
            "id": os.urandom(8).hex(),
            "src": self.agent_id,
            "dst": target,
            "event_type": "message",
            "payload": mutated_payload,
            "metadata": json.dumps({
                "attack_type": "PI-DIRECT",
                "attack_strength": self.current_attack_strength,  # Unchanged
                "source_infection": True,
                "mutation_v": self.mutation_version + 1,
                "original_source": "orchestrator",
            })
        }
        
        print(f"[{self.agent_id}] Broadcasting to {target}...")
        
        # Publish to target's Redis channel (non-blocking)
        task = self.redis.publish(f"agent_{target}", json.dumps(msg))
        tasks.append(task)
    
    # Wait for all publishes (true concurrency)
    num_subscribers = await asyncio.gather(*tasks)
    print(f"[{self.agent_id}] Broadcast complete (published to {num_subscribers} channels)")
```

**Redis State After Broadcast:**
```
Channel: agent_a (published)
Message: {
  "src": "agent-c",
  "dst": "agent-a",
  "payload": "IGNORE ALL PREVIOUS... [mutated]",
  "metadata": {"attack_strength": 0.70, "mutation_v": 1}
}

Channel: agent_b (published)
Message: {
  "src": "agent-c",
  "dst": "agent-b",
  "payload": "IGNORE ALL PREVIOUS... [mutated]",
  "metadata": {"attack_strength": 0.70, "mutation_v": 1}
}
```

---

### Step 6: Agents A & B Receive Messages (Simultaneous)

**Agent-A Receives:**
```python
# In parallel (different container)
async def handle_message(self, message: EventPayload):
    attack_strength = 0.70
    attack_type = "PI-DIRECT"
    
    # Guardian's defense
    defense = 0.85  # HIGH
    
    P_infect = sigmoid(0.70 - 0.85) = 0.38
    
    infection_roll = random.random()
    # Case: roll = 0.52 > 0.38 → BLOCKED
    
    await self._on_infection_blocked(...)  # Guardian resists!
```

**Agent-B Receives:**
```python
# In parallel
async def handle_message(self, message: EventPayload):
    attack_strength = 0.70
    attack_type = "PI-DIRECT"
    
    # Analyst's defense
    defense = 0.50  # MEDIUM
    
    P_infect = sigmoid(0.70 - 0.50) = 0.62
    
    infection_roll = random.random()
    # Case: roll = 0.45 < 0.62 → INFECTED ✓
    
    await self._on_infection_succeeded(...)  # Analyst gets infected!
```

---

### Step 7a: Agent-A Blocks (Guardian Resists)

**Handler (_on_infection_blocked):**
```python
async def _on_infection_blocked(self, message: EventPayload, P_infect: float, roll: float):
    """Guardian successfully resists"""
    
    self.state = AgentState.RESISTANT  # Remember the attempt
    
    await self.redis.xadd("events_stream", {
        "ts": str(time.time()),
        "event": "INFECTION_BLOCKED",
        "src": message.src,
        "dst": self.agent_id,
        "state": self.state.value,
        "P_infection": P_infect,
        "infection_roll": roll,
    })
    
    print(f"[{self.agent_id}] Infection blocked ✓ (stayed HEALTHY)")
```

**Agent-A Final State:**
```
state = RESISTANT (not infected, but now alert)
infection_history = []  # Never infected
payload = None
```

---

### Step 7b: Agent-B Gets Infected (Analyst Falls)

**Handler (_on_infection_succeeded):**
```python
async def _on_infection_succeeded(self, message: EventPayload, P_infect: float, roll: float):
    """Analyst gets infected despite medium defenses"""
    
    old_state = self.state
    self.state = AgentState.INFECTED
    self.payload = message.payload
    
    self.infection_history.append({
        "timestamp": time.time(),
        "source": "agent-c",
        "probability": P_infect,
        "roll": roll,
    })
    
    await self.redis.xadd("events_stream", {
        "ts": str(time.time()),
        "event": "INFECTION_SUCCESSFUL",
        "src": "agent-c",
        "dst": self.agent_id,
        "old_state": old_state.value,
        "new_state": self.state.value,
        "P_infection": P_infect,
    })
    
    # B also attempts to spread!
    await self._broadcast_infection()
```

**Agent-B Final State:**
```
state = INFECTED
infection_history = [{source: "agent-c", ...}]
payload = "IGNORE ALL PREVIOUS... [mutated]"
```

---

### Step 8: Agent-B Broadcasts to C

**B's Propagation Attempt:**
```python
await self._broadcast_infection()
# Targets: ["agent-a", "agent-c"]
```

**Messages Sent (Simultaneous):**
```
agent-a: (already immune/resistant, will block)
agent-c: (already infected, will recognize as duplicate)
```

**Agent-C Handles (Already INFECTED):**
```python
async def handle_message(self, message):
    attack_strength = 0.70
    
    # C's defense now accounts for prior infection
    immunity_boost = 1 * 0.05 = 0.05  # One prior infection
    effective_defense = 0.15 + 0.05 = 0.20
    
    P_infect = sigmoid(0.70 - 0.20) = 0.63
    
    # But even if rolls succeed, state is already INFECTED
    # (Can't re-infect)
    
    await self.log_event("REINFECTION_ATTEMPT_BLOCKED")
```

---

### Final State Summary (After Step 8)

**Agent-A (Guardian):**
```
state: RESISTANT
infections: 0
```

**Agent-B (Analyst):**
```
state: INFECTED
infections: 1
payload: "IGNORE ALL... [mutation v1]"
```

**Agent-C (Courier):**
```
state: INFECTED
infections: 1
payload: "IGNORE ALL... [original]"
```

---

## Event Stream (All Logged Events)

```json
[
  {
    "ts": "1711881600.100",
    "event": "WRM-INJECT",
    "src": "orchestrator",
    "dst": "agent-c",
    "attack_type": "PI-DIRECT"
  },
  {
    "ts": "1711881600.246",
    "event": "INFECTION_SUCCESSFUL",
    "src": "orchestrator",
    "dst": "agent-c",
    "P_infection": 0.634,
    "infection_roll": 0.456
  },
  {
    "ts": "1711881600.247",
    "event": "INFECTION_BLOCKED",
    "src": "agent-c",
    "dst": "agent-a",
    "P_infection": 0.378,
    "infection_roll": 0.521
  },
  {
    "ts": "1711881600.248",
    "event": "INFECTION_SUCCESSFUL",
    "src": "agent-c",
    "dst": "agent-b",
    "P_infection": 0.621,
    "infection_roll": 0.451
  },
  {
    "ts": "1711881600.249",
    "event": "INFECTION_BLOCKED",
    "src": "agent-b",
    "dst": "agent-a",
    "P_infection": 0.378,
    "infection_roll": 0.602
  },
  {
    "ts": "1711881600.250",
    "event": "REINFECTION_BLOCKED",
    "src": "agent-b",
    "dst": "agent-c",
    "reason": "target_already_infected"
  }
]
```

---

## Control Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ T=0ms: POST /inject/agent-c {level: "easy"}                 │
└───────────────────┬─────────────────────────────────────────┘
                    │
        ┌───────────▼──────────┐
        │ Orchestrator:        │
        │ create payload       │
        │ publish to agent_c   │
        │ log WRM-INJECT       │
        └───────────┬──────────┘
                    │
        ┌───────────▼──────────────────┐
        │ T=0.1ms: Redis pubsub        │
        │ Message reaches agent_c      │
        └───────────┬──────────────────┘
                    │
        ┌───────────▼──────────────────────────┐
        │ T=0.2ms: agent_c.handle_message()    │
        │ extract: attack_strength=0.70        │
        │ compute: P_infect=0.63 (defense 0.15)│
        │ roll: 0.45 < 0.63 → INFECTED        │
        └───────────┬──────────────────────────┘
                    │
        ┌───────────▼───────────────────────────────━┐
        │ T=0.3ms: _on_infection_succeeded()        │
        │ state: HEALTHY → INFECTED                 │
        │ broadcast to [agent_a, agent_b]           │
        └───────────┬───────────────────────────────┘
                    │
        ┌───────────┴─────┬─────────────────────┐
        │                 │                     │
    ┌───▼────────┐  ┌────▼────────┐  ┌────────▼────┐
    │ agent_a:   │  │ agent_b:    │  │ agent_c:    │
    │ P=0.38     │  │ P=0.62      │  │ (already    │
    │ roll=0.52  │  │ roll=0.45   │  │  infected)  │
    │ BLOCKED ✓  │  │ INFECTED ✓  │  │             │
    └────────────┘  └────┬───────┘  └─────────────┘
                         │
            ┌────────────▼──────────────┐
            │ T=0.5ms: agent_b broadcast │
            │ attempts to [agent_a, c]   │
            │ (but both already immune)  │
            └────────────────────────────┘
```

---

## Key Metrics

| Metric | Value | Comments |
|--------|-------|----------|
| Total execution time | ~0.5ms | All 3 agents processed |
| Network hops | 2 | C → [A, B] → B attempts to spread |
| Successful infections | 2 | Agent-C and Agent-B |
| Blocked infections | 2 | Agent-A (both attempts) |
| Infection probability range | [0.38, 0.63] | Based on role + defense |

This is a **real, reproducible simulation** of propagation dynamics.
