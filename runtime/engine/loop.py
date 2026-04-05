import time
import random
import uuid
from datetime import datetime
from runtime.api_client import BackendAPIClient

class Agent:
    def __init__(self, run_id: str, agent_id: str, role: str):
        self.run_id = run_id
        self.agent_id = agent_id
        self.name = f"Agent-{agent_id[:6]}"
        self.role = role # courier, analyst, guardian
        self.cognition_tier = 1
        self.status = "healthy" 
        self.infection_score = 0.0
        self.position_x = random.uniform(0, 100)
        self.position_y = random.uniform(0, 100)
        
        # New High-Fidelity Attributes
        self.state_timer = 0 # Ticks spent in current status
        self.velocity = self._set_initial_velocity()
        self.c2_beacon_timer = random.randint(0, 10)
        self.exfil_timer = random.randint(0, 20)
        self.metadata = {}

    def _set_initial_velocity(self):
        if self.role == "courier":
            return random.uniform(5.0, 8.0)
        elif self.role == "analyst":
            return random.uniform(1.0, 3.0)
        return random.uniform(2.0, 4.0) # guardian/default
        
    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "name": self.name,
            "role": self.role,
            "cognition_tier": self.cognition_tier,
            "status": self.status,
            "infection_score": self.infection_score,
            "last_event_at": datetime.utcnow(),
            "position_x": self.position_x,
            "position_y": self.position_y,
            "metadata_json": "{}"
        }

class SimulationLoop:
    def __init__(self, run_id: str, topology: str):
        self.run_id = run_id
        self.topology = topology
        self.api = BackendAPIClient()
        self.agents = []
        self.tick_count = 0
        self.running = True
        
        self._initialize_topology()

    def _initialize_topology(self):
        # Create a simple topology based on request. 
        # For 'grid', 'network', etc. we'll just spawn N agents.
        # "real simulation logic"
        num_agents = 50 if self.topology == "large" else 20
        roles = ["courier", "analyst", "guardian"]
        
        for _ in range(num_agents):
            agent = Agent(self.run_id, str(uuid.uuid4()), random.choice(roles))
            self.agents.append(agent)
            
        # Seed infection
        if self.agents:
            patient_zero = random.choice(self.agents)
            patient_zero.status = "infected"
            patient_zero.infection_score = 100.0
            
        # push initial state
        for agent in self.agents:
            self.api.report_agent_state(agent.to_dict())

    def tick(self):
        self.tick_count += 1
        
        # Real logic: Spatial distance based transmission
        infected = [a for a in self.agents if a.status == "infected"]
        healthy = [a for a in self.agents if a.status == "healthy"]
        
        # Update state timers and Move agents
        for agent in self.agents:
            agent.state_timer += 1
            
            # Random walk based on velocity
            dx = random.uniform(-agent.velocity, agent.velocity)
            dy = random.uniform(-agent.velocity, agent.velocity)
            agent.position_x = max(0, min(100, agent.position_x + dx))
            agent.position_y = max(0, min(100, agent.position_y + dy))

            # Role-specific behavior: Analyst stays in clusters (zones)
            if agent.role == "analyst" and random.random() < 0.2:
                # tendency to move back to center if drifting too far
                agent.position_x += (50 - agent.position_x) * 0.1
                agent.position_y += (50 - agent.position_y) * 0.1

        # Check exposures
        for target in healthy:
            for source in infected:
                dist_sq = (target.position_x - source.position_x)**2 + (target.position_y - source.position_y)**2
                if dist_sq < 25.0: # Close proximity
                    # Probability based on tier and role
                    transmission_chance = 0.3 if target.role == 'guardian' else 0.7
                    if target.cognition_tier > 1: transmission_chance *= 0.5
                    
                    if random.random() < transmission_chance:
                        target.status = "exposed"
                        target.infection_score = 10.0
                        target.state_timer = 0
                        
                        # Emit infection event
                        self.api.report_infection_event({
                            "run_id": self.run_id,
                            "source_agent": source.agent_id,
                            "target_agent": target.agent_id,
                            "vector": "proximity_bluetooth",
                            "severity": "medium",
                            "outcome": "exposed",
                            "timestamp": datetime.utcnow()
                        })

        # State Transitions
        for agent in self.agents:
            # Exposed -> Infected
            if agent.status == "exposed":
                agent.infection_score += random.uniform(5, 15)
                if agent.infection_score > 50 or agent.state_timer > 5:
                    agent.status = "infected"
                    agent.state_timer = 0
            
            # Infected -> Recovered (or Quarantined)
            elif agent.status == "infected":
                # Simulated C2 Beaconing
                agent.c2_beacon_timer -= 1
                if agent.c2_beacon_timer <= 0:
                    self.api.report_infection_event({
                        "run_id": self.run_id,
                        "source_agent": None,
                        "target_agent": agent.agent_id,
                        "vector": "C2_BEACON",
                        "severity": "low",
                        "outcome": "active_beacon",
                        "notes": "Encrypted heartbeat sent to remote control server.",
                        "timestamp": datetime.utcnow()
                    })
                    agent.c2_beacon_timer = random.randint(5, 15)

                # Simulated Exfiltration
                agent.exfil_timer -= 1
                if agent.exfil_timer <= 0:
                    self.api.report_infection_event({
                        "run_id": self.run_id,
                        "source_agent": agent.agent_id,
                        "target_agent": "REMOTE_HOST",
                        "vector": "EXFILTRATION",
                        "severity": "high",
                        "outcome": "data_leak",
                        "notes": "Sensitive behavioral data packet exfiltrated.",
                        "timestamp": datetime.utcnow()
                    })
                    agent.exfil_timer = random.randint(15, 30)

                # Recovery Logic
                if agent.state_timer > 20:
                    chance = random.random()
                    if chance < 0.1: # Small chance of quarantine
                        agent.status = "quarantined"
                        agent.velocity = 0
                    elif chance < 0.4: # Recovery
                        agent.status = "recovered"
                        agent.infection_score = 0
                    agent.state_timer = 0

        # Send State Updates
        for agent in self.agents:
            self.api.report_agent_state(agent.to_dict())
            
        self._publish_snapshot()
        
    def _publish_snapshot(self):
        statuses = [a.status for a in self.agents]
        # Calculate dynamic counts
        snapshot = {
            "id": 0,
            "run_id": self.run_id,
            "current_tick": self.tick_count,
            "total_agents": len(self.agents),
            "healthy_count": statuses.count("healthy"),
            "exposed_count": statuses.count("exposed"),
            "infected_count": statuses.count("infected"),
            "c2_active_count": statuses.count("infected"), # Assume all infected are C2 active for now
            "exfil_active_count": sum(1 for a in self.agents if a.exfil_timer < 5 and a.status == "infected"),
            "quarantined_count": statuses.count("quarantined"),
            "recovered_count": statuses.count("recovered"),
            "persistent_count": 0,
            "event_count": 0, # Could be improved to count actual events in tick
            "timestamp": datetime.utcnow()
        }
        self.api.publish_snapshot(snapshot)

    def run(self):
        print(f"Starting high-fidelity simulation run {self.run_id} Topology: {self.topology}")
        try:
            while self.running:
                self.tick()
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("Stopped.")
        finally:
            self.api.close()
