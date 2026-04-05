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
        self.role = role
        self.cognition_tier = 1
        self.status = "healthy" # healthy, exposed, infected, quarantined, recovered
        self.infection_score = 0.0
        self.position_x = random.uniform(0, 100)
        self.position_y = random.uniform(0, 100)
        self.metadata = {}
        
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
        
        # Move agents (random walk)
        for agent in self.agents:
            agent.position_x = max(0, min(100, agent.position_x + random.uniform(-5, 5)))
            agent.position_y = max(0, min(100, agent.position_y + random.uniform(-5, 5)))
        
        # Check exposures
        for target in healthy:
            for source in infected:
                # distance squared
                dist_sq = (target.position_x - source.position_x)**2 + (target.position_y - source.position_y)**2
                if dist_sq < 25.0: # Close proximity
                    # Probability based on tier and role
                    transmission_chance = 0.3 if target.role == 'guardian' else 0.7
                    
                    if random.random() < transmission_chance:
                        target.status = "exposed"
                        target.infection_score = 10.0
                        
                        # Emit infection event
                        event = {
                            "run_id": self.run_id,
                            "source_agent": source.agent_id,
                            "target_agent": target.agent_id,
                            "vector": "proximity_bluetooth",
                            "severity": "medium",
                            "outcome": "exposed",
                            "timestamp": datetime.utcnow()
                        }
                        self.api.report_infection_event(event)

        # Progression: Exposed -> Infected
        exposed = [a for a in self.agents if a.status == "exposed"]
        for agent in exposed:
            agent.infection_score += random.uniform(5, 15)
            if agent.infection_score > 50:
                agent.status = "infected"
                
        # Send State Updates
        # We'll batch standard state updates.
        for agent in self.agents:
            self.api.report_agent_state(agent.to_dict())
            
        self._publish_snapshot()
        
    def _publish_snapshot(self):
        statuses = [a.status for a in self.agents]
        snapshot = {
            "id": 0,
            "run_id": self.run_id,
            "current_tick": self.tick_count,
            "total_agents": len(self.agents),
            "healthy_count": statuses.count("healthy"),
            "exposed_count": statuses.count("exposed"),
            "infected_count": statuses.count("infected"),
            "c2_active_count": 0,
            "exfil_active_count": 0,
            "quarantined_count": statuses.count("quarantined"),
            "recovered_count": statuses.count("recovered"),
            "persistent_count": 0,
            "event_count": 0,
            "timestamp": datetime.utcnow()
        }
        self.api.publish_snapshot(snapshot)

    def run(self):
        print(f"Starting simulation run {self.run_id} Topology: {self.topology}")
        try:
            while self.running:
                self.tick()
                time.sleep(1.0) # Tick 1Hz for realistic frontend observability
        except KeyboardInterrupt:
            print("Stopped.")
        finally:
            self.api.close()
