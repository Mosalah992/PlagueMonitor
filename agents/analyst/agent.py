import asyncio
from shared.agent_base import AgentBase

class AnalystAgent(AgentBase):
    """Medium-security analyzer - moderate resistance to infection"""
    
    def __init__(self):
        super().__init__()
        # Defense level
        self.defense_level = 0.50  # Analyst: 50% resistant
        
        # TEMPORAL SIMULATION: Medium processing (some analysis)
        self.base_delay_ms = 200      # Base: 200ms (average of 100-300ms range)
        self.jitter_ms = 50           # Jitter: ±50ms
        
        # AUTONOMOUS PROPAGATION: Moderate spread rate
        self.propagation_interval_ms = 300  # Attempt to spread every 300ms
        self.max_broadcasts_per_second = 10
    
    def get_system_prompt(self) -> str:
        with open("system_prompt.txt", "r") as f:
            return f.read()

async def main():
    agent = AnalystAgent()
    await agent.start()

if __name__ == "__main__":
    asyncio.run(main())
