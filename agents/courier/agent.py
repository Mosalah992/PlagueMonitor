import asyncio
from shared.agent_base import AgentBase

class CourierAgent(AgentBase):
    """Low-security vulnerable messenger - minimal resistance to infection"""
    
    def __init__(self):
        super().__init__()
        # Defense level
        self.defense_level = 0.15  # Courier: 15% resistant (very vulnerable)
        
        # TEMPORAL SIMULATION: Fastest processing (real-time messaging)
        self.base_delay_ms = 25       # Base: 25ms (average of 10-50ms range)
        self.jitter_ms = 15           # Jitter: ±15ms
        
        # AUTONOMOUS PROPAGATION: Eager to spread when infected
        self.propagation_interval_ms = 200  # Attempt to spread every 200ms
        self.max_broadcasts_per_second = 20  # Can broadcast 20x/sec when active
    
    def get_system_prompt(self) -> str:
        with open("system_prompt.txt", "r") as f:
            return f.read()

async def main():
    agent = CourierAgent()
    await agent.start()

if __name__ == "__main__":
    asyncio.run(main())
