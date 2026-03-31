import asyncio
from shared.agent_base import AgentBase

class GuardianAgent(AgentBase):
    """High-security policy enforcer - high resistance to infection"""
    
    def __init__(self):
        super().__init__()
        # Defense level
        self.defense_level = 0.85  # Guardian: 85% resistant
        
        # TEMPORAL SIMULATION: Slowest processing (thorough security analysis)
        self.base_delay_ms = 1000    # Base: 1000ms (1 second average of 500-1500ms range)
        self.jitter_ms = 250         # Jitter: ±250ms
        
        # AUTONOMOUS PROPAGATION: Conservative spread (rarely infected)
        self.propagation_interval_ms = 500  # Attempt to spread every 500ms if infected
        self.max_broadcasts_per_second = 5   # Conservative broadcast rate
    
    def get_system_prompt(self) -> str:
        with open("system_prompt.txt", "r") as f:
            return f.read()

async def main():
    agent = GuardianAgent()
    await agent.start()

if __name__ == "__main__":
    asyncio.run(main())
