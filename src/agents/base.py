"""Base agent - abstract base class for all agents."""
import asyncio
import logging
from abc import ABC, abstractmethod


class BaseAgent(ABC):
    """Abstract base class for all incident response agents."""

    def __init__(self, interval: float = 5.0):
        self.interval = interval
        self.logger = logging.getLogger(f"ir.{self.__class__.__name__}")
        self._running = False

    @abstractmethod
    async def run_cycle(self):
        """Execute one cycle of the agent's work."""
        pass

    async def start(self):
        """Start the agent loop."""
        self._running = True
        while self._running:
            try:
                await self.run_cycle()
            except Exception as e:
                self.logger.error(f"Cycle error: {e}")
            await asyncio.sleep(self.interval)

    async def stop(self):
        """Stop the agent."""
        self._running = False
