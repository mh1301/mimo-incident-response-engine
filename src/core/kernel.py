"""Agent Kernel - lifecycle management for all agents."""
import asyncio
import logging
import time
from typing import Dict, Optional

logger = logging.getLogger("ir.kernel")


class AgentKernel:
    """Manages agent lifecycle, dispatch, and health monitoring."""

    def __init__(self):
        self.agents: Dict[str, "BaseAgent"] = {}
        self.tasks: Dict[str, asyncio.Task] = {}
        self.health: Dict[str, dict] = {}
        self._running = False

    def register(self, agent: "BaseAgent"):
        """Register an agent with the kernel."""
        name = agent.__class__.__name__
        self.agents[name] = agent
        self.health[name] = {
            "status": "registered",
            "last_heartbeat": time.time(),
            "cycles": 0,
            "errors": 0,
            "last_error": None,
        }
        logger.info(f"Registered agent: {name}")

    async def start_all(self):
        """Start all registered agents."""
        self._running = True
        for name, agent in self.agents.items():
            task = asyncio.create_task(self._run_agent(name, agent))
            self.tasks[name] = task
            self.health[name]["status"] = "running"
            logger.info(f"Started agent: {name}")

    async def stop_all(self):
        """Stop all agents gracefully."""
        self._running = False
        for name, task in self.tasks.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            self.health[name]["status"] = "stopped"
        logger.info("All agents stopped")

    async def _run_agent(self, name: str, agent: "BaseAgent"):
        """Run agent in isolated loop — error in one agent doesn't affect others."""
        while self._running:
            try:
                await agent.run_cycle()
                self.health[name]["cycles"] += 1
                self.health[name]["last_heartbeat"] = time.time()
                self.health[name]["status"] = "running"
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.health[name]["errors"] += 1
                self.health[name]["last_error"] = str(e)
                self.health[name]["status"] = "error"
                logger.error(f"Agent {name} error: {e}")
            await asyncio.sleep(agent.interval)

    def get_health(self) -> Dict[str, dict]:
        """Get health status of all agents."""
        result = {}
        for name, h in self.health.items():
            result[name] = {
                **h,
                "uptime": time.time() - h.get("last_heartbeat", time.time()),
            }
        return result

    def trigger_agent(self, name: str):
        """Manually trigger an agent cycle."""
        if name in self.agents:
            asyncio.create_task(self.agents[name].run_cycle())
