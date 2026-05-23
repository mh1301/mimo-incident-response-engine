"""TelemetryAgent - collects and normalizes log events."""
import json
from .base import BaseAgent
from ..core.telemetry import collect_events
from ..core.metrics import metrics
from ..config import TELEMETRY_INTERVAL


class TelemetryAgent(BaseAgent):
    """Collects telemetry from all sources, normalizes, and stores events."""

    def __init__(self):
        super().__init__(interval=TELEMETRY_INTERVAL)
        self.events_collected = 0

    async def run_cycle(self):
        events = collect_events()
        self.events_collected += len(events)
        metrics.inc("events_collected", len(events))
        if events:
            self.logger.info(f"Collected {len(events)} events (total: {self.events_collected})")

    def get_status(self):
        return {
            "events_collected": self.events_collected,
            "interval": self.interval,
        }
