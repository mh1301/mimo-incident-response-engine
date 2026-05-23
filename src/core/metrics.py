"""Performance metrics tracking."""
import time
from collections import defaultdict


class Metrics:
    """Track engine performance metrics."""

    def __init__(self):
        self.counters = defaultdict(int)
        self.timers = {}
        self.start_time = time.time()

    def inc(self, name: str, value: int = 1):
        self.counters[name] += value

    def start_timer(self, name: str):
        self.timers[name] = time.time()

    def stop_timer(self, name: str) -> float:
        if name in self.timers:
            elapsed = time.time() - self.timers[name]
            self.counters[f"{name}_total_time"] += elapsed
            self.counters[f"{name}_count"] += 1
            return elapsed
        return 0.0

    def get_all(self) -> dict:
        result = dict(self.counters)
        result["uptime_seconds"] = time.time() - self.start_time
        return result


metrics = Metrics()
