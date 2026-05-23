"""Telemetry collector - simulates log ingestion for demo."""
import random
import time
import json
import logging
from datetime import datetime
from ..database import insert_event
from ..config import ATTACK_SCENARIOS

logger = logging.getLogger("ir.telemetry")

# Track scenario state
_scenario_index = 0
_event_index = 0
_last_scenario_time = 0


def collect_events():
    """Collect and normalize events from simulated sources."""
    global _scenario_index, _event_index, _last_scenario_time

    now = time.time()
    events_generated = []

    # Generate attack scenario events periodically
    if now - _last_scenario_time > 30:
        scenario = ATTACK_SCENARIOS[_scenario_index % len(ATTACK_SCENARIOS)]
        if _event_index < len(scenario["events"]):
            event = scenario["events"][_event_index]
            event["scenario_id"] = scenario["id"]
            event["scenario_name"] = scenario["name"]
            event["scenario_severity"] = scenario["severity"]
            event["timestamp"] = datetime.utcnow().isoformat()

            # Insert to database
            insert_event(
                event_type=event.get("type", "unknown"),
                source_ip=event.get("source_ip"),
                dest_ip=event.get("dest_ip"),
                port=event.get("port"),
                user=event.get("user"),
                process=event.get("process"),
                path=event.get("path"),
                data=json.dumps({k: v for k, v in event.items() if k not in ["type", "source_ip", "dest_ip", "port"]}),
                raw_log=json.dumps(event),
            )
            events_generated.append(event)
            _event_index += 1
        else:
            # Move to next scenario
            _scenario_index += 1
            _event_index = 0
            _last_scenario_time = now

    # Generate ambient background noise
    if random.random() < 0.3:
        noise_event = {
            "type": random.choice(["heartbeat", "log_rotate", "config_change", "user_login"]),
            "source_ip": f"10.0.1.{random.randint(1, 50)}",
            "timestamp": datetime.utcnow().isoformat(),
        }
        insert_event(
            event_type=noise_event["type"],
            source_ip=noise_event["source_ip"],
            raw_log=json.dumps(noise_event),
        )
        events_generated.append(noise_event)

    return events_generated
