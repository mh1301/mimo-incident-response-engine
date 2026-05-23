"""CorrelationAgent - detects attack patterns using Sigma rules."""
import json
from collections import defaultdict
from datetime import datetime, timedelta
from .base import BaseAgent
from ..database import get_db, insert_incident, insert_correlation
from ..core.metrics import metrics
from ..config import CORRELATION_INTERVAL, SIGMA_RULES


class CorrelationAgent(BaseAgent):
    """Correlates events to detect attack patterns using Sigma-like rules."""

    def __init__(self):
        super().__init__(interval=CORRELATION_INTERVAL)
        self.detections = 0
        self._event_buffer = defaultdict(list)

    async def run_cycle(self):
        conn = get_db()
        # Get events from last 2 minutes
        cutoff = (datetime.utcnow() - timedelta(minutes=2)).isoformat()
        rows = conn.execute(
            "SELECT * FROM events WHERE created_at > ? ORDER BY created_at DESC",
            (cutoff,),
        ).fetchall()
        conn.close()

        events = [dict(r) for r in rows]
        if not events:
            return

        # Group events by source IP
        by_source = defaultdict(list)
        for ev in events:
            by_source[ev["source_ip"]].append(ev)

        # Check each rule
        for rule_id, rule in SIGMA_RULES.items():
            matches = self._check_rule(rule_id, rule, by_source)
            for match in matches:
                # Check if incident already exists for this rule+source
                conn = get_db()
                existing = conn.execute(
                    "SELECT id FROM incidents WHERE rule_id=? AND source_ips=? AND status='open'",
                    (rule_id, match["source_ips"]),
                ).fetchone()
                conn.close()

                if not existing:
                    incident_id = insert_incident(
                        rule_id=rule_id,
                        name=rule["name"],
                        severity=rule["severity"],
                        category=rule["category"],
                        description=rule["description"],
                        source_ips=match["source_ips"],
                        event_count=match["event_count"],
                    )
                    insert_correlation(
                        incident_id=incident_id,
                        pattern=rule["condition"],
                        evidence=json.dumps(match["evidence"]),
                        confidence=match["confidence"],
                    )
                    self.detections += 1
                    metrics.inc("correlations_detected")
                    self.logger.warning(f"DETECTED: {rule['name']} from {match['source_ips']} (confidence: {match['confidence']:.0%})")

    def _check_rule(self, rule_id, rule, by_source):
        """Check a specific Sigma rule against events."""
        matches = []

        if rule_id == "ssh_brute_force":
            for ip, events in by_source.items():
                ssh_failures = [e for e in events if e["event_type"] == "auth_failure" and e.get("port") == 22]
                if len(ssh_failures) >= 3:
                    matches.append({
                        "source_ips": ip,
                        "event_count": len(ssh_failures),
                        "evidence": {"failed_attempts": len(ssh_failures), "users_tried": list(set(e.get("user", "") for e in ssh_failures))},
                        "confidence": min(0.5 + len(ssh_failures) * 0.1, 0.95),
                    })

        elif rule_id == "port_scan":
            for ip, events in by_source.items():
                conn_events = [e for e in events if e["event_type"] == "connection_attempt"]
                unique_ports = set(e.get("port") for e in conn_events if e.get("port"))
                if len(unique_ports) >= 10:
                    matches.append({
                        "source_ips": ip,
                        "event_count": len(conn_events),
                        "evidence": {"unique_ports": len(unique_ports), "ports": sorted(list(unique_ports))[:30]},
                        "confidence": min(0.4 + len(unique_ports) * 0.03, 0.95),
                    })

        elif rule_id == "malware_execution":
            for ip, events in by_source.items():
                proc_events = [e for e in events if e["event_type"] == "process_create"]
                net_events = [e for e in events if e["event_type"] == "network_connect"]
                file_events = [e for e in events if e["event_type"] == "file_create"]
                if proc_events and net_events:
                    confidence = 0.6
                    if file_events:
                        confidence = 0.85
                    matches.append({
                        "source_ips": ip,
                        "event_count": len(events),
                        "evidence": {"processes": [e.get("process") for e in proc_events], "connections": len(net_events)},
                        "confidence": confidence,
                    })

        elif rule_id == "data_exfiltration":
            for ip, events in by_source.items():
                upload_events = [e for e in events if e["event_type"] == "network_upload"]
                for ue in upload_events:
                    bytes_val = ue.get("bytes", 0) if isinstance(ue.get("bytes"), (int, float)) else 0
                    if bytes_val >= 100000000:
                        matches.append({
                            "source_ips": ip,
                            "event_count": len(events),
                            "evidence": {"bytes_uploaded": bytes_val, "dest": ue.get("dest_ip")},
                            "confidence": 0.9,
                        })

        elif rule_id == "privilege_escalation":
            for ip, events in by_source.items():
                priv_events = [e for e in events if e["event_type"] in ("process_create", "auth_success") and e.get("process") in ("sudo", "su")]
                file_events = [e for e in events if e["event_type"] == "file_access" and "shadow" in str(e.get("path", ""))]
                if priv_events:
                    confidence = 0.7 if file_events else 0.5
                    matches.append({
                        "source_ips": ip,
                        "event_count": len(events),
                        "evidence": {"privilege_actions": len(priv_events), "shadow_access": bool(file_events)},
                        "confidence": confidence,
                    })

        elif rule_id == "dns_tunneling":
            for ip, events in by_source.items():
                dns_events = [e for e in events if e["event_type"] == "dns_query"]
                long_queries = [e for e in dns_events if len(e.get("data", "").split(".")) > 3]
                if long_queries:
                    matches.append({
                        "source_ips": ip,
                        "event_count": len(dns_events),
                        "evidence": {"suspicious_queries": len(long_queries)},
                        "confidence": 0.6,
                    })

        elif rule_id == "ransomware_activity":
            for ip, events in by_source.items():
                file_events = [e for e in events if e["event_type"] == "file_create"]
                if len(file_events) >= 5:
                    matches.append({
                        "source_ips": ip,
                        "event_count": len(file_events),
                        "evidence": {"files_created": len(file_events)},
                        "confidence": 0.7,
                    })

        elif rule_id == "lateral_movement":
            for ip, events in by_source.items():
                internal_scans = [e for e in events if e["event_type"] == "connection_attempt" and e.get("dest_ip", "").startswith("10.")]
                if len(internal_scans) >= 5:
                    matches.append({
                        "source_ips": ip,
                        "event_count": len(internal_scans),
                        "evidence": {"internal_connections": len(internal_scans)},
                        "confidence": 0.65,
                    })

        return matches

    def get_status(self):
        return {"detections": self.detections, "interval": self.interval}
