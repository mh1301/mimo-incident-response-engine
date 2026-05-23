"""TriageAgent - filters false positives and prioritizes incidents."""
import json
from .base import BaseAgent
from ..database import get_db, update_incident_status
from ..core.metrics import metrics
from ..config import TRIAGE_INTERVAL, SEVERITY


class TriageAgent(BaseAgent):
    """Triages incidents: filters false positives, assigns priority."""

    def __init__(self):
        super().__init__(interval=TRIAGE_INTERVAL)
        self.triaged = 0
        self.false_positives = 0

    async def run_cycle(self):
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM incidents WHERE status='open' ORDER BY created_at DESC"
        ).fetchall()
        conn.close()

        for row in rows:
            incident = dict(row)
            verdict = self._analyze(incident)

            if verdict["is_false_positive"]:
                conn = get_db()
                conn.execute("UPDATE incidents SET false_positive=1, status='dismissed', updated_at=? WHERE id=?",
                             (self._now(), incident["id"]))
                conn.commit()
                conn.close()
                self.false_positives += 1
                metrics.inc("false_positives")
                self.logger.info(f"Dismissed FP: {incident['name']} (reason: {verdict['reason']})")
            else:
                self.triaged += 1
                metrics.inc("incidents_triaged")
                self.logger.info(f"Triaged: {incident['name']} | Severity: {incident['severity']} | Priority: {verdict['priority']}")

    def _analyze(self, incident):
        """Analyze incident for false positive indicators."""
        # Check confidence from correlation
        conn = get_db()
        corr = conn.execute(
            "SELECT confidence FROM correlations WHERE incident_id=?",
            (incident["id"],),
        ).fetchone()
        conn.close()

        confidence = corr["confidence"] if corr else 0.5

        # Low confidence = likely false positive
        if confidence < 0.3:
            return {"is_false_positive": True, "reason": "low_confidence", "priority": 0}

        # Calculate priority score
        sev = SEVERITY.get(incident["severity"], SEVERITY["LOW"])
        priority = sev["score"] * confidence

        # Known safe IPs (example)
        safe_ips = {"10.0.1.1", "10.0.1.2", "127.0.0.1"}
        source_ips = incident.get("source_ips", "").split(",")
        if all(ip.strip() in safe_ips for ip in source_ips):
            return {"is_false_positive": True, "reason": "known_safe_ip", "priority": 0}

        return {
            "is_false_positive": False,
            "reason": None,
            "priority": round(priority, 1),
        }

    def _now(self):
        from datetime import datetime
        return datetime.utcnow().isoformat()

    def get_status(self):
        return {
            "triaged": self.triaged,
            "false_positives": self.false_positives,
            "interval": self.interval,
        }
