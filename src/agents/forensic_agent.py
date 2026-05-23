"""ForensicAgent - automated forensic analysis and timeline reconstruction."""
import json
from datetime import datetime
from .base import BaseAgent
from ..database import get_db, insert_forensic, get_incident_events
from ..core.llm import query_mimo_sync
from ..core.metrics import metrics
from ..config import FORENSIC_INTERVAL


class ForensicAgent(BaseAgent):
    """Performs automated forensic analysis on confirmed incidents."""

    def __init__(self):
        super().__init__(interval=FORENSIC_INTERVAL)
        self.analyses = 0

    async def run_cycle(self):
        # Find incidents that need forensic analysis
        conn = get_db()
        rows = conn.execute("""
            SELECT i.* FROM incidents i
            WHERE i.status='open' AND i.false_positive=0
            AND NOT EXISTS (SELECT 1 FROM forensics f WHERE f.incident_id = i.id)
            ORDER BY i.created_at DESC LIMIT 5
        """).fetchall()
        conn.close()

        for row in rows:
            incident = dict(row)
            self.logger.info(f"Forensic analysis: {incident['name']} (ID: {incident['id']})")

            # Get related events
            events = get_incident_events(incident["id"])

            # Build timeline
            timeline = self._build_timeline(events)

            # Extract IOCs
            iocs = self._extract_iocs(events)

            # Determine attack vector
            attack_vector = self._determine_vector(incident, events)

            # Identify affected systems
            affected = self._identify_affected(events)

            # Get MiMo analysis
            analysis = self._get_analysis(incident, events, timeline)

            # Store forensic results
            insert_forensic(
                incident_id=incident["id"],
                timeline=json.dumps(timeline),
                iocs=json.dumps(iocs),
                attack_vector=attack_vector,
                affected_systems=json.dumps(affected),
                analysis=analysis,
            )

            self.analyses += 1
            metrics.inc("forensic_analyses")
            self.logger.info(f"Forensic complete: {len(timeline)} timeline events, {len(iocs)} IOCs")

    def _build_timeline(self, events):
        """Reconstruct attack timeline from events."""
        timeline = []
        for ev in sorted(events, key=lambda x: x.get("created_at", "")):
            entry = {
                "timestamp": ev.get("created_at"),
                "type": ev.get("event_type"),
                "source_ip": ev.get("source_ip"),
                "detail": "",
            }
            if ev.get("process"):
                entry["detail"] = f"Process: {ev['process']} {ev.get('args', '')}"
            elif ev.get("path"):
                entry["detail"] = f"File: {ev['path']}"
            elif ev.get("port"):
                entry["detail"] = f"Port: {ev['port']}"
            elif ev.get("user"):
                entry["detail"] = f"User: {ev['user']}"
            timeline.append(entry)
        return timeline

    def _extract_iocs(self, events):
        """Extract Indicators of Compromise."""
        iocs = {
            "ips": set(),
            "domains": set(),
            "processes": set(),
            "files": set(),
            "users": set(),
        }
        for ev in events:
            if ev.get("source_ip") and not ev["source_ip"].startswith("10."):
                iocs["ips"].add(ev["source_ip"])
            if ev.get("process"):
                iocs["processes"].add(ev["process"])
            if ev.get("path"):
                iocs["files"].add(ev["path"])
            if ev.get("user"):
                iocs["users"].add(ev["user"])
        return {k: list(v) for k, v in iocs.items()}

    def _determine_vector(self, incident, events):
        """Determine the attack vector."""
        category = incident.get("category", "unknown")
        vector_map = {
            "credential_access": "Brute force / credential stuffing",
            "reconnaissance": "Network scanning / enumeration",
            "execution": "Malicious code execution",
            "exfiltration": "Data theft via network transfer",
            "privilege_escalation": "Local privilege escalation exploit",
            "lateral_movement": "Internal network pivoting",
            "command_and_control": "C2 communication channel",
            "impact": "Destructive / ransomware activity",
        }
        return vector_map.get(category, "Unknown attack vector")

    def _identify_affected(self, events):
        """Identify affected systems."""
        systems = set()
        for ev in events:
            if ev.get("dest_ip"):
                systems.add(ev["dest_ip"])
            if ev.get("source_ip") and ev["source_ip"].startswith("10."):
                systems.add(ev["source_ip"])
        return list(systems)

    def _get_analysis(self, incident, events, timeline):
        """Get MiMo LLM analysis of the incident."""
        prompt = f"""Analyze this security incident:

Incident: {incident['name']}
Severity: {incident['severity']}
Category: {incident['category']}
Description: {incident['description']}
Source IPs: {incident['source_ips']}
Event count: {len(events)}

Timeline summary:
{json.dumps(timeline[:10], indent=2)}

Provide:
1. Root cause analysis
2. Impact assessment
3. Recommended immediate actions
4. Long-term remediation steps

Be concise and technical."""

        return query_mimo_sync(prompt, system="You are a senior security analyst performing incident forensics.")

    def get_status(self):
        return {"analyses": self.analyses, "interval": self.interval}
