"""ContainmentAgent - auto-isolate compromised systems."""
import json
from datetime import datetime
from .base import BaseAgent
from ..database import get_db, insert_containment_action, update_containment_action, update_incident_status
from ..core.metrics import metrics
from ..config import CONTAINMENT_INTERVAL, CONTAINMENT_ACTIONS


class ContainmentAgent(BaseAgent):
    """Automatically contains confirmed incidents."""

    def __init__(self):
        super().__init__(interval=CONTAINMENT_INTERVAL)
        self.actions_taken = 0

    async def run_cycle(self):
        # Find incidents that need containment
        conn = get_db()
        rows = conn.execute("""
            SELECT i.* FROM incidents i
            WHERE i.status='open' AND i.false_positive=0
            AND EXISTS (SELECT 1 FROM forensics f WHERE f.incident_id = i.id)
            AND NOT EXISTS (SELECT 1 FROM containment_actions c WHERE c.incident_id = i.id AND c.status='completed')
            ORDER BY CASE i.severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END
            LIMIT 3
        """).fetchall()
        conn.close()

        for row in rows:
            incident = dict(row)
            self.logger.info(f"Containing incident: {incident['name']} (ID: {incident['id']})")

            # Get forensics data
            conn = get_db()
            forensics = conn.execute(
                "SELECT * FROM forensics WHERE incident_id=? ORDER BY created_at DESC LIMIT 1",
                (incident["id"],),
            ).fetchone()
            conn.close()

            if not forensics:
                continue

            forensics_data = dict(forensics)
            iocs = json.loads(forensics_data.get("iocs", "{}"))
            affected = json.loads(forensics_data.get("affected_systems", "[]"))

            # Determine containment actions based on severity and category
            actions = self._determine_actions(incident, iocs, affected)

            for action in actions:
                # Insert action
                conn = get_db()
                cur = conn.execute(
                    "INSERT INTO containment_actions (incident_id, action_type, target, status, created_at) VALUES (?,?,?,?,?)",
                    (incident["id"], action["type"], action["target"], "executing", datetime.utcnow().isoformat()),
                )
                action_id = cur.lastrowid
                conn.commit()
                conn.close()

                # Execute action
                result = self._execute_action(action)

                # Update action status
                update_containment_action(action_id, "completed", json.dumps(result))
                self.actions_taken += 1
                metrics.inc("containment_actions")
                self.logger.info(f"Containment action: {action['type']} on {action['target']} → {result.get('status', 'done')}")

            # Update incident status
            update_incident_status(incident["id"], "contained")
            self.logger.info(f"Incident {incident['id']} contained")

    def _determine_actions(self, incident, iocs, affected):
        """Determine what containment actions to take."""
        actions = []
        category = incident.get("category", "")
        severity = incident.get("severity", "LOW")

        # Block external IPs
        for ip in iocs.get("ips", []):
            actions.append({"type": "block_ip", "target": ip, "reason": "IOC detected"})

        # Isolate affected hosts for critical/high
        if severity in ("CRITICAL", "HIGH"):
            for host in affected:
                actions.append({"type": "isolate_host", "target": host, "reason": f"Affected by {incident['name']}"})

        # Kill malicious processes
        for proc in iocs.get("processes", []):
            if proc in ("powershell.exe", "nc", "ncat", "netcat"):
                actions.append({"type": "kill_process", "target": proc, "reason": "Malicious process"})

        # Quarantine malicious files
        for f in iocs.get("files", []):
            if "temp" in f.lower() or "public" in f.lower() or ".exe" in f.lower():
                actions.append({"type": "quarantine_file", "target": f, "reason": "Suspicious file"})

        # Disable compromised accounts
        for user in iocs.get("users", []):
            if user in ("root", "admin"):
                actions.append({"type": "disable_account", "target": user, "reason": "Compromised account"})

        return actions

    def _execute_action(self, action):
        """Execute a containment action (simulated)."""
        action_type = action["type"]
        target = action["target"]

        # Simulate execution
        if action_type == "block_ip":
            return {"status": "success", "detail": f"IP {target} added to firewall block list", "rule": f"iptables -A INPUT -s {target} -j DROP"}
        elif action_type == "isolate_host":
            return {"status": "success", "detail": f"Host {target} network isolated", "method": "security_group_deny_all"}
        elif action_type == "kill_process":
            return {"status": "success", "detail": f"Process {target} terminated", "signal": "SIGKILL"}
        elif action_type == "quarantine_file":
            return {"status": "success", "detail": f"File {target} moved to quarantine", "quarantine_path": "/var/quarantine/"}
        elif action_type == "disable_account":
            return {"status": "success", "detail": f"Account {target} disabled", "method": "usermod -L"}
        return {"status": "success", "detail": f"Action {action_type} on {target} completed"}

    def get_status(self):
        return {"actions_taken": self.actions_taken, "interval": self.interval}
