"""RemediationAgent - removes threats, patches, and restores systems."""
import json
from datetime import datetime
from .base import BaseAgent
from ..database import get_db, insert_remediation_action, update_incident_status
from ..core.metrics import metrics
from ..config import REMEDIATION_INTERVAL


class RemediationAgent(BaseAgent):
    """Remediates contained incidents: patch, clean, restore."""

    def __init__(self):
        super().__init__(interval=REMEDIATION_INTERVAL)
        self.actions_taken = 0

    async def run_cycle(self):
        # Find contained incidents that need remediation
        conn = get_db()
        rows = conn.execute("""
            SELECT i.* FROM incidents i
            WHERE i.status='contained'
            AND NOT EXISTS (SELECT 1 FROM remediation_actions r WHERE r.incident_id = i.id AND r.status='completed')
            ORDER BY i.created_at DESC LIMIT 3
        """).fetchall()
        conn.close()

        for row in rows:
            incident = dict(row)
            self.logger.info(f"Remediating incident: {incident['name']} (ID: {incident['id']})")

            # Get forensics and containment data
            conn = get_db()
            forensics = conn.execute(
                "SELECT * FROM forensics WHERE incident_id=? ORDER BY created_at DESC LIMIT 1",
                (incident["id"],),
            ).fetchone()
            containments = conn.execute(
                "SELECT * FROM containment_actions WHERE incident_id=? AND status='completed'",
                (incident["id"],),
            ).fetchall()
            conn.close()

            if not forensics:
                continue

            forensics_data = dict(forensics)
            iocs = json.loads(forensics_data.get("iocs", "{}"))

            # Determine remediation steps
            steps = self._determine_steps(incident, iocs)

            for step in steps:
                # Insert remediation action
                conn = get_db()
                conn.execute(
                    "INSERT INTO remediation_actions (incident_id, action_type, description, status, created_at) VALUES (?,?,?,?,?)",
                    (incident["id"], step["type"], step["description"], "executing", datetime.utcnow().isoformat()),
                )
                conn.commit()
                conn.close()

                # Execute remediation
                result = self._execute(step)

                # Update action
                conn = get_db()
                conn.execute(
                    "UPDATE remediation_actions SET status='completed', result=?, completed_at=? WHERE incident_id=? AND action_type=?",
                    (json.dumps(result), datetime.utcnow().isoformat(), incident["id"], step["type"]),
                )
                conn.commit()
                conn.close()

                self.actions_taken += 1
                metrics.inc("remediation_actions")
                self.logger.info(f"Remediation: {step['type']} → {result.get('status', 'done')}")

            # Verify remediation
            verified = self._verify(incident, iocs)

            # Update incident status
            new_status = "resolved" if verified else "remediation_pending"
            update_incident_status(incident["id"], new_status)
            self.logger.info(f"Incident {incident['id']} → {new_status}")

    def _determine_steps(self, incident, iocs):
        """Determine remediation steps based on incident type."""
        steps = []
        category = incident.get("category", "")

        if category == "credential_access":
            steps.append({"type": "password_reset", "description": "Force password reset for compromised accounts"})
            steps.append({"type": "enable_mfa", "description": "Enable MFA for affected accounts"})
            steps.append({"type": "audit_access", "description": "Audit recent access logs for unauthorized activity"})

        elif category == "execution":
            steps.append({"type": "malware_scan", "description": "Full malware scan on affected systems"})
            steps.append({"type": "file_cleanup", "description": "Remove malicious files and registry entries"})
            steps.append({"type": "patch_system", "description": "Apply security patches"})

        elif category == "exfiltration":
            steps.append({"type": "data_assessment", "description": "Assess scope of data exposure"})
            steps.append({"type": "notify_stakeholders", "description": "Notify affected parties"})
            steps.append({"type": "monitor_darkweb", "description": "Monitor for leaked data"})

        elif category == "privilege_escalation":
            steps.append({"type": "revoke_privileges", "description": "Revoke elevated privileges"})
            steps.append({"type": "audit_sudoers", "description": "Audit and clean sudoers configuration"})
            steps.append({"type": "patch_vuln", "description": "Patch privilege escalation vulnerability"})

        elif category == "reconnaissance":
            steps.append({"type": "harden_perimeter", "description": "Strengthen network perimeter defenses"})
            steps.append({"type": "update_ids", "description": "Update IDS/IPS signatures"})

        elif category == "lateral_movement":
            steps.append({"type": "segment_network", "description": "Implement network segmentation"})
            steps.append({"type": "rotate_credentials", "description": "Rotate all credentials in affected segment"})

        elif category == "impact":
            steps.append({"type": "restore_backup", "description": "Restore from clean backup"})
            steps.append({"type": "verify_integrity", "description": "Verify system integrity"})

        else:
            steps.append({"type": "general_cleanup", "description": "General system cleanup and hardening"})

        return steps

    def _execute(self, step):
        """Execute a remediation step (simulated)."""
        action_type = step["type"]
        results = {
            "password_reset": {"status": "success", "accounts_reset": 3},
            "enable_mfa": {"status": "success", "mfa_enabled": True},
            "audit_access": {"status": "success", "suspicious_entries": 5},
            "malware_scan": {"status": "success", "threats_found": 2, "threats_removed": 2},
            "file_cleanup": {"status": "success", "files_removed": 4},
            "patch_system": {"status": "success", "patches_applied": 3},
            "data_assessment": {"status": "success", "records_exposed": "unknown"},
            "notify_stakeholders": {"status": "success", "notifications_sent": 1},
            "monitor_darkweb": {"status": "success", "monitoring_active": True},
            "revoke_privileges": {"status": "success", "privileges_revoked": 2},
            "audit_sudoers": {"status": "success", "entries_removed": 1},
            "patch_vuln": {"status": "success", "cve_patched": "CVE-2024-XXXX"},
            "harden_perimeter": {"status": "success", "rules_added": 5},
            "update_ids": {"status": "success", "signatures_updated": 15},
            "segment_network": {"status": "success", "vlans_created": 2},
            "rotate_credentials": {"status": "success", "credentials_rotated": 8},
            "restore_backup": {"status": "success", "backup_date": "2026-05-22"},
            "verify_integrity": {"status": "success", "integrity_ok": True},
            "general_cleanup": {"status": "success", "items_cleaned": 10},
        }
        return results.get(action_type, {"status": "success"})

    def _verify(self, incident, iocs):
        """Verify remediation was successful (simulated)."""
        # In production: re-scan, check IOCs are gone, verify patches
        return True

    def get_status(self):
        return {"actions_taken": self.actions_taken, "interval": self.interval}
