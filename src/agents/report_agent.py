"""ReportAgent - generates NIST-format incident reports."""
import json
from datetime import datetime
from .base import BaseAgent
from ..database import get_db, insert_report, get_incident_events
from ..core.llm import query_mimo_sync
from ..core.metrics import metrics
from ..config import REPORT_INTERVAL


class ReportAgent(BaseAgent):
    """Generates professional incident reports in NIST format."""

    def __init__(self):
        super().__init__(interval=REPORT_INTERVAL)
        self.reports_generated = 0

    async def run_cycle(self):
        # Find resolved/contained incidents without reports
        conn = get_db()
        rows = conn.execute("""
            SELECT i.* FROM incidents i
            WHERE i.status IN ('resolved', 'contained')
            AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.incident_id = i.id)
            ORDER BY i.updated_at DESC LIMIT 3
        """).fetchall()
        conn.close()

        for row in rows:
            incident = dict(row)
            self.logger.info(f"Generating report for: {incident['name']} (ID: {incident['id']})")

            # Gather all data
            conn = get_db()
            forensics = conn.execute(
                "SELECT * FROM forensics WHERE incident_id=? ORDER BY created_at DESC LIMIT 1",
                (incident["id"],),
            ).fetchone()
            correlations = conn.execute(
                "SELECT * FROM correlations WHERE incident_id=?",
                (incident["id"],),
            ).fetchall()
            containments = conn.execute(
                "SELECT * FROM containment_actions WHERE incident_id=?",
                (incident["id"],),
            ).fetchall()
            remediations = conn.execute(
                "SELECT * FROM remediation_actions WHERE incident_id=?",
                (incident["id"],),
            ).fetchall()
            conn.close()

            # Build report
            report = self._build_report(incident, forensics, correlations, containments, remediations)

            # Store report
            insert_report(incident["id"], report)
            self.reports_generated += 1
            metrics.inc("reports_generated")
            self.logger.info(f"Report generated: {len(report)} chars")

    def _build_report(self, incident, forensics, correlations, containments, remediations):
        """Build NIST-format incident report."""
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        report = f"""# INCIDENT RESPONSE REPORT
## NIST SP 800-61 Format

---

### 1. INCIDENT IDENTIFICATION

- **Incident ID:** INC-{incident['id']:04d}
- **Report Date:** {now}
- **Incident Name:** {incident['name']}
- **Severity:** {incident['severity']}
- **Category:** {incident.get('category', 'N/A')}
- **Status:** {incident['status']}
- **Detection Time:** {incident['created_at']}
- **Source IPs:** {incident.get('source_ips', 'N/A')}
- **Event Count:** {incident.get('event_count', 0)}

### 2. INCIDENT SUMMARY

{incident.get('description', 'No description available.')}

### 3. TECHNICAL ANALYSIS

"""

        if forensics:
            fd = dict(forensics) if hasattr(forensics, 'keys') else forensics
            report += f"""**Attack Vector:** {fd.get('attack_vector', 'Unknown')}

**Timeline:**
"""
            try:
                timeline = json.loads(fd.get("timeline", "[]"))
                for entry in timeline[:15]:
                    report += f"- [{entry.get('timestamp', 'N/A')}] {entry.get('type', 'N/A')} — {entry.get('detail', '')}\n"
            except:
                report += "- Timeline data unavailable\n"

            report += f"""
**Indicators of Compromise (IOCs):**
"""
            try:
                iocs = json.loads(fd.get("iocs", "{}"))
                for ioc_type, values in iocs.items():
                    if values:
                        report += f"- **{ioc_type.upper()}:** {', '.join(str(v) for v in values)}\n"
            except:
                report += "- IOC data unavailable\n"

            report += f"""
**Affected Systems:**
"""
            try:
                affected = json.loads(fd.get("affected_systems", "[]"))
                for sys in affected:
                    report += f"- {sys}\n"
            except:
                report += "- System data unavailable\n"

            analysis_text = fd.get("analysis", "No analysis available.")
            report += f"""
**MiMo AI Analysis:**
{analysis_text}
"""

        report += """
### 4. CORRELATION DATA

"""
        for corr in correlations:
            cd = dict(corr) if hasattr(corr, 'keys') else corr
            report += f"- **Pattern:** {cd.get('pattern', 'N/A')} (Confidence: {cd.get('confidence', 0):.0%})\n"

        report += """
### 5. CONTAINMENT ACTIONS

"""
        for cont in containments:
            cd = dict(cont) if hasattr(cont, 'keys') else cont
            report += f"- **{cd.get('action_type', 'N/A')}** on `{cd.get('target', 'N/A')}` — {cd.get('status', 'N/A')}\n"

        report += """
### 6. REMEDIATION ACTIONS

"""
        for rem in remediations:
            rd = dict(rem) if hasattr(rem, 'keys') else rem
            report += f"- **{rd.get('action_type', 'N/A')}:** {rd.get('description', 'N/A')} — {rd.get('status', 'N/A')}\n"

        report += f"""
### 7. LESSONS LEARNED

1. Detection effectiveness: {"Good" if incident.get('event_count', 0) > 3 else "Needs improvement"}
2. Response time: Automated containment successful
3. Recommendation: Review and update detection rules

### 8. SIGN-OFF

- **Report Generated By:** MiMo Incident Response Engine (Automated)
- **Reviewed By:** Pending human review
- **Classification:** CONFIDENTIAL

---
*Report generated at {now}*
"""

        return report

    def get_status(self):
        return {"reports_generated": self.reports_generated, "interval": self.interval}
