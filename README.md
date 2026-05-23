# MiMo Incident Response Engine

Multi-agent system for automated security incident detection, triage, forensics, containment, and reporting. Powered by MiMo AI.

## Architecture

7 specialized agents managed by an AgentKernel:

```
TelemetryAgent → CorrelationAgent → TriageAgent → ForensicAgent → ContainmentAgent → RemediationAgent → ReportAgent
```

### Agents

| Agent | Interval | Function |
|---|---|---|
| **TelemetryAgent** | 10s | Collect & normalize log events |
| **CorrelationAgent** | 5s | Detect attack patterns (Sigma rules) |
| **TriageAgent** | 15s | Filter false positives, prioritize |
| **ForensicAgent** | 30s | Timeline reconstruction, IOC extraction |
| **ContainmentAgent** | 20s | Auto-isolate compromised systems |
| **RemediationAgent** | 25s | Patch, clean, restore |
| **ReportAgent** | 60s | Generate NIST incident reports |

### Tech Stack

- **Backend:** FastAPI + SQLite (WAL mode)
- **Communication:** WebSocket (real-time dashboard)
- **LLM:** MiMo v2.5 Pro (reasoning + report generation)
- **Frontend:** Dark theme dashboard, 8 tabs
- **Deployment:** Docker-ready

## Quick Start

```bash
pip install -r requirements.txt
python -m src.main
```

Dashboard: http://localhost:80

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | Dashboard statistics |
| `/api/health` | GET | Agent health status |
| `/api/events` | GET | Recent telemetry events |
| `/api/incidents` | GET | All incidents |
| `/api/incidents/{id}` | GET | Incident detail + forensics |
| `/api/correlations` | GET | Detection correlations |
| `/api/forensics` | GET | Forensic analyses |
| `/api/containments` | GET | Containment actions |
| `/api/remediations` | GET | Remediation actions |
| `/api/reports` | GET | Generated reports |
| `/api/reports/{id}` | GET | Report content |
| `/api/sigma-rules` | GET | Detection rules |
| `/api/simulate` | POST | Trigger attack simulation |
| `/ws` | WebSocket | Real-time updates |

## Detection Rules (Sigma)

- SSH Brute Force
- Port Scanning
- Malware Execution + C2
- Data Exfiltration
- Privilege Escalation
- Lateral Movement
- DNS Tunneling
- Ransomware Activity

## License

MIT
