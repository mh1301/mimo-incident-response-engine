# MiMo Incident Response Engine

Multi-agent system for automated security incident detection, triage, forensics, containment, and reporting. Powered by MiMo AI.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AGENT KERNEL                                │
│                   (Lifecycle Management)                            │
│                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │Telemetry │→ │Correlation│→ │  Triage  │→ │Forensic  │          │
│  │  Agent   │  │  Agent   │  │  Agent   │  │  Agent   │          │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘          │
│       │              │             │              │                  │
│       ▼              ▼             ▼              ▼                  │
│  ┌─────────────────────────────────────────────────────┐           │
│  │              SQLite (WAL Mode) — 7 Tables            │           │
│  │  events • incidents • correlations • forensics       │           │
│  │  containment_actions • remediation_actions • reports │           │
│  └─────────────────────────────────────────────────────┘           │
│       │              │             │              │                  │
│       ▼              ▼             ▼              ▼                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                         │
│  │Containment│→ │Remediation│→ │  Report  │                         │
│  │  Agent   │  │  Agent   │  │  Agent   │                         │
│  └──────────┘  └──────────┘  └──────────┘                         │
│                                                                     │
│  ┌─────────────────────────────────────────────────────┐           │
│  │         MiMo LLM (xmtp/mimo-v2.5-pro)               │           │
│  │  • Attack pattern reasoning    • IOC analysis        │           │
│  │  • False positive detection    • Report generation   │           │
│  └─────────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   FastAPI    │  │  WebSocket   │  │  Dashboard   │
│  REST API    │  │  Real-time   │  │   (8 Tabs)   │
└──────────────┘  └──────────────┘  └──────────────┘
```

### Data Flow

```
Log Sources → TelemetryAgent → CorrelationAgent → TriageAgent
                                                    ↓
                              ForensicAgent ← Confirmed Incident
                                    ↓
                              ContainmentAgent → RemediationAgent → ReportAgent
                                                    ↓
                              Dashboard (WebSocket real-time)
```

### MiMo LLM Integration Points

| Agent | MiMo Usage |
|---|---|
| CorrelationAgent | Pattern reasoning, attack chain detection |
| TriageAgent | Context analysis, false positive detection |
| ForensicAgent | Deep analysis, timeline correlation, root cause |
| ReportAgent | NIST report generation, executive summary |

---

## Agents

| Agent | Interval | Input | Output |
|---|---|---|---|
| **TelemetryAgent** | 10s | Raw logs (syslog, firewall, endpoint) | Normalized events |
| **CorrelationAgent** | 5s | Normalized events | Correlated incidents |
| **TriageAgent** | 15s | Correlated incidents | Prioritized alerts |
| **ForensicAgent** | 30s | Confirmed incidents | Timeline, IOCs, analysis |
| **ContainmentAgent** | 20s | Forensic results | Block/Isolate/Kill actions |
| **RemediationAgent** | 25s | Containment status | Patch/Clean/Restore |
| **ReportAgent** | 60s | All incident data | NIST incident report |

---

## File Structure

```
mimo-incident-response-engine/
├── src/
│   ├── __init__.py
│   ├── main.py                    # FastAPI app, WebSocket, API endpoints
│   ├── config.py                  # Config, Sigma rules, attack scenarios
│   ├── database.py                # SQLite WAL, 7 tables, CRUD operations
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── kernel.py              # AgentKernel — lifecycle management
│   │   ├── llm.py                 # MiMo LLM client (sync + async)
│   │   ├── telemetry.py           # Event collection, attack simulator
│   │   └── metrics.py             # Performance metrics tracking
│   │
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── base.py                # BaseAgent — abstract base class
│   │   ├── telemetry_agent.py     # Log collection & normalization
│   │   ├── correlation_agent.py   # Sigma rules engine & pattern matching
│   │   ├── triage_agent.py        # False positive filter & prioritization
│   │   ├── forensic_agent.py      # Timeline reconstruction & IOC extraction
│   │   ├── containment_agent.py   # Auto-isolation (firewall, network, account)
│   │   ├── remediation_agent.py   # Patch, malware removal, restoration
│   │   └── report_agent.py        # NIST incident report generation
│   │
│   └── utils/
│       ├── __init__.py
│       └── patterns.py            # Data classes (TelemetryEvent, Incident, IOC)
│
├── templates/
│   └── index.html                 # Dashboard (dark theme, 8 tabs, WebSocket)
│
├── requirements.txt
├── README.md
└── .gitignore
```

### Component Details

| File | Lines | Purpose |
|---|---|---|
| `src/main.py` | ~250 | FastAPI app, 15 API endpoints, WebSocket manager, agent orchestration |
| `src/config.py` | ~250 | Server config, MiMo LLM settings, Sigma rules, attack scenarios, containment actions |
| `src/database.py` | ~300 | SQLite with WAL mode, 7 tables, 15+ CRUD functions |
| `src/core/kernel.py` | ~80 | AgentKernel — register, start_all, stop_all, health monitoring |
| `src/core/llm.py` | ~50 | MiMo v2.5 Pro client — sync + async, error handling |
| `src/core/telemetry.py` | ~70 | Event collection, attack scenario rotation, ambient noise |
| `src/core/metrics.py` | ~30 | Counter + timer tracking |
| `src/agents/base.py` | ~30 | BaseAgent abstract class — interval, run_cycle, start/stop |
| `src/agents/correlation_agent.py` | ~200 | 8 Sigma rules, event grouping, confidence scoring |
| `src/agents/forensic_agent.py` | ~150 | Timeline builder, IOC extractor, attack vector detection, MiMo analysis |
| `src/agents/containment_agent.py` | ~150 | 5 containment action types, severity-based prioritization |
| `src/agents/remediation_agent.py` | ~200 | 7 category-specific remediation steps, verification |
| `src/agents/report_agent.py` | ~150 | NIST SP 800-61 format, MiMo report generation |
| `templates/index.html` | ~600 | Dark theme dashboard, 8 tabs, real-time WebSocket, charts |

---

## Tech Stack

- **Backend:** FastAPI + Python asyncio
- **Database:** SQLite with WAL mode (7 tables)
- **Communication:** WebSocket (real-time dashboard updates)
- **LLM:** MiMo v2.5 Pro (http://43.153.206.68:20128)
- **Frontend:** Dark theme HTML/CSS/JS dashboard
- **Detection:** Sigma rules engine (8 patterns)
- **Deployment:** Docker-ready

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the engine
python -m src.main

# Dashboard: http://localhost:80
```

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | Dashboard statistics |
| `/api/health` | GET | Agent health status |
| `/api/metrics` | GET | Performance metrics |
| `/api/events` | GET | Recent telemetry events |
| `/api/incidents` | GET | All incidents |
| `/api/incidents/open` | GET | Open incidents only |
| `/api/incidents/{id}` | GET | Incident detail + forensics + correlations + containments + remediations + reports |
| `/api/correlations` | GET | Detection correlations |
| `/api/forensics` | GET | Forensic analyses |
| `/api/containments` | GET | Containment actions |
| `/api/remediations` | GET | Remediation actions |
| `/api/reports` | GET | Generated reports |
| `/api/reports/{id}` | GET | Report content |
| `/api/sigma-rules` | GET | Detection rules |
| `/api/simulate` | POST | Trigger attack simulation |
| `/ws` | WebSocket | Real-time dashboard updates |

---

## Detection Rules (Sigma)

| Rule | Severity | Category | Condition |
|---|---|---|---|
| SSH Brute Force | HIGH | credential_access | 5+ failed SSH from same IP |
| Port Scanning | MEDIUM | reconnaissance | 20+ unique ports in 30s |
| Malware Execution | CRITICAL | execution | Suspicious process + network connection |
| Data Exfiltration | CRITICAL | exfiltration | 100MB+ outbound to unknown IP |
| Privilege Escalation | HIGH | privilege_escalation | sudo/su + shadow file access |
| Lateral Movement | HIGH | lateral_movement | Internal scanning + credential use |
| DNS Tunneling | MEDIUM | command_and_control | Long DNS labels + high query rate |
| Ransomware Activity | CRITICAL | impact | 100+ file renames in 60s |

---

## Dashboard Tabs

1. **Overview** — Stats cards, severity/category charts, agent health grid
2. **Telemetry** — Live event feed (timestamp, type, source, detail)
3. **Correlations** — Detected patterns with confidence scores
4. **Triage** — Incident queue with severity badges
5. **Forensics** — Timeline, IOCs, attack vectors
6. **Containment** — Isolation actions (block IP, isolate host, kill process)
7. **Remediation** — Patch/clean actions with verification
8. **Reports** — NIST incident reports (viewable in-app)

---

## Database Schema

```sql
events              — Raw telemetry (type, source_ip, dest_ip, port, user, process, path)
incidents           — Detected incidents (rule_id, severity, category, status)
correlations        — Detection patterns (pattern, evidence, confidence)
forensics           — Analysis results (timeline, iocs, attack_vector, affected_systems)
containment_actions — Isolation actions (action_type, target, status, result)
remediation_actions — Fix actions (action_type, description, status, verified)
reports             — Generated reports (report_type, content)
```

---

## License

MIT
