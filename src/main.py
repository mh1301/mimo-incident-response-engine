"""MiMo Incident Response Engine - Main Application
Multi-agent system for automated incident detection, triage, forensics, containment, and reporting.
"""
import asyncio
import json
import time
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .database import init_db, get_db, get_stats, get_recent_events, get_open_incidents
from .core.kernel import AgentKernel
from .core.metrics import metrics
from .agents.telemetry_agent import TelemetryAgent
from .agents.correlation_agent import CorrelationAgent
from .agents.triage_agent import TriageAgent
from .agents.forensic_agent import ForensicAgent
from .agents.containment_agent import ContainmentAgent
from .agents.remediation_agent import RemediationAgent
from .agents.report_agent import ReportAgent
from .config import HOST, PORT


# ── WebSocket Manager ──────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()

# ── Global instances ───────────────────────────────────────────
kernel = AgentKernel()
telemetry_agent = TelemetryAgent()
correlation_agent = CorrelationAgent()
triage_agent = TriageAgent()
forensic_agent = ForensicAgent()
containment_agent = ContainmentAgent()
remediation_agent = RemediationAgent()
report_agent = ReportAgent()


# ── Background broadcast loop ─────────────────────────────────
async def broadcast_loop():
    """Push real-time updates to dashboard via WebSocket."""
    while True:
        try:
            if manager.active:
                stats = get_stats()
                health = kernel.get_health()
                await manager.broadcast({
                    "type": "update",
                    "timestamp": datetime.utcnow().isoformat(),
                    "stats": stats,
                    "health": health,
                    "metrics": metrics.get_all(),
                })
        except Exception as e:
            pass
        await asyncio.sleep(3)


# ── Lifespan ───────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    # Register all agents
    kernel.register(telemetry_agent)
    kernel.register(correlation_agent)
    kernel.register(triage_agent)
    kernel.register(forensic_agent)
    kernel.register(containment_agent)
    kernel.register(remediation_agent)
    kernel.register(report_agent)

    # Start all agents
    await kernel.start_all()
    broadcaster = asyncio.create_task(broadcast_loop())

    yield

    broadcaster.cancel()
    await kernel.stop_all()


# ── FastAPI App ────────────────────────────────────────────────
app = FastAPI(title="MiMo Incident Response Engine", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Frontend ───────────────────────────────────────────────────
@app.get("/")
async def index():
    return FileResponse("templates/index.html")


# ── WebSocket ──────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ── API Endpoints ──────────────────────────────────────────────
@app.get("/api/stats")
async def api_stats():
    return get_stats()


@app.get("/api/health")
async def api_health():
    return kernel.get_health()


@app.get("/api/metrics")
async def api_metrics():
    return metrics.get_all()


@app.get("/api/events")
async def api_events(limit: int = 100):
    return get_recent_events(limit)


@app.get("/api/incidents")
async def api_incidents():
    conn = get_db()
    rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 100").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/incidents/open")
async def api_open_incidents():
    return get_open_incidents()


@app.get("/api/incidents/{incident_id}")
async def api_incident_detail(incident_id: int):
    conn = get_db()
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not inc:
        conn.close()
        return JSONResponse({"error": "Not found"}, 404)

    forensics = conn.execute("SELECT * FROM forensics WHERE incident_id=?", (incident_id,)).fetchall()
    correlations = conn.execute("SELECT * FROM correlations WHERE incident_id=?", (incident_id,)).fetchall()
    containments = conn.execute("SELECT * FROM containment_actions WHERE incident_id=?", (incident_id,)).fetchall()
    remediations = conn.execute("SELECT * FROM remediation_actions WHERE incident_id=?", (incident_id,)).fetchall()
    reports = conn.execute("SELECT * FROM reports WHERE incident_id=?", (incident_id,)).fetchall()
    conn.close()

    return {
        "incident": dict(inc),
        "forensics": [dict(r) for r in forensics],
        "correlations": [dict(r) for r in correlations],
        "containments": [dict(r) for r in containments],
        "remediations": [dict(r) for r in remediations],
        "reports": [dict(r) for r in reports],
    }


@app.get("/api/correlations")
async def api_correlations():
    conn = get_db()
    rows = conn.execute("SELECT * FROM correlations ORDER BY created_at DESC LIMIT 100").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/forensics")
async def api_forensics():
    conn = get_db()
    rows = conn.execute("SELECT * FROM forensics ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/containments")
async def api_containments():
    conn = get_db()
    rows = conn.execute("SELECT * FROM containment_actions ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/remediations")
async def api_remediations():
    conn = get_db()
    rows = conn.execute("SELECT * FROM remediation_actions ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/reports")
async def api_reports():
    conn = get_db()
    rows = conn.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/reports/{report_id}")
async def api_report_detail(report_id: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
    conn.close()
    if not row:
        return JSONResponse({"error": "Not found"}, 404)
    return dict(row)


@app.get("/api/sigma-rules")
async def api_sigma_rules():
    from .config import SIGMA_RULES
    return SIGMA_RULES


@app.post("/api/simulate")
async def api_simulate():
    """Trigger a new attack simulation."""
    from .config import ATTACK_SCENARIOS
    import random
    scenario = random.choice(ATTACK_SCENARIOS)
    return {"message": f"Simulating: {scenario['name']}", "scenario": scenario["id"]}


# ── Run ────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
