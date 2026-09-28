"""
FastAPI Server & Real-Time WebSocket Telemetry Gateway
Provides REST endpoints and bi-directional WebSockets for the AegisHarness Security Console.
"""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from aegis import __version__
from aegis.attacks.library import ATTACK_LIBRARY, AttackPayload, get_all_attacks, get_attack_by_id
from aegis.attacks.runner import RedTeamRunner
from aegis.config import CONFIG
from aegis.core.orchestrator import TriWorkloadOrchestrator
from aegis.api.models import (
    AttackExecutionResponse,
    AttackLaunchRequest,
    LedgerVerifyResponse,
    ManualQuarantineRequest,
    SystemStatusResponse,
)

# Global orchestrator and runner instances
ORCHESTRATOR = TriWorkloadOrchestrator()
RUNNER = RedTeamRunner(orchestrator=ORCHESTRATOR, ledger=ORCHESTRATOR.ledger)


class ConnectionManager:
    """Manages real-time WebSocket clients subscribing to Tri-Workload events."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._loop = None

    def set_loop(self, loop):
        self._loop = loop

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    def broadcast_sync(self, message: dict):
        """Thread-safe bridge called by synchronous orchestrator callbacks."""
        if not self._loop or not self.active_connections:
            return
        asyncio.run_coroutine_threadsafe(self.broadcast(message), self._loop)

    async def broadcast(self, message: dict):
        dead_conns = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_conns.append(connection)

        for dead in dead_conns:
            self.disconnect(dead)


MANAGER = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Setup event loop for WebSocket thread-safe bridge
    loop = asyncio.get_running_loop()
    MANAGER.set_loop(loop)

    # Wire orchestrator telemetry callbacks to WebSocket manager
    ORCHESTRATOR.subscribe_telemetry(MANAGER.broadcast_sync)
    print(f"[AegisHarness v{__version__}] Tri-Workload Control Plane Initialized.")
    yield
    print("[AegisHarness] Shutting down.")


app = FastAPI(
    title="AegisHarness API",
    description="Secure Multi-Tenant Infrastructure for Adversarial AI Safety Testing",
    version=__version__,
    lifespan=lifespan,
)

# Enable CORS for external testing or development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static Dashboard Directory
WEB_DIR = Path(__file__).parent.parent.parent / "web"
os.makedirs(WEB_DIR, exist_ok=True)
os.makedirs(WEB_DIR / "css", exist_ok=True)
os.makedirs(WEB_DIR / "js", exist_ok=True)

app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    index_file = WEB_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "AegisHarness API online. Dashboard files mounting in web/."}


@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await MANAGER.connect(websocket)
    try:
        # Send initial greeting and current state
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "zone": "BLUE",
            "message": "Connected to AegisHarness Out-of-Band Telemetry Stream.",
        })
        while True:
            # Keepalive listener
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        MANAGER.disconnect(websocket)


@app.get("/api/status", response_model=SystemStatusResponse)
async def get_system_status():
    is_valid, _, _ = ORCHESTRATOR.ledger.verify_integrity()
    records = ORCHESTRATOR.ledger.get_records()
    return SystemStatusResponse(
        status="ACTIVE",
        version=__version__,
        active_sandboxes=len(ORCHESTRATOR._active_sandboxes),
        total_ledger_records=len(records),
        zero_trust_egress=not CONFIG.SECURITY_POLICY.ALLOW_EGRESS,
        read_only_weights=True,
        ledger_integrity_valid=is_valid,
    )


@app.get("/api/attacks")
async def list_attacks():
    """Returns library of pre-configured exploits and baseline controls."""
    return get_all_attacks()


@app.post("/api/attacks/launch", response_model=AttackExecutionResponse)
async def launch_attack(req: AttackLaunchRequest):
    """Launches an attack payload (library or custom) through the Tri-Workload pipeline."""
    session_id = req.session_id or f"sess-{int(asyncio.get_event_loop().time() * 1000)}"

    if req.attack_id and req.attack_id in ATTACK_LIBRARY:
        attack = ATTACK_LIBRARY[req.attack_id]
    elif req.custom_prompt or req.custom_command:
        attack = AttackPayload(
            id="custom-exploit",
            name="Custom Adversarial Payload",
            category="Custom Ingress",
            severity_level="SEV-1_CRITICAL",
            description="User-defined exploit injected via dashboard console.",
            prompt=req.custom_prompt or "Execute custom command",
            target_tool_command=req.custom_command or "cat /etc/passwd",
            expected_syscall="openat",
            mitre_atlas_tag="AML.T0043",
        )
    else:
        raise HTTPException(status_code=400, detail="Must specify attack_id or custom_prompt/command")

    result = RUNNER.execute_payload(attack=attack, session_id=session_id)
    return AttackExecutionResponse(
        session_id=session_id,
        sandbox_id=result.details.get("sandbox_id", "unknown"),
        attack_id=result.attack_id,
        trapped=result.trapped_by_sandbox,
        syscall_intercepted=result.syscall_intercepted,
        quarantined=result.quarantined,
        quarantine_latency_ms=result.quarantine_latency_ms,
        output=result.details.get("output", ""),
        last_audit_hash=result.audit_hash,
        status=result.details.get("status", "TERMINATED"),
    )


@app.post("/api/attacks/run-suite")
async def run_full_suite():
    """Executes the complete battery of 9 tests and returns a scorecard."""
    return RUNNER.run_full_suite()


@app.get("/api/ledger")
async def get_ledger_records(session_id: Optional[str] = None, limit: int = 100):
    """Retrieves immutable records from the Blue Zone audit ledger."""
    return ORCHESTRATOR.ledger.get_records(session_id=session_id, limit=limit)


@app.get("/api/ledger/verify", response_model=LedgerVerifyResponse)
async def verify_ledger():
    """Mathematically checks every block in the SHA-256 hash chain for tampering."""
    is_valid, msg, comp_idx = ORCHESTRATOR.ledger.verify_integrity()
    records = ORCHESTRATOR.ledger.get_records()
    tip_hash = records[-1]["current_hash"] if records else None
    return LedgerVerifyResponse(
        is_valid=is_valid,
        message=msg or "Verification complete",
        block_count=len(records),
        tip_hash=tip_hash,
        compromised_index=comp_idx,
    )


@app.post("/api/quarantine")
async def trigger_quarantine(req: ManualQuarantineRequest):
    """Operator kill switch to manually slaughter an active sandbox."""
    res = ORCHESTRATOR.trigger_manual_quarantine(session_id=req.session_id, reason=req.reason)
    return res


@app.get("/api/session/{session_id}")
async def get_session_snapshot(session_id: str):
    snapshot = ORCHESTRATOR.get_session_snapshot(session_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Session not found")
    return snapshot


def main():
    uvicorn.run(
        "aegis.api.server:app",
        host=CONFIG.HOST,
        port=CONFIG.PORT,
        reload=False,
    )


if __name__ == "__main__":
    main()
