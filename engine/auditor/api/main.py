"""FastAPI surface. Binds :3001 to match the frontend's vite proxy."""
from __future__ import annotations
import asyncio
import json
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from auditor.pipeline import run_audit
from auditor.schema import AuditReport, TemplateInfo

app = FastAPI(title="HexAudit Engine", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORTS: dict[str, AuditReport] = {}
WS_CLIENTS: set[WebSocket] = set()
TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "templates"


class AuditRequest(BaseModel):
    contractName: str
    sourceCode: str
    contractAddress: str | None = None
    network: str | None = None


async def _broadcast(payload: dict[str, Any]) -> None:
    dead = []
    for ws in WS_CLIENTS:
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            dead.append(ws)
    for ws in dead:
        WS_CLIENTS.discard(ws)


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "engine": "python", "version": "1.0.0"}


@app.post("/api/audit", response_model=AuditReport)
async def audit(req: AuditRequest) -> AuditReport:
    if not req.contractName.strip() or not req.sourceCode.strip():
        raise HTTPException(400, "contractName and sourceCode are required")
    loop = asyncio.get_running_loop()

    def progress(stage: str, pct: float, msg: str, data: dict | None = None) -> None:
        payload = {"stage": stage, "progress": pct, "message": msg, "data": data}
        asyncio.run_coroutine_threadsafe(_broadcast(payload), loop)

    try:
        report = await asyncio.to_thread(
            run_audit, req.contractName.strip(), req.sourceCode, progress
        )
    except Exception as e:
        raise HTTPException(500, f"audit failed: {e}") from e

    REPORTS[report.report_id] = report
    return report


@app.post("/api/upload", response_model=AuditReport)
async def upload(file: UploadFile = File(...)) -> AuditReport:
    source = (await file.read()).decode("utf-8", errors="replace")
    name = (file.filename or "Contract.sol").rsplit(".", 1)[0]
    return await audit(AuditRequest(contractName=name, sourceCode=source))


@app.get("/api/report/{report_id}", response_model=AuditReport)
async def get_report(report_id: str) -> AuditReport:
    if report_id not in REPORTS:
        raise HTTPException(404, "report not found")
    return REPORTS[report_id]


@app.get("/api/templates", response_model=list[TemplateInfo])
async def list_templates() -> list[TemplateInfo]:
    out: list[TemplateInfo] = []
    if TEMPLATE_DIR.exists():
        for p in sorted(TEMPLATE_DIR.glob("*.sol")):
            src = p.read_text(encoding="utf-8", errors="replace")
            out.append(TemplateInfo(
                id=p.stem.lower(),
                name=p.stem.replace("_", " ").title(),
                description=f"Secure template: {p.stem}",
                solidity_version="0.8.20",
                source_code=src,
            ))
    return out

DEMO_DIR = Path(__file__).resolve().parents[2] / "templates" / "demos"


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "name": "HexAudit Python Engine",
        "status": "live",
        "docs": "/docs",
        "health": "/api/health",
    }


@app.get("/api/demos")
async def list_demos() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if DEMO_DIR.exists():
        for p in sorted(DEMO_DIR.glob("*.sol")):
            try:
                src = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            name = p.stem
            out.append({
                "id": name.lower(),
                "name": name,
                "description": _demo_description(name),
                "sourceCode": src,
            })
    return out


def _demo_description(name: str) -> str:
    n = name.lower()
    if "reentrancy" in n:
        return "Classic reentrancy — external call before state update."
    if "accesscontrol" in n:
        return "Missing access control — privileged setter is public."
    if "overflow" in n:
        return "Integer overflow/underflow on Solidity <0.8, no SafeMath."
    if "unchecked" in n:
        return "Unchecked low-level call — return value ignored."
    if "timestamp" in n:
        return "Timestamp used for randomness — miner-manipulable."
    if "delegatecall" in n:
        return "Delegatecall to user-supplied target."
    if "oracle" in n:
        return "Spot-price oracle from balanceOf — flash-loan manipulable."
    if "txorigin" in n:
        return "tx.origin used for authorization — phishing vector."
    return f"Demo contract: {name}"



@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    WS_CLIENTS.add(ws)
    try:
        await ws.send_text(json.dumps({"type": "connected", "message": "ws ready"}))
        while True:
            await ws.receive_text()  # keepalive; we ignore inbound messages
    except WebSocketDisconnect:
        pass
    finally:
        WS_CLIENTS.discard(ws)