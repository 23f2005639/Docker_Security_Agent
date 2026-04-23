import asyncio
import json
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import JSONResponse

from models.attack import AttackRun, ContainerInfo
from attacks import docker_socket, nsenter_escape, lateral_redis, runc_cve, authz_bypass, dos_attack, supply_chain_attack

router = APIRouter()

# In-memory store for attack history
_history: List[AttackRun] = []
_current_run: Optional[AttackRun] = None

# Active WebSocket connections
_ws_clients: List[WebSocket] = []


async def _broadcast(message: str) -> None:
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)


@router.websocket("/ws/attacks")
async def ws_attacks(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()   # keep connection alive
    except WebSocketDisconnect:
        _ws_clients.remove(websocket)


ATTACK_REGISTRY = {
    "docker_socket":   (docker_socket,   "Docker Socket Abuse"),
    "nsenter_escape":  (nsenter_escape,  "Privileged nsenter Escape"),
    "lateral_redis":   (lateral_redis,   "Redis Lateral Movement"),
    "runc_cve":        (runc_cve,        "CVE-2025-31133 runc Symlink Swap"),
    "authz_bypass":    (authz_bypass,    "CVE-2026-34040 Docker AuthZ Bypass"),
    "dos_attack":         (dos_attack,          "DoS — Resource Exhaustion & HTTP Flood"),
    "supply_chain_attack": (supply_chain_attack, "Supply Chain — Image Tampering & Dependency Poisoning"),
}


async def _launch_attack(attack_type: str) -> AttackRun:
    global _current_run

    if _current_run and _current_run.status == "running":
        raise HTTPException(status_code=409, detail="An attack is already running")

    module, label = ATTACK_REGISTRY[attack_type]

    run = AttackRun(
        id=str(uuid.uuid4())[:8],
        attack_type=attack_type,
        attack_label=label,
        status="running",
        started_at=datetime.utcnow(),
    )
    _history.append(run)
    _current_run = run

    await _broadcast(f"[!] STARTING: {label}  id={run.id}  {run.started_at.strftime('%H:%M:%S')}")

    async def run_and_save():
        try:
            await module.run(run, _broadcast)
        except Exception as exc:
            run.status = "failed"
            run.finished_at = datetime.utcnow()
            await _broadcast(f"[!] ERROR: {exc}")
        finally:
            _save_history()

    asyncio.create_task(run_and_save())

    # Auto-trigger Supply Chain monitor agent when supply chain attack starts
    if attack_type == "supply_chain_attack":
        async def _run_supply_chain_monitor():
            try:
                from agents import Runner
                from ai_agents.supply_chain_agent import supply_chain_agent
                await Runner.run(
                    supply_chain_agent,
                    "Run a full supply chain risk assessment on all sentinel containers right now. "
                    "Check image provenance, filesystem writability, package tampering, and secret exposure.",
                )
            except Exception:
                pass
        asyncio.create_task(_run_supply_chain_monitor())

    # Auto-trigger DoS monitor agent when a DoS attack starts
    if attack_type == "dos_attack":
        async def _run_dos_monitor():
            try:
                from agents import Runner
                from ai_agents.dos_monitor_agent import dos_monitor_agent
                await Runner.run(
                    dos_monitor_agent,
                    "Run a full DoS detection scan on all sentinel containers right now. "
                    "Check cgroup limits, poll live stats, and push alerts for any anomalies found.",
                )
            except Exception:
                pass
        asyncio.create_task(_run_dos_monitor())
    return run


def _save_history():
    try:
        import os
        os.makedirs("../reports", exist_ok=True)
        with open("../reports/attacks.json", "w") as f:
            json.dump([r.model_dump(mode="json") for r in _history], f, indent=2, default=str)
    except Exception:
        pass


@router.post("/api/attacks/docker-socket")
async def attack_docker_socket():
    run = await _launch_attack("docker_socket")
    return {"id": run.id, "status": run.status, "attack_type": run.attack_type}


@router.post("/api/attacks/nsenter-escape")
async def attack_nsenter_escape():
    run = await _launch_attack("nsenter_escape")
    return {"id": run.id, "status": run.status, "attack_type": run.attack_type}


@router.post("/api/attacks/lateral-redis")
async def attack_lateral_redis():
    run = await _launch_attack("lateral_redis")
    return {"id": run.id, "status": run.status, "attack_type": run.attack_type}


@router.post("/api/attacks/runc-cve-2025")
async def attack_runc_cve():
    run = await _launch_attack("runc_cve")
    return {"id": run.id, "status": run.status, "attack_type": run.attack_type}


@router.post("/api/attacks/authz-bypass-2026")
async def attack_authz_bypass():
    run = await _launch_attack("authz_bypass")
    return {"id": run.id, "status": run.status, "attack_type": run.attack_type}


@router.post("/api/attacks/dos-attack")
async def attack_dos():
    run = await _launch_attack("dos_attack")
    return {"id": run.id, "status": run.status, "attack_type": run.attack_type}


@router.post("/api/attacks/supply-chain-attack")
async def attack_supply_chain():
    run = await _launch_attack("supply_chain_attack")
    return {"id": run.id, "status": run.status, "attack_type": run.attack_type}


@router.get("/api/attacks/status")
async def get_attack_status():
    if _current_run is None:
        return {"status": "idle", "run": None}
    return {"status": _current_run.status, "run": _current_run.model_dump(mode="json")}


@router.get("/api/attacks/history")
async def get_attack_history():
    return [
        {
            "id": r.id,
            "attack_type": r.attack_type,
            "attack_label": r.attack_label,
            "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "duration_seconds": r.duration_seconds,
            "exit_code": r.exit_code,
            "line_count": len(r.output),
        }
        for r in reversed(_history)
    ]


@router.get("/api/attacks/history/{run_id}")
async def get_attack_run(run_id: str):
    for r in _history:
        if r.id == run_id:
            return r.model_dump(mode="json")
    raise HTTPException(status_code=404, detail="Run not found")


CONTAINER_FLAGS = {
    "flask-target": ["PRIVILEGED", "SOCK", "SYS_ADMIN"],
    "redis-target": ["NO-AUTH"],
    "nginx-target": ["OLD-IMAGE"],
    "attacker":     ["TOOLS-READY"],
}


@router.get("/api/containers/status")
async def get_containers_status():
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "ps",
            "--format", "{{.Names}}|{{.Status}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        running = {}
        for line in stdout.decode().splitlines():
            if "|" in line:
                name, status = line.split("|", 1)
                running[name.strip()] = status.strip()

        # Get IPs via docker inspect
        targets = ["nginx-target", "flask-target", "redis-target", "attacker"]
        result = []
        for name in targets:
            ip = "unknown"
            try:
                ip_proc = await asyncio.create_subprocess_exec(
                    "docker", "inspect",
                    "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                ip_out, _ = await ip_proc.communicate()
                ip = ip_out.decode().strip() or "unknown"
            except Exception:
                pass

            status_str = running.get(name, "stopped")
            is_running = "Up" in status_str or "running" in status_str.lower()

            result.append(
                ContainerInfo(
                    name=name,
                    ip=ip,
                    status="running" if is_running else "stopped",
                    flags=CONTAINER_FLAGS.get(name, []),
                ).model_dump()
            )
        return result

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
