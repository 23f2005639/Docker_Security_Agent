import json
import os
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

router = APIRouter()

_findings: List[dict] = []
_agent_ws_clients: List[WebSocket] = []


async def broadcast_agent_msg(message: dict) -> None:
    text = json.dumps(message)
    dead = []
    for ws in _agent_ws_clients:
        try:
            await ws.send_text(text)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _agent_ws_clients.remove(ws)


@router.websocket("/ws/agents")
async def ws_agents(websocket: WebSocket):
    await websocket.accept()
    _agent_ws_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in _agent_ws_clients:
            _agent_ws_clients.remove(websocket)



@router.post("/api/agents/findings")
async def post_finding(finding: dict):
    _findings.append(finding)
    await broadcast_agent_msg({"type": "finding", "data": finding})
    return {"status": "ok", "id": finding.get("id")}


@router.get("/api/agents/findings")
async def get_findings():
    return _findings


@router.get("/api/agents/findings/latest")
async def get_latest_finding():
    if not _findings:
        return JSONResponse(status_code=404, content={"detail": "No findings yet"})
    return _findings[-1]




class ImageScanRequest(BaseModel):
    image: str


@router.get("/api/scan/local-images")
async def list_local_images():
    import asyncio
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "images",
            "--format", "{{.Repository}}|||{{.Tag}}|||{{.ID}}|||{{.Size}}|||{{.CreatedSince}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        images = []
        for line in stdout.decode().strip().splitlines():
            parts = line.split("|||")
            if len(parts) != 5:
                continue
            repo, tag, img_id, size, created = parts
            if repo == "<none>" or tag == "<none>":
                continue
            images.append({
                "name": f"{repo}:{tag}",
                "repository": repo,
                "tag": tag,
                "id": img_id[:12],
                "size": size,
                "created": created,
            })
        return images
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": str(e)})


@router.post("/api/scan/image")
async def scan_image(req: ImageScanRequest):
    from agents import Runner
    from ai_agents.image_scanner_agent import image_scanner_agent
    import re

    image = req.image.strip()
    if not image:
        return JSONResponse(status_code=400, content={"detail": "image name is required"})

    try:
        result = await Runner.run(
            image_scanner_agent,
            f"Perform a full security analysis of the Docker image: {image}"
        )
        output = result.final_output

        if isinstance(output, dict):
            report = output
        elif isinstance(output, str):
            m = re.search(r"```(?:json)?\s*(\{.*?})\s*```", output, re.DOTALL)
            raw = m.group(1) if m else output
            m2 = re.search(r"(\{.*})", raw, re.DOTALL)
            raw = m2.group(1) if m2 else raw
            try:
                report = json.loads(raw)
            except Exception:
                report = {"image": image, "raw_output": output[:2000], "error": "parse_failed"}
        else:
            report = {"image": image, "error": "unexpected output type"}

        report.setdefault("scan_timestamp", datetime.now(timezone.utc).isoformat())
        return report

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": str(e), "image": image}
        )


UI_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "ui")


@router.get("/report")
async def report_page():
    return FileResponse(os.path.join(UI_DIR, "report.html"))


@router.get("/scanner")
async def scanner_page():
    return FileResponse(os.path.join(UI_DIR, "scanner.html"))


@router.post("/api/agents/supply-chain-monitor")
async def trigger_supply_chain_monitor():
    from agents import Runner
    from ai_agents.supply_chain_agent import supply_chain_agent

    try:
        result = await Runner.run(
            supply_chain_agent,
            "Run a full supply chain risk assessment on all sentinel containers right now. "
            "Check image provenance, filesystem writability, package tampering, and secret exposure.",
        )
        output = result.final_output
        if isinstance(output, str):
            import re
            m = re.search(r"(\{.*})", output, re.DOTALL)
            output = json.loads(m.group(1)) if m else {"summary": output}
        return {"status": "ok", "result": output}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"detail": str(exc)})


@router.post("/api/agents/dos-monitor")
async def trigger_dos_monitor():
    from agents import Runner
    from ai_agents.dos_monitor_agent import dos_monitor_agent

    try:
        result = await Runner.run(
            dos_monitor_agent,
            "Run a full DoS detection scan on all sentinel containers right now. "
            "Check cgroup limits, poll live stats, and push alerts for any anomalies found.",
        )
        output = result.final_output
        if isinstance(output, str):
            import re
            m = re.search(r"(\{.*})", output, re.DOTALL)
            output = json.loads(m.group(1)) if m else {"summary": output}
        return {"status": "ok", "result": output}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"detail": str(exc)})
