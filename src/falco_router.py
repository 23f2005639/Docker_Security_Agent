from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from collections import deque
import asyncio
import json
import re

router = APIRouter()

_events: deque = deque(maxlen=200)
_clients: list[WebSocket] = []
_event_counter: int = 0
_analysis_cache: dict = {}
_analyze_running: bool = False


def get_events_snapshot() -> list:
    return list(_events)


def get_analysis_snapshot() -> dict:
    return dict(_analysis_cache)


async def _broadcast(message: dict):
    text = json.dumps(message)
    dead = []
    for ws in list(_clients):
        try:
            await ws.send_text(text)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _clients.remove(ws)


def _parse_json(text) -> dict:
    if isinstance(text, dict):
        return text
    if not isinstance(text, str):
        return {}
    try:
        return json.loads(text)
    except Exception:
        pass
    m = re.search(r"```(?:json)?\s*(\{.*?})\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    m = re.search(r"(\{.*})", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    return {"threat_summary": text[:90], "risk": "", "action": ""}


async def _analyze_event(event: dict):
    rule = event["rule"]
    event_id = event["id"]

    if rule in _analysis_cache:
        await _broadcast({
            "type": "falco_analysis",
            "event_id": event_id,
            "rule": rule,
            "analysis": _analysis_cache[rule],
        })
        return

    try:
        from agents import Runner
        from ai_agents.falco_analyst import falco_analyst_agent
        prompt = (
            f"Rule: {event['rule']}\n"
            f"Priority: {event['priority']}\n"
            f"Container: {event['container']}\n"
            f"Output: {event['output']}"
        )
        result = await Runner.run(falco_analyst_agent, prompt)
        analysis = _parse_json(result.final_output)
    except Exception:
        analysis = {
            "threat_summary": f"Runtime anomaly: {rule}",
            "risk": "Potential container security violation detected.",
            "action": "Review container activity and Falco logs immediately.",
        }

    _analysis_cache[rule] = analysis
    await _broadcast({
        "type": "falco_analysis",
        "event_id": event_id,
        "rule": rule,
        "analysis": analysis,
    })



async def _run_full_analysis():
    global _analyze_running
    _analyze_running = True
    await _broadcast({
        "type": "falco_analyze_status",
        "state": "RUNNING",
        "message": "FalcoIntelligence agent analyzing all runtime events...",
    })
    try:
        from agents import Runner
        from ai_agents.falco_agent import falco_agent

        prompt = (
            "Analyze ALL recent Falco security events and produce a comprehensive "
            "FalcoAnalysisReport. Follow EVERY step in your instructions exactly:\n"
            "1. Call get_attack_timeline() first\n"
            "2. Call get_events_by_container() for each unique container\n"
            "3. Call map_rule_to_mitre() for each unique rule\n"
            "4. For EVERY unique rule that fired, produce a RuleRootCause entry in "
            "rule_analysis — this field MUST be non-empty. Include the exact technical "
            "root cause, realistic attack scenario, copy-pasteable fix command, "
            "docker-compose fix, and urgency for each rule."
        )
        result = await Runner.run(falco_agent, prompt)
        report = result.final_output
        await _broadcast({
            "type": "falco_report",
            "report": report.model_dump(),
        })
        await _broadcast({
            "type": "falco_analyze_status",
            "state": "DONE",
            "message": "Analysis complete.",
        })
    except Exception as e:
        await _broadcast({
            "type": "falco_analyze_status",
            "state": "ERROR",
            "message": str(e),
        })
    finally:
        _analyze_running = False


@router.post("/api/falco/events")
async def receive_falco_event(payload: dict):
    global _event_counter
    _event_counter += 1
    event_id = _event_counter

    output_fields = payload.get("output_fields") or {}
    event = {
        "id": event_id,
        "rule": payload.get("rule", ""),
        "priority": payload.get("priority", ""),
        "container": output_fields.get("container.name") or "host",
        "output": payload.get("output", ""),
        "time": payload.get("time", ""),
    }
    _events.append(event)

    await _broadcast({"type": "event", **event})
    asyncio.create_task(_analyze_event(event))
    return {"ok": True}


@router.post("/api/falco/analyze")
async def trigger_analysis():
    if not _events:
        return JSONResponse(
            status_code=400,
            content={"error": "No Falco events to analyze yet. Run an attack first."},
        )
    if _analyze_running:
        return JSONResponse(
            status_code=409,
            content={"error": "Analysis already running."},
        )
    asyncio.create_task(_run_full_analysis())
    return {"status": "running"}


@router.get("/api/falco/events")
def get_falco_events(limit: int = 50):
    return list(_events)[-limit:]


@router.delete("/api/falco/events")
async def clear_falco_events():
    global _event_counter
    _events.clear()
    _analysis_cache.clear()
    _event_counter = 0
    await _broadcast({"type": "falco_cleared"})
    return {"ok": True}


@router.websocket("/ws/falco")
async def falco_ws(websocket: WebSocket):
    await websocket.accept()
    # replay buffered events to reconnecting clients
    for event in list(_events):
        try:
            await websocket.send_text(json.dumps({"type": "event", **event}))
            rule = event.get("rule", "")
            if rule in _analysis_cache:
                await websocket.send_text(json.dumps({
                    "type": "falco_analysis",
                    "event_id": event.get("id", 0),
                    "rule": rule,
                    "analysis": _analysis_cache[rule],
                }))
        except Exception:
            return
    _clients.append(websocket)
    try:
        while True:
            await asyncio.sleep(30)
    except (WebSocketDisconnect, Exception):
        if websocket in _clients:
            _clients.remove(websocket)
