import asyncio
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

import httpx
import websockets

from ai_agents.orchestrator import run_analysis
from ai_agents.tools.mitre_tools import ATTACK_LABEL_MAP

logging.basicConfig(level=logging.INFO, format="%(asctime)s [AGENT] %(message)s")
logger = logging.getLogger("agent_runner")

API_BASE = os.getenv("API_BASE", "http://localhost:8765")
WS_URL = os.getenv("WS_URL", "ws://localhost:8765/ws/attacks")
AGENT_WS_URL = os.getenv("AGENT_WS_URL", "ws://localhost:8765/ws/agents")

_busy = False
_collecting = False
_buffer: list[str] = []
_current_attack_type: str | None = None
_current_attack_id: str | None = None


def extract_attack_type(starting_line: str) -> str | None:
    for key, label in ATTACK_LABEL_MAP.items():
        if label in starting_line:
            return key
    return None


def extract_attack_id(starting_line: str) -> str | None:
    if "id=" in starting_line:
        parts = starting_line.split("id=")
        if len(parts) > 1:
            return parts[1].split()[0].strip()
    return None


_agent_ws = None


async def _get_agent_ws():
    global _agent_ws
    try:
        if _agent_ws:
            pong = await _agent_ws.ping()
            await asyncio.wait_for(pong, timeout=2)
    except Exception:
        _agent_ws = None

    if not _agent_ws:
        try:
            _agent_ws = await websockets.connect(AGENT_WS_URL)
            logger.info("Connected to /ws/agents for broadcasting")
        except Exception:
            pass
    return _agent_ws


async def broadcast_status(agent: str, state: str, summary: str = None):
    msg = {"type": "agent_status", "agent": agent, "state": state}
    if summary:
        msg["summary"] = summary
    agent_ws = await _get_agent_ws()
    if not agent_ws:
        return
    try:
        await agent_ws.send(json.dumps(msg))
    except websockets.ConnectionClosed:
        logger.warning("Agent WS closed, cannot broadcast")
    except Exception as e:
        logger.warning(f"Could not broadcast status: {e}")


async def post_finding(report: dict):
    url = f"{API_BASE}/api/agents/findings"
    for attempt in range(2):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json=report, timeout=10)
                if resp.status_code == 200:
                    logger.info(f"Finding posted: id={report.get('id')}")
                    return
                logger.warning(f"POST finding failed: {resp.status_code}")
        except Exception as e:
            logger.warning(f"POST finding error (attempt {attempt+1}): {e}")
            if attempt == 0:
                await asyncio.sleep(2)


async def handle_attack_complete(attack_type: str, output_lines: list[str]):
    global _busy

    logger.info(f"Running agents for {attack_type} ({len(output_lines)} lines)")

    async def status_cb(agent, state, summary=None):
        await broadcast_status(agent, state, summary)

    try:
        report = await run_analysis(attack_type, output_lines, status_callback=status_cb)
        await post_finding(report)
    except Exception as e:
        logger.error(f"Agent pipeline failed: {e}")
        await broadcast_status("orchestrator", "ERROR", str(e))
    finally:
        _busy = False


async def main():
    global _busy, _collecting, _buffer, _current_attack_type, _current_attack_id

    logger.info(f"Connecting to attack WS: {WS_URL}")

    while True:
        try:
            async with websockets.connect(WS_URL) as ws:
                logger.info("Connected to /ws/attacks — waiting for attacks...")

                async for message in ws:
                    line = message.strip() if isinstance(message, str) else message.decode().strip()

                    if line.startswith("[!] STARTING:"):
                        if _busy or _collecting:
                            attack_id = extract_attack_id(line)
                            logger.warning(f"Agents busy, skipping run id={attack_id}")
                            continue
                        _collecting = True
                        _buffer.clear()
                        _current_attack_type = extract_attack_type(line)
                        _current_attack_id = extract_attack_id(line)
                        _buffer.append(line)
                        logger.info(f"Attack started: {_current_attack_type} id={_current_attack_id}")

                        await broadcast_status("orchestrator", "RUNNING")

                    elif _collecting:
                        _buffer.append(line)

                        if line.startswith("[+] ATTACK COMPLETE") or line.startswith("[!] ERROR"):
                            # Snapshot and stop collecting before dispatching
                            attack_type = _current_attack_type
                            output_lines = list(_buffer)
                            _collecting = False
                            _buffer.clear()
                            _current_attack_type = None
                            _current_attack_id = None

                            if not attack_type:
                                logger.warning("No attack type detected, skipping")
                                continue

                            _busy = True
                            asyncio.create_task(
                                handle_attack_complete(attack_type, output_lines)
                            )

        except (websockets.ConnectionClosedError, ConnectionRefusedError, OSError) as e:
            logger.warning(f"WS connection lost: {e}. Reconnecting in 3s...")
            await asyncio.sleep(3)
        except KeyboardInterrupt:
            logger.info("Shutting down agent runner")
            break


if __name__ == "__main__":
    asyncio.run(main())
