import os
import json as _json
from agents import Agent, function_tool
from ai_agents.tools.docker_tools import get_network_topology as _topology


@function_tool
async def get_network_topology() -> str:
    result = await _topology()
    return _json.dumps(result)


@function_tool
def detect_pivot_path(attack_type: str, output_lines: str) -> str:
    lines = output_lines.split("\n") if output_lines else []
    pivot_map = {
        "docker_socket":  "attacker -> flask-target (docker.sock) -> host",
        "nsenter_escape": "attacker -> flask-target (nsenter PID 1) -> host",
        "lateral_redis":  "attacker -> nmap 172.20.0.0/24 -> redis-target:6379",
        "runc_cve":       "attacker -> flask-target (runc symlink) -> host /proc",
    }
    pivot = pivot_map.get(attack_type, "unknown")
    indicators = []
    for line in lines:
        lower = line.lower()
        if "nmap" in lower or "open" in lower:
            indicators.append(f"scan: {line.strip()[:80]}")
        elif "nsenter" in lower:
            indicators.append(f"namespace entry: {line.strip()[:80]}")
        elif "docker exec" in lower or "docker run" in lower:
            indicators.append(f"container command: {line.strip()[:80]}")
    return _json.dumps({"pivot_path": pivot, "indicators": indicators[:5]})


@function_tool
def check_exposed_services(output_lines: str) -> str:
    lines = output_lines.split("\n") if output_lines else []
    exposed = []
    host_breach = False
    for line in lines:
        lower = line.lower()
        if "/var/run/docker.sock" in line:
            exposed.append("/var/run/docker.sock")
        if "/hostroot" in line or "/host" in lower:
            exposed.append(line.strip()[:80])
            host_breach = True
        if "/etc/shadow" in line:
            exposed.append("/etc/shadow (host)")
            host_breach = True
        if "6379" in line:
            exposed.append("redis:6379 (no auth)")
        if "/proc/kcore" in line or "/proc/1/environ" in line:
            exposed.append(line.strip()[:80])
            host_breach = True
    exposed = list(dict.fromkeys(exposed))[:10]
    return _json.dumps({"exposed": exposed, "host_breach": host_breach})


network_agent = Agent(
    name="Network",
    instructions=(
        "You are a network security analyst for container environments. Examine the attack for "
        "lateral movement paths, exposed services, and host namespace breaches.\n\n"
        "Steps:\n"
        "1. Use get_network_topology to see the container network layout\n"
        "2. Use detect_pivot_path with the attack_type and output lines\n"
        "3. Use check_exposed_services with the output lines\n\n"
        "Return your findings as a JSON object with these exact keys:\n"
        '{"pivot_path": "attacker -> ...", "exposed": [...], "host_breach": true/false, "summary": "..."}'
    ),
    model=os.getenv("AI_MODEL", "gpt-5.3-codex"),
    tools=[get_network_topology, detect_pivot_path, check_exposed_services],
)
