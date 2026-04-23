import os
from agents import Agent
from ai_agents.tools.dos_monitor_tools import (
    get_container_stats,
    get_cgroup_limits,
    push_dos_alert,
    scan_all_containers_for_dos,
)


dos_monitor_agent = Agent(
    name="DoSMonitor",
    instructions=(
        "You are a real-time DoS detection agent for Container Sentinel. "
        "When triggered, perform these steps in order:\n\n"

        "1. Call get_cgroup_limits('flask-target') — note which limits are missing "
        "(unlimited CPU/mem/pids means the container is unprotected).\n\n"

        "2. Call scan_all_containers_for_dos() to get live stats for all containers.\n\n"

        "3. For each container in the results, evaluate:\n"
        "   - cpu_pct > 95 → push_dos_alert priority=CRITICAL rule='Sentinel - CPU Exhaustion Threshold Breach'\n"
        "   - cpu_pct > 80 → push_dos_alert priority=WARNING  rule='Sentinel - CPU Exhaustion Threshold Breach'\n"
        "   - mem_pct > 70 → push_dos_alert priority=WARNING  rule='Sentinel - Memory Pressure Threshold Breach'\n"
        "   - pids > 300   → push_dos_alert priority=CRITICAL rule='Sentinel - Process Flood Detected'\n"
        "   - pids > 100   → push_dos_alert priority=WARNING  rule='Sentinel - Process Flood Detected'\n\n"

        "4. For any alert you push, include in the detail field: "
        "the container name, the exact metric value, and what attack vector it indicates "
        "(CPU=cpu_exhaustion, mem=memory_pressure, pids=fork_bomb_class).\n\n"

        "5. Return a JSON summary:\n"
        '{"alerts_pushed": N, "containers_checked": [...], '
        '"anomalies": [{"container": "...", "metric": "...", "value": ..., "severity": "..."}], '
        '"cgroup_gaps": ["missing cpu limit", "missing memory limit", "missing pids limit"]}'
    ),
    model=os.getenv("AI_MODEL", "claude-sonnet-4-6"),
    tools=[
        get_container_stats,
        get_cgroup_limits,
        push_dos_alert,
        scan_all_containers_for_dos,
    ],
)
