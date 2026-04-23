import asyncio
import json
import subprocess
from agents import function_tool


@function_tool
def get_container_stats(container_name: str) -> str:
    try:
        result = subprocess.run(
            [
                "docker", "stats", "--no-stream", "--format",
                "{{.Name}}|{{.CPUPerc}}|{{.MemPerc}}|{{.MemUsage}}|{{.PIDs}}",
                container_name,
            ],
            capture_output=True, text=True, timeout=8,
        )
        line = result.stdout.strip()
        if not line:
            return json.dumps({"error": f"No stats for {container_name} (not running?)"})

        parts = line.split("|")
        if len(parts) < 5:
            return json.dumps({"error": f"Unexpected docker stats output: {line}"})

        name, cpu_str, mem_pct_str, mem_usage, pids_str = parts

        def _pct(s):
            try:
                return float(s.replace("%", "").strip())
            except ValueError:
                return 0.0

        mem_parts = mem_usage.split("/")
        return json.dumps({
            "container": name.strip(),
            "cpu_pct":   _pct(cpu_str),
            "mem_pct":   _pct(mem_pct_str),
            "mem_usage": mem_parts[0].strip() if mem_parts else "?",
            "mem_limit": mem_parts[1].strip() if len(mem_parts) > 1 else "?",
            "pids":      int(pids_str.strip()) if pids_str.strip().isdigit() else -1,
        })
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "docker stats timed out"})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@function_tool
def get_cgroup_limits(container_name: str) -> str:
    script = (
        "echo -n 'cpu_quota:'; "
        "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null "
        "|| cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unlimited; "
        "echo -n 'memory_max:'; "
        "cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null "
        "|| cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unlimited; "
        "echo -n 'pids_max:'; "
        "cat /sys/fs/cgroup/pids/pids.max 2>/dev/null "
        "|| cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unlimited"
    )
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", script],
            capture_output=True, text=True, timeout=8,
        )
        out = result.stdout.strip()
        limits: dict = {}
        for line in out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                limits[k.strip()] = v.strip()
        return json.dumps({"container": container_name, **limits})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@function_tool
def push_dos_alert(container: str, rule: str, priority: str, detail: str) -> str:
    import requests  # noqa: PLC0415
    payload = {
        "rule": rule,
        "priority": priority,
        "output": detail,
        "output_fields": {"container.name": container},
        "time": "",
    }
    try:
        resp = requests.post(
            "http://localhost:8765/api/falco/events",
            json=payload,
            timeout=4,
        )
        return json.dumps({"status": "pushed", "http": resp.status_code})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@function_tool
def scan_all_containers_for_dos() -> str:
    targets = ["flask-target", "nginx-target", "redis-target", "attacker"]
    results = []
    for name in targets:
        try:
            result = subprocess.run(
                [
                    "docker", "stats", "--no-stream", "--format",
                    "{{.Name}}|{{.CPUPerc}}|{{.MemPerc}}|{{.MemUsage}}|{{.PIDs}}",
                    name,
                ],
                capture_output=True, text=True, timeout=8,
            )
            line = result.stdout.strip()
            if not line:
                results.append({"container": name, "status": "stopped"})
                continue
            parts = line.split("|")
            if len(parts) < 5:
                results.append({"container": name, "status": "parse_error"})
                continue

            _, cpu_str, mem_pct_str, mem_usage, pids_str = parts

            def _pct(s):
                try:
                    return float(s.replace("%", "").strip())
                except ValueError:
                    return 0.0

            mem_parts = mem_usage.split("/")
            results.append({
                "container": name,
                "cpu_pct":  _pct(cpu_str),
                "mem_pct":  _pct(mem_pct_str),
                "mem_usage": mem_parts[0].strip() if mem_parts else "?",
                "pids":     int(pids_str.strip()) if pids_str.strip().isdigit() else -1,
            })
        except Exception as exc:
            results.append({"container": name, "error": str(exc)})
    return json.dumps(results)
