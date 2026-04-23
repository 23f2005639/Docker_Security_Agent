import asyncio
import json as _json

# Same flags as attacks/router.py CONTAINER_FLAGS
CONTAINER_FLAGS = {
    "flask-target": ["PRIVILEGED", "SOCK", "SYS_ADMIN"],
    "redis-target": ["NO-AUTH"],
    "nginx-target": ["OLD-IMAGE"],
    "attacker":     ["TOOLS-READY"],
}

SENTINEL_CONTAINERS = ["nginx-target", "flask-target", "redis-target", "attacker"]


async def inspect_container(name: str) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        data = _json.loads(stdout.decode())[0]
        host_config = data.get("HostConfig", {})
        return {
            "name": name,
            "image": data.get("Config", {}).get("Image", "unknown"),
            "privileged": host_config.get("Privileged", False),
            "security_opt": host_config.get("SecurityOpt") or [],
            "cap_add": host_config.get("CapAdd") or [],
            "mounts": [
                {"source": m.get("Source", ""), "destination": m.get("Destination", "")}
                for m in data.get("Mounts", [])
            ],
            "network_mode": host_config.get("NetworkMode", ""),
        }
    except Exception as e:
        return {"name": name, "error": str(e)}


async def get_container_flags(name: str) -> dict:
    flags = CONTAINER_FLAGS.get(name, [])
    return {"name": name, "flags": flags}


async def get_network_topology() -> dict:
    topology = {}
    for name in SENTINEL_CONTAINERS:
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect",
                "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            ip = stdout.decode().strip() or "unknown"
            topology[name] = ip
        except Exception:
            topology[name] = "unknown"
    return {"network": "sentinel_net", "containers": topology}
