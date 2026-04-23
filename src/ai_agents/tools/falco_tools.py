import json
from agents import function_tool

# MITRE ATT&CK mappings for the 4 Sentinel custom rules
_MITRE_MAP = {
    "sentinel - shell in privileged container": {
        "ttp_id": "T1611",
        "tactic": "Privilege Escalation",
        "technique": "Escape to Host",
        "description": (
            "Attacker spawns a shell inside a privileged container. "
            "Because --privileged removes all kernel capability restrictions, "
            "they can then use nsenter to jump into the host PID namespace and "
            "gain full root on the underlying host."
        ),
    },
    "sentinel - docker socket abuse": {
        "ttp_id": "T1611",
        "tactic": "Privilege Escalation",
        "technique": "Escape to Host via Docker Socket",
        "description": (
            "Container connects to the Docker daemon socket (/var/run/docker.sock). "
            "With socket access the attacker can spawn new root containers that "
            "bind-mount the host filesystem, read /etc/shadow, install backdoors, "
            "or modify host configuration — full container escape."
        ),
    },
    "sentinel - redis lateral movement": {
        "ttp_id": "T1570",
        "tactic": "Lateral Movement",
        "technique": "Lateral Tool Transfer / Internal Network Pivot",
        "description": (
            "Attacker pivots from a compromised container to the unauthenticated "
            "Redis service on port 6379. Using FLUSHALL and CONFIG SET they can "
            "write cron backdoors, SSH keys, or arbitrary files on the Redis host, "
            "expanding their foothold within the container network."
        ),
    },
    "sentinel - cpu exhaustion process detected": {
        "ttp_id": "T1499",
        "tactic": "Impact",
        "technique": "Endpoint Denial of Service — CPU Exhaustion",
        "description": (
            "The `yes` command was spawned inside a container. "
            "With no --cpus cgroup limit set, it will spin on all available cores, "
            "starving other containers and host processes of CPU time."
        ),
    },
    "sentinel - abnormal process spawn rate": {
        "ttp_id": "T1499",
        "tactic": "Impact",
        "technique": "Endpoint Denial of Service — Process Table Flood",
        "description": (
            "A shell inside the container spawned a flood of background processes. "
            "Without a --pids-limit cgroup cap (pids.max = unlimited), this fork-bomb "
            "class attack can exhaust the host kernel's process table, causing OOM kills "
            "across all containers on the host."
        ),
    },
    "sentinel - http flood outbound": {
        "ttp_id": "T1499",
        "tactic": "Impact",
        "technique": "Endpoint Denial of Service — Application-Layer HTTP Flood",
        "description": (
            "The attacker container launched hundreds of concurrent curl requests "
            "targeting an internal service. This saturates the target's HTTP worker pool "
            "and can exhaust ephemeral port ranges on the host network stack."
        ),
    },
    "sentinel - cpu exhaustion threshold breach": {
        "ttp_id": "T1499",
        "tactic": "Impact",
        "technique": "Endpoint Denial of Service — CPU Threshold Exceeded",
        "description": (
            "Live docker stats show container CPU usage above safe threshold. "
            "Detected by the DoSMonitor agent via cgroup polling — no Falco syscall rule "
            "can catch percentage thresholds, so metric-based alerting fills the gap."
        ),
    },
    "sentinel - memory pressure threshold breach": {
        "ttp_id": "T1499",
        "tactic": "Impact",
        "technique": "Endpoint Denial of Service — Memory Exhaustion",
        "description": (
            "Live docker stats show container memory usage above safe threshold. "
            "With no --memory cgroup limit the container can grow until the host OOM "
            "killer fires, taking down unrelated workloads."
        ),
    },
    "sentinel - process flood detected": {
        "ttp_id": "T1499",
        "tactic": "Impact",
        "technique": "Endpoint Denial of Service — PID Exhaustion",
        "description": (
            "Live pids count inside the container exceeded safe threshold. "
            "Detected by DoSMonitor agent. Indicates an active fork-bomb or runaway "
            "process spawner that will degrade the entire host if not contained."
        ),
    },
    "sentinel - docker content trust disabled": {
        "ttp_id": "T1195",
        "tactic": "Initial Access",
        "technique": "Supply Chain Compromise — Image Tampering",
        "description": (
            "DOCKER_CONTENT_TRUST is not set to 1. Any image pulled by tag can be "
            "silently replaced with a malicious image — no cryptographic signature "
            "is verified. Attackers can substitute a backdoored image at any point "
            "in the CI/CD pipeline or registry."
        ),
    },
    "sentinel - image not digest pinned": {
        "ttp_id": "T1195",
        "tactic": "Initial Access",
        "technique": "Supply Chain Compromise — Tag Substitution",
        "description": (
            "The container was started from a mutable image tag (e.g. :latest or :1.0) "
            "rather than an immutable digest (sha256:...). A registry-level compromise "
            "or a man-in-the-middle on the pull path can substitute any content under "
            "the same tag without the operator's knowledge."
        ),
    },
    "sentinel - supply chain backdoor write": {
        "ttp_id": "T1195",
        "tactic": "Initial Access",
        "technique": "Supply Chain Compromise — Backdoor Injection via Writable FS",
        "description": (
            "A process wrote to a critical path (/usr/local/bin, /usr/bin, /etc) inside "
            "a container with a writable root filesystem. This is the persistence mechanism "
            "for a supply chain backdoor: a malicious image layer or post-start script "
            "drops an executable that runs on every subsequent container start."
        ),
    },
    "sentinel - dependency confusion attack": {
        "ttp_id": "T1195",
        "tactic": "Initial Access",
        "technique": "Supply Chain Compromise — Dependency Confusion / Typosquatting",
        "description": (
            "A known typosquatted or dependency-confusion package name was detected in "
            "the container's installed packages. No pip hash verification (--require-hashes) "
            "or index URL pinning is in place, allowing a malicious package to install "
            "silently alongside legitimate dependencies."
        ),
    },
    "sentinel - secrets exposed via environment": {
        "ttp_id": "T1552",
        "tactic": "Credential Access",
        "technique": "Unsecured Credentials — Environment Variables",
        "description": (
            "Sensitive credentials (API keys, passwords, tokens) are stored as plaintext "
            "environment variables. Any process running inside the container — including "
            "a supply chain backdoor activated on startup — can read and exfiltrate all "
            "secrets via /proc/1/environ or the env command."
        ),
    },
    "sentinel - unpinned package dependencies": {
        "ttp_id": "T1195",
        "tactic": "Initial Access",
        "technique": "Supply Chain Compromise — Unpinned Dependencies",
        "description": (
            "Packages are installed without hash verification or a locked requirements file. "
            "A compromised PyPI package (dependency confusion, maintainer account takeover) "
            "would be installed on the next build without any integrity check alerting the team."
        ),
    },
    "sentinel - missing image provenance labels": {
        "ttp_id": "T1195",
        "tactic": "Initial Access",
        "technique": "Supply Chain Compromise — Missing Provenance",
        "description": (
            "The container image has no OCI/Docker labels for build timestamp, source "
            "repository, commit SHA, or build pipeline ID. Without provenance metadata "
            "it is impossible to trace the image back to a known-good build, making "
            "supply chain tampering undetectable through metadata inspection alone."
        ),
    },
    "sentinel - suspicious write in container root fs": {
        "ttp_id": "T1068",
        "tactic": "Privilege Escalation",
        "technique": "Exploitation for Privilege Escalation (maskedPaths bypass)",
        "description": (
            "Attacker writes to /proc/self or the container root (/). "
            "In the runc CVE-2025-31133 scenario this is a symlink-swap attack "
            "that bypasses masked paths, allowing reads of /proc/kcore and "
            "/proc/1/environ — leaking kernel memory and host environment secrets."
        ),
    },
}


@function_tool
def get_recent_events(limit: int = 50) -> str:
    from falco_router import get_events_snapshot
    events = get_events_snapshot()
    return json.dumps(events[-limit:], default=str)


@function_tool
def get_events_by_rule(rule_name: str) -> str:
    from falco_router import get_events_snapshot
    events = [
        e for e in get_events_snapshot()
        if rule_name.lower() in e.get("rule", "").lower()
    ]
    return json.dumps(events, default=str)


@function_tool
def get_events_by_container(container_name: str) -> str:
    from falco_router import get_events_snapshot
    events = [
        e for e in get_events_snapshot()
        if container_name.lower() in e.get("container", "").lower()
    ]
    return json.dumps(events, default=str)


@function_tool
def get_attack_timeline() -> str:
    from falco_router import get_events_snapshot
    events = get_events_snapshot()
    timeline = [{"seq": i + 1, **e} for i, e in enumerate(events)]
    return json.dumps(timeline, default=str)


@function_tool
def map_rule_to_mitre(rule_name: str) -> str:
    key = rule_name.strip().lower()
    for map_key, mapping in _MITRE_MAP.items():
        if map_key in key or key in map_key:
            return json.dumps({"rule": rule_name, **mapping})

    # fallback: infer from keywords
    if "privilege" in key or "shell" in key or "escape" in key or "socket" in key:
        return json.dumps({
            "rule": rule_name,
            "ttp_id": "T1611",
            "tactic": "Privilege Escalation",
            "technique": "Escape to Host",
            "description": "Container escape or privilege escalation technique detected.",
        })
    if "lateral" in key or "redis" in key or "pivot" in key:
        return json.dumps({
            "rule": rule_name,
            "ttp_id": "T1570",
            "tactic": "Lateral Movement",
            "technique": "Internal Network Pivot",
            "description": "Lateral movement between containers detected.",
        })
    if "supply" in key or "chain" in key or "digest" in key or "trust" in key or "dependency" in key or "provenance" in key or "typosquat" in key:
        return json.dumps({
            "rule": rule_name,
            "ttp_id": "T1195",
            "tactic": "Initial Access",
            "technique": "Supply Chain Compromise",
            "description": "Supply chain tampering detected — image integrity or dependency verification failure.",
        })
    if "secret" in key or "credential" in key or "environ" in key:
        return json.dumps({
            "rule": rule_name,
            "ttp_id": "T1552",
            "tactic": "Credential Access",
            "technique": "Unsecured Credentials",
            "description": "Credentials or secrets exposed in container environment.",
        })
    if "write" in key or "proc" in key or "root" in key:
        return json.dumps({
            "rule": rule_name,
            "ttp_id": "T1068",
            "tactic": "Privilege Escalation",
            "technique": "Exploitation for Privilege Escalation",
            "description": "Suspicious filesystem write indicative of privilege escalation.",
        })
    return json.dumps({
        "rule": rule_name,
        "ttp_id": "T1059",
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
        "description": "Runtime anomaly detected — manual MITRE mapping required.",
    })
