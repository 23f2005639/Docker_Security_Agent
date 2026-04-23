ATTACK_LABEL_MAP = {
    "docker_socket":  "Docker Socket Abuse",
    "nsenter_escape": "Privileged nsenter Escape",
    "lateral_redis":  "Redis Lateral Movement",
    "runc_cve":       "CVE-2025-31133 runc Symlink Swap",
    "authz_bypass":   "CVE-2026-34040 Docker AuthZ Bypass",
    "dos_attack":          "DoS — Resource Exhaustion & HTTP Flood",
    "supply_chain_attack": "Supply Chain — Image Tampering & Dependency Poisoning",
}

MITRE_TTP_MAP = {
    "Docker Socket Abuse":              {"ttp": "T1611", "tactic": "Privilege Escalation", "description": "Escape to Host via Docker Socket"},
    "Privileged nsenter Escape":        {"ttp": "T1611", "tactic": "Privilege Escalation", "description": "Escape to Host via nsenter into PID 1 namespace"},
    "Redis Lateral Movement":           {"ttp": "T1570", "tactic": "Lateral Movement",     "description": "Lateral Tool Transfer via Redis exploitation"},
    "CVE-2025-31133 runc Symlink Swap": {"ttp": "T1068", "tactic": "Privilege Escalation", "description": "Exploitation for Privilege Escalation via runc maskedPaths bypass"},
    "CVE-2026-34040 Docker AuthZ Bypass": {"ttp": "T1611", "tactic": "Privilege Escalation", "description": "Container escape via Docker Engine authorization plugin bypass (oversized HTTP body silently dropped before AuthZ inspection)"},
    "DoS — Resource Exhaustion & HTTP Flood": {"ttp": "T1499", "tactic": "Impact", "description": "Endpoint Denial of Service via container resource exhaustion (CPU, memory, process flood) and HTTP application-layer flood"},
    "Supply Chain — Image Tampering & Dependency Poisoning": {"ttp": "T1195", "tactic": "Initial Access", "description": "Supply chain compromise via unverified container images (no Content Trust / digest pinning), typosquatted pip dependencies, backdoor injection into writable container filesystems, and credential exfiltration from exposed environment variables"},
}

CVSS_TABLE = {
    "docker_socket":  {"score": 9.0, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
    "nsenter_escape": {"score": 9.0, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
    "lateral_redis":  {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "runc_cve":       {"score": 7.8, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    "authz_bypass":   {"score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
    "dos_attack":          {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
    "supply_chain_attack": {"score": 9.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
}

TECHNIQUE_DESCRIPTIONS = {
    "docker_socket":  "Attacker abuses a mounted Docker socket (/var/run/docker.sock) to spawn a privileged container with full host filesystem access, enabling container escape and host compromise.",
    "nsenter_escape": "Attacker uses nsenter from a privileged container to enter the host PID 1 namespace, gaining a root shell on the host system.",
    "lateral_redis":  "Attacker performs network reconnaissance, discovers an unauthenticated Redis instance, and exploits it to inject a cron-based reverse shell payload.",
    "runc_cve":       "Attacker exploits CVE-2025-31133 to bypass runc maskedPaths by swapping /dev/null with a symlink during container init, reading sensitive host files like /proc/kcore.",
    "authz_bypass":   "Attacker sends an oversized (>1 MB) HTTP POST directly to the Docker daemon API via a mounted socket. Docker silently drops the body before forwarding to the AuthZ plugin — the plugin sees an empty benign request and permits it. The daemon executes the full original payload, spawning a privileged container with the host filesystem mounted at /hostroot and reading /etc/shadow. (CVE-2026-34040, April 2026, CVSS 8.8)",
    "dos_attack":          "Attacker exploits absent container resource limits (no --cpus, --memory, or --pids-limit) to exhaust host CPU via parallel `yes` workers, allocate 256 MB memory pressure, spawn 500+ processes (fork-bomb class), and flood nginx-target with 500 concurrent HTTP requests — all from within containers that Docker imposes no cgroup restrictions on.",
    "supply_chain_attack": "Attacker exploits four supply chain weaknesses: (1) DOCKER_CONTENT_TRUST disabled — any image tag can be silently replaced with a malicious lookalike or typosquatted variant; (2) no image digest pinning — tag-based pulls allow upstream image substitution; (3) pip packages installed without hash verification — typosquatted packages (e.g. setup-tools vs setuptools) install silently; (4) writable container filesystem + secrets exposed in env vars — a backdoor baked into any layer runs on startup and exfiltrates all credentials. (T1195.001/T1195.002, Initial Access, CVSS 9.3)",
}


def classify_attack_technique(attack_type: str, output_lines: list[str]) -> dict:
    label = ATTACK_LABEL_MAP.get(attack_type, attack_type)
    description = TECHNIQUE_DESCRIPTIONS.get(attack_type, "Unknown attack technique")
    return {"technique": label, "description": description}


def lookup_mitre_ttp(technique_name: str) -> dict:
    entry = MITRE_TTP_MAP.get(technique_name)
    if entry:
        return entry
    return {"ttp": "UNKNOWN", "tactic": "Unknown", "description": "No mapping found"}


def calculate_cvss_score(attack_type: str, flags: list[str] = None) -> dict:
    entry = CVSS_TABLE.get(attack_type)
    if entry:
        return {"score": entry["score"], "vector": entry["vector"]}
    return {"score": 0.0, "vector": "UNKNOWN"}
