import json
import subprocess
from agents import function_tool


@function_tool
def inspect_image_provenance(container_name: str) -> str:
    result = {
        "container": container_name,
        "image": "unknown",
        "digest": "unknown",
        "labels": {},
        "content_trust_status": "DISABLED",
        "risk_flags": [],
    }
    try:
        proc = subprocess.run(
            ["docker", "inspect", container_name,
             "--format", "{{json .Config}}"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            cfg = json.loads(proc.stdout.strip())
            result["image"] = cfg.get("Image", "unknown")
            result["labels"] = cfg.get("Labels") or {}
            env = cfg.get("Env") or []
            dct = next((e for e in env if "DOCKER_CONTENT_TRUST" in e), None)
            if dct and "=1" in dct:
                result["content_trust_status"] = "ENABLED"
            else:
                result["content_trust_status"] = "DISABLED"
                result["risk_flags"].append("DOCKER_CONTENT_TRUST not enabled — image signatures not verified")

        img_proc = subprocess.run(
            ["docker", "inspect", container_name,
             "--format", "{{.Image}}"],
            capture_output=True, text=True, timeout=10,
        )
        if img_proc.returncode == 0:
            result["digest"] = img_proc.stdout.strip()
            if not result["digest"].startswith("sha256:"):
                result["risk_flags"].append("Image not pinned by digest — tag can be silently replaced")

        if not result["labels"]:
            result["risk_flags"].append("No image labels — no provenance metadata (build date, source repo, etc.)")

    except Exception as exc:
        result["error"] = str(exc)

    return json.dumps(result)


@function_tool
def check_filesystem_writability(container_name: str) -> str:
    result = {
        "container": container_name,
        "read_only": False,
        "writable_paths": [],
        "risk_flags": [],
    }
    try:
        proc = subprocess.run(
            ["docker", "inspect", container_name,
             "--format", "{{.HostConfig.ReadonlyRootfs}}"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            result["read_only"] = proc.stdout.strip().lower() == "true"
            if not result["read_only"]:
                result["risk_flags"].append("Container root filesystem is writable — malicious layers can persist")

        for path in ["/usr/local/bin", "/usr/bin", "/etc", "/tmp"]:
            test_proc = subprocess.run(
                ["docker", "exec", container_name,
                 "sh", "-c", f"touch {path}/.sentinel_test 2>/dev/null && echo writable || echo readonly"],
                capture_output=True, text=True, timeout=5,
            )
            if test_proc.returncode == 0 and "writable" in test_proc.stdout:
                result["writable_paths"].append(path)
                subprocess.run(
                    ["docker", "exec", container_name, "rm", "-f", f"{path}/.sentinel_test"],
                    capture_output=True, timeout=5,
                )

        if result["writable_paths"]:
            result["risk_flags"].append(
                f"Critical paths writable: {', '.join(result['writable_paths'])} — backdoor injection possible"
            )

    except Exception as exc:
        result["error"] = str(exc)

    return json.dumps(result)


@function_tool
def scan_for_tampered_packages(container_name: str) -> str:
    KNOWN_TYPOSQUATS = {
        "setup-tools": "setuptools",
        "urllib4": "urllib3",
        "requestes": "requests",
        "pyton": "python",
        "djang": "django",
        "flaskk": "flask",
        "nump": "numpy",
        "panads": "pandas",
        "pillow2": "Pillow",
        "cryptographyy": "cryptography",
        "boto": "boto3",
        "coloramma": "colorama",
    }

    result = {
        "container": container_name,
        "packages_checked": 0,
        "suspicious": [],
        "risk_flags": [],
    }
    try:
        proc = subprocess.run(
            ["docker", "exec", container_name,
             "sh", "-c", "pip3 list --format=columns 2>/dev/null || pip list --format=columns 2>/dev/null"],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode == 0:
            lines = proc.stdout.strip().splitlines()[2:]  # skip header
            packages = [l.split()[0].lower() for l in lines if l.strip()]
            result["packages_checked"] = len(packages)
            for pkg in packages:
                if pkg in KNOWN_TYPOSQUATS:
                    result["suspicious"].append({
                        "installed": pkg,
                        "likely_intended": KNOWN_TYPOSQUATS[pkg],
                        "severity": "HIGH",
                        "reason": "Known typosquat name",
                    })

        if result["suspicious"]:
            result["risk_flags"].append(
                f"{len(result['suspicious'])} suspicious package(s) detected — possible dependency confusion attack"
            )
        else:
            result["risk_flags"].append("No pip index URL pinning — supply chain substitution still possible via upstream PyPI compromise")

    except Exception as exc:
        result["error"] = str(exc)

    return json.dumps(result)


@function_tool
def check_environment_secrets_exposure(container_name: str) -> str:
    SECRET_PATTERNS = [
        "key", "secret", "token", "password", "api", "db_", "dsn",
        "auth", "credential", "private", "passwd", "pwd",
    ]
    result = {
        "container": container_name,
        "secrets_found": [],
        "count": 0,
        "risk_flags": [],
    }
    try:
        proc = subprocess.run(
            ["docker", "exec", container_name, "env"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                key = line.split("=", 1)[0].lower()
                val = line.split("=", 1)[1] if "=" in line else ""
                for pattern in SECRET_PATTERNS:
                    if pattern in key and val and val != "" and len(val) > 3:
                        result["secrets_found"].append({
                            "var": line.split("=", 1)[0],
                            "value_preview": val[:8] + "..." if len(val) > 8 else val,
                        })
                        break

        result["count"] = len(result["secrets_found"])
        if result["secrets_found"]:
            result["risk_flags"].append(
                f"{result['count']} secret(s) exposed as env vars — a supply chain backdoor running on startup would exfiltrate all"
            )
        result["risk_flags"].append(
            "Container env vars readable by any process running inside — use Docker secrets or Vault instead"
        )

    except Exception as exc:
        result["error"] = str(exc)

    return json.dumps(result)


@function_tool
def push_supply_chain_alert(rule: str, priority: str, container: str, detail: str) -> str:
    import httpx
    import asyncio
    from datetime import datetime, timezone

    payload = {
        "rule": rule,
        "priority": priority,
        "container": container,
        "output": f"{rule} ({detail})",
        "time": datetime.now(timezone.utc).isoformat(),
        "source": "supply_chain_monitor",
    }
    try:
        response = httpx.post(
            "http://localhost:8000/api/falco/events",
            json=payload,
            timeout=5.0,
        )
        return json.dumps({"status": "pushed", "http_status": response.status_code, "rule": rule})
    except Exception as exc:
        return json.dumps({"status": "error", "error": str(exc), "rule": rule})
