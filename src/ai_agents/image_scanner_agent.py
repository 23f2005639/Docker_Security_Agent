import asyncio
import json as _json
import os
from agents import Agent, function_tool


def _trivy_bin() -> str:
    import shutil
    path = shutil.which("trivy")
    if path:
        return path
    for candidate in ("/usr/local/bin/trivy", os.path.expanduser("~/.local/bin/trivy")):
        if os.path.isfile(candidate):
            return candidate
    return "trivy"


async def _run_trivy_full(image: str) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            _trivy_bin(), "image",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--format", "json",
            "--quiet",
            image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            err = stderr.decode().strip() if stderr else f"exit code {proc.returncode}"
            return {"image": image, "error": err, "results": []}

        data = _json.loads(stdout.decode())
        results = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

        for result in data.get("Results", []):
            target = result.get("Target", "")
            vuln_type = result.get("Type", "")
            vulns = []
            for v in result.get("Vulnerabilities", []):
                sev = v.get("Severity", "UNKNOWN")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                cvss_v3 = None
                cvss_data = v.get("CVSS", {})
                for source in ("nvd", "redhat", "ghsa"):
                    if source in cvss_data and "V3Score" in cvss_data[source]:
                        cvss_v3 = cvss_data[source]["V3Score"]
                        break
                vulns.append({
                    "id": v.get("VulnerabilityID", ""),
                    "severity": sev,
                    "package": v.get("PkgName", ""),
                    "installed_version": v.get("InstalledVersion", ""),
                    "fixed_version": v.get("FixedVersion", "") or "no fix available",
                    "title": v.get("Title", ""),
                    "description": (v.get("Description", "") or "")[:300],
                    "cvss_v3": cvss_v3,
                    "published": v.get("PublishedDate", ""),
                    "references": v.get("References", [])[:2],
                })
            if vulns:
                results.append({"target": target, "type": vuln_type, "vulnerabilities": vulns})

        return {
            "image": image,
            "schema_version": data.get("SchemaVersion"),
            "created_at": data.get("CreatedAt", ""),
            "severity_counts": severity_counts,
            "total_vulnerabilities": sum(severity_counts.values()),
            "results": results,
        }

    except FileNotFoundError:
        return {"image": image, "error": "trivy not installed — install via: https://trivy.dev/docs/getting-started/installation/", "results": []}
    except Exception as e:
        return {"image": image, "error": str(e), "results": []}


async def _run_trivy_config(image: str) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            _trivy_bin(), "image",
            "--scanners", "misconfig,secret",
            "--format", "json",
            "--quiet",
            image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            return {"misconfigs": [], "secrets": []}

        data = _json.loads(stdout.decode())
        misconfigs = []
        secrets = []

        for result in data.get("Results", []):
            for m in result.get("Misconfigurations", []):
                misconfigs.append({
                    "id": m.get("ID", ""),
                    "type": m.get("Type", ""),
                    "title": m.get("Title", ""),
                    "severity": m.get("Severity", ""),
                    "description": (m.get("Description", "") or "")[:200],
                    "resolution": (m.get("Resolution", "") or "")[:200],
                })
            for s in result.get("Secrets", []):
                secrets.append({
                    "rule_id": s.get("RuleID", ""),
                    "category": s.get("Category", ""),
                    "severity": s.get("Severity", ""),
                    "title": s.get("Title", ""),
                })

        return {"misconfigs": misconfigs[:20], "secrets": secrets[:10]}
    except Exception:
        return {"misconfigs": [], "secrets": []}


@function_tool
async def scan_image_vulnerabilities(image: str) -> str:
    result = await _run_trivy_full(image)
    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    _KEEP = ("id", "severity", "package", "installed_version", "fixed_version", "title", "cvss_v3")
    for r in result.get("results", []):
        vulns = sorted(
            r.get("vulnerabilities", []),
            key=lambda v: _SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4),
        )
        r["vulnerabilities"] = [
            {k: v[k] for k in _KEEP if k in v}
            for v in vulns[:25]
        ]
    return _json.dumps(result)


@function_tool
async def scan_image_misconfigs(image: str) -> str:
    result = await _run_trivy_config(image)
    return _json.dumps(result)


@function_tool
def calculate_risk_score(severity_counts_json: str) -> str:
    try:
        counts = _json.loads(severity_counts_json)
    except Exception:
        return _json.dumps({"risk_score": 0.0, "risk_level": "UNKNOWN", "rationale": "parse error"})

    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    medium = counts.get("MEDIUM", 0)
    low = counts.get("LOW", 0)

    weighted = (critical * 10.0) + (high * 7.0) + (medium * 4.0) + (low * 1.0)
    total = critical + high + medium + low

    if total == 0:
        return _json.dumps({"risk_score": 0.0, "risk_level": "CLEAN", "rationale": "No vulnerabilities detected"})

    normalized = min(10.0, weighted / max(total, 1) * (1 + (total / 50.0)))
    normalized = round(normalized, 1)

    if normalized >= 9.0 or critical >= 5:
        level = "CRITICAL"
    elif normalized >= 7.0 or critical >= 1:
        level = "HIGH"
    elif normalized >= 4.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    rationale = (
        f"{critical} CRITICAL, {high} HIGH, {medium} MEDIUM, {low} LOW vulnerabilities. "
        f"Weighted score formula: (C×10 + H×7 + M×4 + L×1) / total × volume factor."
    )

    return _json.dumps({"risk_score": normalized, "risk_level": level, "rationale": rationale})


image_scanner_agent = Agent(
    name="ImageScanner",
    instructions=(
        "You are a professional container security analyst producing industry-grade vulnerability reports.\n\n"
        "Given a Docker image name, perform a comprehensive security assessment:\n\n"
        "1. Call scan_image_vulnerabilities(image) to get all CVEs\n"
        "2. Call scan_image_misconfigs(image) to get misconfigurations and exposed secrets\n"
        "3. Call calculate_risk_score with the severity_counts JSON from step 1\n"
        "4. Using your expert knowledge, produce deep root cause analysis for every CRITICAL and HIGH CVE found "
        "(up to 10 entries). For each CVE, explain the specific technical root cause, describe a realistic "
        "attack scenario, and provide the exact shell command or Dockerfile line that fixes it.\n\n"
        "Return a single JSON object with these EXACT keys:\n"
        "{\n"
        '  "image": "<image name>",\n'
        '  "risk_score": <0.0-10.0>,\n'
        '  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|CLEAN",\n'
        '  "severity_counts": {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N},\n'
        '  "total_vulnerabilities": N,\n'
        '  "top_cves": [<top 10 by severity, each: {id, severity, package, installed_version, fixed_version, title, cvss_v3}>],\n'
        '  "cve_analysis": [\n'
        '    {\n'
        '      "id": "<CVE-ID>",\n'
        '      "package": "<package name>",\n'
        '      "severity": "CRITICAL|HIGH",\n'
        '      "root_cause": "<specific technical explanation of WHY this version is vulnerable — mention the exact flaw, e.g. heap overflow in X function due to missing bounds check>",\n'
        '      "attack_scenario": "<concrete realistic attack: how an attacker exploits this in a container context, what they gain>",\n'
        '      "exact_fix": "<exact shell command to remediate, e.g. apt-get install -y --only-upgrade libssl3=3.0.11-1>",\n'
        '      "dockerfile_fix": "<one-liner Dockerfile RUN command that fixes this>",\n'
        '      "urgency": "immediate|within-30-days|routine"\n'
        '    }\n'
        '  ],\n'
        '  "misconfigs": [<list of misconfig objects>],\n'
        '  "secrets_found": N,\n'
        '  "fixable_count": N,\n'
        '  "remediation_priority": ["<action 1>", "<action 2>", ...],\n'
        '  "compliance_notes": "<CIS/DISA-STIG/NIST observations>",\n'
        '  "executive_summary": "<2-3 sentence professional summary for a CISO>",\n'
        '  "scan_timestamp": "<ISO timestamp>"\n'
        "}\n\n"
        "Be precise and professional. Executive summary should be suitable for a CISO briefing. "
        "Remediation priority should list the 3-5 highest-impact actions first. "
        "Compliance notes should reference relevant frameworks (CIS Docker Benchmark, NIST SP 800-190, DISA STIG). "
        "Root cause analysis must be technically specific — never generic. "
        "Exact fix commands must be copy-pasteable and version-pinned where possible."
    ),
    model=os.getenv("AI_MODEL", "gpt-5.3-codex"),
    tools=[scan_image_vulnerabilities, scan_image_misconfigs, calculate_risk_score],
)
