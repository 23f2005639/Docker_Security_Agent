import json as _json
import os
import uuid
from datetime import datetime, timezone

from ai_agents.tools.mitre_tools import ATTACK_LABEL_MAP

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "reports")


def calculate_overall_severity(scanner: dict, monitor: dict, network: dict) -> str:
    cvss = monitor.get("cvss", 0) if isinstance(monitor, dict) else 0
    has_host_breach = network.get("host_breach", False) if isinstance(network, dict) else False
    cve_count = len(scanner.get("cves", [])) if isinstance(scanner, dict) else 0

    if cvss >= 9.0 or has_host_breach:
        return "CRITICAL"
    elif cvss >= 7.0 or cve_count >= 3:
        return "HIGH"
    elif cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def compile_findings(attack_type: str, scanner: dict, monitor: dict, network: dict) -> dict:
    report_id = str(uuid.uuid4())[:8]
    severity = calculate_overall_severity(scanner, monitor, network)
    label = ATTACK_LABEL_MAP.get(attack_type, attack_type)

    return {
        "id": report_id,
        "attack_type": attack_type,
        "attack_label": label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_severity": severity,
        "cvss_score": monitor.get("cvss", 0) if isinstance(monitor, dict) else 0,
        "mitre_ttp": monitor.get("ttp", "UNKNOWN") if isinstance(monitor, dict) else "UNKNOWN",
        "mitre_tactic": monitor.get("tactic", "Unknown") if isinstance(monitor, dict) else "Unknown",
        "findings": {
            "scanner": scanner,
            "monitor": monitor,
            "network": network,
            "reporter": {
                "root_cause": "",
                "remediation": "",
                "summary": "",
            },
        },
    }


def save_json_report(findings: dict) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = os.path.join(REPORTS_DIR, f"agent_report_{ts}.json")
    latest_path = os.path.join(REPORTS_DIR, "latest_report.json")

    with open(path, "w") as f:
        _json.dump(findings, f, indent=2)
    with open(latest_path, "w") as f:
        _json.dump(findings, f, indent=2)

    return path
