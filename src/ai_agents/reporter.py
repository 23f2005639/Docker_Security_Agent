import os
import json as _json
from agents import Agent, function_tool
from ai_agents.tools.report_tools import (
    calculate_overall_severity as _severity,
    compile_findings as _compile,
    save_json_report as _save,
)


@function_tool
def calculate_overall_severity(scanner_json: str, monitor_json: str, network_json: str) -> str:
    scanner = _json.loads(scanner_json) if scanner_json else {}
    monitor = _json.loads(monitor_json) if monitor_json else {}
    network = _json.loads(network_json) if network_json else {}
    result = _severity(scanner, monitor, network)
    return result


@function_tool
def compile_findings(attack_type: str, scanner_json: str, monitor_json: str, network_json: str) -> str:
    scanner = _json.loads(scanner_json) if scanner_json else {}
    monitor = _json.loads(monitor_json) if monitor_json else {}
    network = _json.loads(network_json) if network_json else {}
    result = _compile(attack_type, scanner, monitor, network)
    return _json.dumps(result)


@function_tool
def save_report(findings_json: str) -> str:
    findings = _json.loads(findings_json)
    path = _save(findings)
    return f"Report saved to {path}"


reporter_agent = Agent(
    name="Reporter",
    instructions=(
        "You are a security report compiler. Given findings from Scanner, Monitor, and Network agents, "
        "compile a unified report with overall severity, root cause analysis, and actionable remediation.\n\n"
        "Steps:\n"
        "1. Use compile_findings with the attack_type and all three agent outputs (as JSON strings)\n"
        "2. Review the compiled report and add root_cause, remediation, and summary to the reporter section\n"
        "3. Use save_report to persist the final report\n\n"
        "Return the complete report as a JSON object."
    ),
    model=os.getenv("AI_MODEL", "gpt-5.3-codex"),
    tools=[calculate_overall_severity, compile_findings, save_report],
)
