import os
import json as _json
from agents import Agent, function_tool
from ai_agents.tools.mitre_tools import (
    classify_attack_technique as _classify,
    lookup_mitre_ttp as _lookup_ttp,
    calculate_cvss_score as _calc_cvss,
)


@function_tool
def classify_attack_technique(attack_type: str, output_lines: str) -> str:
    lines = output_lines.split("\n") if output_lines else []
    result = _classify(attack_type, lines)
    return _json.dumps(result)


@function_tool
def lookup_mitre_ttp(technique_name: str) -> str:
    result = _lookup_ttp(technique_name)
    return _json.dumps(result)


@function_tool
def calculate_cvss_score(attack_type: str) -> str:
    result = _calc_cvss(attack_type)
    return _json.dumps(result)


monitor_agent = Agent(
    name="Monitor",
    instructions=(
        "You are a runtime threat analyst for container security. Classify the attack technique, "
        "map it to MITRE ATT&CK TTPs, and calculate the CVSS score.\n\n"
        "Steps:\n"
        "1. Use classify_attack_technique with the attack_type and output lines\n"
        "2. Use lookup_mitre_ttp with the technique name from step 1\n"
        "3. Use calculate_cvss_score with the attack_type\n\n"
        "Return your findings as a JSON object with these exact keys:\n"
        '{"technique": "...", "ttp": "T1611", "tactic": "...", "cvss": 9.0, '
        '"vector": "CVSS:3.1/...", "description": "..."}'
    ),
    model=os.getenv("AI_MODEL", "gpt-5.3-codex"),
    tools=[classify_attack_technique, lookup_mitre_ttp, calculate_cvss_score],
)
