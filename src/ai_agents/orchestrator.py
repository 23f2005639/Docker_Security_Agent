import asyncio
import json
import logging
import os
import re

from agents import Runner

from ai_agents.scanner import scanner_agent
from ai_agents.monitor import monitor_agent
from ai_agents.network import network_agent
from ai_agents.reporter import reporter_agent
from ai_agents.tools.mitre_tools import ATTACK_LABEL_MAP

logger = logging.getLogger(__name__)


async def run_analysis(attack_type: str, output_lines: list[str], status_callback=None) -> dict:
    label = ATTACK_LABEL_MAP.get(attack_type, attack_type)
    output_text = "\n".join(output_lines)

    target_map = {
        "docker_socket":  "flask-target",
        "nsenter_escape": "flask-target",
        "lateral_redis":  "redis-target",
        "runc_cve":       "flask-target",
        "authz_bypass":   "flask-target",
    }
    target = target_map.get(attack_type, "flask-target")

    scanner_prompt = (
        f"Analyze the container '{target}' used in the '{label}' attack. "
        f"Inspect the container, check its misconfiguration flags, and scan its image for vulnerabilities. "
        f"Attack output:\n{output_text[:2000]}"
    )
    monitor_prompt = (
        f"Analyze this '{label}' attack (type={attack_type}). "
        f"Classify the technique, look up the MITRE TTP, and calculate the CVSS score. "
        f"Attack output:\n{output_text[:2000]}"
    )
    network_prompt = (
        f"Analyze network aspects of this '{label}' attack (type={attack_type}). "
        f"Get the network topology, detect pivot paths, and check for exposed services. "
        f"Attack output:\n{output_text[:2000]}"
    )

    async def run_agent(agent, prompt, name):
        if status_callback:
            await status_callback(name, "RUNNING")
        try:
            result = await Runner.run(agent, prompt)
            output = result.final_output
            if status_callback:
                summary = output[:150] if isinstance(output, str) else str(output)[:150]
                await status_callback(name, "DONE", summary)
            return output
        except Exception as e:
            logger.error(f"{name} agent failed: {e}")
            if status_callback:
                await status_callback(name, "ERROR", str(e))
            return json.dumps({"error": str(e)})

    if status_callback:
        await status_callback("orchestrator", "RUNNING")

    scanner_out, monitor_out, network_out = await asyncio.gather(
        run_agent(scanner_agent, scanner_prompt, "scanner"),
        run_agent(monitor_agent, monitor_prompt, "monitor"),
        run_agent(network_agent, network_prompt, "network"),
    )

    reporter_prompt = (
        f"Compile a security report for the '{label}' attack (type={attack_type}).\n\n"
        f"Scanner findings:\n{scanner_out}\n\n"
        f"Monitor findings:\n{monitor_out}\n\n"
        f"Network findings:\n{network_out}\n\n"
        f"Use compile_findings to create the report, then save it."
    )

    report_out = await run_agent(reporter_agent, reporter_prompt, "reporter")

    if status_callback:
        await status_callback("orchestrator", "DONE")

    scanner_dict = _safe_parse(scanner_out)
    monitor_dict = _safe_parse(monitor_out)
    network_dict = _safe_parse(network_out)

    reporter_dict = _safe_parse(report_out)

    if "attack_type" in reporter_dict and "findings" in reporter_dict:
        report = reporter_dict
    else:
        from ai_agents.tools.report_tools import compile_findings, save_json_report
        report = compile_findings(attack_type, scanner_dict, monitor_dict, network_dict)
        if isinstance(reporter_dict, dict) and "raw" not in reporter_dict:
            report["findings"]["reporter"].update(reporter_dict)
        else:
            report["findings"]["reporter"]["summary"] = str(report_out)[:500] if report_out else ""
        save_json_report(report)

    return report


def _extract_json(text: str) -> str | None:
    if not text:
        return None
    m = re.search(r"```(?:json)?\s*(\{.*?})\s*```", text, re.DOTALL)
    if m:
        return m.group(1)
    m = re.search(r"(\{.*})", text, re.DOTALL)
    if m:
        return m.group(1)
    return None


def _safe_parse(text) -> dict:
    if isinstance(text, dict):
        return text
    if not isinstance(text, str):
        return {}
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass
    extracted = _extract_json(text)
    if extracted:
        try:
            return json.loads(extracted)
        except (json.JSONDecodeError, TypeError):
            pass
    return {"raw": text[:500]}
