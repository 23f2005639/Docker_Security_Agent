import os
from agents import Agent
from ai_agents.tools.supply_chain_tools import (
    inspect_image_provenance,
    check_filesystem_writability,
    scan_for_tampered_packages,
    check_environment_secrets_exposure,
    push_supply_chain_alert,
)


supply_chain_agent = Agent(
    name="SupplyChainMonitor",
    instructions=(
        "You are a supply chain security analysis agent for Container Sentinel. "
        "When triggered, perform a full supply chain risk assessment across running containers.\n\n"

        "Execute these steps in order:\n\n"

        "1. Call inspect_image_provenance('flask-target') — check for:\n"
        "   - DOCKER_CONTENT_TRUST disabled → push_supply_chain_alert priority=CRITICAL "
        "     rule='Sentinel - Docker Content Trust Disabled'\n"
        "   - Image not pinned by digest → push_supply_chain_alert priority=WARNING "
        "     rule='Sentinel - Image Not Digest Pinned'\n"
        "   - No image labels (no provenance) → push_supply_chain_alert priority=WARNING "
        "     rule='Sentinel - Missing Image Provenance Labels'\n\n"

        "2. Call check_filesystem_writability('flask-target') — check for:\n"
        "   - Writable root FS → push_supply_chain_alert priority=CRITICAL "
        "     rule='Sentinel - Supply Chain Backdoor Write'\n"
        "   - Critical paths writable (/usr/local/bin, /usr/bin, /etc) → "
        "     push_supply_chain_alert priority=CRITICAL "
        "     rule='Sentinel - Supply Chain Backdoor Write'\n\n"

        "3. Call scan_for_tampered_packages('flask-target') — check for:\n"
        "   - Any suspicious/typosquatted packages → push_supply_chain_alert priority=CRITICAL "
        "     rule='Sentinel - Dependency Confusion Attack'\n"
        "   - No pip index pinning → push_supply_chain_alert priority=WARNING "
        "     rule='Sentinel - Unpinned Package Dependencies'\n\n"

        "4. Call check_environment_secrets_exposure('flask-target') — check for:\n"
        "   - Secrets in env vars → push_supply_chain_alert priority=WARNING "
        "     rule='Sentinel - Secrets Exposed via Environment'\n\n"

        "5. For every alert pushed, include in the detail field: "
        "the container name, the exact risk finding, and which supply chain vector it represents "
        "(image=image_tampering, fs=backdoor_persistence, pkg=dependency_confusion, env=credential_theft).\n\n"

        "6. Return a JSON summary:\n"
        '{"alerts_pushed": N, '
        '"risk_categories": {"image_tampering": true/false, "backdoor_persistence": true/false, '
        '"dependency_confusion": true/false, "credential_theft": true/false}, '
        '"findings": [{"category": "...", "severity": "...", "detail": "..."}], '
        '"overall_risk": "CRITICAL|HIGH|MEDIUM|LOW"}'
    ),
    model=os.getenv("AI_MODEL", "claude-sonnet-4-6"),
    tools=[
        inspect_image_provenance,
        check_filesystem_writability,
        scan_for_tampered_packages,
        check_environment_secrets_exposure,
        push_supply_chain_alert,
    ],
)
