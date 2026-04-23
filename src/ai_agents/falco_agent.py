import os
from pydantic import BaseModel, Field
from agents import Agent

from ai_agents.tools.falco_tools import (
    get_recent_events,
    get_events_by_rule,
    get_events_by_container,
    get_attack_timeline,
    map_rule_to_mitre,
)


class AttackEvent(BaseModel):
    seq: int
    time: str
    rule: str
    container: str
    priority: str


class MitreMapping(BaseModel):
    rule: str
    ttp_id: str
    tactic: str
    technique: str


class RuleRootCause(BaseModel):
    rule: str
    ttp_id: str
    root_cause: str       # exact technical reason this rule fired
    attack_scenario: str  # what the attacker gains/achieves via this technique
    exact_fix: str        # copy-pasteable shell/config command to remediate
    container_fix: str    # docker-compose.yml or runtime flag change
    urgency: str          # immediate | within-30-days | routine


class FalcoAnalysisReport(BaseModel):
    overall_threat_level: str = Field(description="CRITICAL / HIGH / MEDIUM / LOW")
    affected_containers: list[str]
    total_events: int
    unique_rules_fired: list[str]
    attack_sequence: list[AttackEvent]
    mitre_mappings: list[MitreMapping]
    remediation_steps: list[str] = Field(description="4-6 specific actionable remediation steps in priority order")
    summary: str = Field(description="2-3 sentence executive summary for a security incident ticket")
    threat_narrative: str = Field(description="REQUIRED: 3-5 detailed paragraphs covering the attack entry point, step-by-step progression referencing specific containers and rule names, why each technique is dangerous, and overall host impact. Must not be empty.")
    rule_analysis: list[RuleRootCause] = Field(description="REQUIRED — MUST NOT BE EMPTY. One RuleRootCause entry for every rule name in unique_rules_fired. For each rule provide: exact technical root_cause (syscall/capability/config flaw), concrete attack_scenario naming the container, copy-pasteable exact_fix shell command, docker-compose container_fix, and urgency (immediate/within-30-days/routine).")


falco_agent = Agent(
    name="FalcoIntelligence",
    instructions=(
        "You are a senior container security threat intelligence analyst. "
        "Your job is to analyze ALL recent Falco runtime detections and produce "
        "a comprehensive, detailed threat intelligence report.\n\n"

        "REQUIRED STEPS — follow this exact order:\n"
        "1. Call get_attack_timeline() to get all events in chronological order\n"
        "2. For each UNIQUE container name you see in the timeline, call "
        "   get_events_by_container(container_name) to get a full per-container view\n"
        "3. For each UNIQUE rule name you see, call map_rule_to_mitre(rule_name) "
        "   to get the MITRE ATT&CK mapping\n"
        "4. Call get_events_by_rule(rule_name) for any rule you need to examine more closely\n"
        "5. MANDATORY — produce one RuleRootCause entry in rule_analysis for EVERY unique "
        "   rule that fired. An empty rule_analysis list is NEVER acceptable. For each rule:\n"
        "   - root_cause: exact syscall / capability / config flaw that caused the trigger\n"
        "   - attack_scenario: what the attacker gains, naming the specific container\n"
        "   - exact_fix: copy-pasteable shell command (version-pinned where possible)\n"
        "   - container_fix: exact docker-compose.yml line or runtime flag to change\n"
        "   - urgency: 'immediate' for CRITICAL/HIGH TTP, 'within-30-days' for MEDIUM, 'routine' for LOW\n"
        "6. Compile and return a FalcoAnalysisReport where rule_analysis has one entry per unique rule\n\n"

        "CRITICAL CONSTRAINT: rule_analysis MUST contain one RuleRootCause entry per unique "
        "rule in unique_rules_fired. Never return an empty rule_analysis.\n\n"
        "REPORT FIELD REQUIREMENTS (fill in this order):\n"
        "- overall_threat_level: 'CRITICAL' if T1611/T1068 TTP present or host breach; "
        "  'HIGH' if T1570; 'MEDIUM' for other TTPs; 'LOW' if no known TTP\n"
        "- affected_containers: deduplicated list of container names from events\n"
        "- total_events: count of all events\n"
        "- unique_rules_fired: deduplicated list of rule names\n"
        "- attack_sequence: all timeline events as AttackEvent objects (seq, time, rule, container, priority)\n"
        "- mitre_mappings: one MitreMapping per unique rule from map_rule_to_mitre\n"
        "- remediation_steps: 4-6 specific steps, each naming the exact misconfiguration and fix\n"
        "- summary: 2-3 sentences for a security incident ticket\n"
        "- threat_narrative: MUST BE FILLED — 3-5 paragraphs covering: (1) attack entry point, "
        "  (2) step-by-step progression referencing specific containers and rules, "
        "  (3) why each technique is dangerous, (4) overall host impact\n"
        "- rule_analysis: MUST BE FILLED — one RuleRootCause for every name in unique_rules_fired. "
        "  Fields per entry:\n"
        "  * rule: exact rule name as seen in events\n"
        "  * ttp_id: MITRE code from map_rule_to_mitre\n"
        "  * root_cause: exact syscall / Linux capability / config flaw that caused the trigger\n"
        "  * attack_scenario: what the attacker gains, naming the specific container\n"
        "  * exact_fix: copy-pasteable shell command (e.g. 'sed -i ...' or 'docker update ...')\n"
        "  * container_fix: exact docker-compose.yml change (e.g. 'Remove privileged:true')\n"
        "  * urgency: 'immediate' for CRITICAL/HIGH TTP, 'within-30-days' for MEDIUM, 'routine' for LOW"
    ),
    model=os.getenv("AI_MODEL", "gpt-5.3-codex"),
    tools=[
        get_recent_events,
        get_events_by_rule,
        get_events_by_container,
        get_attack_timeline,
        map_rule_to_mitre,
    ],
    output_type=FalcoAnalysisReport,
)
