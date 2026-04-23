import os
from agents import Agent, function_tool
from ai_agents.tools.docker_tools import (
    inspect_container as _inspect,
    get_container_flags as _flags,
)
from ai_agents.tools.trivy_tools import scan_image_trivy as _trivy


@function_tool
async def inspect_container(name: str) -> str:
    import json
    result = await _inspect(name)
    return json.dumps(result)


@function_tool
async def get_container_flags(name: str) -> str:
    import json
    result = await _flags(name)
    return json.dumps(result)


@function_tool
async def scan_image_trivy(image: str) -> str:
    import json
    result = await _trivy(image)
    return json.dumps(result)


scanner_agent = Agent(
    name="Scanner",
    instructions=(
        "You are a container security scanner. Analyze the target container for image vulnerabilities "
        "and insecure configurations.\n\n"
        "Steps:\n"
        "1. Use inspect_container to get the container's security configuration\n"
        "2. Use get_container_flags to check for known misconfigurations\n"
        "3. Use scan_image_trivy to scan the container image for CVEs\n\n"
        "Return your findings as a JSON object with these exact keys:\n"
        '{"image": "...", "cves": [...], "misconfigs": [...], "summary": "..."}\n'
        "where cves is a list of {id, severity, package, fix} and misconfigs is a list of flag strings."
    ),
    model=os.getenv("AI_MODEL", "gpt-5.3-codex"),
    tools=[inspect_container, get_container_flags, scan_image_trivy],
)
