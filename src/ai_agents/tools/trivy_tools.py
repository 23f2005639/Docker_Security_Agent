import asyncio
import json as _json


async def scan_image_trivy(image: str) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            "trivy", "image",
            "--severity", "CRITICAL,HIGH",
            "--format", "json",
            "--quiet",
            image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            return {"image": image, "cves": [], "error": f"trivy exit code {proc.returncode}"}

        data = _json.loads(stdout.decode())
        cves = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                cves.append({
                    "id": vuln.get("VulnerabilityID", ""),
                    "severity": vuln.get("Severity", ""),
                    "package": vuln.get("PkgName", ""),
                    "fix": vuln.get("FixedVersion", "upgrade"),
                })
                if len(cves) >= 5:
                    break
            if len(cves) >= 5:
                break

        return {"image": image, "cves": cves}

    except FileNotFoundError:
        return {"image": image, "cves": [], "error": "trivy not installed"}
    except Exception as e:
        return {"image": image, "cves": [], "error": str(e)}
