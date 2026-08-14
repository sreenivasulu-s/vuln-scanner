import asyncio
import ipaddress
from urllib.parse import urlparse

from backend.scanner.tool_runner import ToolRunner


class ReconManager:
    """Authorized-target reconnaissance pipeline."""

    def __init__(self):
        self.runner = ToolRunner()

    @staticmethod
    def hostname(target: str) -> str:
        value = target.strip()

        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            return parsed.hostname or value

        return value.split("/", 1)[0].split(":", 1)[0]

    @staticmethod
    def _finding(tool: str, title: str, output: str, severity="info"):
        return {
            "title": title,
            "severity": severity,
            "confidence": "medium",
            "description": (
                f"Authorized reconnaissance result produced by {tool}."
            ),
            "evidence": output[:12000],
            "impact": "Reconnaissance result requiring analyst review.",
            "remediation": (
                "Review the discovered asset/service and validate "
                "whether it is expected."
            ),
            "tool": tool,
        }

    @staticmethod
    def _is_ip_or_localhost(host: str) -> bool:
        if host in {"localhost", "127.0.0.1", "::1"}:
            return True

        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    async def _run_tool(
        self,
        tool: str,
        args: list[str],
        title: str,
        timeout: float,
    ):
        result = await self.runner.run(
            tool,
            args,
            timeout=timeout,
        )

        output = (result.stdout or result.stderr).strip()

        if not output:
            return None

        return self._finding(
            tool,
            title,
            output,
        )

    async def run(self, target: str) -> list[dict]:
        host = self.hostname(target)
        findings: list[dict] = []

        tasks = []

        # Subfinder/DNSX are domain-oriented. Do not waste time on IP targets.
        if not self._is_ip_or_localhost(host):
            tasks.extend(
                [
                    self._run_tool(
                        "subfinder",
                        ["-d", host, "-silent"],
                        "Subdomain discovery completed",
                        25,
                    ),
                    self._run_tool(
                        "dnsx",
                        ["-silent", "-resp", "-d", host],
                        "DNS resolution results available",
                        25,
                    ),
                ]
            )

        tasks.extend(
            [
                self._run_tool(
                    "httpx",
                    [
                        "-silent",
                        "-status-code",
                        "-title",
                        "-tech-detect",
                        "-u",
                        target,
                    ],
                    "HTTP service fingerprinting completed",
                    20,
                ),
                self._run_tool(
                    "naabu",
                    [
                        "-host",
                        host,
                        "-silent",
                        "-top-ports",
                        "20",
                    ],
                    "Port discovery completed",
                    30,
                ),
                self._run_tool(
                    "nmap",
                    [
                        "-Pn",
                        "-T3",
                        "--top-ports",
                        "20",
                        host,
                    ],
                    "Nmap service enumeration completed",
                    30,
                ),
                self._run_tool(
                    "whatweb",
                    [
                        "--no-errors",
                        target,
                    ],
                    "Technology fingerprinting completed",
                    20,
                ),
            ]
        )

        results = await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, Exception):
                continue

            if result:
                findings.append(result)

        return findings
