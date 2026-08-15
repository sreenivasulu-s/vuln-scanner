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
        stdin_data: str | None = None,
    ):
        result = await self.runner.run(
            tool,
            args,
            timeout=timeout,
            stdin_data=stdin_data,
        )

        output = (result.stdout or result.stderr).strip()

        if not output and result.returncode == 0:
            return None

        # Tool failures/timeouts are assessment status, never vulnerabilities.
        if result.timed_out or result.returncode != 0:
            return {
                "title": f"{tool} timed out" if result.timed_out
                         else f"{tool} execution failed",
                "severity": "info",
                "confidence": "high",
                "finding_type": "tool_status",
                "automation_status": "incomplete",
                "description": (
                    f"{tool} did not complete successfully during "
                    "authorized reconnaissance."
                ),
                "evidence": (
                    output[:12000]
                    or (
                        f"timeout after {timeout}s"
                        if result.timed_out
                        else f"exit code {result.returncode}"
                    )
                ),
                "impact": (
                    "Reconnaissance coverage is incomplete. "
                    "This is not itself a vulnerability."
                ),
                "remediation": (
                    "Review the tool configuration, target responsiveness, "
                    "and execution timeout."
                ),
                "tool": tool,
                "category_key": None,
            }

        return self._finding(tool, title, output)

    async def run(self, target: str) -> list[dict]:
        host = self.hostname(target)
        findings: list[dict] = []

        async def run_one(task):
            try:
                result = await task
            except Exception as exc:
                print(f"[ReconManager] tool exception: {exc}", flush=True)
                return None
            return result

        # Do not launch all network-heavy reconnaissance tools together.
        # Some targets/rate-limiters behave badly when subfinder/whatweb,
        # port scanners and HTTP fingerprinting all compete simultaneously.
        #
        # Phase 1: domain reconnaissance, one tool at a time.
        if not self._is_ip_or_localhost(host):
            for task in (
                self._run_tool(
                    "subfinder",
                    ["-d", host, "-silent"],
                    "Subdomain discovery completed",
                    45,
                ),
                self._run_tool(
                    "dnsx",
                    ["-silent", "-resp"],
                    "DNS resolution results available",
                    30,
                    stdin_data=f"{host}\\n",
                ),
            ):
                result = await run_one(task)
                if result:
                    findings.append(result)

        # Phase 2: HTTP fingerprinting, one request-heavy tool at a time.
        for task in (
            self._run_tool(
                "httpx-toolkit",
                [
                    "-silent",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-u",
                    target,
                ],
                "HTTP service fingerprinting completed",
                30,
            ),
            self._run_tool(
                "whatweb",
                [
                    "--no-errors",
                    target,
                ],
                "Technology fingerprinting completed",
                45,
            ),
        ):
            result = await run_one(task)
            if result:
                findings.append(result)

        # Phase 3: port enumeration can safely run together because these
        # tools do not compete for the same HTTP request path.
        try:
            port_results = await asyncio.gather(
                self._run_tool(
                    "naabu",
                    [
                        "-host",
                        host,
                        "-silent",
                        "-top-ports",
                        "100",
                    ],
                    "Port discovery completed",
                    35,
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
                    35,
                ),
                return_exceptions=True,
            )
        except Exception as exc:
            print(f"[ReconManager] port phase exception: {exc}", flush=True)
            port_results = []

        for result in port_results:
            if not isinstance(result, Exception) and result:
                findings.append(result)

        return findings
