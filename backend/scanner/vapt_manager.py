import asyncio

from backend.scanner.tool_runner import ToolRunner
from backend.burp_mcp_client import BurpMCPClient
from backend.scanner.burp_passive import analyze_history
from backend.bugbounty.registry import classify


class VaptManager:
    """Run selected authorized web assessment tools."""

    def __init__(self):
        self.runner = ToolRunner()

    @staticmethod
    def finding(tool: str, title: str, result) -> dict:
        output = (result.stdout or result.stderr).strip()

        category = classify(
            title,
            f"{tool} produced an authorized assessment result.",
            output,
            tool,
        )

        return {
            "title": title,
            "severity": category.severity if category else "info",
            "confidence": "low" if not output else "medium",
            "description": (
                f"{tool} produced an authorized assessment result."
            ),
            "evidence": output[:12000],
            "impact": (
                "Scanner output requires analyst validation before "
                "being treated as a vulnerability."
            ),
            "remediation": (
                "Review the scanner evidence and manually verify "
                "the reported condition."
            ),
            "tool": tool,
            "category_key": category.key if category else None,
        }

    async def _run(
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

        if getattr(result, "timed_out", False):
            return {
                "title": f"{tool} timed out",
                "severity": "info",
                "confidence": "high",
                "finding_type": "tool_status",
                "automation_status": "incomplete",
                "category_key": None,
                "description": f"{tool} exceeded its authorized execution timeout.",
                "evidence": output[:12000] or f"timeout after {timeout}s",
                "impact": "Assessment was incomplete and requires analyst review.",
                "remediation": "Review target responsiveness and adjust the tool timeout if appropriate.",
                "tool": tool,
            }

        if not output:
            return None

        # Non-zero tool failures are status records, not vulnerabilities.
        if getattr(result, "returncode", 0) not in (0, None):
            return {
                "title": f"{tool} execution failed",
                "severity": "info",
                "confidence": "high",
                "finding_type": "tool_status",
                "automation_status": "incomplete",
                "category_key": None,
                "description": (
                    f"{tool} did not complete successfully during "
                    "authorized assessment."
                ),
                "evidence": output[:12000],
                "impact": (
                    "Assessment coverage is incomplete. "
                    "This is not itself a vulnerability."
                ),
                "remediation": (
                    "Review the tool error and retry after correcting "
                    "the tool configuration."
                ),
                "tool": tool,
            }

        # Connection failures are execution/coverage status, never
        # vulnerability evidence.
        failure_markers = (
            "unable to connect",
            "could not connect",
            "connection refused",
            "connection error",
            "failed to connect",
            "no connection",
            "could not resolve",
            "host unreachable",
            "network is unreachable",
            "timed out",
        )

        lowered = output.lower()

        if any(marker in lowered for marker in failure_markers):
            return {
                "title": f"{tool} execution incomplete",
                "severity": "info",
                "confidence": "high",
                "finding_type": "tool_status",
                "automation_status": "incomplete",
                "category_key": None,
                "description": (
                    f"{tool} could not complete its authorized assessment "
                    "against the target."
                ),
                "evidence": output[:12000],
                "impact": (
                    "Assessment coverage is incomplete. "
                    "This is not itself a vulnerability."
                ),
                "remediation": (
                    "Review target connectivity, proxy configuration, "
                    "and tool execution settings."
                ),
                "tool": tool,
            }

        return self.finding(tool, title, result)

    async def _burp_findings(self) -> list[dict]:
        """Import passive Burp Scanner issues when Burp MCP is enabled."""
        import os

        if os.getenv("BURP_MCP_ENABLED", "").strip().lower() not in {
            "1",
            "true",
            "yes",
            "on",
        }:
            return []

        try:
            client = BurpMCPClient()
            result = await client.get_scanner_issues(
                count=int(os.getenv("BURP_MCP_ISSUE_LIMIT", "100")),
                offset=0,
            )

            issues = client.normalize_scanner_issues(result)
            findings: list[dict] = []

            for issue in issues:
                title = (
                    issue.get("name")
                    or issue.get("issueName")
                    or issue.get("title")
                    or issue.get("issue_type")
                    or issue.get("issueType")
                    or "Burp Scanner issue"
                )

                description = (
                    issue.get("description")
                    or issue.get("detail")
                    or issue.get("issueBackground")
                    or ""
                )

                evidence = (
                    issue.get("evidence")
                    or issue.get("remediation")
                    or issue.get("issueDetail")
                    or repr(issue)
                )

                category = classify(
                    str(title),
                    str(description),
                    str(evidence),
                    "burp",
                )

                findings.append(
                    {
                        "title": str(title),
                        "severity": (
                            str(issue.get("severity")).lower()
                            if issue.get("severity")
                            else category.severity if category else "info"
                        ),
                        "confidence": (
                            str(issue.get("confidence")).lower()
                            if issue.get("confidence")
                            else "medium"
                        ),
                        "description": str(description)[:12000],
                        "evidence": str(evidence)[:12000],
                        "impact": (
                            "Burp Scanner reported this condition. "
                            "Analyst validation is required."
                        ),
                        "remediation": str(
                            issue.get("remediation")
                            or "Review Burp evidence and manually validate the finding."
                        )[:12000],
                        "tool": "burp",
                        "category_key": category.key if category else None,
                    }
                )

            return findings

        except Exception:
            # Burp is an optional integration; never break the core scanner.
            return []

    async def _burp_passive_findings(
        self,
        target: str,
    ) -> list[dict]:
        """Read Burp Proxy HTTP history and extract safe passive indicators."""
        import os

        if os.getenv("BURP_MCP_ENABLED", "").strip().lower() not in {
            "1",
            "true",
            "yes",
            "on",
        }:
            return []

        try:
            client = BurpMCPClient()
            tools = await client.list_tools()
            tool_names = {tool["name"] for tool in tools}

            if "get_proxy_http_history" not in tool_names:
                return []

            result = await client.get_proxy_http_history(
                count=int(os.getenv("BURP_MCP_HISTORY_LIMIT", "100")),
                offset=0,
            )

            return analyze_history(result, target)

        except Exception:
            return []

    async def run(self, target: str) -> list[dict]:
        findings: list[dict] = []

        # Run the heavy HTTP assessment tools sequentially.
        # Running nuclei + nikto + ffuf + feroxbuster concurrently against
        # the same target was the main source of artificial execution
        # timeouts observed in the backend.
        tool_tasks = (
            self._run(
                "nuclei",
                [
                    "-u",
                    target,
                    "-silent",
                    "-jsonl",
                    "-tags",
                    "misconfig,exposure",
                    "-severity",
                    "low,medium,high,critical",
                    "-concurrency",
                    "1",
                    "-bulk-size",
                    "1",
                    "-rate-limit",
                    "2",
                    "-timeout",
                    "3",
                    "-retries",
                    "0",
                    "-exclude-type",
                    "headless,javascript,code",
                    "-disable-update-check",
                    "-no-interactsh",
                    "-no-color",
                ],
                "Nuclei assessment completed",
                40,
            ),
            self._run(
                "nikto",
                [
                    "-h",
                    target,
                    "-maxtime",
                    "10s",
                    "-timeout",
                    "3",
                    "-Tuning",
                    "123b",
                    "-nointeractive",
                ],
                "Nikto assessment completed",
                20,
            ),
            self._run(
                "ffuf",
                [
                    "-u",
                    target.rstrip("/") + "/FUZZ",
                    "-w",
                    "/usr/share/wordlists/dirb/common.txt",
                    "-mc",
                    "200,204,301,302,307,401,403",
                    "-t",
                    "10",
                    "-rate",
                    "20",
                    "-timeout",
                    "3",
                    "-maxtime",
                    "15",
                    "-s",
                ],
                "Endpoint discovery completed",
                25,
            ),
            self._run(
                "feroxbuster",
                [
                    "-u",
                    target,
                    "--silent",
                    "--no-state",
                    "-n",
                    "--threads",
                    "5",
                    "--depth",
                    "1",
                    "--timeout",
                    "2",
                    "--time-limit",
                    "10s",
                ],
                "Feroxbuster endpoint discovery completed",
                20,
            ),
        )

        for task in tool_tasks:
            try:
                result = await task
            except Exception as exc:
                print(f"[VaptManager] tool exception: {exc}", flush=True)
                continue

            if isinstance(result, dict):
                findings.append(result)

        import os

        if os.getenv("BURP_MCP_ENABLED", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            try:
                burp_findings = await self._burp_findings()
                findings.extend(
                    item for item in burp_findings
                    if isinstance(item, dict)
                )
            except Exception as exc:
                print(f"[VaptManager] Burp scanner exception: {exc}", flush=True)

            try:
                passive_findings = await self._burp_passive_findings(target)
                findings.extend(
                    item for item in passive_findings
                    if isinstance(item, dict)
                )
            except Exception as exc:
                print(f"[VaptManager] Burp passive exception: {exc}", flush=True)

        return findings
