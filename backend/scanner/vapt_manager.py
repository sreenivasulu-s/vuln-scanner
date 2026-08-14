import asyncio

from backend.scanner.tool_runner import ToolRunner


class VaptManager:
    """Run selected authorized web assessment tools."""

    def __init__(self):
        self.runner = ToolRunner()

    @staticmethod
    def finding(tool: str, title: str, result) -> dict:
        output = (result.stdout or result.stderr).strip()

        return {
            "title": title,
            "severity": "info",
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

        if not (result.stdout.strip() or result.stderr.strip()):
            return None

        return self.finding(
            tool,
            title,
            result,
        )

    async def run(self, target: str) -> list[dict]:
        tasks = [
            self._run(
                "nuclei",
                ["-u", target, "-silent", "-jsonl"],
                "Nuclei assessment completed",
                35,
            ),
            self._run(
                "nikto",
                ["-h", target],
                "Nikto assessment completed",
                35,
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
                    "-s",
                ],
                "Endpoint discovery completed",
                35,
            ),
            self._run(
                "feroxbuster",
                [
                    "-u",
                    target,
                    "--silent",
                    "--no-state",
                    "-n",
                ],
                "Feroxbuster endpoint discovery completed",
                35,
            ),
        ]

        results = await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        return [
            result
            for result in results
            if result and not isinstance(result, Exception)
        ]
