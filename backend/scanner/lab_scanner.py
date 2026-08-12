from backend.scanner.base import ScannerBase


class LabScanner(ScannerBase):
    """
    Authorized lab కోసం scanner adapter.
    ప్రస్తుతం demo finding మాత్రమే return చేస్తుంది.
    """

    async def scan(self, target: str) -> list[dict]:
        return [
            {
                "title": "Lab scanner demo finding",
                "severity": "info",
                "description": "Demo finding from the lab scanner adapter.",
                "evidence": "No real security tool executed.",
                "tool": "lab-demo",
            }
        ]
