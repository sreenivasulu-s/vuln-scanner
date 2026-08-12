import httpx

from backend.scanner.base import ScannerBase


class LabScanner(ScannerBase):
    """
    Authorized lab scanner adapter.
    Performs a harmless HTTP GET request.
    """

    async def scan(self, target: str) -> list[dict]:
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=5.0,
            ) as client:
                response = await client.get(target)

            return [
                {
                    "title": "HTTP service reachable",
                    "severity": "info",
                    "description": "The authorized lab target responded to an HTTP GET request.",
                    "evidence": f"HTTP {response.status_code} from {response.url}",
                    "tool": "httpx",
                }
            ]

        except httpx.HTTPError as exc:
            return [
                {
                    "title": "HTTP request failed",
                    "severity": "info",
                    "description": "The authorized lab target could not be reached with the configured HTTP client.",
                    "evidence": str(exc),
                    "tool": "httpx",
                }
            ]
