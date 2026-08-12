import httpx

from backend.scanner.lab_scanner import LabScanner


def test_lab_scanner_returns_http_finding(monkeypatch):
    class FakeResponse:
        status_code = 200
        url = "http://127.0.0.1:8000"

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        async def get(self, target):
            assert target == "http://127.0.0.1:8000"
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: FakeClient())

    findings = __import__("asyncio").run(
        LabScanner().scan("http://127.0.0.1:8000")
    )

    assert len(findings) == 1
    assert findings[0]["title"] == "HTTP service reachable"
    assert findings[0]["severity"] == "info"
    assert findings[0]["tool"] == "httpx"
