import asyncio

import httpx

from backend.scanner.lab_scanner import LabScanner


def test_lab_scanner_returns_http_finding(monkeypatch):
    class FakeResponse:
        status_code = 200
        url = "http://127.0.0.1:8000"
        headers = {
            "x-content-type-options": "nosniff",
            "content-security-policy": "default-src 'self'",
        }

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        async def get(self, target):
            assert target == "http://127.0.0.1:8000"
            return FakeResponse()

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: FakeClient(),
    )

    findings = asyncio.run(
        LabScanner().scan("http://127.0.0.1:8000")
    )

    assert len(findings) == 1
    assert findings[0]["title"] == "HTTP service reachable"
    assert findings[0]["severity"] == "info"
    assert findings[0]["tool"] == "httpx"


def test_lab_scanner_handles_http_error(monkeypatch):
    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        async def get(self, target):
            raise httpx.ConnectError("connection failed")

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: FakeClient(),
    )

    findings = asyncio.run(
        LabScanner().scan("http://127.0.0.1:9999")
    )

    assert len(findings) == 1
    assert findings[0]["title"] == "HTTP request failed"
    assert findings[0]["severity"] == "info"
    assert findings[0]["tool"] == "httpx"


def test_lab_scanner_reports_missing_security_headers(monkeypatch):
    class FakeResponse:
        status_code = 200
        url = "http://127.0.0.1:8000"
        headers = {
            "content-type": "text/html",
        }

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        async def get(self, target):
            assert target == "http://127.0.0.1:8000"
            return FakeResponse()

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: FakeClient(),
    )

    findings = asyncio.run(
        LabScanner().scan("http://127.0.0.1:8000")
    )

    titles = [finding["title"] for finding in findings]

    assert "Missing X-Content-Type-Options header" in titles
    assert "Missing Content-Security-Policy header" in titles
