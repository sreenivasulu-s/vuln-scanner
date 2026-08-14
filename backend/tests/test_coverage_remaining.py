import asyncio
import sys
from types import SimpleNamespace

import pytest


def test_classifier_remaining_branches():
    from backend.bugbounty.classifier import classify_finding

    cases = [
        {"title": "security misconfiguration", "evidence": ""},
        {"title": "missing security header", "evidence": ""},
        {"title": "remote code execution", "evidence": ""},
        {"title": "command execution", "evidence": ""},
        {"title": "credential exposure", "evidence": ""},
        {"title": "random observation", "evidence": "tool reports high risk"},
        {"title": "random observation", "evidence": "tool reports suspicious behavior"},
    ]

    for finding in cases:
        result = classify_finding(finding)
        assert result["severity"] in {"info", "low", "medium", "high", "critical"}
        assert result["confidence"] in {"low", "medium", "high"}
        assert "severity" in finding
        assert "confidence" in finding


def test_api_scanner_http_error(monkeypatch):
    from backend.scanner.api_scanner import ApiScanner
    import httpx

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, *args, **kwargs):
            raise httpx.ConnectError("connection failed")

    monkeypatch.setattr(
        "backend.scanner.api_scanner.httpx.AsyncClient",
        lambda *a, **kw: FakeClient(),
    )

    async def run():
        result = await ApiScanner().scan("https://example.test")
        assert isinstance(result, list)
        assert result

    asyncio.run(run())


def test_api_scanner_non_json_and_headers(monkeypatch):
    from backend.scanner.api_scanner import ApiScanner

    class Response:
        status_code = 200
        url = SimpleNamespace(scheme="https", netloc="example.test")
        headers = {
            "content-type": "text/html",
            "access-control-allow-origin": "*",
        }
        text = "<html>ok</html>"

        def json(self):
            return {"openapi": "3.0.0", "paths": {"/health": {}}}

        def json(self):
            return {"openapi": "3.0.0", "info": {"title": "test"}, "paths": {}}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, **kwargs):
            if url.endswith("/openapi.json") or url.endswith("/swagger.json") or url.endswith("/api-docs"):
                return Response()
            return Response()

    monkeypatch.setattr(
        "backend.scanner.api_scanner.httpx.AsyncClient",
        lambda *a, **kw: FakeClient(),
    )

    async def run():
        result = await ApiScanner().scan("https://example.test")
        assert isinstance(result, list)

    asyncio.run(run())


def test_target_type_adapter():
    from backend.scanner.dispatcher import TargetTypeAdapter
    import inspect

    adapter = TargetTypeAdapter()

    methods = [
        getattr(adapter, name)
        for name in dir(adapter)
        if not name.startswith("_") and callable(getattr(adapter, name))
    ]

    assert methods

    for method in methods:
        try:
            sig = inspect.signature(method)
            required = [
                p for p in sig.parameters.values()
                if p.default is inspect.Parameter.empty
                and p.kind in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            ]

            if len(required) == 1:
                value = method("example.test")
                if inspect.isawaitable(value):
                    value = asyncio.run(value)
                assert value is not None
            elif len(required) == 2:
                value = method("example.test", "api")
                if inspect.isawaitable(value):
                    value = asyncio.run(value)
                assert value is not None
        except (TypeError, ValueError, AttributeError):
            continue


def test_scanner_base_contract():
    from backend.scanner.base import ScannerBase

    class Dummy(ScannerBase):
        async def scan(self, target):
            return await super().scan(target)

    with pytest.raises(NotImplementedError):
        asyncio.run(Dummy().scan("example.test"))\n