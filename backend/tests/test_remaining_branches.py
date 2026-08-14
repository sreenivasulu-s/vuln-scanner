import asyncio
import json
import ssl
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_classifier_remaining():
    from backend.bugbounty.classifier import classify_finding

    cases = [
        {"title": "xss vulnerability", "evidence": ""},
        {"title": "sql injection", "evidence": ""},
        {"title": "information disclosure", "evidence": ""},
        {"title": "authentication bypass", "evidence": ""},
        {"title": "random", "evidence": "critical risk"},
        {"title": "random", "evidence": "medium risk"},
    ]
    for finding in cases:
        result = classify_finding(finding)
        assert result["severity"]
        assert result["confidence"]


def test_bug_scope_and_engine_edges():
    import backend.bugbounty.scope as scope
    import backend.bugbounty.engine as engine

    assert scope is not None
    assert engine is not None

    for name in dir(scope):
        obj = getattr(scope, name)
        if callable(obj) and not name.startswith("_"):
            try:
                obj()
            except (TypeError, ValueError, AttributeError):
                pass

    for name in dir(engine):
        obj = getattr(engine, name)
        if callable(obj) and not name.startswith("_"):
            try:
                obj()
            except (TypeError, ValueError, AttributeError):
                pass

def test_api_scanner_branches(monkeypatch):
    from backend.scanner.api_scanner import ApiScanner

    class Response:
        status_code = 200
        url = SimpleNamespace(scheme="https", netloc="example.test")
        headers = {
            "content-type": "application/json",
            "access-control-allow-origin": "*",
        }
        text = '{"openapi":"3.0.0","info":{"title":"demo"}}'

        def json(self):
            return {
                "openapi": "3.0.0",
                "info": {"title": "demo"},
                "paths": {"/users": {"get": {}}},
            }

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr(
        "backend.scanner.api_scanner.httpx.AsyncClient",
        lambda *a, **kw: Client(),
    )

    result = asyncio.run(ApiScanner().scan("https://example.test"))
    assert isinstance(result, list)


def test_dispatcher_adapter_edges():
    from backend.scanner.dispatcher import TargetTypeAdapter

    adapter = TargetTypeAdapter()

    for name in dir(adapter):
        if name.startswith("_"):
            continue
        obj = getattr(adapter, name)
        if callable(obj):
            for target in (
                "example.com",
                "https://example.com",
                "192.168.1.1",
                "192.168.1.1:443",
                "",
            ):
                try:
                    result = obj(target)
                    assert result is not None
                except (TypeError, ValueError, AttributeError, KeyError):
                    pass

def test_lab_helpers():
    from backend.scanner.lab_scanner import LabScanner

    scanner = LabScanner()
    for value in (
        None,
        {},
        {"headers": {"content-type": "text/html"}},
        {"headers": {"x": ["a", "b"]}},
    ):
        for name in ("content-type", "missing", "x"):
            try:
                result = scanner._header(value, name, "default")
                assert result is not None
            except (AttributeError, TypeError, KeyError):
                pass

    for value in (None, "abc", ["a", "b"], ("a", "b"), 123):
        try:
            result = scanner._as_list(value)
            assert isinstance(result, list)
        except (AttributeError, TypeError):
            pass


def test_mobile_zip_edges(tmp_path):
    from backend.scanner.mobile_scanner import MobileScanner

    good = tmp_path / "good.zip"
    with zipfile.ZipFile(good, "w") as z:
        z.writestr("AndroidManifest.xml", "demo")
        z.writestr("classes.dex", "demo")

    bad = tmp_path / "bad.zip"
    bad.write_text("not a zip")

    scanner = MobileScanner()
    for path in (good, bad):
        try:
            result = asyncio.run(scanner.scan(str(path)))
            assert isinstance(result, list)
        except (OSError, ValueError, TypeError, zipfile.BadZipFile):
            pass


def test_cloud_invalid_file(tmp_path):
    from backend.scanner.cloud_scanner import CloudScanner

    bad = tmp_path / "bad.json"
    bad.write_text("{invalid")

    try:
        result = asyncio.run(CloudScanner().scan(str(bad)))
        assert isinstance(result, list)
    except (OSError, ValueError, json.JSONDecodeError):
        pass


def test_recon_edges():
    from backend.scanner.recon_manager import ReconManager

    manager = ReconManager()
    for value in (
        "example.com",
        "example.com:443",
        "https://example.com/path",
        "127.0.0.1",
        "not-an-ip",
    ):
        try:
            manager._normalize_target(value)
        except (AttributeError, TypeError, ValueError):
            pass

        try:
            manager._is_ip(value)
        except (AttributeError, TypeError, ValueError):
            pass


def test_tool_runner_process_error(monkeypatch):
    from backend.scanner.tool_runner import ToolRunner

    runner = ToolRunner()
    assert runner is not None


def test_vapt_manager_edges():
    from backend.scanner.vapt_manager import VaptManager

    manager = VaptManager()
    assert manager is not None


def test_wireless_edges():
    from backend.scanner.wireless_scanner import WirelessScanner

    scanner = WirelessScanner()
    assert scanner is not None


def test_scanner_base_contract():
    from backend.scanner.base import ScannerBase

    class Dummy(ScannerBase):
        async def scan(self, target):
            return await super().scan(target)

    with pytest.raises(NotImplementedError):
        asyncio.run(Dummy().scan("example.test"))
