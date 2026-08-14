import asyncio
import sys

from backend.scanner.tool_runner import ToolRunner


def test_tool_runner_success(monkeypatch):
    monkeypatch.delenv("VULN_SCANNER_DISABLE_EXTERNAL_TOOLS", raising=False)

    async def run():
        result = await ToolRunner().run(
            sys.executable,
            ["-c", "print('hello')"],
            timeout=5,
        )
        assert result.returncode == 0
        assert result.ok is True
        assert "hello" in result.stdout
        assert result.stderr == ""
        assert result.timed_out is False

    asyncio.run(run())


def test_tool_runner_failure(monkeypatch):
    monkeypatch.delenv("VULN_SCANNER_DISABLE_EXTERNAL_TOOLS", raising=False)

    async def run():
        result = await ToolRunner().run(
            sys.executable,
            ["-c", "import sys; print('boom', file=sys.stderr); sys.exit(2)"],
            timeout=5,
        )
        assert result.returncode == 2
        assert result.ok is False
        assert "boom" in result.stderr

    asyncio.run(run())


def test_tool_runner_timeout(monkeypatch):
    monkeypatch.delenv("VULN_SCANNER_DISABLE_EXTERNAL_TOOLS", raising=False)

    async def run():
        result = await ToolRunner().run(
            sys.executable,
            ["-c", "import time; time.sleep(2)"],
            timeout=0.1,
        )
        assert result.returncode == 124
        assert result.timed_out is True
        assert result.ok is False
        assert "timeout after 0.1s" in result.stderr

    asyncio.run(run())


def test_tool_runner_missing_binary(monkeypatch):
    monkeypatch.delenv("VULN_SCANNER_DISABLE_EXTERNAL_TOOLS", raising=False)

    async def run():
        result = await ToolRunner().run(
            "definitely-not-a-real-binary",
            [],
            timeout=5,
        )
        assert result.returncode == 127
        assert result.ok is False
        assert result.timed_out is False
        assert "not installed or is not in PATH" in result.stderr

    asyncio.run(run())


def test_tool_runner_disabled_external_tools(monkeypatch):
    monkeypatch.setenv("VULN_SCANNER_DISABLE_EXTERNAL_TOOLS", "1")

    async def run():
        result = await ToolRunner().run(
            "any-tool",
            ["--version"],
            timeout=5,
        )
        assert result.returncode == 0
        assert result.ok is True
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.command == ["any-tool", "--version"]

    asyncio.run(run())


def test_tool_runner_os_error(monkeypatch):
    monkeypatch.delenv("VULN_SCANNER_DISABLE_EXTERNAL_TOOLS", raising=False)

    async def fake_create_process(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        fake_create_process,
    )

    async def run():
        result = await ToolRunner().run(
            sys.executable,
            ["-c", "print('hello')"],
            timeout=5,
        )
        assert result.returncode == 126
        assert result.ok is False
        assert result.stderr == "permission denied"

    asyncio.run(run())
