from __future__ import annotations

import os
from typing import Any

from mcp import ClientSession
from mcp.client.sse import sse_client


class BurpMCPClient:
    """Small async client for Burp's SSE-based MCP endpoint."""

    def __init__(self, url: str | None = None) -> None:
        self.url = (
            url
            or os.getenv("BURP_MCP_URL", "http://127.0.0.1:9876")
        ).rstrip("/")

    async def list_tools(self) -> list[dict[str, Any]]:
        async with sse_client(
            self.url,
            timeout=5,
            sse_read_timeout=15,
        ) as (read, write):
            async with ClientSession(read, write) as session:
                result = await session.initialize()
                tools = await session.list_tools()

                return [
                    {
                        "name": tool.name,
                        "description": tool.description or "",
                        "input_schema": tool.input_schema,
                    }
                    for tool in tools.tools
                ]

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        """Call a Burp MCP tool through the SSE MCP session."""
        async with sse_client(
            self.url,
            timeout=5,
            sse_read_timeout=20,
        ) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    name,
                    arguments or {},
                )

                return result.model_dump(mode="json")

    async def get_scanner_issues(
        self,
        count: int = 100,
        offset: int = 0,
    ) -> dict:
        """Fetch Burp scanner issues through MCP."""
        return await self.call_tool(
            "get_scanner_issues",
            {
                "count": int(count),
                "offset": int(offset),
            },
        )

    @staticmethod
    def _text_from_content(content: Any) -> str:
        parts: list[str] = []

        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    text = item.get("text")
                    if isinstance(text, str):
                        parts.append(text)
                elif isinstance(item, str):
                    parts.append(item)

        return "\n".join(parts).strip()

    @classmethod
    def normalize_scanner_issues(cls, result: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalize Burp MCP scanner output into scanner findings."""
        if not result or result.get("is_error"):
            return []

        candidates: list[Any] = []

        structured = result.get("structured_content")
        if structured is not None:
            candidates.append(structured)

        content = result.get("content")
        if content is not None:
            text = cls._text_from_content(content)
            if text:
                candidates.append(text)

        def walk(value: Any) -> list[dict[str, Any]]:
            found: list[dict[str, Any]] = []

            if isinstance(value, dict):
                # Burp/MCP may expose an issue directly or nested in a list.
                if any(
                    key in value
                    for key in (
                        "name",
                        "issueName",
                        "title",
                        "issue_type",
                        "issueType",
                    )
                ):
                    found.append(value)

                for child in value.values():
                    found.extend(walk(child))

            elif isinstance(value, list):
                for child in value:
                    found.extend(walk(child))

            return found

        normalized: list[dict[str, Any]] = []

        for candidate in candidates:
            if isinstance(candidate, str):
                # Some MCP servers return JSON as text.
                import json
                try:
                    decoded = json.loads(candidate)
                except Exception:
                    continue
                normalized.extend(walk(decoded))
            else:
                normalized.extend(walk(candidate))

        # Remove duplicates while preserving order.
        unique: list[dict[str, Any]] = []
        seen: set[str] = set()

        for issue in normalized:
            key = repr(sorted(issue.items(), key=lambda item: item[0]))
            if key not in seen:
                seen.add(key)
                unique.append(issue)

        return unique

    async def status(self) -> dict[str, Any]:
        try:
            async with sse_client(
                self.url,
                timeout=5,
                sse_read_timeout=15,
            ) as (read, write):
                async with ClientSession(read, write) as session:
                    result = await session.initialize()
                    tools = await session.list_tools()

                    return {
                        "configured": True,
                        "reachable": True,
                        "initialized": True,
                        "endpoint": self.url,
                        "transport": "sse",
                        "protocol_version": result.protocol_version,
                        "server": {
                            "name": result.server_info.name,
                            "version": result.server_info.version,
                        },
                        "tool_count": len(tools.tools),
                        "tools": [
                            tool.name for tool in tools.tools
                        ],
                        "manual_setup_required": False,
                        "message": "Burp MCP SSE endpoint is connected and initialized.",
                    }

        except Exception as exc:
            return {
                "configured": True,
                "reachable": False,
                "initialized": False,
                "endpoint": self.url,
                "transport": "sse",
                "tool_count": 0,
                "tools": [],
                "manual_setup_required": True,
                "message": f"Burp MCP connection failed: {type(exc).__name__}: {exc}",
            }
