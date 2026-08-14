from __future__ import annotations

import os
from typing import Any

import httpx
from mcp.server import MCPServer

from backend.automation.planner import build_plan, normalize_target
from backend.bugbounty.scope import ScopeManager

BACKEND_URL = os.getenv(
    "VULN_SCANNER_BACKEND_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

MCP_HOST = os.getenv("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.getenv("MCP_PORT", "8765"))

mcp = MCPServer(
    "Nayak The Hacker Security Gateway",
    version="1.0.0",
    description="Authorized security assessment gateway for Nayak The Hacker.",
    instructions=(
        "Only assess authorized targets. Never perform destructive actions "
        "or provide raw shell access to the AI."
    ),
)


async def backend_request(
    method: str,
    path: str,
    **kwargs: Any,
) -> Any:
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.request(
            method,
            f"{BACKEND_URL}{path}",
            **kwargs,
        )
        response.raise_for_status()
        return response.json()

async def authorized(target: str) -> bool:
    target = normalize_target(target)

    host = (
        target.split("://", 1)[1]
        .split("/", 1)[0]
        .split(":", 1)[0]
        .lower()
    )

    if host in {"127.0.0.1", "localhost", "::1"}:
        return True

    rules = await backend_request("GET", "/scope")
    manager = ScopeManager()

    for rule in rules:
        manager.add_rule(
            rule["target"],
            rule["in_scope"],
            rule.get("notes", ""),
        )

    return manager.is_in_scope(target)

@mcp.tool()
async def scanner_capabilities() -> dict:
    """Show scanner capabilities and safety boundaries."""
    return {
        "name": "Nayak The Hacker",
        "mode": "authorized_security_assessment",
        "target_types": [
            "web",
            "api",
            "network",
            "mobile",
            "cloud",
            "wireless",
        ],
        "destructive_actions": False,
        "raw_shell_access_to_ai": False,
        "external_targets_require_scope": True,
        "manual_alerts": True,
    }

@mcp.tool()
async def plan_authorized_scan(
    target: str,
    target_type: str = "web",
) -> dict:
    """Create a scan plan without executing tools."""
    plan = build_plan(target, target_type)
    plan["authorized"] = await authorized(target)

    if not plan["authorized"]:
        plan["blocked_reason"] = (
            "Target is not in explicit authorized scope."
        )

    return plan

@mcp.tool()
async def start_authorized_scan(
    target: str,
    target_type: str = "web",
) -> dict:
    """Start a scan only after authorization checks pass."""
    plan = build_plan(target, target_type)

    if not await authorized(target):
        return {
            "status": "manual_action_required",
            "alert": (
                "Authorization is required before scanning this target."
            ),
            "plan": plan,
        }

    try:
        scan = await backend_request(
            "POST",
            "/scan",
            json={
                "url": target,
                "target_type": target_type,
            },
        )

        return {
            "status": "started",
            "plan": plan,
            "scan": scan,
        }

    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 403:
            return {
                "status": "manual_action_required",
                "alert": (
                    "Backend rejected the target because it is "
                    "outside authorized scope."
                ),
                "plan": plan,
            }
        raise

@mcp.tool()
async def get_scan_status(scan_id: str) -> dict:
    """Read scan status and current findings."""
    return await backend_request(
        "GET",
        f"/scan/{scan_id}",
    )

@mcp.tool()
async def get_scan_report(scan_id: str) -> dict:
    """Return the final normalized security report."""
    return await backend_request(
        "GET",
        f"/scan/{scan_id}/report",
    )

@mcp.tool()
async def get_manual_alerts(scan_id: str) -> dict:
    """Return conditions requiring human action or review."""
    scan = await backend_request(
        "GET",
        f"/scan/{scan_id}",
    )

    alerts = []

    for finding in scan.get("findings", []):
        title = str(finding.get("title", ""))
        evidence = str(finding.get("evidence", ""))
        tool = finding.get("tool", "scanner")

        if "timed out" in title.lower():
            alerts.append({
                "type": "timeout",
                "tool": tool,
                "message": (
                    f"{tool} timed out. "
                    "Manual analyst review is required."
                ),
            })

        if "not installed" in evidence.lower():
            alerts.append({
                "type": "tool_unavailable",
                "tool": tool,
                "message": (
                    f"{tool} is unavailable. "
                    "Install/configure it before treating "
                    "the assessment as complete."
                ),
            })

    return {
        "scan_id": scan_id,
        "alerts": alerts,
    }

if __name__ == "__main__":
    mcp.run(transport="streamable-http", host=MCP_HOST, port=MCP_PORT)
