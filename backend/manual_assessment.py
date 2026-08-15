from __future__ import annotations

import os

from typing import Any

from fastapi import APIRouter, HTTPException

from backend.bugbounty.registry import catalog, coverage
from backend.burp_mcp_client import BurpMCPClient

router = APIRouter()


async def _authorized(target: str) -> bool:
    from backend.main import scope_manager
    return scope_manager.is_in_scope(target)


def _manual_categories() -> list[dict[str, Any]]:
    return [
        item
        for item in catalog()
        if item["manual_validation"]
    ]


@router.get("/status")
async def manual_status() -> dict[str, Any]:
    burp = await BurpMCPClient().status()

    return {
        "mode": "manual_assisted_assessment",
        "authorized_only": True,
        "destructive_actions": False,
        "burp_mcp": burp,
        "manual_category_count": len(_manual_categories()),
        "total_category_count": len(catalog()),
        "chatgpt_role": "MCP client/analyst; no raw shell access",
    }


@router.get("/catalog")
def manual_catalog() -> dict[str, Any]:
    categories = catalog()

    return {
        "count": len(categories),
        "manual_count": sum(
            1 for item in categories
            if item["manual_validation"]
        ),
        "categories": categories,
    }


@router.get("/scan/{scan_id}")
async def manual_scan_state(scan_id: str) -> dict[str, Any]:
    from backend.main import scans

    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    items = coverage(scan.get("findings", []))

    manual_required = [
        item
        for item in items
        if item["manual_validation"]
    ]

    burp = await BurpMCPClient().status()

    alerts = []

    if scan.get("status") == "completed":
        alerts.append({
            "type": "manual_validation",
            "severity": "action_required",
            "message": (
                "Automated scan completed. "
                "Manual security assessment is required "
                "for the applicable vulnerability categories."
            ),
        })

    for finding in scan.get("findings", []):
        if "timed out" in str(
            finding.get("title", "")
        ).lower():
            alerts.append({
                "type": "tool_timeout",
                "severity": "review",
                "tool": finding.get("tool", "scanner"),
                "message": (
                    f"{finding.get('tool', 'scanner')} timed out; "
                    "review manually."
                ),
            })

    if not burp.get("reachable"):
        alerts.append({
            "type": "burp_unavailable",
            "severity": "setup_required",
            "message": (
                "Burp MCP is not connected. "
                "Start/configure Burp's MCP endpoint before "
                "manual testing."
            ),
        })

    return {
        "scan_id": scan_id,
        "target": scan["target"],
        "scan_status": scan["status"],
        "burp_mcp": burp,
        "alerts": alerts,
        "coverage": items,
        "manual_category_count": len(manual_required),
    }


@router.post("/scan/{scan_id}/burp-sync")
async def sync_burp_findings(
    scan_id: str,
) -> dict[str, Any]:
    """
    Import findings already produced by Burp Scanner
    through the configured MCP endpoint.
    """
    from backend.main import add_finding, scans
    from backend.bugbounty.classifier import classify_finding
    from backend.bugbounty.evidence import (
        clean_evidence,
        evidence_fingerprint,
    )
    from backend.bugbounty.knowledge import enrich_finding
    from backend.bugbounty.registry import (
        classify as classify_category,
    )

    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    if not await _authorized(scan["target"]):
        raise HTTPException(
            status_code=403,
            detail="Target is not in authorized scope",
        )

    client = BurpMCPClient()
    burp = await client.status()

    if not burp.get("reachable"):
        return {
            "status": "manual_action_required",
            "message": (
                "Burp MCP is not reachable. "
                "Start/configure Burp MCP first."
            ),
            "burp_mcp": burp,
            "imported": 0,
        }

    result = await client.get_scanner_issues()
    issues = client.normalize_scanner_issues(result)
    scanner_issue_count = len(issues)

    # Also import passive indicators from Burp Proxy HTTP history.
    # This keeps /burp-sync useful even when Burp Scanner has no findings.
    try:
        from backend.scanner.burp_passive import analyze_history

        history_result = await client.get_proxy_http_history(
            count=int(os.getenv("BURP_MCP_HISTORY_LIMIT", "100")),
            offset=0,
        )
        passive_findings = analyze_history(
            history_result,
            scan["target"],
        )

        for passive in passive_findings:
            issues.append(
                {
                    "name": passive.get("title", "Burp passive finding"),
                    "description": passive.get("description", ""),
                    "evidence": passive.get("evidence", ""),
                    "severity": passive.get("severity", "info"),
                    "confidence": passive.get("confidence", "low"),
                    "impact": passive.get("impact", ""),
                    "remediation": passive.get("remediation", ""),
                    "references": [],
                }
            )
    except Exception as e:
        import traceback
        print("BURP PASSIVE SYNC ERROR:", type(e).__name__, str(e))
        traceback.print_exc()

    existing = {
        evidence_fingerprint(item)
        for item in scan.get("findings", [])
    }

    imported = 0

    for issue in issues:
        title = str(
            issue.get("name")
            or issue.get("issueName")
            or issue.get("title")
            or "Burp Scanner finding"
        )

        description = str(
            issue.get("description")
            or issue.get("issueBackground")
            or "Finding reported by Burp Scanner through MCP."
        )

        evidence = str(
            issue.get("evidence")
            or issue.get("remediationBackground")
            or "Burp MCP scanner issue metadata"
        )

        category = classify_category(
            title,
            description,
            evidence,
            "burp",
        )

        finding = {
            "title": title,
            "severity": str(
                issue.get("severity")
                or (
                    category.severity
                    if category
                    else "info"
                )
            ).lower(),
            "confidence": str(
                issue.get("confidence")
                or "medium"
            ).lower(),
            "finding_type": "vulnerability",
            "target": scan["target"],
            "description": description,
            "evidence": clean_evidence(evidence),
            "impact": str(
                issue.get("impact")
                or "Validate impact in the authorized target scope."
            ),
            "remediation": str(
                issue.get("remediation")
                or (
                    "Review Burp remediation guidance "
                    "and validate the fix."
                )
            ),
            "tool": "burp-mcp",
            "references": (
                issue.get("references", [])
                if isinstance(
                    issue.get("references"),
                    list,
                )
                else []
            ),
            "category_key": (
                category.key
                if category
                else None
            ),
            "category": (
                category.name
                if category
                else "Unclassified"
            ),
            "validation_status": "needs_manual_validation",
            "automation_status": "burp_observed",
        }

        finding = classify_finding(finding)
        finding = enrich_finding(finding)

        key = evidence_fingerprint(finding)

        if key in existing:
            continue

        existing.add(key)
        add_finding(scan_id, finding)
        imported += 1

    return {
        "status": "completed",
        "scan_id": scan_id,
        "imported": imported,
        "burp_issues_seen": scanner_issue_count,
        "burp_history_findings_seen": len(issues) - scanner_issue_count,
        "burp_mcp": burp,
    }
