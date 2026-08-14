from uuid import uuid4
import asyncio
import re

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from backend.scanner.dispatcher import TargetTypeAdapter
from backend.bugbounty.scope import ScopeManager
from backend.bugbounty.models import BugBountyFinding
from backend.bugbounty.classifier import classify_finding
from backend.bugbounty.report import build_report, render_markdown
from backend.db import init_db, load_scans, save_scan


app = FastAPI(
    title="Nayak The Hacker",
    version="0.7.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
        "http://localhost:5175",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str
    target_type: str = "web"

    @field_validator("target_type")
    @classmethod
    def validate_target_type(cls, value: str) -> str:
        value = value.strip().lower()

        allowed = {
            "web",
            "api",
            "network",
            "mobile",
            "cloud",
            "wireless",
        }

        if value not in allowed:
            raise ValueError(
                "target_type must be one of: "
                "web, api, network, mobile, cloud, wireless"
            )

        return value

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip().strip("`").strip()

        if "](" in value and value.endswith(")"):
            value = value.split("](", 1)[1][:-1].strip()

        if not (
            value.startswith("http://")
            or value.startswith("https://")
        ):
            raise ValueError(
                "URL must start with http:// or https://"
            )

        return value


class Finding(BaseModel):
    title: str
    severity: str
    confidence: str = "medium"
    target: str = ""
    description: str
    evidence: str
    impact: str = ""
    remediation: str = ""
    tool: str
    references: list[str] = []


init_db()
scans: dict[str, dict] = load_scans()

# Default-deny scope manager. Targets must be explicitly authorized.
scope_manager = ScopeManager()


def add_finding(
    scan_id: str,
    finding: dict,
) -> None:
    scans[scan_id]["findings"].append(
        Finding(**finding).model_dump()
    )
    save_scan(scans[scan_id])


async def run_scan(scan_id: str):
    scan = scans[scan_id]

    try:
        scanner = TargetTypeAdapter()
        findings = await asyncio.wait_for(
            scanner.scan(
                scan["target"],
                scan.get("target_type", "web"),
            ),
            timeout=300,
        )

        # Normalize scanner findings through the bug-bounty analysis layer.
        normalized_findings = []
        for finding in findings:
            normalized_findings.append({
                "title": finding.get("title", "Scanner finding"),
                "severity": finding.get("severity", "info"),
                "confidence": finding.get("confidence", "medium"),
                "target": scan["target"],
                "description": finding.get(
                    "description",
                    "Finding reported by the authorized scanner.",
                ),
                "evidence": finding.get("evidence", ""),
                "impact": finding.get(
                    "impact",
                    "Review the evidence and validate impact within the authorized program scope.",
                ),
                "remediation": finding.get(
                    "remediation",
                    "Review the finding and apply the appropriate security control.",
                ),
                "tool": finding.get("tool", "scanner"),
                "references": finding.get("references", []),
            })

        # Keep persisted scan results normalized and deduplicated.
        seen = set()
        for finding in normalized_findings:
            key = (
                finding["target"],
                finding["title"],
                finding["evidence"],
            )
            if key in seen:
                continue
            seen.add(key)
            add_finding(scan_id, finding)

        scan["status"] = "completed"

    except Exception as exc:
        scan["status"] = "failed"
        scan["error"] = str(exc)
    save_scan(scan)


@app.get("/")
def home():
    return {
        "status": "ok",
        "message": "Nayak The Hacker Security Scanner API is running",
    }


@app.post("/scan")
def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
):
    # Built-in local lab targets are always allowed.
    # External targets must pass the configured authorization scope.
    from urllib.parse import urlparse

    hostname = urlparse(request.url).hostname

    if (
        hostname not in {"127.0.0.1", "localhost"}
        and not scope_manager.is_in_scope(request.url)
    ):
        raise HTTPException(
            status_code=403,
            detail="Target is not in the configured authorized scope.",
        )

    scan_id = str(uuid4())

    scans[scan_id] = {
        "scan_id": scan_id,
        "target": request.url,
        "target_type": request.target_type,
        "status": "queued",
        "findings": [],
    }

    save_scan(scans[scan_id])
    background_tasks.add_task(run_scan, scan_id)

    return scans[scan_id]


@app.post("/scope")
def add_scope(
    target: str,
    in_scope: bool = True,
    notes: str = "",
):
    scope_manager.add_rule(
        target=target,
        in_scope=in_scope,
        notes=notes,
    )

    return {
        "target": target,
        "in_scope": in_scope,
        "notes": notes,
    }


@app.get("/scope")
def get_scope():
    return [
        {
            "target": rule.target,
            "in_scope": rule.in_scope,
            "notes": rule.notes,
        }
        for rule in scope_manager.rules
    ]


@app.get("/scan/{scan_id}/report/markdown")
def get_scan_report_markdown(scan_id: str):
    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = [
        BugBountyFinding(
            title=finding.get("title", "Scanner finding"),
            severity=finding.get("severity", "info"),
            confidence=finding.get("confidence", "medium"),
            target=finding.get("target", scan["target"]),
            description=finding.get(
                "description",
                "Finding reported by the authorized scanner.",
            ),
            evidence=finding.get("evidence", ""),
            impact=finding.get(
                "impact",
                "Review the evidence and validate impact within the authorized program scope.",
            ),
            remediation=finding.get(
                "remediation",
                "Review the finding and apply the appropriate security control.",
            ),
            tool=finding.get("tool", "scanner"),
        )
        for finding in scan["findings"]
    ]

    report = build_report(
        target=scan["target"],
        findings=findings,
    )

    return Response(
        content=render_markdown(report),
        media_type="text/markdown",
        headers={
            "Content-Disposition": (
                f'attachment; filename="scan-{scan_id}.md"'
            )
        },
    )


@app.get("/scans")
def get_scans():
    return [
        {
            "scan_id": scan["scan_id"],
            "target": scan["target"],
            "target_type": scan.get("target_type", "web"),
            "status": scan["status"],
            "findings_count": len(scan["findings"]),
        }
        for scan in reversed(list(scans.values()))
    ]


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return scan


@app.get("/scan/{scan_id}/report")
def get_scan_report(scan_id: str):
    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = scan["findings"]

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "info")
        if severity in severity_counts:
            severity_counts[severity] += 1

    report = {
        "report": "Nayak The Hacker Security Assessment Report",
        "scan_id": scan["scan_id"],
        "target": scan["target"],
        "target_type": scan.get("target_type", "web"),
        "status": scan["status"],
        "summary": {
            "total_findings": len(findings),
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "info": severity_counts["info"],
        },
        "findings": findings,
    }

    return JSONResponse(
        content=report,
        headers={
            "Content-Disposition": (
                f'attachment; filename="scan-{scan_id}.json"'
            )
        },
    )


@app.get("/scan/{scan_id}/findings")
def get_findings(
    scan_id: str,
    severity: str | None = Query(default=None),
):
    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = scan["findings"]

    if severity:
        findings = [
            finding
            for finding in findings
            if finding["severity"] == severity
        ]

    return {
        "scan_id": scan_id,
        "count": len(findings),
        "findings": findings,
    }
