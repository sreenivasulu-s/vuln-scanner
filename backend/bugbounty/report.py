from datetime import datetime, timezone

from backend.bugbounty.models import BugBountyFinding


def build_report(
    target: str,
    findings: list[BugBountyFinding],
) -> dict:
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity_counts[finding.severity] += 1

    return {
        "report": "Bug Bounty Security Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "summary": {
            "total_findings": len(findings),
            **severity_counts,
        },
        "findings": [
            finding.to_dict()
            for finding in findings
        ],
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# Bug Bounty Security Report",
        "",
        f"**Target:** {report['target']}",
        f"**Generated:** {report['generated_at']}",
        "",
        "## Summary",
        "",
        f"- Total findings: {report['summary']['total_findings']}",
        f"- Critical: {report['summary']['critical']}",
        f"- High: {report['summary']['high']}",
        f"- Medium: {report['summary']['medium']}",
        f"- Low: {report['summary']['low']}",
        f"- Info: {report['summary']['info']}",
        "",
        "## Findings",
        "",
    ]

    for index, finding in enumerate(report["findings"], 1):
        lines.extend(
            [
                f"### {index}. {finding['title']}",
                "",
                f"**Severity:** {finding['severity']}",
                f"**Confidence:** {finding['confidence']}",
                f"**Target:** {finding['target']}",
                "",
                "#### Description",
                finding["description"],
                "",
                "#### Evidence",
                finding["evidence"],
                "",
                "#### Impact",
                finding["impact"],
                "",
                "#### Remediation",
                finding["remediation"],
                "",
                f"**Tool:** {finding['tool']}",
                "",
            ]
        )

    return "\n".join(lines)
