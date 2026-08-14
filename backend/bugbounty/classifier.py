from __future__ import annotations


def classify_finding(finding: dict) -> dict:
    """Apply conservative severity/confidence classification.

    Scanner output is evidence, not proof of exploitability.
    """
    title = str(finding.get("title", "")).lower()
    evidence = str(finding.get("evidence", "")).lower()
    tool = str(finding.get("tool", "")).lower()

    severity = "info"
    confidence = finding.get("confidence", "medium")

    if "strict-transport-security" in title:
        severity = "low"
        confidence = "high"

    elif "server header disclosure" in title:
        severity = "low"
        confidence = "high"

    elif any(
        marker in title
        for marker in (
            "critical",
            "remote code execution",
            "rce",
        )
    ):
        severity = "critical"
        confidence = "medium"

    elif any(
        marker in title
        for marker in (
            "sql injection",
            "command injection",
            "authentication bypass",
        )
    ):
        severity = "high"
        confidence = "medium"

    elif any(
        marker in title
        for marker in (
            "xss",
            "cross-site scripting",
            "ssrf",
            "open redirect",
        )
    ):
        severity = "medium"
        confidence = "medium"

    elif any(
        marker in title
        for marker in (
            "endpoint discovery",
            "port discovery",
            "service enumeration",
            "technology fingerprinting",
            "subdomain discovery",
            "dns resolution",
            "http service fingerprinting",
        )
    ):
        severity = "info"
        confidence = "medium"

    # Tool output containing an explicit high-risk signal gets a
    # conservative bump, but never directly becomes critical.
    if severity == "info" and any(
        marker in evidence
        for marker in (
            "sql injection",
            "command injection",
            "remote code execution",
            "authentication bypass",
        )
    ):
        severity = "medium"
        confidence = "low"

    finding["severity"] = severity
    finding["confidence"] = confidence
    return finding
