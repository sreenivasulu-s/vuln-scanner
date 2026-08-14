from __future__ import annotations

from dataclasses import asdict
from typing import Any
from urllib.parse import urlparse

from .models import BugBountyFinding


def _finding(
    *,
    title: str,
    severity: str,
    confidence: str,
    target: str,
    description: str,
    evidence: str,
    impact: str,
    remediation: str,
    tool: str = "bugbounty-v1",
) -> BugBountyFinding:
    return BugBountyFinding(
        title=title,
        severity=severity,
        confidence=confidence,
        target=target,
        description=description,
        evidence=evidence,
        impact=impact,
        remediation=remediation,
        tool=tool,
    )


def analyze_response(
    target: str,
    *,
    status_code: int,
    headers: dict[str, Any],
) -> list[BugBountyFinding]:
    """
    Passive response analysis only.

    This function does not exploit the target. It inspects the supplied
    HTTP response metadata and produces normalized bug-bounty findings.
    """
    findings: list[BugBountyFinding] = []
    normalized = {str(k).lower(): str(v) for k, v in headers.items()}
    parsed = urlparse(target)

    if "server" in normalized:
        findings.append(
            _finding(
                title="Server technology disclosure",
                severity="info",
                confidence="high",
                target=target,
                description="The HTTP response exposes a Server header.",
                evidence=f"Server: {normalized['server']}",
                impact="Server fingerprinting can provide useful information to an attacker.",
                remediation="Remove or minimize unnecessary server identification headers.",
            )
        )

    if "x-powered-by" in normalized:
        findings.append(
            _finding(
                title="Technology disclosure via X-Powered-By",
                severity="low",
                confidence="high",
                target=target,
                description="The response exposes an X-Powered-By header.",
                evidence=f"X-Powered-By: {normalized['x-powered-by']}",
                impact="Exposed framework/runtime information can assist technology fingerprinting.",
                remediation="Remove X-Powered-By where practical.",
            )
        )

    if parsed.scheme == "https":
        security_headers = {
            "strict-transport-security": (
                "Missing Strict-Transport-Security header",
                "medium",
                "The HTTPS response does not advertise HSTS.",
                "Browsers may remain vulnerable to downgrade/first-visit interception scenarios.",
                "Configure an appropriate Strict-Transport-Security policy after validating HTTPS deployment.",
            ),
            "content-security-policy": (
                "Missing Content-Security-Policy header",
                "low",
                "The HTTPS response does not advertise a Content-Security-Policy.",
                "A CSP can reduce the impact of some classes of client-side injection.",
                "Deploy a restrictive Content-Security-Policy appropriate for the application.",
            ),
            "x-content-type-options": (
                "Missing X-Content-Type-Options header",
                "low",
                "The response does not advertise X-Content-Type-Options.",
                "Missing browser hardening can increase exposure to content-type sniffing issues.",
                "Set X-Content-Type-Options to nosniff where appropriate.",
            ),
        }

        for header, data in security_headers.items():
            if header not in normalized:
                title, severity, description, impact, remediation = data
                findings.append(
                    _finding(
                        title=title,
                        severity=severity,
                        confidence="medium",
                        target=target,
                        description=description,
                        evidence=f"HTTP {status_code}; header absent: {header}",
                        impact=impact,
                        remediation=remediation,
                    )
                )

    set_cookie = normalized.get("set-cookie")
    if set_cookie:
        cookie_lower = set_cookie.lower()

        if "secure" not in cookie_lower and parsed.scheme == "https":
            findings.append(
                _finding(
                    title="Cookie missing Secure attribute",
                    severity="medium",
                    confidence="medium",
                    target=target,
                    description="A cookie is set over HTTPS without a Secure attribute.",
                    evidence=f"Set-Cookie: {set_cookie}",
                    impact="The cookie may be exposed if it is later transmitted over an insecure connection.",
                    remediation="Add the Secure attribute to sensitive cookies.",
                )
            )

        if "httponly" not in cookie_lower:
            findings.append(
                _finding(
                    title="Cookie missing HttpOnly attribute",
                    severity="low",
                    confidence="medium",
                    target=target,
                    description="A cookie is set without an HttpOnly attribute.",
                    evidence=f"Set-Cookie: {set_cookie}",
                    impact="Client-side scripts may be able to access the cookie.",
                    remediation="Add HttpOnly to sensitive session/authentication cookies.",
                )
            )

        if "samesite" not in cookie_lower:
            findings.append(
                _finding(
                    title="Cookie missing SameSite attribute",
                    severity="low",
                    confidence="medium",
                    target=target,
                    description="A cookie is set without an explicit SameSite attribute.",
                    evidence=f"Set-Cookie: {set_cookie}",
                    impact="Cross-site request behavior is less explicitly constrained.",
                    remediation="Set an appropriate SameSite policy for the cookie.",
                )
            )

    return findings


def deduplicate_findings(
    findings: list[BugBountyFinding],
) -> list[BugBountyFinding]:
    seen: set[tuple[str, str, str]] = set()
    result: list[BugBountyFinding] = []

    for finding in findings:
        key = (
            finding.target,
            finding.title,
            finding.evidence,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)

    return result


def finding_to_dict(finding: BugBountyFinding) -> dict[str, Any]:
    return asdict(finding)


def analyze_and_deduplicate(
    target: str,
    *,
    status_code: int,
    headers: dict[str, Any],
) -> list[BugBountyFinding]:
    return deduplicate_findings(
        analyze_response(
            target,
            status_code=status_code,
            headers=headers,
        )
    )
