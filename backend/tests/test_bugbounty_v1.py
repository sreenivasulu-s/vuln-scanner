from backend.bugbounty.models import BugBountyFinding, ScopeRule
from backend.bugbounty.report import build_report, render_markdown
from backend.bugbounty.scope import ScopeManager


def test_scope_manager_matches_exact_host():
    scope = ScopeManager(
        [ScopeRule("example.com")]
    )

    assert scope.is_in_scope("https://example.com") is True
    assert scope.is_in_scope("https://other.com") is False


def test_scope_manager_matches_subdomain():
    scope = ScopeManager(
        [ScopeRule("example.com")]
    )

    assert scope.is_in_scope("https://api.example.com") is True


def test_scope_manager_rejects_out_of_scope_rule():
    scope = ScopeManager(
        [ScopeRule("example.com", in_scope=False)]
    )

    assert scope.is_in_scope("https://example.com") is False


def test_report_contains_finding_summary():
    finding = BugBountyFinding(
        title="Missing security header",
        severity="low",
        confidence="high",
        target="https://example.com",
        description="Security header is missing.",
        evidence="HTTP response did not contain the header.",
        impact="Reduced browser-side protection.",
        remediation="Configure the appropriate security header.",
        tool="httpx",
    )

    report = build_report(
        "https://example.com",
        [finding],
    )

    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["low"] == 1
    assert report["findings"][0]["title"] == "Missing security header"


def test_markdown_report_contains_sections():
    finding = BugBountyFinding(
        title="Test finding",
        severity="info",
        confidence="medium",
        target="https://example.com",
        description="Description",
        evidence="Evidence",
        impact="Impact",
        remediation="Remediation",
        tool="scanner",
    )

    report = build_report(
        "https://example.com",
        [finding],
    )

    markdown = render_markdown(report)

    assert "# Bug Bounty Security Report" in markdown
    assert "## Summary" in markdown
    assert "## Findings" in markdown
    assert "Test finding" in markdown
