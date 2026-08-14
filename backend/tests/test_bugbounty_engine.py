from backend.bugbounty.engine import analyze_and_deduplicate


def test_https_security_headers_are_detected():
    findings = analyze_and_deduplicate(
        "https://example.com",
        status_code=200,
        headers={},
    )

    titles = {finding.title for finding in findings}

    assert "Missing Strict-Transport-Security header" in titles
    assert "Missing Content-Security-Policy header" in titles
    assert "Missing X-Content-Type-Options header" in titles


def test_server_and_powered_by_disclosure_are_detected():
    findings = analyze_and_deduplicate(
        "https://example.com",
        status_code=200,
        headers={
            "Server": "ExampleServer/1.0",
            "X-Powered-By": "ExampleFramework",
        },
    )

    titles = {finding.title for finding in findings}

    assert "Server technology disclosure" in titles
    assert "Technology disclosure via X-Powered-By" in titles


def test_cookie_flags_are_detected():
    findings = analyze_and_deduplicate(
        "https://example.com",
        status_code=200,
        headers={
            "Set-Cookie": "session=abc",
        },
    )

    titles = {finding.title for finding in findings}

    assert "Cookie missing Secure attribute" in titles
    assert "Cookie missing HttpOnly attribute" in titles
    assert "Cookie missing SameSite attribute" in titles


def test_duplicate_findings_are_removed():
    findings = analyze_and_deduplicate(
        "https://example.com",
        status_code=200,
        headers={
            "Server": "ExampleServer/1.0",
        },
    )

    assert len(findings) == len(
        {(item.title, item.evidence) for item in findings}
    )
