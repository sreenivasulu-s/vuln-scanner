from __future__ import annotations


KNOWLEDGE = {
    "missing strict-transport-security header": {
        "cwe": "CWE-319",
        "owasp": "A05:2021 Security Misconfiguration",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://cwe.mitre.org/data/definitions/319.html",
        ],
    },
    "server header disclosure": {
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "references": [
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
    },
    "sql injection": {
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
    "cross-site scripting": {
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },
    "xss": {
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },
    "open redirect": {
        "cwe": "CWE-601",
        "owasp": "A01:2021 Broken Access Control",
        "references": [
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
    },
    "authentication bypass": {
        "cwe": "CWE-287",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "references": [
            "https://cwe.mitre.org/data/definitions/287.html",
        ],
    },
}


def enrich_finding(finding: dict) -> dict:
    title = str(finding.get("title", "")).lower()

    for marker, metadata in KNOWLEDGE.items():
        if marker in title:
            finding["cwe"] = metadata["cwe"]
            finding["owasp"] = metadata["owasp"]
            finding["references"] = list(metadata["references"])
            return finding

    finding.setdefault("cwe", "")
    finding.setdefault("owasp", "")
    finding.setdefault("references", [])
    return finding
