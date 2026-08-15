
from __future__ import annotations

import json
import re
from typing import Any


INDICATORS = (
    (
        "SQL error indicator",
        re.compile(
            r"sql syntax|mysql|postgres(?:ql)?|sqlite|ora-\d+|odbc|syntax error",
            re.I,
        ),
    ),
    (
        "XSS payload indicator",
        re.compile(r"<script|javascript:|onerror\s*=|onload\s*=", re.I),
    ),
    (
        "CORS wildcard indicator",
        re.compile(r"access-control-allow-origin\s*:\s*\*", re.I),
    ),
    (
        "Path traversal indicator",
        re.compile(r"\.\./|\.\\\\|/etc/passwd|boot\.ini", re.I),
    ),
    (
        "Information disclosure indicator",
        re.compile(
            r"stack trace|traceback \(|exception in thread|debug toolbar|server version",
            re.I,
        ),
    ),
    (
        "JWT indicator",
        re.compile(
            r"authorization:\s*bearer\s+eyJ|eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.",
            re.I,
        ),
    ),
)


def _text(value: Any) -> str:
    parts: list[str] = []

    if isinstance(value, str):
        return value

    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            parts.append(value["text"])
        for child in value.values():
            parts.append(_text(child))

    elif isinstance(value, list):
        for child in value:
            parts.append(_text(child))

    return "\n".join(p for p in parts if p).strip()


def _decode(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return text


def _target_present(text: str, target: str) -> bool:
    host = (
        target.split("://", 1)[-1]
        .split("/", 1)[0]
        .split(":", 1)[0]
        .lower()
    )
    return host in text.lower()


def analyze_history(
    result: dict[str, Any],
    target: str,
) -> list[dict[str, Any]]:
    raw = _text(result)

    if not raw or not _target_present(raw, target):
        return []

    text = _text(_decode(raw))
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for title, pattern in INDICATORS:
        match = pattern.search(text)

        if not match:
            continue

        key = title.lower()

        if key in seen:
            continue

        seen.add(key)

        start = max(0, match.start() - 300)
        end = min(len(text), match.end() + 700)

        findings.append(
            {
                "title": f"Burp passive: {title}",
                "severity": (
                    "medium"
                    if "SQL" in title or "XSS" in title
                    else "low"
                ),
                "confidence": "low",
                "description": (
                    "Burp Proxy HTTP history contains a passive "
                    "security indicator. No exploit payload was sent."
                ),
                "evidence": text[start:end][:4000],
                "impact": (
                    "Potential security condition; evidence is not confirmation."
                ),
                "remediation": (
                    "Review the corresponding Burp request/response and "
                    "manually validate within authorized scope."
                ),
                "tool": "burp",
                "category_key": None,
            }
        )

    return findings
