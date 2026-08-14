from __future__ import annotations

import re


def clean_evidence(value: str, limit: int = 12000) -> str:
    text = str(value or "").replace("\x00", "").strip()

    # Collapse excessive blank lines without destroying scanner output.
    text = re.sub(r"\n[ \t]*\n[ \t]*\n+", "\n\n", text)

    return text[:limit]


def evidence_fingerprint(finding: dict) -> tuple[str, str, str]:
    target = str(finding.get("target", "")).strip().lower()
    title = str(finding.get("title", "")).strip().lower()
    evidence = clean_evidence(
        str(finding.get("evidence", ""))
    ).lower()

    return target, title, evidence
