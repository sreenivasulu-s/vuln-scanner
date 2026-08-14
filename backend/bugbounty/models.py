from dataclasses import dataclass, field
from typing import Literal


Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass
class ScopeRule:
    target: str
    in_scope: bool = True
    notes: str = ""


@dataclass
class BugBountyFinding:
    title: str
    severity: Severity
    confidence: str
    target: str
    description: str
    evidence: str
    impact: str
    remediation: str
    tool: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "tool": self.tool,
            "references": self.references,
        }
