from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse

@dataclass(frozen=True)
class ToolPlan:
    name: str
    purpose: str
    mode: str = "authorized_non_destructive"

TOOL_PLANS = {
    "web": [
        ToolPlan("httpx", "HTTP reachability and security-response checks"),
        ToolPlan("nuclei", "Template-based vulnerability assessment"),
        ToolPlan("nikto", "Web-server configuration assessment"),
        ToolPlan("ffuf", "Authorized endpoint/content discovery"),
        ToolPlan("feroxbuster", "Authorized endpoint/content discovery"),
    ],
    "api": [
        ToolPlan("httpx", "API reachability, CORS, headers and documentation"),
        ToolPlan("openapi-static", "OpenAPI inventory and structural checks"),
    ],
    "network": [
        ToolPlan("network-scanner", "Configured authorized network assessment"),
        ToolPlan("recon", "Configured authorized reconnaissance"),
    ],
    "mobile": [
        ToolPlan("mobile-scanner", "Configured authorized mobile assessment"),
    ],
    "cloud": [
        ToolPlan("cloud-scanner", "Configured authorized cloud assessment"),
    ],
    "wireless": [
        ToolPlan("wireless-scanner", "Configured authorized wireless assessment"),
    ],
}

def normalize_target(target: str) -> str:
    value = str(target).strip()
    if not value:
        raise ValueError("Target cannot be empty")
    if not value.startswith(("http://", "https://")):
        raise ValueError("Target must use http:// or https://")
    if not urlparse(value).hostname:
        raise ValueError("Target must contain a hostname")
    return value

def build_plan(target: str, target_type: str = "web") -> dict:
    target = normalize_target(target)
    target_type = target_type.strip().lower()

    if target_type not in TOOL_PLANS:
        raise ValueError(f"Unsupported target type: {target_type}")

    host = urlparse(target).hostname or ""
    local = host.lower() in {"127.0.0.1", "localhost", "::1"}

    return {
        "target": target,
        "target_type": target_type,
        "authorization_required": not local,
        "authorized_scope_rule": (
            "local target"
            if local
            else "explicit scanner scope required"
        ),
        "safety_mode": "authorized_non_destructive",
        "steps": [
            "validate target",
            "validate authorization scope",
            "execute configured assessment pipeline",
            "normalize and deduplicate findings",
            "return evidence, severity, confidence and remediation",
        ],
        "tools": [tool.__dict__ for tool in TOOL_PLANS[target_type]],
        "manual_alert_conditions": [
            "target outside authorized scope",
            "required tool unavailable",
            "tool timeout",
            "credentials or privileged access required",
        ],
    }
