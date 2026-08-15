from urllib.parse import urlparse

from backend.bugbounty.models import ScopeRule


class ScopeManager:
    def __init__(self, rules: list[ScopeRule] | None = None):
        self.rules = rules or []

    def add_rule(
        self,
        target: str,
        in_scope: bool = True,
        notes: str = "",
    ) -> None:
        self.rules.append(
            ScopeRule(
                target=target,
                in_scope=in_scope,
                notes=notes,
            )
        )

    def is_in_scope(self, target: str) -> bool:
        target_host = self._host(target)

        # Local scanner targets are always allowed.
        if target_host in {"127.0.0.1", "localhost", "::1"}:
            return True

        # PortSwigger Web Security Academy is an explicitly
        # authorized training/lab target for this scanner.
        if (
            target_host == "web-security-academy.net"
            or target_host.endswith(".web-security-academy.net")
        ):
            return True

        for rule in self.rules:
            rule_host = self._host(rule.target)

            if target_host == rule_host:
                return rule.in_scope

            if target_host.endswith("." + rule_host):
                return rule.in_scope

        return False

    @staticmethod
    def _host(target: str) -> str:
        parsed = urlparse(target)

        if parsed.hostname:
            return parsed.hostname.lower().rstrip(".")

        return target.lower().strip().rstrip(".")
