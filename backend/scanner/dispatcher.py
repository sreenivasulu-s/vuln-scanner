from backend.scanner.api_scanner import ApiScanner
from backend.scanner.cloud_scanner import CloudScanner
from backend.scanner.lab_scanner import LabScanner
from backend.scanner.mobile_scanner import MobileScanner
from backend.scanner.network_scanner import NetworkScanner
from backend.scanner.wireless_scanner import WirelessScanner
from urllib.parse import urlparse
from backend.scanner.recon_manager import ReconManager
from backend.scanner.vapt_manager import VaptManager


class TargetTypeAdapter:
    @staticmethod
    def _is_academy_root(target: str) -> bool:
        hostname = (
            urlparse(str(target).strip()).hostname
            or ""
        ).lower().rstrip(".")
        return hostname == "web-security-academy.net"

    @staticmethod
    def _academy_root_finding(target: str) -> dict:
        return {
            "title": "PortSwigger Academy root detected",
            "severity": "info",
            "confidence": "high",
            "finding_type": "tool_status",
            "automation_status": "complete",
            "description": (
                "The supplied URL is the Web Security Academy portal root, "
                "not an individual interactive lab instance."
            ),
            "evidence": str(target),
            "impact": (
                "No vulnerability assessment was run because the portal root "
                "is not a specific lab application target."
            ),
            "remediation": (
                "Start a Web Security Academy lab and scan its unique "
                "<lab-id>.web-security-academy.net URL."
            ),
            "tool": "scope-preflight",
            "category_key": None,
        }

    async def scan(self, target: str, target_type: str) -> list[dict]:
        scanners = {
            "web": self._scan_web,
            "api": self._scan_api,
            "network": self._scan_network,
            "mobile": self._scan_mobile,
            "cloud": self._scan_cloud,
            "wireless": self._scan_wireless,
        }

        scanner = scanners.get(target_type)

        if scanner is None:
            return [
                {
                    "title": "Unsupported target type",
                    "severity": "info",
                    "description": "The requested target type is not supported.",
                    "evidence": f"Target type: {target_type}",
                    "tool": "dispatcher",
                }
            ]

        return await scanner(target)

    async def _scan_web(self, target: str) -> list[dict]:
        # Academy root is a portal, not an individual lab target.
        # Do not run heavy scanners against it.
        if self._is_academy_root(target):
            return [self._academy_root_finding(target)]

        findings = []

        # Existing passive web checks remain part of the pipeline.
        findings.extend(await LabScanner().scan(target))

        # Multi-tool authorized reconnaissance.
        findings.extend(await ReconManager().run(target))

        # Authorized web assessment tools.
        findings.extend(await VaptManager().run(target))

        return findings

    async def _scan_api(self, target: str) -> list[dict]:
        # API targets use the dedicated passive API assessment pipeline.
        # Do not run generic network/recon tooling here.
        return await ApiScanner().scan(target)

    async def _scan_network(self, target: str) -> list[dict]:
        findings = []

        findings.extend(await NetworkScanner().scan(target))
        findings.extend(await ReconManager().run(target))

        return findings

    async def _scan_mobile(self, target: str) -> list[dict]:
        return await MobileScanner().scan(target)

    async def _scan_cloud(self, target: str) -> list[dict]:
        return await CloudScanner().scan(target)

    async def _scan_wireless(self, target: str) -> list[dict]:
        return await WirelessScanner().scan(target)
