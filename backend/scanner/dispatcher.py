from backend.scanner.api_scanner import ApiScanner
from backend.scanner.cloud_scanner import CloudScanner
from backend.scanner.lab_scanner import LabScanner
from backend.scanner.mobile_scanner import MobileScanner
from backend.scanner.network_scanner import NetworkScanner
from backend.scanner.wireless_scanner import WirelessScanner
from backend.scanner.recon_manager import ReconManager
from backend.scanner.vapt_manager import VaptManager


class TargetTypeAdapter:
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
        findings = []

        # Existing passive web checks remain part of the pipeline.
        findings.extend(await LabScanner().scan(target))

        # Multi-tool authorized reconnaissance.
        findings.extend(await ReconManager().run(target))

        # Authorized web assessment tools.
        findings.extend(await VaptManager().run(target))

        return findings

    async def _scan_api(self, target: str) -> list[dict]:
        findings = []

        findings.extend(await ApiScanner().scan(target))

        # Recon is useful for API hosts as well.
        findings.extend(await ReconManager().run(target))

        return findings

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
