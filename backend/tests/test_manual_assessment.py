
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from backend.main import app, scans

client = TestClient(app)


def fake_burp_status():
    return {
        "configured": True,
        "reachable": False,
        "initialized": False,
        "endpoint": "http://127.0.0.1:9876",
        "transport": "sse",
        "tool_count": 0,
        "tools": [],
        "manual_setup_required": True,
        "message": "test",
    }


def test_manual_catalog_has_30_categories():
    response = client.get("/manual/catalog")

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 30
    assert data["manual_count"] > 0
    assert len(data["categories"]) == 30


def test_manual_status_exposes_burp_state():
    with patch(
        "backend.manual_assessment.BurpMCPClient.status",
        new=AsyncMock(return_value=fake_burp_status()),
    ):
        response = client.get("/manual/status")

    assert response.status_code == 200

    data = response.json()

    assert data["authorized_only"] is True
    assert data["total_category_count"] == 30
    assert data["burp_mcp"]["reachable"] is False


def test_manual_scan_creates_action_alert():
    scan_id = "manual-test-scan"

    scans[scan_id] = {
        "scan_id": scan_id,
        "target": "http://127.0.0.1:3000",
        "target_type": "web",
        "status": "completed",
        "findings": [],
    }

    try:
        with patch(
            "backend.manual_assessment.BurpMCPClient.status",
            new=AsyncMock(return_value=fake_burp_status()),
        ):
            response = client.get(
                f"/manual/scan/{scan_id}",
            )

        assert response.status_code == 200

        data = response.json()

        assert data["manual_category_count"] > 0
        assert any(
            alert["type"] == "manual_validation"
            for alert in data["alerts"]
        )
        assert any(
            alert["type"] == "burp_unavailable"
            for alert in data["alerts"]
        )
        assert len(data["coverage"]) == 30
    finally:
        scans.pop(scan_id, None)
