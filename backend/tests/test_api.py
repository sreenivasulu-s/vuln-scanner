from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_start_scan():
    response = client.post(
        "/scan",
        json={"url": "http://127.0.0.1:8000"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "queued"
    assert data["target"] == "http://127.0.0.1:8000"
    assert "scan_id" in data
    assert data["findings"] == []


def test_get_scan_findings():
    response = client.post(
        "/scan",
        json={"url": "http://127.0.0.1:8000"},
    )

    assert response.status_code == 200

    scan_id = response.json()["scan_id"]

    status_response = client.get(
        f"/scan/{scan_id}"
    )

    assert status_response.status_code == 200

    data = status_response.json()

    assert data["scan_id"] == scan_id
    assert data["status"] in {"queued", "completed"}


def test_scan_produces_httpx_finding():
    response = client.post(
        "/scan",
        json={"url": "http://127.0.0.1:8000"},
    )

    assert response.status_code == 200

    scan_id = response.json()["scan_id"]

    findings_response = client.get(
        f"/scan/{scan_id}/findings"
    )

    assert findings_response.status_code == 200

    data = findings_response.json()

    assert data["scan_id"] == scan_id
    assert data["count"] == 1

    finding = data["findings"][0]

    assert finding["title"] == "HTTP service reachable"
    assert finding["severity"] == "info"
    assert finding["tool"] == "httpx"
