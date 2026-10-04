import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_full_api_workflow(client: AsyncClient, admin_auth_headers: dict):
    headers = {"Authorization": admin_auth_headers["Authorization"]}

    # 1. Register API
    api_payload = {
        "name": "Integration Test Gateway",
        "description": "API created for automated testing",
        "base_url": "http://127.0.0.1:8001",
        "environment": "TESTING",
        "technology": "Python / FastAPI",
        "version": "v1.0.0",
        "monitoring_status": "ENABLED",
        "risk_classification": "HIGH",
    }
    create_resp = await client.post("/api/v1/apis", json=api_payload, headers=headers)
    assert create_resp.status_code == 200
    api_data = create_resp.json()["data"]
    api_id = api_data["id"]
    assert api_data["name"] == "Integration Test Gateway"

    # 2. List APIs
    list_resp = await client.get("/api/v1/apis", headers=headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()["data"]) >= 1

    # 3. Trigger Scan
    scan_resp = await client.post(f"/api/v1/scans?api_id={api_id}", json={"profile_type": "STANDARD"}, headers=headers)
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()["data"]
    assert scan_data["api_id"] == api_id
    assert scan_data["status"] in ("PENDING", "RUNNING", "COMPLETED")

    # 4. Generate Security Report
    report_payload = {
        "title": "Automated Test Security Report",
        "scope": "ALL_APIS",
        "report_format": "HTML",
    }
    report_resp = await client.post("/api/v1/reports/generate", json=report_payload, headers=headers)
    assert report_resp.status_code == 200
    assert report_resp.json()["success"] is True

    # 5. Fetch Dashboard Stats
    dash_resp = await client.get("/api/v1/dashboard/stats", headers=headers)
    assert dash_resp.status_code == 200
    stats = dash_resp.json()["data"]
    assert "total_apis" in stats
    assert "average_security_score" in stats
