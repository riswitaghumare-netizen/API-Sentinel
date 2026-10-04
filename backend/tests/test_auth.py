import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_and_login(client: AsyncClient):
    # 1. Register new user
    reg_payload = {
        "email": "analyst.test@sentinel.sec",
        "password": "SecurePassword2026!",
        "full_name": "Test Analyst",
        "organization_name": "Test SecOps Corp",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert reg_data["success"] is True
    assert "access_token" in reg_data["data"]
    assert reg_data["data"]["user"]["email"] == "analyst.test@sentinel.sec"

    # 2. Login with valid credentials
    login_payload = {
        "email": "analyst.test@sentinel.sec",
        "password": "SecurePassword2026!",
    }
    login_resp = await client.post("/api/v1/auth/login", json=login_payload)
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert login_data["success"] is True
    token = login_data["data"]["access_token"]

    # 3. Access protected /me route
    me_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["data"]["email"] == "analyst.test@sentinel.sec"


@pytest.mark.asyncio
async def test_invalid_login_rejected(client: AsyncClient):
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@sentinel.sec", "password": "WrongPassword!"},
    )
    assert login_resp.status_code == 401
    assert login_resp.json()["success"] is False
    assert login_resp.json()["error"]["code"] == "UNAUTHORIZED"
