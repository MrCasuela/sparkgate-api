from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.routes import auth

VALID_TOKEN = "valid-jwt-token"


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_logout_requires_token(client):
    async with client as ac:
        response = await ac.post("/api/v1/auth/logout")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_logout_signs_out_with_global_scope(client, monkeypatch):
    fake_admin = MagicMock()
    monkeypatch.setattr(auth, "get_supabase_admin", lambda: fake_admin)

    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {VALID_TOKEN}"},
        )

    assert response.status_code == 200
    assert response.json() == {"message": "Logged out"}
    fake_admin.auth.admin.sign_out.assert_called_once_with(VALID_TOKEN, scope="global")


@pytest.mark.asyncio
async def test_logout_invalid_token_returns_401(client, monkeypatch):
    fake_admin = MagicMock()
    fake_admin.auth.admin.sign_out.side_effect = Exception("invalid")
    monkeypatch.setattr(auth, "get_supabase_admin", lambda: fake_admin)

    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/logout",
            headers={"Authorization": "Bearer bad-token"},
        )

    assert response.status_code == 401
    assert "Invalid or expired token" in response.json()["detail"]
