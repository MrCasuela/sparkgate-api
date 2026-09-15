from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.routes import auth as auth_routes


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


def _mock_supabase(sign_up_return=None, sign_up_side_effect=None):
    mock_client = MagicMock()
    if sign_up_side_effect is not None:
        mock_client.auth.sign_up.side_effect = sign_up_side_effect
    else:
        mock_client.auth.sign_up.return_value = sign_up_return
    return mock_client


@pytest.mark.asyncio
async def test_register_rejects_invalid_email_format(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/register",
            json={"email": "not-an-email", "password": "Sup3rSecret!"},
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_sets_plan_gratuito_and_returns_token(client, monkeypatch):
    fake_result = SimpleNamespace(
        user=SimpleNamespace(id="user-123", identities=[SimpleNamespace(id="identity-1")]),
        session=SimpleNamespace(access_token="tok-abc"),
    )
    monkeypatch.setattr(
        auth_routes, "create_auth_client", lambda: _mock_supabase(sign_up_return=fake_result)
    )
    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/register",
            json={"email": "new@example.com", "password": "Sup3rSecret!"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["plan"] == "Gratuito"
    assert body["access_token"] == "tok-abc"
    assert body["user_id"] == "user-123"


@pytest.mark.asyncio
async def test_register_duplicate_email_via_empty_identities(client, monkeypatch):
    fake_result = SimpleNamespace(
        user=SimpleNamespace(id="user-123", identities=[]),
        session=None,
    )
    monkeypatch.setattr(
        auth_routes, "create_auth_client", lambda: _mock_supabase(sign_up_return=fake_result)
    )
    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/register",
            json={"email": "existing@example.com", "password": "Sup3rSecret!"},
        )
    assert response.status_code == 409
    assert "ya está registrado" in response.json()["detail"]


@pytest.mark.asyncio
async def test_register_duplicate_email_via_exception(client, monkeypatch):
    monkeypatch.setattr(
        auth_routes,
        "create_auth_client",
        lambda: _mock_supabase(sign_up_side_effect=Exception("User already registered")),
    )
    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/register",
            json={"email": "existing@example.com", "password": "Sup3rSecret!"},
        )
    assert response.status_code == 409
    assert "ya está registrado" in response.json()["detail"]
