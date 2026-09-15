from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.routes import auth as auth_routes
from app.services import db_client


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


def _mock_supabase(sign_in_return=None, sign_in_side_effect=None):
    mock_client = MagicMock()
    if sign_in_side_effect is not None:
        mock_client.auth.sign_in_with_password.side_effect = sign_in_side_effect
    else:
        mock_client.auth.sign_in_with_password.return_value = sign_in_return
    return mock_client


@pytest.mark.asyncio
async def test_login_returns_token_and_premium_flag(client, monkeypatch):
    fake_result = SimpleNamespace(
        user=SimpleNamespace(id="user-123", user_metadata={"premium": True}),
        session=SimpleNamespace(access_token="tok-abc"),
    )
    monkeypatch.setattr(
        auth_routes, "create_auth_client", lambda: _mock_supabase(sign_in_return=fake_result)
    )
    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": "Sup3rSecret!"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"] == "tok-abc"
    assert body["user_id"] == "user-123"
    assert body["premium"] is True


@pytest.mark.asyncio
async def test_login_defaults_premium_false_when_missing_metadata(client, monkeypatch):
    fake_result = SimpleNamespace(
        user=SimpleNamespace(id="user-456", user_metadata=None),
        session=SimpleNamespace(access_token="tok-def"),
    )
    monkeypatch.setattr(
        auth_routes, "create_auth_client", lambda: _mock_supabase(sign_in_return=fake_result)
    )
    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": "Sup3rSecret!"},
        )
    assert response.status_code == 200
    assert response.json()["premium"] is False


@pytest.mark.asyncio
async def test_login_wrong_credentials_returns_401(client, monkeypatch):
    monkeypatch.setattr(
        auth_routes,
        "create_auth_client",
        lambda: _mock_supabase(sign_in_side_effect=Exception("Invalid login credentials")),
    )
    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/login",
            json={"email": "user@example.com", "password": "wrong-password"},
        )
    assert response.status_code == 401
    assert "Invalid login credentials" in response.json()["detail"]


@pytest.mark.asyncio
async def test_login_never_signs_in_on_the_shared_client(client, monkeypatch):
    """supabase-py rewrites a client's Authorization header on SIGNED_IN, so a login
    on the shared singleton would leave it acting as that user process-wide."""
    fake_result = SimpleNamespace(
        user=SimpleNamespace(id="user-123", user_metadata={}),
        session=SimpleNamespace(access_token="tok-abc"),
    )
    shared = MagicMock()
    monkeypatch.setattr(db_client, "_supabase_client", shared)

    issued = []

    def _factory():
        mock_client = _mock_supabase(sign_in_return=fake_result)
        issued.append(mock_client)
        return mock_client

    monkeypatch.setattr(auth_routes, "create_auth_client", _factory)

    async with client as ac:
        for _ in range(2):
            response = await ac.post(
                "/api/v1/auth/login",
                json={"email": "user@example.com", "password": "Sup3rSecret!"},
            )
            assert response.status_code == 200

    shared.auth.sign_in_with_password.assert_not_called()
    assert len(issued) == 2 and issued[0] is not issued[1]
    for mock_client in issued:
        mock_client.auth.close.assert_called_once()


@pytest.mark.asyncio
async def test_login_rejects_missing_fields(client):
    async with client as ac:
        response = await ac.post("/api/v1/auth/login", json={"email": "user@example.com"})
    assert response.status_code == 422
