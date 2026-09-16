from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.dependencies import verify_token
from app.api.routes import auth

USER_ID = "user-1"
SESSION_EMAIL = "Pablo@Correo.CL"
CORRECT_PASSWORD = "correct-horse-battery-staple"


class _FakeAuthClient:
    """Stand-in for create_auth_client(): raises on sign_in_with_password unless
    the password matches, and records whether close() ran."""

    def __init__(self, valid_password: str):
        self._valid_password = valid_password
        self.closed = False
        self.sign_in_calls = []

    @property
    def auth(self):
        return self

    def sign_in_with_password(self, credentials):
        self.sign_in_calls.append(credentials)
        if credentials["password"] != self._valid_password:
            raise Exception("Invalid login credentials")

    def close(self):
        self.closed = True


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[verify_token] = lambda: {"id": USER_ID, "email": SESSION_EMAIL, "user_metadata": {}}
    yield
    app.dependency_overrides.clear()


def _patch_happy_path(monkeypatch, fake_client, delete_user=None):
    monkeypatch.setattr(auth, "create_auth_client", lambda: fake_client)
    monkeypatch.setattr(auth.vault_repo, "delete_all_items", lambda user_id: 2)
    audit_calls = []
    monkeypatch.setattr(
        auth.vault_repo, "insert_audit", lambda **kwargs: audit_calls.append(kwargs) or kwargs
    )
    monkeypatch.setattr(auth.dashboard_repo, "detach_supabase_user", lambda user_id: 1)
    fake_admin = MagicMock()
    if delete_user is not None:
        fake_admin.auth.admin.delete_user.side_effect = delete_user
    monkeypatch.setattr(auth, "get_supabase_admin", lambda: fake_admin)
    return audit_calls, fake_admin


@pytest.mark.asyncio
async def test_requires_auth(client):
    app.dependency_overrides[verify_token] = lambda: None
    async with client as ac:
        response = await ac.request(
            "DELETE",
            "/api/v1/auth/account",
            json={"confirm_email": SESSION_EMAIL, "password": CORRECT_PASSWORD},
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_wrong_confirm_email_rejected_before_touching_network(client, monkeypatch):
    create_auth_client = MagicMock()
    monkeypatch.setattr(auth, "create_auth_client", create_auth_client)
    delete_all_items = MagicMock()
    monkeypatch.setattr(auth.vault_repo, "delete_all_items", delete_all_items)

    async with client as ac:
        response = await ac.request(
            "DELETE",
            "/api/v1/auth/account",
            json={"confirm_email": "not-my-email@example.com", "password": CORRECT_PASSWORD},
        )

    assert response.status_code == 400
    create_auth_client.assert_not_called()
    delete_all_items.assert_not_called()


@pytest.mark.asyncio
async def test_confirm_email_normalizes_case_and_whitespace(client, monkeypatch):
    fake_client = _FakeAuthClient(CORRECT_PASSWORD)
    _patch_happy_path(monkeypatch, fake_client)

    async with client as ac:
        response = await ac.request(
            "DELETE",
            "/api/v1/auth/account",
            json={"confirm_email": f"  {SESSION_EMAIL.upper()}  ", "password": CORRECT_PASSWORD},
        )

    assert response.status_code == 204


@pytest.mark.asyncio
async def test_wrong_password_rejected_and_nothing_deleted(client, monkeypatch):
    fake_client = _FakeAuthClient(CORRECT_PASSWORD)
    delete_all_items = MagicMock()
    monkeypatch.setattr(auth, "create_auth_client", lambda: fake_client)
    monkeypatch.setattr(auth.vault_repo, "delete_all_items", delete_all_items)
    fake_admin = MagicMock()
    monkeypatch.setattr(auth, "get_supabase_admin", lambda: fake_admin)

    async with client as ac:
        response = await ac.request(
            "DELETE",
            "/api/v1/auth/account",
            json={"confirm_email": SESSION_EMAIL, "password": "wrong-password"},
        )

    assert response.status_code == 401
    delete_all_items.assert_not_called()
    fake_admin.auth.admin.delete_user.assert_not_called()
    assert fake_client.closed is True


@pytest.mark.asyncio
async def test_happy_path_purges_then_detaches_then_deletes_user(client, monkeypatch):
    fake_client = _FakeAuthClient(CORRECT_PASSWORD)
    audit_calls, fake_admin = _patch_happy_path(monkeypatch, fake_client)

    async with client as ac:
        response = await ac.request(
            "DELETE",
            "/api/v1/auth/account",
            json={"confirm_email": SESSION_EMAIL, "password": CORRECT_PASSWORD},
        )

    assert response.status_code == 204
    assert fake_client.closed is True
    fake_admin.auth.admin.delete_user.assert_called_once_with(USER_ID)
    assert audit_calls == [
        {"user_id": USER_ID, "item_id": None, "action": "eliminar_cuenta", "result": "ok", "deleted_count": 2}
    ]
    for call in audit_calls:
        assert CORRECT_PASSWORD not in str(call)


@pytest.mark.asyncio
async def test_delete_user_failure_returns_502_after_data_already_purged(client, monkeypatch):
    fake_client = _FakeAuthClient(CORRECT_PASSWORD)
    audit_calls, fake_admin = _patch_happy_path(
        monkeypatch, fake_client, delete_user=Exception("GoTrue down")
    )

    async with client as ac:
        response = await ac.request(
            "DELETE",
            "/api/v1/auth/account",
            json={"confirm_email": SESSION_EMAIL, "password": CORRECT_PASSWORD},
        )

    assert response.status_code == 502
    assert CORRECT_PASSWORD not in response.json()["detail"]
    # the purge and audit entry already happened before delete_user was attempted
    assert audit_calls[0]["action"] == "eliminar_cuenta"
