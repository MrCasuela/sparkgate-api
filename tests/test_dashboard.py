from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.dependencies import verify_token
from app.api.routes import dashboard

NOW = datetime.now(timezone.utc).isoformat()

ACTIVE_INTERNAL_CREDENTIAL = {
    "id": "cred-internal-1",
    "member_id": "member-1",
    "type": "interna",
    "service_name": "SparkGate (cuenta interna)",
    "supabase_user_id": "supabase-user-1",
    "status": "activa",
    "updated_at": NOW,
}

ACTIVE_EXTERNAL_CREDENTIAL = {
    "id": "cred-external-1",
    "member_id": "member-2",
    "type": "externa",
    "service_name": "Google Workspace",
    "supabase_user_id": None,
    "status": "activa",
    "updated_at": NOW,
}

REVOKED_INTERNAL_CREDENTIAL = dict(ACTIVE_INTERNAL_CREDENTIAL, status="revocada")
PENDING_EXTERNAL_CREDENTIAL = dict(ACTIVE_EXTERNAL_CREDENTIAL, status="pendiente_aplicacion_manual")

NEW_PASSWORD = "NuevaClave#Segura99"


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[verify_token] = lambda: {
        "id": "admin-1",
        "email": "admin@pyme-demo.sparkgate.test",
        "user_metadata": {"is_admin": True},
    }
    yield
    app.dependency_overrides.clear()


def credential_lookup_returning(*rows):
    """Returns each row in order on successive calls, regardless of id — simulates
    the handler's own get_credential(before) ... get_credential(after) sequence
    against a row whose status changed in between."""
    queue = list(rows)

    def _get(cid):
        return queue.pop(0)

    return _get


@pytest.mark.asyncio
async def test_members_endpoint_requires_admin(client):
    app.dependency_overrides[verify_token] = lambda: {
        "id": "user-1",
        "email": "user@example.com",
        "user_metadata": {},
    }
    async with client as ac:
        response = await ac.get("/api/v1/dashboard/members")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_revoke_rejects_external_credential(client, monkeypatch):
    monkeypatch.setattr(dashboard.dashboard_repo, "get_credential", lambda cid: ACTIVE_EXTERNAL_CREDENTIAL)
    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{ACTIVE_EXTERNAL_CREDENTIAL['id']}/revoke",
            json={"new_password": NEW_PASSWORD},
        )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_suggest_rejects_internal_credential(client, monkeypatch):
    monkeypatch.setattr(dashboard.dashboard_repo, "get_credential", lambda cid: ACTIVE_INTERNAL_CREDENTIAL)
    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{ACTIVE_INTERNAL_CREDENTIAL['id']}/suggest",
            json={"new_password": NEW_PASSWORD},
        )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_revoke_rejects_own_admin_account(client, monkeypatch):
    own_credential = dict(ACTIVE_INTERNAL_CREDENTIAL, supabase_user_id="admin-1")
    monkeypatch.setattr(dashboard.dashboard_repo, "get_credential", lambda cid: own_credential)
    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{own_credential['id']}/revoke",
            json={"new_password": NEW_PASSWORD},
        )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_revoke_rejects_short_password(client, monkeypatch):
    monkeypatch.setattr(dashboard.dashboard_repo, "get_credential", lambda cid: dict(ACTIVE_INTERNAL_CREDENTIAL))
    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{ACTIVE_INTERNAL_CREDENTIAL['id']}/revoke",
            json={"new_password": "short"},
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_revoke_internal_applies_password_and_bans(client, monkeypatch):
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "get_credential",
        credential_lookup_returning(dict(ACTIVE_INTERNAL_CREDENTIAL), REVOKED_INTERNAL_CREDENTIAL),
    )

    status_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo, "update_credential_status", lambda cid, status: status_calls.append((cid, status))
    )

    audit_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "insert_audit_log",
        lambda **kwargs: audit_calls.append(kwargs),
    )

    fake_admin_client = MagicMock()
    monkeypatch.setattr(dashboard, "get_supabase_admin", lambda: fake_admin_client)

    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{ACTIVE_INTERNAL_CREDENTIAL['id']}/revoke",
            json={"new_password": NEW_PASSWORD},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["admin_api_success"] is True
    assert body["credential"]["status"] == "revocada"

    fake_admin_client.auth.admin.update_user_by_id.assert_called_once_with(
        "supabase-user-1", {"password": NEW_PASSWORD, "ban_duration": "87600h"}
    )
    assert status_calls == [(ACTIVE_INTERNAL_CREDENTIAL["id"], "revocada")]
    assert audit_calls == [
        {
            "actor_email": "admin@pyme-demo.sparkgate.test",
            "member_id": "member-1",
            "credential_id": ACTIVE_INTERNAL_CREDENTIAL["id"],
            "credential_type": "interna",
            "action": "revocar_interna",
        }
    ]
    for call in audit_calls:
        assert "password" not in call
        assert "new_password" not in call


@pytest.mark.asyncio
async def test_suggest_external_does_not_call_admin_api(client, monkeypatch):
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "get_credential",
        credential_lookup_returning(dict(ACTIVE_EXTERNAL_CREDENTIAL), PENDING_EXTERNAL_CREDENTIAL),
    )

    status_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo, "update_credential_status", lambda cid, status: status_calls.append((cid, status))
    )

    audit_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "insert_audit_log",
        lambda **kwargs: audit_calls.append(kwargs),
    )

    fake_admin_client = MagicMock()
    monkeypatch.setattr(dashboard, "get_supabase_admin", lambda: fake_admin_client)

    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{ACTIVE_EXTERNAL_CREDENTIAL['id']}/suggest",
            json={"new_password": NEW_PASSWORD},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["credential"]["status"] == "pendiente_aplicacion_manual"

    fake_admin_client.auth.admin.update_user_by_id.assert_not_called()
    assert status_calls == [(ACTIVE_EXTERNAL_CREDENTIAL["id"], "pendiente_aplicacion_manual")]
    assert audit_calls[0]["action"] == "sugerir_externa"
    for call in audit_calls:
        assert "password" not in call
        assert "new_password" not in call


@pytest.mark.asyncio
async def test_restore_rejects_already_active(client, monkeypatch):
    monkeypatch.setattr(dashboard.dashboard_repo, "get_credential", lambda cid: dict(ACTIVE_INTERNAL_CREDENTIAL))
    async with client as ac:
        response = await ac.post(f"/api/v1/dashboard/credentials/{ACTIVE_INTERNAL_CREDENTIAL['id']}/restore")
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_restore_internal_unbans_and_sets_activa(client, monkeypatch):
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "get_credential",
        credential_lookup_returning(dict(REVOKED_INTERNAL_CREDENTIAL), dict(ACTIVE_INTERNAL_CREDENTIAL)),
    )

    status_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo, "update_credential_status", lambda cid, status: status_calls.append((cid, status))
    )
    audit_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo, "insert_audit_log", lambda **kwargs: audit_calls.append(kwargs)
    )

    fake_admin_client = MagicMock()
    monkeypatch.setattr(dashboard, "get_supabase_admin", lambda: fake_admin_client)

    async with client as ac:
        response = await ac.post(f"/api/v1/dashboard/credentials/{REVOKED_INTERNAL_CREDENTIAL['id']}/restore")

    assert response.status_code == 200
    assert response.json()["credential"]["status"] == "activa"
    fake_admin_client.auth.admin.update_user_by_id.assert_called_once_with(
        "supabase-user-1", {"ban_duration": "none"}
    )
    assert status_calls == [(REVOKED_INTERNAL_CREDENTIAL["id"], "activa")]
    assert audit_calls[0]["action"] == "restaurar_interna"


@pytest.mark.asyncio
async def test_restore_external_sets_activa_without_admin_call(client, monkeypatch):
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "get_credential",
        credential_lookup_returning(dict(PENDING_EXTERNAL_CREDENTIAL), dict(ACTIVE_EXTERNAL_CREDENTIAL)),
    )

    status_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo, "update_credential_status", lambda cid, status: status_calls.append((cid, status))
    )
    audit_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo, "insert_audit_log", lambda **kwargs: audit_calls.append(kwargs)
    )

    fake_admin_client = MagicMock()
    monkeypatch.setattr(dashboard, "get_supabase_admin", lambda: fake_admin_client)

    async with client as ac:
        response = await ac.post(f"/api/v1/dashboard/credentials/{PENDING_EXTERNAL_CREDENTIAL['id']}/restore")

    assert response.status_code == 200
    assert response.json()["credential"]["status"] == "activa"
    fake_admin_client.auth.admin.update_user_by_id.assert_not_called()
    assert status_calls == [(PENDING_EXTERNAL_CREDENTIAL["id"], "activa")]
    assert audit_calls[0]["action"] == "restaurar_externa"


@pytest.mark.asyncio
async def test_audit_log_endpoint_returns_entries(client, monkeypatch):
    entry = {
        "id": "log-1",
        "actor_email": "admin@pyme-demo.sparkgate.test",
        "member_id": "member-1",
        "credential_id": "cred-internal-1",
        "credential_type": "interna",
        "action": "revocar_interna",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    monkeypatch.setattr(dashboard.dashboard_repo, "list_audit_log", lambda: [entry])

    async with client as ac:
        response = await ac.get("/api/v1/dashboard/audit-log")

    assert response.status_code == 200
    assert response.json()[0]["action"] == "revocar_interna"


@pytest.mark.asyncio
async def test_revoke_internal_generates_password_server_side(client, monkeypatch):
    """No new_password body → the backend generates it and never writes it to audit."""
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "get_credential",
        credential_lookup_returning(dict(ACTIVE_INTERNAL_CREDENTIAL), REVOKED_INTERNAL_CREDENTIAL),
    )
    monkeypatch.setattr(
        dashboard.dashboard_repo, "update_credential_status", lambda cid, status: None
    )
    audit_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo, "insert_audit_log", lambda **kwargs: audit_calls.append(kwargs)
    )

    generated = {}
    monkeypatch.setattr(
        dashboard.random_generator,
        "generate",
        lambda **kwargs: generated.setdefault("value", "SrvGen#Clave#99aA"),
    )

    fake_admin_client = MagicMock()
    monkeypatch.setattr(dashboard, "get_supabase_admin", lambda: fake_admin_client)

    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{ACTIVE_INTERNAL_CREDENTIAL['id']}/revoke",
            json={},
        )

    assert response.status_code == 200
    fake_admin_client.auth.admin.update_user_by_id.assert_called_once_with(
        "supabase-user-1", {"password": "SrvGen#Clave#99aA", "ban_duration": "87600h"}
    )
    assert audit_calls[0]["action"] == "revocar_interna"
    for call in audit_calls:
        assert "password" not in call
        assert "new_password" not in call


@pytest.mark.asyncio
async def test_suggest_external_generates_but_does_not_persist_password(client, monkeypatch):
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "get_credential",
        credential_lookup_returning(dict(ACTIVE_EXTERNAL_CREDENTIAL), PENDING_EXTERNAL_CREDENTIAL),
    )
    monkeypatch.setattr(
        dashboard.dashboard_repo, "update_credential_status", lambda cid, status: None
    )
    audit_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo, "insert_audit_log", lambda **kwargs: audit_calls.append(kwargs)
    )

    generated = {}
    monkeypatch.setattr(
        dashboard.random_generator,
        "generate",
        lambda **kwargs: generated.setdefault("value", "SrvGen#Externa#77zZ"),
    )

    fake_admin_client = MagicMock()
    monkeypatch.setattr(dashboard, "get_supabase_admin", lambda: fake_admin_client)

    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{ACTIVE_EXTERNAL_CREDENTIAL['id']}/suggest",
            json={},
        )

    assert response.status_code == 200
    fake_admin_client.auth.admin.update_user_by_id.assert_not_called()
    assert audit_calls[0]["action"] == "sugerir_externa"
    for call in audit_calls:
        assert "password" not in call
        assert "new_password" not in call


@pytest.mark.asyncio
async def test_revoke_rejects_already_revoked(client, monkeypatch):
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_credential", lambda cid: dict(REVOKED_INTERNAL_CREDENTIAL)
    )
    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{REVOKED_INTERNAL_CREDENTIAL['id']}/revoke",
            json={"new_password": NEW_PASSWORD},
        )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_suggest_rejects_already_pending(client, monkeypatch):
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "get_credential",
        lambda cid: dict(PENDING_EXTERNAL_CREDENTIAL),
    )
    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{PENDING_EXTERNAL_CREDENTIAL['id']}/suggest",
            json={"new_password": NEW_PASSWORD},
        )
    assert response.status_code == 400
