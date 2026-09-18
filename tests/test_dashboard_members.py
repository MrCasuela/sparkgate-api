"""Alta de trabajador desde el panel (HU21 AC2)."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.api import dependencies
from app.api.dependencies import verify_token
from app.api.routes import dashboard
from app.main import app

ORG_ID = "org-1"
NEW_USER_ID = "supabase-user-nuevo"
MEMBER_ID = "member-nuevo"

MEMBER_ROW = {
    "id": MEMBER_ID,
    "org_id": ORG_ID,
    "full_name": "Elena Pérez",
    "email": "elena.perez@pyme-demo.sparkgate.test",
    "role_title": "Marketing",
    "supabase_user_id": NEW_USER_ID,
}

REQUEST_BODY = {
    "full_name": "Elena Pérez",
    "email": "elena.perez@pyme-demo.sparkgate.test",
    "role_title": "Marketing",
}


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[verify_token] = lambda: {
        "id": "admin-1",
        "email": "admin@pyme-demo.sparkgate.test",
        "type_account": "enterprise",
        "claimed_org_id": ORG_ID,
        "user_metadata": {"type_account": "enterprise", "org_id": ORG_ID},
    }
    yield
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def stub_organization(monkeypatch):
    monkeypatch.setattr(
        dependencies.org_repo,
        "get_organization_by_owner",
        lambda owner_user_id: {"id": ORG_ID, "owner_user_id": owner_user_id, "name": "PYME Demo"},
    )


def _fake_admin(monkeypatch, create_user_side_effect=None):
    fake = MagicMock()
    if create_user_side_effect is not None:
        fake.auth.admin.create_user.side_effect = create_user_side_effect
    else:
        fake.auth.admin.create_user.return_value = SimpleNamespace(
            user=SimpleNamespace(id=NEW_USER_ID)
        )
    monkeypatch.setattr(dashboard, "get_supabase_admin", lambda: fake)
    return fake


@pytest.mark.asyncio
async def test_alta_devuelve_contrasena_temporal_y_crea_usuario(client, monkeypatch):
    fake_admin = _fake_admin(monkeypatch)
    create_member_calls = []
    credential_calls = []

    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "create_member",
        lambda **kwargs: (create_member_calls.append(kwargs), dict(MEMBER_ROW))[1],
    )
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "create_internal_credential",
        lambda **kwargs: (credential_calls.append(kwargs), {"id": "cred-1"})[1],
    )
    monkeypatch.setattr(dashboard.dashboard_repo, "insert_audit_log", lambda **kwargs: None)

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/members", json=REQUEST_BODY)

    assert response.status_code == 201
    body = response.json()
    assert body["member"]["id"] == MEMBER_ID
    assert len(body["temporary_password"]) == 16

    fake_admin.auth.admin.create_user.assert_called_once()
    payload = fake_admin.auth.admin.create_user.call_args[0][0]
    assert payload["email_confirm"] is True
    assert payload["user_metadata"]["type_account"] == "personal"
    assert payload["user_metadata"]["org_id"] == ORG_ID
    assert payload["password"] == body["temporary_password"]

    assert create_member_calls[0]["org_id"] == ORG_ID
    assert create_member_calls[0]["supabase_user_id"] == NEW_USER_ID
    assert credential_calls[0]["supabase_user_id"] == NEW_USER_ID


@pytest.mark.asyncio
async def test_la_contrasena_temporal_no_llega_a_la_auditoria(client, monkeypatch):
    _fake_admin(monkeypatch)
    audit_calls = []

    monkeypatch.setattr(
        dashboard.dashboard_repo, "create_member", lambda **kwargs: dict(MEMBER_ROW)
    )
    monkeypatch.setattr(
        dashboard.dashboard_repo, "create_internal_credential", lambda **kwargs: {"id": "cred-1"}
    )
    monkeypatch.setattr(
        dashboard.dashboard_repo, "insert_audit_log", lambda **kwargs: audit_calls.append(kwargs)
    )

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/members", json=REQUEST_BODY)

    temporary_password = response.json()["temporary_password"]
    assert audit_calls == [
        {
            "org_id": ORG_ID,
            "actor_email": "admin@pyme-demo.sparkgate.test",
            "member_id": MEMBER_ID,
            "action": "crear_trabajador",
        }
    ]
    # La contraseña acá existe de verdad como valor, así que no alcanza con
    # mirar las claves: se busca el valor literal en el payload serializado.
    for call in audit_calls:
        assert "password" not in call
        assert temporary_password not in json.dumps(call)


@pytest.mark.asyncio
async def test_fallo_del_insert_borra_el_usuario_recien_creado(client, monkeypatch):
    fake_admin = _fake_admin(monkeypatch)

    def _explode(**kwargs):
        raise RuntimeError("PostgREST caído")

    monkeypatch.setattr(dashboard.dashboard_repo, "create_member", _explode)
    audit_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo, "insert_audit_log", lambda **kwargs: audit_calls.append(kwargs)
    )

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/members", json=REQUEST_BODY)

    assert response.status_code == 502
    fake_admin.auth.admin.delete_user.assert_called_once_with(NEW_USER_ID)
    assert audit_calls == []


@pytest.mark.asyncio
async def test_email_duplicado_responde_409(client, monkeypatch):
    _fake_admin(monkeypatch, create_user_side_effect=Exception("User already registered"))
    member_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "create_member",
        lambda **kwargs: member_calls.append(kwargs),
    )

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/members", json=REQUEST_BODY)

    assert response.status_code == 409
    assert member_calls == []


@pytest.mark.asyncio
async def test_cuenta_personal_no_puede_dar_de_alta(client, monkeypatch):
    app.dependency_overrides[verify_token] = lambda: {
        "id": "user-1",
        "email": "user@example.com",
        "type_account": "personal",
        "claimed_org_id": None,
        "user_metadata": {},
    }
    fake_admin = _fake_admin(monkeypatch)

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/members", json=REQUEST_BODY)

    assert response.status_code == 403
    fake_admin.auth.admin.create_user.assert_not_called()


@pytest.mark.asyncio
async def test_email_invalido_es_422(client, monkeypatch):
    fake_admin = _fake_admin(monkeypatch)

    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/members", json={**REQUEST_BODY, "email": "no-es-un-email"}
        )

    assert response.status_code == 422
    fake_admin.auth.admin.create_user.assert_not_called()
