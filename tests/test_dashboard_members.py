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


FAKE_ENVELOPE = {
    "ciphertext": "Y2lwaGVy",
    "nonce": "bm9uY2U",
    "wrapped_dek": "d3JhcHBlZA",
    "dek_nonce": "ZGVrbm9uY2U",
    "kek_version": 1,
}


@pytest.fixture(autouse=True)
def secret_storage(monkeypatch):
    """El alta guarda la contraseña temporal cifrada. Sin este stub el test pegaría
    contra el repositorio real del sobre: como el guardado es best-effort, el fallo se
    tragaría en silencio y nadie lo notaría."""
    calls = {"sealed": [], "upserts": [], "marked": []}

    def _seal(*, subject_id, password, notes=None):
        calls["sealed"].append({"subject_id": subject_id, "password": password})
        return dict(FAKE_ENVELOPE)

    monkeypatch.setattr(dashboard.secret_access, "seal_secret", _seal)
    monkeypatch.setattr(
        dashboard.credential_secret_repo, "upsert_secret", lambda **kw: calls["upserts"].append(kw)
    )
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "mark_secret_saved",
        lambda credential_id, org_id, **kw: calls["marked"].append(credential_id),
    )
    return calls


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
async def test_la_contrasena_temporal_no_llega_a_la_auditoria(client, monkeypatch, secret_storage):
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
            "actor_user_id": "admin-1",
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


@pytest.mark.asyncio
async def test_la_temporal_se_guarda_cifrada_con_la_organizacion_como_dueña(
    client, monkeypatch, secret_storage
):
    """La contraseña temporal es la vigente de la cuenta interna hasta que el trabajador
    la cambie. Se guarda para que la empresa pueda volver a verla si se le pierde, con
    la organización como dueña del dato (AAD = org_id) y no el trabajador."""
    _fake_admin(monkeypatch)
    monkeypatch.setattr(
        dashboard.dashboard_repo, "create_member", lambda **kwargs: dict(MEMBER_ROW)
    )
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "create_internal_credential",
        lambda **kwargs: {"id": "cred-interna-1", "member_id": MEMBER_ID},
    )
    monkeypatch.setattr(dashboard.dashboard_repo, "insert_audit_log", lambda **kwargs: None)

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/members", json=REQUEST_BODY)

    body = response.json()
    assert response.status_code == 201
    assert body["secret_stored"] is True
    assert secret_storage["sealed"] == [
        {"subject_id": ORG_ID, "password": body["temporary_password"]}
    ]
    assert [c["credential_id"] for c in secret_storage["upserts"]] == ["cred-interna-1"]
    # Lo que llega al repositorio es el sobre, nunca la contraseña en claro.
    assert body["temporary_password"] not in json.dumps(secret_storage["upserts"])


@pytest.mark.asyncio
async def test_si_el_guardado_falla_el_alta_igual_se_completa_y_lo_dice(client, monkeypatch):
    """Dar de alta a un trabajador no puede depender de que la clave maestra esté arriba.
    Si el sobre no se puede guardar, la cuenta se crea igual y la respuesta dice
    secret_stored=false: en ese caso ES la única copia de la contraseña, y el panel tiene
    que poder avisarlo."""
    _fake_admin(monkeypatch)
    monkeypatch.setattr(
        dashboard.dashboard_repo, "create_member", lambda **kwargs: dict(MEMBER_ROW)
    )
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "create_internal_credential",
        lambda **kwargs: {"id": "cred-interna-1", "member_id": MEMBER_ID},
    )
    audit_calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo, "insert_audit_log", lambda **kwargs: audit_calls.append(kwargs)
    )

    def _no_hay_clave(**kwargs):
        raise RuntimeError("vault_crypto sin clave maestra")

    monkeypatch.setattr(dashboard.secret_access, "seal_secret", _no_hay_clave)

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/members", json=REQUEST_BODY)

    assert response.status_code == 201
    assert response.json()["secret_stored"] is False
    assert response.json()["temporary_password"]
    # Queda rastro del fallo, sin la contraseña.
    assert [c["action"] for c in audit_calls] == ["crear_trabajador", "guardar_secreto_fallido"]
    for call in audit_calls:
        assert response.json()["temporary_password"] not in json.dumps(call)
