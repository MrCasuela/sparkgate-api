"""Modelo de cuentas personal/empresa (HU21 etapa A, AC1).

Cubre el registro con type_account y, sobre todo, la regresión de R-HU21-3: el
claim de user_metadata es cache y el filtro de tenencia tiene que resolverse
siempre contra la tabla organizations.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.api import dependencies
from app.api.dependencies import verify_token
from app.api.routes import auth as auth_route
from app.api.routes import dashboard
from app.main import app

ORG_ID = "org-de-la-tabla"
CLAIMED_ORG_ID = "org-del-claim"
NEW_USER_ID = "user-nuevo-1"


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture(autouse=True)
def clear_overrides():
    yield
    app.dependency_overrides.clear()


def _fake_sign_up_result(user_id: str = NEW_USER_ID):
    user = SimpleNamespace(id=user_id, identities=[{"id": "identity-1"}])
    session = SimpleNamespace(access_token="token-de-la-sesion")
    return SimpleNamespace(user=user, session=session)


def _patch_sign_up(monkeypatch, captured: dict):
    fake_client = MagicMock()

    def _sign_up(payload):
        captured["sign_up"] = payload
        return _fake_sign_up_result()

    fake_client.auth.sign_up.side_effect = _sign_up
    monkeypatch.setattr(auth_route, "create_auth_client", lambda: fake_client)
    return fake_client


@pytest.mark.asyncio
async def test_registro_enterprise_crea_organizacion_y_actualiza_metadata(client, monkeypatch):
    captured = {}
    _patch_sign_up(monkeypatch, captured)

    created_orgs = []

    def _create_org(*, owner_user_id, name):
        created_orgs.append({"owner_user_id": owner_user_id, "name": name})
        return {"id": ORG_ID, "owner_user_id": owner_user_id, "name": name}

    monkeypatch.setattr(auth_route.org_repo, "create_organization", _create_org)

    fake_admin = MagicMock()
    monkeypatch.setattr(auth_route, "get_supabase_admin", lambda: fake_admin)

    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/register",
            json={
                "email": "empresa@example.com",
                "password": "ClaveSegura#123",
                "type_account": "enterprise",
                "organization_name": "PYME Demo",
            },
        )

    assert response.status_code == 200
    assert created_orgs == [{"owner_user_id": NEW_USER_ID, "name": "PYME Demo"}]

    fake_admin.auth.admin.update_user_by_id.assert_called_once()
    _, metadata_payload = fake_admin.auth.admin.update_user_by_id.call_args[0]
    assert metadata_payload["user_metadata"]["type_account"] == "enterprise"
    assert metadata_payload["user_metadata"]["org_id"] == ORG_ID


@pytest.mark.asyncio
async def test_type_account_viaja_en_el_sign_up(client, monkeypatch):
    """El access_token se mintea en el sign_up: si type_account se seteara
    después por Admin API, el token del auto-login no lo llevaría y la empresa
    no vería su panel hasta re-loguearse."""
    captured = {}
    _patch_sign_up(monkeypatch, captured)
    monkeypatch.setattr(
        auth_route.org_repo,
        "create_organization",
        lambda *, owner_user_id, name: {"id": ORG_ID},
    )
    monkeypatch.setattr(auth_route, "get_supabase_admin", lambda: MagicMock())

    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/register",
            json={
                "email": "empresa2@example.com",
                "password": "ClaveSegura#123",
                "type_account": "enterprise",
                "organization_name": "Otra PYME",
            },
        )

    assert response.status_code == 200
    assert captured["sign_up"]["options"]["data"]["type_account"] == "enterprise"
    assert response.json()["type_account"] == "enterprise"


@pytest.mark.asyncio
async def test_registro_enterprise_sin_nombre_de_organizacion_es_422(client, monkeypatch):
    fake_client = MagicMock()
    monkeypatch.setattr(auth_route, "create_auth_client", lambda: fake_client)

    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/register",
            json={
                "email": "empresa3@example.com",
                "password": "ClaveSegura#123",
                "type_account": "enterprise",
            },
        )

    assert response.status_code == 422
    fake_client.auth.sign_up.assert_not_called()


@pytest.mark.asyncio
async def test_registro_personal_no_crea_organizacion(client, monkeypatch):
    captured = {}
    _patch_sign_up(monkeypatch, captured)

    org_calls = []
    monkeypatch.setattr(
        auth_route.org_repo,
        "create_organization",
        lambda **kwargs: org_calls.append(kwargs),
    )
    fake_admin = MagicMock()
    monkeypatch.setattr(auth_route, "get_supabase_admin", lambda: fake_admin)

    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/register",
            json={"email": "persona@example.com", "password": "ClaveSegura#123"},
        )

    assert response.status_code == 200
    assert response.json()["type_account"] == "personal"
    assert org_calls == []
    fake_admin.auth.admin.update_user_by_id.assert_not_called()
    assert captured["sign_up"]["options"]["data"]["type_account"] == "personal"


@pytest.mark.asyncio
async def test_tipo_de_cuenta_invalido_es_422(client, monkeypatch):
    monkeypatch.setattr(auth_route, "create_auth_client", lambda: MagicMock())

    async with client as ac:
        response = await ac.post(
            "/api/v1/auth/register",
            json={
                "email": "raro@example.com",
                "password": "ClaveSegura#123",
                "type_account": "superadmin",
            },
        )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_require_enterprise_sin_token_es_401(client):
    app.dependency_overrides[verify_token] = lambda: None
    async with client as ac:
        response = await ac.get("/api/v1/dashboard/members")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_el_filtro_usa_el_org_id_de_la_tabla_y_no_el_del_claim(client, monkeypatch):
    """R-HU21-3. Un token con el org_id de otra organización no debe poder
    leer sus datos: el guard descarta el claim y resuelve contra la tabla."""
    app.dependency_overrides[verify_token] = lambda: {
        "id": "owner-1",
        "email": "empresa@example.com",
        "type_account": "enterprise",
        "claimed_org_id": CLAIMED_ORG_ID,
        "user_metadata": {"type_account": "enterprise", "org_id": CLAIMED_ORG_ID},
    }
    monkeypatch.setattr(
        dependencies.org_repo,
        "get_organization_by_owner",
        lambda owner_user_id: {"id": ORG_ID, "owner_user_id": owner_user_id, "name": "PYME"},
    )

    received = {}

    def _list_audit(org_id):
        received["org_id"] = org_id
        return []

    monkeypatch.setattr(dashboard.dashboard_repo, "list_audit_log", _list_audit)

    async with client as ac:
        response = await ac.get("/api/v1/dashboard/audit-log")

    assert response.status_code == 200
    assert received["org_id"] == ORG_ID
    assert received["org_id"] != CLAIMED_ORG_ID
