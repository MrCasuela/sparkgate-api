"""La empresa consulta la bóveda de su trabajador (HU21 etapa B).

El test central es el del AAD: el descifrado usa el user_id del DUEÑO del ítem,
nunca el del caller. Si eso se invirtiera, el cifrado quedaría debilitado y una
fila movida a otro usuario podría descifrarse.
"""

import json
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.api import dependencies
from app.api.dependencies import verify_token
from app.api.routes import dashboard
from app.main import app
from app.services import vault_crypto

ORG_ID = "org-1"
CALLER_ID = "empresa-1"
CALLER_EMAIL = "admin@pyme-demo.sparkgate.test"
OWNER_ID = "trabajador-1"
MEMBER_ID = "member-1"
ITEM_ID = "item-1"

MEMBER_WITH_ACCOUNT = {
    "id": MEMBER_ID,
    "org_id": ORG_ID,
    "full_name": "Bruno Díaz",
    "email": "bruno.diaz@pyme-demo.sparkgate.test",
    "role_title": "Ventas",
    "supabase_user_id": OWNER_ID,
}

MEMBER_WITHOUT_ACCOUNT = dict(MEMBER_WITH_ACCOUNT, id="member-2", supabase_user_id=None)

ITEM_METADATA = {
    "id": ITEM_ID,
    "service_name": "Google Workspace",
    "username": "bruno@pyme.cl",
    "created_at": "2026-09-16T12:00:00+00:00",
    "updated_at": "2026-09-16T12:00:00+00:00",
}

STORED_ITEM = {
    **ITEM_METADATA,
    "user_id": OWNER_ID,
    "ciphertext": "Y2lwaGVy",
    "nonce": "bm9uY2U",
    "wrapped_dek": "d3JhcHBlZA",
    "dek_nonce": "ZGVrbm9uY2U",
    "kek_version": 1,
}

PLAINTEXT = {"password": "ClaveDelTrabajador#1", "notes": "cuenta corporativa"}


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[verify_token] = lambda: {
        "id": CALLER_ID,
        "email": CALLER_EMAIL,
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


def _personal_account():
    app.dependency_overrides[verify_token] = lambda: {
        "id": "user-1",
        "email": "user@example.com",
        "type_account": "personal",
        "claimed_org_id": None,
        "user_metadata": {},
    }


def _vault_audit_recorder(monkeypatch):
    calls = []
    monkeypatch.setattr(dashboard.vault_repo, "insert_audit", lambda **kwargs: calls.append(kwargs))
    return calls


def _dashboard_audit_recorder(monkeypatch):
    calls = []
    monkeypatch.setattr(
        dashboard.dashboard_repo, "insert_audit_log", lambda **kwargs: calls.append(kwargs)
    )
    return calls


def _member_returning(member):
    return lambda member_id, org_id: member


# --------------------------------------------------------------------------
# Guard y aislamiento
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cuenta_personal_rechazada_en_ambos_endpoints(client):
    _personal_account()
    async with client as ac:
        listado = await ac.get(f"/api/v1/dashboard/members/{MEMBER_ID}/vault")
        reveal = await ac.post(
            f"/api/v1/dashboard/members/{MEMBER_ID}/vault/{ITEM_ID}/reveal"
        )
    assert listado.status_code == 403
    assert reveal.status_code == 403


@pytest.mark.asyncio
async def test_integrante_de_otra_organizacion_responde_404(client, monkeypatch):
    received = {}

    def _get_member(member_id, org_id):
        received["org_id"] = org_id
        return None  # el repo filtró por org_id y no encontró nada

    monkeypatch.setattr(dashboard.dashboard_repo, "get_member", _get_member)
    monkeypatch.setattr(dashboard.vault_crypto, "is_available", lambda: True)

    async with client as ac:
        listado = await ac.get(f"/api/v1/dashboard/members/{MEMBER_ID}/vault")
        reveal = await ac.post(
            f"/api/v1/dashboard/members/{MEMBER_ID}/vault/{ITEM_ID}/reveal"
        )

    assert listado.status_code == 404
    assert reveal.status_code == 404
    assert received["org_id"] == ORG_ID


# --------------------------------------------------------------------------
# AC5 — listado de metadata
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_listado_devuelve_metadata_sin_secretos(client, monkeypatch):
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_member", _member_returning(dict(MEMBER_WITH_ACCOUNT))
    )
    received = {}

    def _list_items(user_id):
        received["user_id"] = user_id
        return [dict(ITEM_METADATA)]

    monkeypatch.setattr(dashboard.vault_repo, "list_items", _list_items)
    vault_audit = _vault_audit_recorder(monkeypatch)
    dashboard_audit = _dashboard_audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.get(f"/api/v1/dashboard/members/{MEMBER_ID}/vault")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["service_name"] == "Google Workspace"
    assert "password" not in body[0]
    assert "ciphertext" not in body[0]
    # Se listan los ítems del dueño, no los del caller.
    assert received["user_id"] == OWNER_ID

    assert vault_audit == [
        {
            "user_id": OWNER_ID,
            "item_id": None,
            "action": "listar_admin",
            "result": "ok",
            "actor_user_id": CALLER_ID,
        }
    ]
    assert dashboard_audit[0]["action"] == "listar_vault_miembro"
    assert dashboard_audit[0]["org_id"] == ORG_ID


@pytest.mark.asyncio
async def test_integrante_sin_cuenta_vinculada_devuelve_lista_vacia(client, monkeypatch):
    """AC5: un contratista externo sin cuenta SparkGate no es un error, es una
    bóveda vacía."""
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_member", _member_returning(dict(MEMBER_WITHOUT_ACCOUNT))
    )
    list_items = MagicMock()
    monkeypatch.setattr(dashboard.vault_repo, "list_items", list_items)

    async with client as ac:
        response = await ac.get(f"/api/v1/dashboard/members/{MEMBER_ID}/vault")

    assert response.status_code == 200
    assert response.json() == []
    list_items.assert_not_called()


@pytest.mark.asyncio
async def test_listado_sigue_funcionando_sin_clave_maestra(client, monkeypatch):
    """AC8: listar metadata no descifra nada, así que no depende de la KEK."""
    monkeypatch.setattr(dashboard.vault_crypto, "is_available", lambda: False)
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_member", _member_returning(dict(MEMBER_WITH_ACCOUNT))
    )
    monkeypatch.setattr(dashboard.vault_repo, "list_items", lambda user_id: [dict(ITEM_METADATA)])
    _vault_audit_recorder(monkeypatch)
    _dashboard_audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.get(f"/api/v1/dashboard/members/{MEMBER_ID}/vault")

    assert response.status_code == 200
    assert len(response.json()) == 1


# --------------------------------------------------------------------------
# AC6 / AC7 — reveal, AAD y doble auditoría
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reveal_descifra_con_el_aad_del_dueno_no_el_del_caller(client, monkeypatch):
    """El assert central de HU21. El AAD identifica de quién es el dato, no
    quién pregunta."""
    monkeypatch.setattr(dashboard.vault_crypto, "is_available", lambda: True)
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_member", _member_returning(dict(MEMBER_WITH_ACCOUNT))
    )
    monkeypatch.setattr(
        dashboard.vault_repo, "get_item", lambda item_id, user_id: dict(STORED_ITEM)
    )

    received = {}

    def _decrypt(row, aad):
        received["aad"] = aad
        return dict(PLAINTEXT)

    monkeypatch.setattr(dashboard.vault_crypto, "decrypt_secret", _decrypt)
    _vault_audit_recorder(monkeypatch)
    _dashboard_audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/members/{MEMBER_ID}/vault/{ITEM_ID}/reveal"
        )

    assert response.status_code == 200
    assert response.json()["password"] == PLAINTEXT["password"]
    assert received["aad"] == OWNER_ID
    assert received["aad"] != CALLER_ID


@pytest.mark.asyncio
async def test_reveal_busca_el_item_bajo_el_dueno(client, monkeypatch):
    monkeypatch.setattr(dashboard.vault_crypto, "is_available", lambda: True)
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_member", _member_returning(dict(MEMBER_WITH_ACCOUNT))
    )
    received = {}

    def _get_item(item_id, user_id):
        received["item_id"] = item_id
        received["user_id"] = user_id
        return dict(STORED_ITEM)

    monkeypatch.setattr(dashboard.vault_repo, "get_item", _get_item)
    monkeypatch.setattr(
        dashboard.vault_crypto, "decrypt_secret", lambda row, aad: dict(PLAINTEXT)
    )
    _vault_audit_recorder(monkeypatch)
    _dashboard_audit_recorder(monkeypatch)

    async with client as ac:
        await ac.post(f"/api/v1/dashboard/members/{MEMBER_ID}/vault/{ITEM_ID}/reveal")

    assert received == {"item_id": ITEM_ID, "user_id": OWNER_ID}


@pytest.mark.asyncio
async def test_reveal_escribe_las_dos_entradas_de_auditoria(client, monkeypatch):
    """AC7. La entrada del vault es la que ve el trabajador: sin ella la
    mitigación de privacidad de la historia no existe."""
    monkeypatch.setattr(dashboard.vault_crypto, "is_available", lambda: True)
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_member", _member_returning(dict(MEMBER_WITH_ACCOUNT))
    )
    monkeypatch.setattr(
        dashboard.vault_repo, "get_item", lambda item_id, user_id: dict(STORED_ITEM)
    )
    monkeypatch.setattr(
        dashboard.vault_crypto, "decrypt_secret", lambda row, aad: dict(PLAINTEXT)
    )
    vault_audit = _vault_audit_recorder(monkeypatch)
    dashboard_audit = _dashboard_audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/members/{MEMBER_ID}/vault/{ITEM_ID}/reveal"
        )

    assert response.status_code == 200

    assert vault_audit == [
        {
            "user_id": OWNER_ID,
            "item_id": ITEM_ID,
            "action": "consultar_admin",
            "result": "ok",
            "actor_user_id": CALLER_ID,
        }
    ]
    # El dueño y el actor son personas distintas: eso es exactamente lo que el
    # trabajador tiene que poder ver en su propia auditoría.
    assert vault_audit[0]["user_id"] != vault_audit[0]["actor_user_id"]

    assert dashboard_audit == [
        {
            "org_id": ORG_ID,
            "actor_email": CALLER_EMAIL,
            "member_id": MEMBER_ID,
            "action": "consultar_vault_miembro",
            "vault_item_id": ITEM_ID,
        }
    ]


@pytest.mark.asyncio
async def test_ningun_payload_de_auditoria_lleva_el_secreto(client, monkeypatch):
    monkeypatch.setattr(dashboard.vault_crypto, "is_available", lambda: True)
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_member", _member_returning(dict(MEMBER_WITH_ACCOUNT))
    )
    monkeypatch.setattr(
        dashboard.vault_repo, "get_item", lambda item_id, user_id: dict(STORED_ITEM)
    )
    monkeypatch.setattr(
        dashboard.vault_crypto, "decrypt_secret", lambda row, aad: dict(PLAINTEXT)
    )
    vault_audit = _vault_audit_recorder(monkeypatch)
    dashboard_audit = _dashboard_audit_recorder(monkeypatch)

    async with client as ac:
        await ac.post(f"/api/v1/dashboard/members/{MEMBER_ID}/vault/{ITEM_ID}/reveal")

    for call in vault_audit + dashboard_audit:
        serialized = json.dumps(call)
        assert "password" not in call
        assert "notes" not in call
        assert PLAINTEXT["password"] not in serialized
        assert PLAINTEXT["notes"] not in serialized
        assert "service_name" not in call


@pytest.mark.asyncio
async def test_item_inexistente_audita_denegado_y_responde_404(client, monkeypatch):
    monkeypatch.setattr(dashboard.vault_crypto, "is_available", lambda: True)
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_member", _member_returning(dict(MEMBER_WITH_ACCOUNT))
    )
    monkeypatch.setattr(dashboard.vault_repo, "get_item", lambda item_id, user_id: None)
    vault_audit = _vault_audit_recorder(monkeypatch)
    dashboard_audit = _dashboard_audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/members/{MEMBER_ID}/vault/{ITEM_ID}/reveal"
        )

    assert response.status_code == 404
    assert vault_audit[0]["action"] == "consultar_admin_denegado"
    assert vault_audit[0]["result"] == "denegado"
    assert vault_audit[0]["actor_user_id"] == CALLER_ID
    assert dashboard_audit[0]["action"] == "consultar_vault_miembro_denegado"


@pytest.mark.asyncio
async def test_integrante_sin_cuenta_no_puede_revelarse(client, monkeypatch):
    monkeypatch.setattr(dashboard.vault_crypto, "is_available", lambda: True)
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_member", _member_returning(dict(MEMBER_WITHOUT_ACCOUNT))
    )
    get_item = MagicMock()
    monkeypatch.setattr(dashboard.vault_repo, "get_item", get_item)

    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/members/{MEMBER_ID}/vault/{ITEM_ID}/reveal"
        )

    assert response.status_code == 404
    get_item.assert_not_called()


# --------------------------------------------------------------------------
# AC8 y fallos de integridad
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reveal_sin_clave_maestra_es_503_y_no_toca_la_base(client, monkeypatch):
    monkeypatch.setattr(dashboard.vault_crypto, "is_available", lambda: False)
    get_member = MagicMock()
    get_item = MagicMock()
    monkeypatch.setattr(dashboard.dashboard_repo, "get_member", get_member)
    monkeypatch.setattr(dashboard.vault_repo, "get_item", get_item)

    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/members/{MEMBER_ID}/vault/{ITEM_ID}/reveal"
        )

    assert response.status_code == 503
    get_member.assert_not_called()
    get_item.assert_not_called()


@pytest.mark.asyncio
async def test_fallo_de_integridad_responde_503_y_audita_error(client, monkeypatch):
    monkeypatch.setattr(dashboard.vault_crypto, "is_available", lambda: True)
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_member", _member_returning(dict(MEMBER_WITH_ACCOUNT))
    )
    monkeypatch.setattr(
        dashboard.vault_repo, "get_item", lambda item_id, user_id: dict(STORED_ITEM)
    )

    def _explode(row, aad):
        raise vault_crypto.InvalidTag()

    monkeypatch.setattr(dashboard.vault_crypto, "decrypt_secret", _explode)
    vault_audit = _vault_audit_recorder(monkeypatch)
    dashboard_audit = _dashboard_audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/members/{MEMBER_ID}/vault/{ITEM_ID}/reveal"
        )

    # 503 y no 404: esconder una adulteración es justo lo que el tag GCM existe
    # para evitar.
    assert response.status_code == 503
    assert vault_audit[0]["result"] == "error"
    assert vault_audit[0]["action"] == "consultar_admin"
    assert dashboard_audit[0]["action"] == "consultar_vault_miembro"
