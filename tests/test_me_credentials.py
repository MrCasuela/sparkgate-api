"""Lo que la organización le asignó al trabajador (HU21 etapa C, router /api/v1/me).

Es la otra cara de test_dashboard_credentials: acá el caller es un TRABAJADOR (require_user,
sin org_id en el token) y solo puede ver y retirar lo que se le asignó.
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.api.dependencies import verify_token
from app.api.routes import me
from app.main import app
from app.services import secret_access, vault_crypto

NOW = datetime.now(timezone.utc).isoformat()
ORG_ID = "org-1"
WORKER_ID = "worker-1"
WORKER_EMAIL = "bruno@pyme-demo.sparkgate.test"
ENVELOPE = {"ciphertext": "Y2lwaGVy", "nonce": "bm9uY2U", "wrapped_dek": "d3JhcHBlZA",
            "dek_nonce": "ZGVrbm9uY2U", "kek_version": 1, "org_id": ORG_ID}


def _credential(**overrides):
    base = {
        "id": "cred-1", "org_id": ORG_ID, "member_id": "member-1", "type": "externa",
        "service_name": "Google Workspace", "username": "ws@pyme.cl",
        "supabase_user_id": None, "status": "activa", "secret_updated_at": NOW,
        "rotation_required": False, "updated_at": NOW,
    }
    base.update(overrides)
    return base


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture(autouse=True)
def worker():
    # Un trabajador común: cuenta personal, SIN organización en el token.
    app.dependency_overrides[verify_token] = lambda: {
        "id": WORKER_ID, "email": WORKER_EMAIL, "type_account": "personal",
        "claimed_org_id": ORG_ID, "user_metadata": {},
    }
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def env(monkeypatch):
    state = {"credential": _credential(), "envelope": dict(ENVELOPE), "revoked": False,
             "audit": [], "aad": [], "kek": True}
    monkeypatch.setattr(me.dashboard_repo, "list_assigned_credentials",
                        lambda user_id: [dict(state["credential"])] if user_id == WORKER_ID else [])
    monkeypatch.setattr(me.dashboard_repo, "get_assigned_credential",
                        lambda cid, user_id: dict(state["credential"])
                        if state["credential"] and cid == "cred-1" and user_id == WORKER_ID else None)
    monkeypatch.setattr(me.dashboard_repo, "has_revoked_internal", lambda member_id: state["revoked"])
    monkeypatch.setattr(me.dashboard_repo, "insert_audit_log", lambda **kw: state["audit"].append(kw))
    monkeypatch.setattr(me.org_repo, "get_organization", lambda org_id: {"id": org_id, "name": "PYME Demo"})
    monkeypatch.setattr(me.credential_secret_repo, "get_envelope",
                        lambda cid, org_id: dict(state["envelope"]) if state["envelope"] else None)
    monkeypatch.setattr(secret_access.vault_crypto, "is_available", lambda: state["kek"])

    def _decrypt(row, aad):
        state["aad"].append(aad)
        return {"password": "Clave-Real#1", "notes": "nota"}

    monkeypatch.setattr(secret_access.vault_crypto, "decrypt_secret", _decrypt)
    return state


@pytest.mark.asyncio
async def test_el_trabajador_lista_lo_que_se_le_asigno_sin_ver_el_secreto(client, env):
    async with client as ac:
        response = await ac.get("/api/v1/me/credentials")

    assert response.status_code == 200
    [item] = response.json()
    assert item["organization_name"] == "PYME Demo"
    assert item["service_name"] == "Google Workspace"
    assert item["has_secret"] is True
    assert "Clave-Real#1" not in response.text
    assert "password" not in item
    # Listar lo propio no es un evento de privacidad: no audita.
    assert env["audit"] == []


@pytest.mark.asyncio
async def test_no_hace_falta_ser_cuenta_de_empresa(client, env):
    """/me cuelga de require_user y NO del router /dashboard: un endpoint de trabajador ahí
    quedaría a un Depends mal escrito de ser un agujero de tenencia."""
    async with client as ac:
        assert (await ac.get("/api/v1/me/credentials")).status_code == 200
        assert (await ac.get("/api/v1/dashboard/members")).status_code == 403


@pytest.mark.asyncio
async def test_sin_token_es_401(client, env):
    app.dependency_overrides[verify_token] = lambda: None
    async with client as ac:
        assert (await ac.get("/api/v1/me/credentials")).status_code == 401
        assert (await ac.post("/api/v1/me/credentials/cred-1/reveal")).status_code == 401


@pytest.mark.asyncio
async def test_retirar_la_contrasena_la_devuelve_y_queda_en_la_cadena_de_la_empresa(client, env):
    async with client as ac:
        response = await ac.post("/api/v1/me/credentials/cred-1/reveal")

    assert response.status_code == 200
    assert response.json()["password"] == "Clave-Real#1"
    # El AAD es la ORGANIZACIÓN, no el trabajador que la retira.
    assert env["aad"] == [ORG_ID]
    # La empresa ve quién retiró qué. El autor es el trabajador, no un administrador.
    assert env["audit"] == [
        {
            "org_id": ORG_ID, "actor_user_id": WORKER_ID, "actor_email": WORKER_EMAIL,
            "member_id": "member-1", "credential_id": "cred-1", "credential_type": "externa",
            "action": "consultar_secreto_asignado",
        }
    ]
    assert "Clave-Real#1" not in json.dumps(env["audit"])


@pytest.mark.asyncio
async def test_una_credencial_no_asignada_a_este_usuario_es_404(client, env):
    env["credential"] = None  # el repositorio no la devuelve: no es suya
    async with client as ac:
        response = await ac.post("/api/v1/me/credentials/cred-1/reveal")
    assert response.status_code == 404
    assert env["aad"] == []


@pytest.mark.asyncio
async def test_un_integrante_revocado_no_retira_nada(client, env):
    """La guarda no es cosmética. Un revoke real ya invalida el token (se midió: 401), pero si
    la llamada a Auth de un revoke falla, la credencial queda 'revocada' en la base con el
    usuario aún activo, y ahí esta guarda es lo único que lo frena. Se mira el estado de SU
    cuenta interna, no el de la credencial externa, que sigue 'activa'."""
    env["revoked"] = True
    async with client as ac:
        response = await ac.post("/api/v1/me/credentials/cred-1/reveal")
    assert response.status_code == 403
    assert env["aad"] == []
    assert env["audit"] == []


@pytest.mark.asyncio
async def test_una_credencial_pendiente_de_actualizacion_no_se_entrega(client, env):
    """El secreto guardado es el nuevo, que todavía no está aplicado en el servicio."""
    env["credential"] = _credential(status="pendiente_aplicacion_manual")
    async with client as ac:
        response = await ac.post("/api/v1/me/credentials/cred-1/reveal")
    assert response.status_code == 403
    assert env["aad"] == []


@pytest.mark.asyncio
async def test_sin_contrasena_guardada_es_404(client, env):
    env["envelope"] = None
    async with client as ac:
        response = await ac.post("/api/v1/me/credentials/cred-1/reveal")
    assert response.status_code == 404
    assert "no tiene una contraseña guardada" in response.json()["detail"]


@pytest.mark.asyncio
async def test_sin_clave_maestra_es_503_antes_de_tocar_la_base(client, env, monkeypatch):
    env["kek"] = False
    lookup = MagicMock()
    monkeypatch.setattr(me.dashboard_repo, "get_assigned_credential", lookup)
    async with client as ac:
        response = await ac.post("/api/v1/me/credentials/cred-1/reveal")
    assert response.status_code == 503
    lookup.assert_not_called()


@pytest.mark.asyncio
async def test_un_fallo_de_integridad_es_503_y_queda_denegado(client, env, monkeypatch):
    def _explode(row, aad):
        raise vault_crypto.InvalidTag()

    monkeypatch.setattr(secret_access.vault_crypto, "decrypt_secret", _explode)
    async with client as ac:
        response = await ac.post("/api/v1/me/credentials/cred-1/reveal")
    assert response.status_code == 503
    assert [a["action"] for a in env["audit"]] == ["consultar_secreto_denegado"]


@pytest.mark.asyncio
async def test_el_segundo_factor_de_hu18_tambien_cubre_al_trabajador(client, env, monkeypatch):
    """Mismo punto de paso único: HU18 lo cubre sin tocar esta ruta."""
    def _exige_totp(caller, scope, code):
        if code != "123456":
            raise secret_access.StepUpRequired()

    monkeypatch.setattr(secret_access, "_verify_step_up", _exige_totp)
    async with client as ac:
        sin = await ac.post("/api/v1/me/credentials/cred-1/reveal")
        con = await ac.post("/api/v1/me/credentials/cred-1/reveal", headers={"X-SparkGate-TOTP": "123456"})
    assert (sin.status_code, con.status_code) == (403, 200)
