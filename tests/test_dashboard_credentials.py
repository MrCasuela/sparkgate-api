"""Credenciales propias de la organización (HU21 etapa C): registrar, guardar y revelar
la contraseña, reasignar al reemplazo, y sugerir rotación.

Un "mundo" en memoria reemplaza los repositorios y el cifrado, para que cada test se
lea como una regla de negocio y no como cableado de mocks. La pieza clave es el último
test: ninguna contraseña llega jamás a ningún payload de auditoría, por ningún camino.
"""

import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.api import dependencies
from app.api.dependencies import verify_token
from app.api.routes import dashboard, passwords
from app.core.config import settings
from app.main import app
from app.schemas.passwords import PasswordGenerateResponse
from app.services import ai_engine, dashboard_repo, password_factory, secret_access, vault_crypto
from tests.totp_fakes import Factor, enroll_real_factor, totp_env

NOW = datetime.now(timezone.utc).isoformat()
ORG_ID = "org-1"
OTHER_ORG_ID = "org-2"
ADMIN_ID = "admin-1"
ADMIN_EMAIL = "admin@pyme-demo.sparkgate.test"
WORKER_USER_ID = "worker-1"

FAKE_ENVELOPE = {
    "ciphertext": "Y2lwaGVy",
    "nonce": "bm9uY2U",
    "wrapped_dek": "d3JhcHBlZA",
    "dek_nonce": "ZGVrbm9uY2U",
    "kek_version": 1,
}


def _credential(**overrides):
    base = {
        "id": "cred-ext-1",
        "org_id": ORG_ID,
        "member_id": "member-1",
        "type": "externa",
        "service_name": "Google Workspace",
        "username": "ws@pyme.cl",
        "supabase_user_id": None,
        "status": "activa",
        "secret_updated_at": None,
        "rotation_required": False,
        "updated_at": NOW,
    }
    base.update(overrides)
    return base


class World:
    """Estado en memoria + registro de todo lo que las rutas hicieron."""

    def __init__(self):
        self.credentials = {
            "cred-ext-1": _credential(),
            "cred-int-1": _credential(
                id="cred-int-1",
                type="interna",
                service_name="SparkGate (cuenta interna)",
                supabase_user_id=WORKER_USER_ID,
                username=None,
            ),
        }
        self.members = {
            "member-1": {"id": "member-1", "org_id": ORG_ID, "full_name": "Bruno Díaz"},
            "member-2": {"id": "member-2", "org_id": ORG_ID, "full_name": "Carla Muñoz"},
            "member-ajeno": {"id": "member-ajeno", "org_id": OTHER_ORG_ID, "full_name": "Ajeno"},
        }
        self.secrets = {}          # credential_id -> envelope (con org_id)
        self.audit = []            # dashboard_audit_log
        self.vault_audit = []      # vault_audit_log
        self.sealed = []           # lo que se cifró: {subject_id, password, notes}
        self.deleted = []
        self.rotation_marked = []
        self.list_args = []
        self.events = []
        self.decrypt_aad = []
        self.plaintext = {"password": "Clave-Real#1", "notes": "nota interna"}
        self.kek_available = True
        self.fail_upsert = False
        self.reassigned = []

    def all_plaintexts(self):
        return {self.plaintext["password"], self.plaintext["notes"]}


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture(autouse=True)
def sin_segundo_factor(monkeypatch):
    """Estos tests miden las RUTAS (auditoría, AAD, orden de efectos), no el factor: se anula
    el verificador. El factor lo miden test_totp_service y test_secret_access; que cada ruta
    LO EXIJA de verdad lo miden los tests de este archivo con «segundo_factor» en el nombre,
    que reponen la cadena real con totp_env()."""
    monkeypatch.setattr(secret_access, "_verify_step_up", lambda caller, scope, code: None)


@pytest.fixture(autouse=True)
def caller():
    app.dependency_overrides[verify_token] = lambda: {
        "id": ADMIN_ID,
        "email": ADMIN_EMAIL,
        "type_account": "enterprise",
        "claimed_org_id": ORG_ID,
        "user_metadata": {"type_account": "enterprise", "org_id": ORG_ID},
    }
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def world(monkeypatch):
    w = World()

    monkeypatch.setattr(
        dependencies.org_repo,
        "get_organization_by_owner",
        lambda owner_user_id: {"id": ORG_ID, "owner_user_id": owner_user_id, "name": "PYME Demo"},
    )

    # ---- dashboard_repo ----
    def get_credential(cid, org_id):
        row = w.credentials.get(cid)
        return deepcopy(row) if row and row["org_id"] == org_id else None

    def get_member(mid, org_id):
        row = w.members.get(mid)
        return dict(row) if row and row["org_id"] == org_id else None

    def list_credentials(org_id, *, assigned=None):
        w.list_args.append(assigned)
        rows = [r for r in w.credentials.values() if r["org_id"] == org_id]
        if assigned is False:
            rows = [r for r in rows if r["member_id"] is None]
        return deepcopy(rows)

    def create_external_credential(*, org_id, member_id, service_name, username):
        row = _credential(
            id="cred-new-1", org_id=org_id, member_id=member_id,
            service_name=service_name, username=username,
        )
        w.credentials[row["id"]] = row
        return deepcopy(row)

    def reassign_credential(cid, org_id, member_id):
        w.reassigned.append((cid, member_id))
        w.credentials[cid]["member_id"] = member_id

    def mark_secret_saved(cid, org_id, *, username=None):
        w.credentials[cid]["secret_updated_at"] = NOW
        w.credentials[cid]["rotation_required"] = False
        if username is not None:
            w.credentials[cid]["username"] = username
        w.events.append("marca-guardado")

    def delete_credential(cid, org_id):
        w.deleted.append(cid)
        w.credentials.pop(cid, None)

    def list_member_credentials(member_id, org_id):
        return deepcopy([r for r in w.credentials.values() if r["member_id"] == member_id])

    def set_rotation_required(ids, org_id):
        w.rotation_marked.append(list(ids))
        for cid in ids:
            w.credentials[cid]["rotation_required"] = True

    monkeypatch.setattr(dashboard_repo, "get_credential", get_credential)
    monkeypatch.setattr(dashboard_repo, "get_member", get_member)
    monkeypatch.setattr(dashboard_repo, "list_credentials", list_credentials)
    monkeypatch.setattr(dashboard_repo, "create_external_credential", create_external_credential)
    monkeypatch.setattr(dashboard_repo, "reassign_credential", reassign_credential)
    monkeypatch.setattr(dashboard_repo, "mark_secret_saved", mark_secret_saved)
    monkeypatch.setattr(dashboard_repo, "delete_credential", delete_credential)
    monkeypatch.setattr(dashboard_repo, "list_member_credentials", list_member_credentials)
    monkeypatch.setattr(dashboard_repo, "set_rotation_required", set_rotation_required)
    monkeypatch.setattr(dashboard_repo, "update_credential_status",
                        lambda cid, status: w.credentials[cid].update(status=status))
    monkeypatch.setattr(dashboard_repo, "insert_audit_log", lambda **kw: w.audit.append(kw))

    # ---- sobres ----
    def upsert_secret(*, credential_id, org_id, envelope):
        if w.fail_upsert:
            raise RuntimeError("la base se cayó")
        w.events.append("guarda-sobre")
        w.secrets[credential_id] = {**envelope, "credential_id": credential_id, "org_id": org_id}

    monkeypatch.setattr(dashboard.credential_secret_repo, "upsert_secret", upsert_secret)
    monkeypatch.setattr(dashboard.credential_secret_repo, "get_envelope",
                        lambda cid, org_id: deepcopy(w.secrets.get(cid)))

    # ---- cifrado: el sobre falso NUNCA contiene el plaintext ----
    def seal_secret(*, subject_id, password, notes=None):
        w.events.append("cifra")
        w.sealed.append({"subject_id": subject_id, "password": password, "notes": notes})
        return dict(FAKE_ENVELOPE)

    monkeypatch.setattr(secret_access, "seal_secret", seal_secret)
    monkeypatch.setattr(secret_access.vault_crypto, "is_available", lambda: w.kek_available)

    def decrypt_secret(row, aad):
        w.decrypt_aad.append(aad)
        return dict(w.plaintext)

    monkeypatch.setattr(secret_access.vault_crypto, "decrypt_secret", decrypt_secret)

    # ---- vault + Auth ----
    monkeypatch.setattr(dashboard.vault_repo, "insert_audit", lambda **kw: w.vault_audit.append(kw))
    w.admin = MagicMock()
    monkeypatch.setattr(dashboard, "get_supabase_admin", lambda: w.admin)
    return w


def _put_secret(client, cid, **body):
    return client.put(f"/api/v1/dashboard/credentials/{cid}/secret", json=body)


# =========================================================================== registrar


@pytest.mark.asyncio
async def test_registrar_una_cuenta_externa_sin_contrasena(client, world):
    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/credentials",
            json={"service_name": "Dropbox", "username": "ops@pyme.cl"},
        )

    assert response.status_code == 201
    body = response.json()
    assert body["type"] == "externa"
    assert body["has_secret"] is False
    assert world.sealed == []
    assert world.audit == [
        {
            "org_id": ORG_ID,
            "actor_user_id": ADMIN_ID,
            "actor_email": ADMIN_EMAIL,
            "member_id": None,
            "credential_id": "cred-new-1",
            "credential_type": "externa",
            "action": "crear_credencial_externa",
        }
    ]


@pytest.mark.asyncio
async def test_registrar_con_contrasena_la_guarda_cifrada_con_la_organizacion(client, world):
    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/credentials",
            json={"member_id": "member-1", "service_name": "Google Ads",
                  "password": "Ads#Secreta1", "notes": "cuenta compartida"},
        )

    assert response.status_code == 201
    assert response.json()["has_secret"] is True
    # El dueño del dato es la organización, no el integrante ni quien la registra.
    assert world.sealed == [
        {"subject_id": ORG_ID, "password": "Ads#Secreta1", "notes": "cuenta compartida"}
    ]
    assert "Ads#Secreta1" not in response.text
    assert "Ads#Secreta1" not in json.dumps(world.secrets)


@pytest.mark.asyncio
async def test_registrar_con_contrasena_sin_clave_maestra_es_503_y_no_toca_la_base(
    client, world, monkeypatch
):
    world.kek_available = False
    created = MagicMock()
    monkeypatch.setattr(dashboard_repo, "create_external_credential", created)

    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/credentials",
            json={"service_name": "Dropbox", "password": "Ops#Secreta1"},
        )

    assert response.status_code == 503
    created.assert_not_called()


@pytest.mark.asyncio
async def test_registrar_con_un_integrante_de_otra_organizacion_es_404(client, world):
    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/credentials",
            json={"member_id": "member-ajeno", "service_name": "Dropbox"},
        )
    assert response.status_code == 404
    assert "cred-new-1" not in world.credentials


@pytest.mark.asyncio
async def test_si_no_se_puede_guardar_el_secreto_se_borra_la_credencial(client, world):
    """Una credencial que el usuario cree guardada con su contraseña y no lo está es peor
    que no tenerla: se compensa en vez de dejar una fila a medias que parece completa."""
    world.fail_upsert = True

    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/credentials",
            json={"service_name": "Dropbox", "password": "Ops#Secreta1"},
        )

    assert response.status_code == 502
    assert world.deleted == ["cred-new-1"]
    assert "cred-new-1" not in world.credentials
    assert world.audit == []


# =========================================================================== listar


@pytest.mark.asyncio
async def test_listar_pasa_el_filtro_de_asignacion_al_repositorio(client, world):
    async with client as ac:
        await ac.get("/api/v1/dashboard/credentials?assigned=false")
        await ac.get("/api/v1/dashboard/credentials?assigned=true")
        await ac.get("/api/v1/dashboard/credentials")
    assert world.list_args == [False, True, None]


# =========================================================================== reasignar


@pytest.mark.asyncio
async def test_reasignar_una_externa_al_reemplazo(client, world):
    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/credentials/cred-ext-1/reassign", json={"member_id": "member-2"}
        )

    assert response.status_code == 200
    body = response.json()
    assert body["credential"]["member_id"] == "member-2"
    assert world.reassigned == [("cred-ext-1", "member-2")]
    # member_id es de quién sale y target_member_id a quién pasa.
    assert world.audit == [
        {
            "org_id": ORG_ID,
            "actor_user_id": ADMIN_ID,
            "actor_email": ADMIN_EMAIL,
            "member_id": "member-1",
            "target_member_id": "member-2",
            "credential_id": "cred-ext-1",
            "credential_type": "externa",
            "action": "reasignar_credencial",
        }
    ]
    # No se re-cifra nada: el secreto es de la organización, que no cambia.
    assert world.sealed == []


@pytest.mark.asyncio
async def test_reasignar_sugiere_rotar_la_que_cambia_de_manos(client, world):
    """Quien la tenía ya conoce su contraseña: la que hay que rotar es LA MISMA credencial,
    no las otras del integrante anterior."""
    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/credentials/cred-ext-1/reassign", json={"member_id": "member-2"}
        )

    assert world.rotation_marked == [["cred-ext-1"]]
    assert response.json()["rotation_suggested"] == [
        {
            "credential_id": "cred-ext-1",
            "service_name": "Google Workspace",
            "type": "externa",
            "member_name": "Bruno Díaz",
        }
    ]


@pytest.mark.asyncio
async def test_reasignar_una_cuenta_interna_es_400(client, world):
    """Una interna es una cuenta de Supabase Auth atada a una persona: pasársela al
    reemplazo sería darle la identidad del anterior."""
    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/credentials/cred-int-1/reassign", json={"member_id": "member-2"}
        )
    assert response.status_code == 400
    assert world.reassigned == []


@pytest.mark.asyncio
async def test_reasignar_devuelve_la_credencial_al_pool(client, world):
    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/credentials/cred-ext-1/reassign", json={"member_id": None}
        )
    assert response.status_code == 200
    assert response.json()["credential"]["member_id"] is None
    assert world.audit[0]["target_member_id"] is None


@pytest.mark.parametrize(
    "credential_id, body, expected",
    [
        ("cred-ajena", {"member_id": "member-2"}, 404),          # credencial que no es de la org
        ("cred-ext-1", {"member_id": "member-ajeno"}, 404),      # destino de otra organización
        ("cred-ext-1", {"member_id": "member-1"}, 400),          # ya es el portador
    ],
)
@pytest.mark.asyncio
async def test_reasignar_rechaza_lo_que_no_corresponde(client, world, credential_id, body, expected):
    world.credentials["cred-ajena"] = _credential(id="cred-ajena", org_id=OTHER_ORG_ID)

    async with client as ac:
        response = await ac.post(f"/api/v1/dashboard/credentials/{credential_id}/reassign", json=body)

    assert response.status_code == expected
    assert world.reassigned == []


# =========================================================================== guardar


@pytest.mark.asyncio
async def test_guardar_el_secreto_de_una_externa(client, world):
    async with client as ac:
        response = await _put_secret(
            ac, "cred-ext-1", password="Nueva#Clave2", username="nuevo@pyme.cl", notes="rotada"
        )

    assert response.status_code == 200
    body = response.json()
    assert body["secret_stored"] is True
    assert body["credential"]["has_secret"] is True
    assert body["credential"]["username"] == "nuevo@pyme.cl"
    # NUNCA devuelve el plaintext: el cliente ya lo tiene, y verlo de nuevo es el reveal.
    assert "Nueva#Clave2" not in response.text
    assert world.sealed == [{"subject_id": ORG_ID, "password": "Nueva#Clave2", "notes": "rotada"}]
    assert world.audit == [
        {
            "org_id": ORG_ID,
            "actor_user_id": ADMIN_ID,
            "actor_email": ADMIN_EMAIL,
            "member_id": "member-1",
            "credential_id": "cred-ext-1",
            "credential_type": "externa",
            "action": "guardar_secreto",
        }
    ]
    world.admin.auth.admin.update_user_by_id.assert_not_called()


@pytest.mark.asyncio
async def test_aplicar_a_la_cuenta_solo_vale_para_internas(client, world):
    async with client as ac:
        response = await _put_secret(ac, "cred-ext-1", password="Nueva#Clave2", apply_to_account=True)

    assert response.status_code == 400
    assert world.sealed == []
    world.admin.auth.admin.update_user_by_id.assert_not_called()


@pytest.mark.asyncio
async def test_aplicar_a_una_interna_va_primero_a_auth_y_despues_al_sobre(client, world):
    """Lo guardado tiene que ser la contraseña VIGENTE, no una anotación que no coincide con
    la cuenta: por eso Auth va antes que el sobre."""
    world.admin.auth.admin.update_user_by_id.side_effect = lambda *a, **k: world.events.append("auth")

    async with client as ac:
        response = await _put_secret(ac, "cred-int-1", password="Nueva#Clave2", apply_to_account=True)

    assert response.status_code == 200
    assert world.events[:2] == ["auth", "cifra"]
    world.admin.auth.admin.update_user_by_id.assert_called_once_with(
        WORKER_USER_ID, {"password": "Nueva#Clave2"}
    )


@pytest.mark.asyncio
async def test_si_auth_falla_no_se_guarda_nada(client, world):
    world.admin.auth.admin.update_user_by_id.side_effect = RuntimeError("Auth caído")

    async with client as ac:
        response = await _put_secret(ac, "cred-int-1", password="Nueva#Clave2", apply_to_account=True)

    assert response.status_code == 502
    assert world.sealed == []
    assert world.secrets == {}


@pytest.mark.asyncio
async def test_si_el_sobre_falla_despues_de_aplicar_lo_dice_con_todas_las_letras(client, world):
    """El caso peligroso: la cuenta ya cambió de contraseña y el sobre no se guardó. El
    cliente todavía tiene el plaintext y hay que decírselo, no dejarlo creer que se guardó."""
    world.fail_upsert = True

    async with client as ac:
        response = await _put_secret(ac, "cred-int-1", password="Nueva#Clave2", apply_to_account=True)

    assert response.status_code == 502
    assert "se aplicó a la cuenta" in response.json()["detail"]
    assert [a["action"] for a in world.audit] == ["guardar_secreto_fallido"]
    assert "Nueva#Clave2" not in json.dumps(world.audit)


@pytest.mark.asyncio
async def test_guardar_sin_clave_maestra_es_503_antes_de_tocar_la_base(client, world, monkeypatch):
    world.kek_available = False
    get_credential = MagicMock()
    monkeypatch.setattr(dashboard_repo, "get_credential", get_credential)

    async with client as ac:
        response = await _put_secret(ac, "cred-ext-1", password="Nueva#Clave2")

    assert response.status_code == 503
    get_credential.assert_not_called()


@pytest.mark.asyncio
async def test_guardar_el_secreto_de_una_credencial_ajena_es_404(client, world):
    world.credentials["cred-ajena"] = _credential(id="cred-ajena", org_id=OTHER_ORG_ID)
    async with client as ac:
        response = await _put_secret(ac, "cred-ajena", password="Nueva#Clave2")
    assert response.status_code == 404
    assert world.sealed == []


# =========================================================================== revelar


def _store(world, cid="cred-ext-1"):
    world.secrets[cid] = {**FAKE_ENVELOPE, "credential_id": cid, "org_id": ORG_ID}
    world.credentials[cid]["secret_updated_at"] = NOW


@pytest.mark.asyncio
async def test_revelar_devuelve_la_contrasena_y_audita_sin_ella(client, world):
    _store(world)

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/credentials/cred-ext-1/secret/reveal")

    assert response.status_code == 200
    body = response.json()
    assert body["password"] == "Clave-Real#1"
    assert body["notes"] == "nota interna"
    assert body["service_name"] == "Google Workspace"
    assert world.audit == [
        {
            "org_id": ORG_ID,
            "actor_user_id": ADMIN_ID,
            "actor_email": ADMIN_EMAIL,
            "member_id": "member-1",
            "credential_id": "cred-ext-1",
            "credential_type": "externa",
            "action": "consultar_secreto",
        }
    ]
    for entry in world.audit:
        assert "Clave-Real#1" not in json.dumps(entry)


@pytest.mark.asyncio
async def test_el_aad_es_la_organizacion_leida_de_la_fila_del_sobre_no_del_caller(client, world):
    """El AAD dice de quién es el dato, no quién lo pide: la organización, tomada de la
    misma fila que guarda el criptograma. Por eso reasignar o borrar al integrante no
    puede dejar el secreto irrecuperable."""
    _store(world)

    async with client as ac:
        await ac.post("/api/v1/dashboard/credentials/cred-ext-1/secret/reveal")

    assert world.decrypt_aad == [ORG_ID]
    assert ADMIN_ID not in world.decrypt_aad
    assert "member-1" not in world.decrypt_aad


@pytest.mark.asyncio
async def test_revelar_una_externa_no_toca_la_auditoria_del_trabajador(client, world):
    _store(world)
    async with client as ac:
        await ac.post("/api/v1/dashboard/credentials/cred-ext-1/secret/reveal")
    assert world.vault_audit == []


@pytest.mark.asyncio
async def test_revelar_una_interna_deja_rastro_en_la_auditoria_del_trabajador(client, world):
    """Mitigación compensatoria de la suplantación (R-HU21-5): con la contraseña vigente de
    su cuenta la empresa podría entrar como él. Lo mínimo es que él vea que la retiró."""
    _store(world, "cred-int-1")

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/credentials/cred-int-1/secret/reveal")

    assert response.status_code == 200
    assert world.vault_audit == [
        {
            "user_id": WORKER_USER_ID,
            "item_id": None,
            "action": "consultar_credencial_interna_admin",
            "result": "ok",
            "actor_user_id": ADMIN_ID,
        }
    ]


@pytest.mark.asyncio
async def test_revelar_sin_contrasena_guardada_es_404(client, world):
    async with client as ac:
        response = await ac.post("/api/v1/dashboard/credentials/cred-ext-1/secret/reveal")

    assert response.status_code == 404
    assert "no tiene una contraseña guardada" in response.json()["detail"]
    assert world.audit == []


@pytest.mark.asyncio
async def test_revelar_una_credencial_ajena_es_404_y_queda_denegado(client, world):
    world.credentials["cred-ajena"] = _credential(id="cred-ajena", org_id=OTHER_ORG_ID)

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/credentials/cred-ajena/secret/reveal")

    assert response.status_code == 404
    assert [a["action"] for a in world.audit] == ["consultar_secreto_denegado"]
    assert world.decrypt_aad == []


@pytest.mark.asyncio
async def test_revelar_sin_clave_maestra_es_503_y_no_toca_la_base(client, world, monkeypatch):
    _store(world)
    world.kek_available = False
    get_credential = MagicMock()
    monkeypatch.setattr(dashboard_repo, "get_credential", get_credential)

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/credentials/cred-ext-1/secret/reveal")

    assert response.status_code == 503
    get_credential.assert_not_called()


@pytest.mark.asyncio
async def test_un_fallo_de_integridad_responde_503_y_queda_denegado(client, world, monkeypatch):
    _store(world)

    def _explode(row, aad):
        raise vault_crypto.InvalidTag()

    monkeypatch.setattr(secret_access.vault_crypto, "decrypt_secret", _explode)

    async with client as ac:
        response = await ac.post("/api/v1/dashboard/credentials/cred-ext-1/secret/reveal")

    # 503 y no 404: esconder una adulteración es justo lo que el tag GCM existe para evitar.
    assert response.status_code == 503
    assert [a["action"] for a in world.audit] == ["consultar_secreto_denegado"]


@pytest.mark.asyncio
async def test_el_segundo_factor_de_hu18_entra_sin_tocar_la_ruta_de_lectura(client, world, monkeypatch):
    """Se reemplaza _verify_step_up por uno que exige el header, y la ruta, tal cual está,
    pasa a rechazar sin descifrar y a dejar la entrada de denegado. HU18 = un solo cambio."""
    _store(world)

    def _exige_totp(caller, scope, code):
        if code != "123456":
            raise secret_access.StepUpRequired()

    monkeypatch.setattr(secret_access, "_verify_step_up", _exige_totp)

    async with client as ac:
        sin_factor = await ac.post("/api/v1/dashboard/credentials/cred-ext-1/secret/reveal")
        con_factor = await ac.post(
            "/api/v1/dashboard/credentials/cred-ext-1/secret/reveal",
            headers={"X-SparkGate-TOTP": "123456"},
        )

    assert sin_factor.status_code == 403
    assert con_factor.status_code == 200
    assert [a["action"] for a in world.audit] == ["consultar_secreto_denegado", "consultar_secreto"]
    assert len(world.decrypt_aad) == 1  # solo se descifró con el factor


# =========================================================================== rotación


@pytest.mark.asyncio
async def test_bloquear_a_alguien_sugiere_rotar_sus_otras_credenciales_activas(client, world):
    """Bloquear a alguien no cambia las contraseñas que ya conocía. Se sugiere rotar sus
    otras credenciales todavía activas; no la interna que se acaba de revocar (ya se rotó)
    ni una que no sea una cuenta viva."""
    world.credentials["cred-ext-2"] = _credential(id="cred-ext-2", service_name="Dropbox")
    world.credentials["cred-ext-revocada"] = _credential(
        id="cred-ext-revocada", service_name="Vieja", status="revocada"
    )

    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/credentials/cred-int-1/revoke", json={"new_password": "Nueva#Clave99"}
        )

    assert response.status_code == 200
    suggested = {s["credential_id"] for s in response.json()["rotation_suggested"]}
    assert suggested == {"cred-ext-1", "cred-ext-2"}
    assert sorted(world.rotation_marked[0]) == ["cred-ext-1", "cred-ext-2"]
    assert all(s["member_name"] == "Bruno Díaz" for s in response.json()["rotation_suggested"])


@pytest.mark.asyncio
async def test_guardar_una_contrasena_nueva_es_rotar_y_apaga_la_bandera(client, world):
    """La bandera solo se apaga rotando de verdad. Deliberadamente no hay un 'descartar':
    descartarla sin rotar es exactamente la conducta que la función existe para evitar."""
    world.credentials["cred-ext-1"]["rotation_required"] = True

    async with client as ac:
        response = await _put_secret(ac, "cred-ext-1", password="Nueva#Clave2")

    assert response.json()["credential"]["rotation_required"] is False


def test_mark_secret_saved_apaga_rotation_required(monkeypatch):
    """El repositorio REAL (no el mundo en memoria): guardar una contraseña es lo único que
    apaga la bandera, y eso se decide en esta función."""
    admin = MagicMock()
    monkeypatch.setattr(dashboard_repo, "get_supabase_admin", lambda: admin)

    dashboard_repo.mark_secret_saved("cred-1", "org-1")

    written = admin.table.return_value.update.call_args[0][0]
    assert written["rotation_required"] is False
    assert written["secret_updated_at"]


# =========================================================================== la piedra angular


@pytest.mark.asyncio
async def test_ninguna_contrasena_llega_a_ningun_payload_de_auditoria_por_ningun_camino(
    client, world
):
    """Es LO ÚNICO que sostiene AC4 ahora que las contraseñas SÍ se persisten (cifradas):
    ningún payload de ninguno de los dos logs lleva una contraseña, por ningún camino. Se
    recorren todos los que producen o leen una."""
    secretos = {
        "Registro#Uno1", "Guardar#Dos22", "Revocada#Tres3", "Sugerida#Cuatro4",
        world.plaintext["password"], world.plaintext["notes"],
    }
    world.credentials["cred-ext-2"] = _credential(id="cred-ext-2", service_name="Dropbox")

    async with client as ac:
        await ac.post("/api/v1/dashboard/credentials",
                      json={"service_name": "Ads", "password": "Registro#Uno1"})
        await _put_secret(ac, "cred-ext-1", password="Guardar#Dos22", notes="nota-guardar")
        _store(world)
        await ac.post("/api/v1/dashboard/credentials/cred-ext-1/secret/reveal")
        await ac.post("/api/v1/dashboard/credentials/cred-ext-1/reassign", json={"member_id": "member-2"})
        await ac.post("/api/v1/dashboard/credentials/cred-int-1/revoke",
                      json={"new_password": "Revocada#Tres3"})
        _store(world, "cred-int-1")
        await ac.post("/api/v1/dashboard/credentials/cred-int-1/secret/reveal")
        await ac.post("/api/v1/dashboard/credentials/cred-ext-2/suggest",
                      json={"new_password": "Sugerida#Cuatro4"})

    assert world.audit and world.vault_audit  # recorrió los dos logs
    serialized = json.dumps({"panel": world.audit, "vault": world.vault_audit})
    for secreto in secretos | {"nota-guardar"}:
        assert secreto not in serialized, f"'{secreto}' llegó a un payload de auditoría"

    forbidden_keys = {"password", "new_password", "notes", "ciphertext", "wrapped_dek", "secret"}
    for entry in world.audit + world.vault_audit:
        assert forbidden_keys.isdisjoint(entry), f"clave prohibida en {entry}"

    # Y tampoco en lo persistido: lo que llega a la tabla es un sobre, nunca texto.
    assert not any(secreto in json.dumps(world.secrets) for secreto in secretos)


@pytest.mark.asyncio
async def test_ni_el_secreto_del_factor_ni_un_codigo_llegan_a_ningun_payload_de_auditoria(
    client, world, monkeypatch
):
    """La piedra angular, con el segundo factor. El recorrido de arriba corre con el verificador
    anulado, así que no puede producir un solo denegado. Este recorre, con la cadena REAL, el
    enrolamiento, las tres lecturas/escrituras DENEGADAS (sin código y con código malo) y las
    tres EXITOSAS, y exige que en ninguno de los dos logs aparezca: una contraseña, el secreto
    TOTP, el URI otpauth://, ni un solo código de seis dígitos que se haya mandado."""
    env = totp_env(monkeypatch)
    world.credentials["cred-ext-2"] = _credential(id="cred-ext-2", service_name="Dropbox")
    contrasenas = {"Guardar#Dos22", "Revocada#Tres3", "Sugerida#Cuatro4", "nota-guardar",
                   world.plaintext["password"], world.plaintext["notes"]}
    codigos: list[str] = []

    async def con_codigo(ac, method, url, factor, **kw):
        code = factor.code()
        codigos.append(code)
        response = await ac.request(method, url, headers={TOTP: code}, **kw)
        factor.tick()
        return response

    async def con_codigo_malo(ac, method, url, factor, **kw):
        wrong = factor.wrong_code()
        codigos.append(wrong)
        return await ac.request(method, url, headers={TOTP: wrong}, **kw)

    async with client as ac:
        enrol = (await ac.post("/api/v1/me/mfa/enroll")).json()
        factor = Factor(env, enrol["secret"])
        assert (await con_codigo(ac, "POST", "/api/v1/me/mfa/confirm", factor)).status_code == 200

        put = "/api/v1/dashboard/credentials/cred-ext-1/secret"
        put_body = {"password": "Guardar#Dos22", "notes": "nota-guardar"}
        await ac.put(put, json=put_body)                                   # sin código
        await con_codigo_malo(ac, "PUT", put, factor, json=put_body)       # código malo
        assert (await con_codigo(ac, "PUT", put, factor, json=put_body)).status_code == 200

        reveal = "/api/v1/dashboard/credentials/cred-ext-1/secret/reveal"
        _store(world)
        await ac.post(reveal)
        assert (await con_codigo(ac, "POST", reveal, factor)).status_code == 200

        revoke = "/api/v1/dashboard/credentials/cred-int-1/revoke"
        await ac.post(revoke, json={"new_password": "Revocada#Tres3"})
        await con_codigo_malo(ac, "POST", revoke, factor, json={"new_password": "Revocada#Tres3"})
        assert (await con_codigo(ac, "POST", revoke, factor, json={"new_password": "Revocada#Tres3"})).status_code == 200

        suggest = "/api/v1/dashboard/credentials/cred-ext-2/suggest"
        await ac.post(suggest, json={"new_password": "Sugerida#Cuatro4"})
        assert (await con_codigo(ac, "POST", suggest, factor, json={"new_password": "Sugerida#Cuatro4"})).status_code == 200

        assert (await con_codigo(ac, "DELETE", "/api/v1/me/mfa", factor)).status_code == 204

    acciones = {a["action"] for a in world.audit}
    assert {"guardar_secreto_denegado", "consultar_secreto_denegado", "revocar_interna_denegado",
            "sugerir_externa_denegado", "guardar_secreto", "consultar_secreto", "revocar_interna",
            "sugerir_externa"} <= acciones, "el recorrido no llegó a todos los caminos"
    assert {"mfa_enrolar", "mfa_activar", "mfa_desactivar"} <= {a["action"] for a in world.vault_audit}

    serializado = json.dumps({"panel": world.audit, "vault": world.vault_audit}, default=str)
    prohibidos = contrasenas | {enrol["secret"], enrol["otpauth_uri"]} | set(codigos)
    for valor in prohibidos:
        assert valor not in serializado, f"'{valor[:6]}…' llegó a un payload de auditoría"

    claves_prohibidas = {"password", "new_password", "notes", "ciphertext", "wrapped_dek", "secret",
                         "totp_secret", "secret_envelope", "otpauth_uri", "code"}
    for entrada in world.audit + world.vault_audit:
        assert claves_prohibidas.isdisjoint(entrada), f"clave prohibida en {entrada}"

    # El motivo de una denegación es SIEMPRE un enum: nunca algo que pueda ser un código.
    motivos = {a["denied_reason"] for a in world.audit if a.get("denied_reason")}
    assert motivos <= {"totp_no_enrolado", "totp_invalido", "totp_reutilizado", "totp_bloqueado"}
    assert not any(re.fullmatch(r"\d{6}", m) for m in motivos)

    # Y lo persistido del factor es un sobre: el secreto no está en claro ni en la fila ni
    # en lo que recibió el repositorio.
    assert enrol["secret"] not in json.dumps(env.repo.envelopes_sealed)


# =========================================================================== segundo factor real (HU18)

TOTP = "X-SparkGate-TOTP"


@pytest.mark.asyncio
async def test_revelar_una_credencial_exige_el_segundo_factor_de_verdad(client, world, monkeypatch):
    """Cableado con la cadena REAL: ruta -> _verify_step_up -> totp_service -> repo en memoria.

    Cubre AC4 en la lectura: un código inválido o ausente deniega, NO descifra, y deja la
    entrada de denegado con el MOTIVO. El factor en sí lo prueba test_totp_service."""
    _store(world)
    env = totp_env(monkeypatch)
    url = "/api/v1/dashboard/credentials/cred-ext-1/secret/reveal"

    async with client as ac:
        no_enrolado = await ac.post(url)                         # el admin nunca se enroló
        factor = enroll_real_factor(env, ADMIN_ID)
        sin_codigo = await ac.post(url)                          # enrolado, sin header
        malo = await ac.post(url, headers={TOTP: "000000" if factor.code() != "000000" else "000001"})
        code = factor.code()
        bueno = await ac.post(url, headers={TOTP: code})
        repetido = await ac.post(url, headers={TOTP: code})      # anti-replay

    assert [r.status_code for r in (no_enrolado, sin_codigo, malo, bueno, repetido)] == [403, 403, 403, 200, 403]
    assert [r.json().get("code") for r in (no_enrolado, sin_codigo, malo, repetido)] == [
        "totp_no_enrolado", "totp_invalido", "totp_invalido", "totp_reutilizado",
    ]
    # Solo el intento válido descifró, y solo ahí sale el plaintext.
    assert len(world.decrypt_aad) == 1
    secret = world.plaintext["password"]
    assert secret in bueno.text
    assert all(secret not in r.text for r in (no_enrolado, sin_codigo, malo, repetido))
    # AC4: cada intento fallido quedó auditado, con su motivo, y hay una sola lectura exitosa.
    assert [(a["action"], a.get("denied_reason")) for a in world.audit] == [
        ("consultar_secreto_denegado", "totp_no_enrolado"),
        ("consultar_secreto_denegado", "totp_invalido"),
        ("consultar_secreto_denegado", "totp_invalido"),
        ("consultar_secreto", None),
        ("consultar_secreto_denegado", "totp_reutilizado"),
    ]


# --------------------------------------------------------------------------- escrituras (AC2/AC3/AC4)

REVOKE = "/api/v1/dashboard/credentials/cred-int-1/revoke"
SUGGEST = "/api/v1/dashboard/credentials/cred-ext-1/suggest"
SECRET_INT = "/api/v1/dashboard/credentials/cred-int-1/secret"
SECRET_EXT = "/api/v1/dashboard/credentials/cred-ext-1/secret"


def _denegados(world):
    return [(a["action"], a.get("denied_reason")) for a in world.audit]


def _sin_efectos(world, *, cid):
    """Nada se ejecutó: ni Auth, ni sobre, ni estado, ni sugerencias de rotación."""
    world.admin.auth.admin.update_user_by_id.assert_not_called()
    assert world.sealed == [] and world.secrets == {} and world.rotation_marked == []
    assert world.credentials[cid]["status"] == "activa"
    assert world.credentials[cid]["secret_updated_at"] is None


@pytest.mark.asyncio
async def test_revocar_exige_el_segundo_factor_y_un_rechazo_no_toca_nada(client, world, monkeypatch):
    """AC2 + AC4 con la cadena REAL. Un código ausente o inválido deniega, no toca Auth ni la
    base, y deja la entrada de denegado con el motivo. Con un código vigente rota la contraseña
    y banea (revoca sesiones y refresh tokens) en UNA llamada a la Admin API."""
    env = totp_env(monkeypatch)
    factor = enroll_real_factor(env, ADMIN_ID)

    async with client as ac:
        sin_codigo = await ac.post(REVOKE, json={})
        malo = await ac.post(REVOKE, json={}, headers={TOTP: factor.wrong_code()})
        assert (sin_codigo.status_code, malo.status_code) == (403, 403)
        assert sin_codigo.json()["code"] == malo.json()["code"] == "totp_invalido"
        _sin_efectos(world, cid="cred-int-1")

        bueno = await ac.post(REVOKE, json={}, headers={TOTP: factor.code()})

    assert bueno.status_code == 200
    body = bueno.json()
    assert body["admin_api_success"] is True and body["applied_password"]
    world.admin.auth.admin.update_user_by_id.assert_called_once_with(
        WORKER_USER_ID, {"password": body["applied_password"], "ban_duration": "87600h"}
    )
    assert world.credentials["cred-int-1"]["status"] == "revocada"
    assert _denegados(world) == [
        ("revocar_interna_denegado", "totp_invalido"),
        ("revocar_interna_denegado", "totp_invalido"),
        ("revocar_interna", None),
    ]
    assert world.audit[0]["credential_id"] == "cred-int-1" and world.audit[0]["credential_type"] == "interna"


@pytest.mark.asyncio
async def test_revocar_sin_haber_enrolado_lleva_a_enrolarse(client, world, monkeypatch):
    totp_env(monkeypatch)  # nadie enrolado
    async with client as ac:
        response = await ac.post(REVOKE, json={}, headers={TOTP: "123456"})

    assert response.status_code == 403 and response.json()["code"] == "totp_no_enrolado"
    _sin_efectos(world, cid="cred-int-1")
    assert _denegados(world) == [("revocar_interna_denegado", "totp_no_enrolado")]


@pytest.mark.asyncio
async def test_revocar_con_la_kek_caida_sigue_funcionando_con_el_segundo_factor(client, world, monkeypatch):
    """La razón de tener DOS claves. Revocar a quien se va no puede depender de la KEK de la
    bóveda, y ahora exige un factor sellado con otra clave. Con la KEK caída: verifica el
    TOTP, banea y rota; solo secret_stored=false, y la respuesta es la única copia."""
    env = totp_env(monkeypatch)
    factor = enroll_real_factor(env, ADMIN_ID)
    world.kek_available = False

    def seal_sin_kek(*, subject_id, password, notes=None):
        # Lo que hace el seal_secret REAL sin clave maestra (el del World no lo modela).
        raise RuntimeError("seal_secret sin KEK")

    monkeypatch.setattr(secret_access, "seal_secret", seal_sin_kek)

    async with client as ac:
        response = await ac.post(REVOKE, json={}, headers={TOTP: factor.code()})

    body = response.json()
    assert response.status_code == 200
    assert body["admin_api_success"] is True and body["applied_password"]
    assert body["secret_stored"] is False
    assert world.credentials["cred-int-1"]["status"] == "revocada"


@pytest.mark.asyncio
async def test_sin_la_clave_del_factor_revocar_falla_cerrado_y_no_hace_nada(client, world, monkeypatch):
    """No poder verificar el segundo factor NO es «código inválido» y NUNCA deja pasar."""
    env = totp_env(monkeypatch)
    factor = enroll_real_factor(env, ADMIN_ID)
    monkeypatch.setattr(settings, "totp_master_key", "")

    async with client as ac:
        response = await ac.post(REVOKE, json={}, headers={TOTP: factor.code()})

    assert response.status_code == 503
    _sin_efectos(world, cid="cred-int-1")
    assert world.audit == []  # no es una denegación del usuario


@pytest.mark.asyncio
async def test_sugerir_exige_el_segundo_factor_y_deja_la_externa_pendiente_sin_afirmar_el_cambio(
    client, world, monkeypatch
):
    """AC3 + AC4. Denegado: la externa sigue `activa` y no se generó nada. Con código: queda
    `pendiente_aplicacion_manual`, se devuelve una contraseña sugerida, y NO se llama a Auth
    (SparkGate no controla el proveedor: el cambio no se declara efectuado)."""
    env = totp_env(monkeypatch)
    factor = enroll_real_factor(env, ADMIN_ID)

    async with client as ac:
        denegado = await ac.post(SUGGEST, json={}, headers={TOTP: factor.wrong_code()})
        assert denegado.status_code == 403
        _sin_efectos(world, cid="cred-ext-1")
        bueno = await ac.post(SUGGEST, json={}, headers={TOTP: factor.code()})

    assert bueno.status_code == 200
    body = bueno.json()
    assert body["suggested_password"]
    assert body["applied_password"] is None  # no se declara aplicado
    assert body["credential"]["status"] == "pendiente_aplicacion_manual"
    world.admin.auth.admin.update_user_by_id.assert_not_called()
    assert _denegados(world) == [("sugerir_externa_denegado", "totp_invalido"), ("sugerir_externa", None)]
    assert world.audit[0]["credential_type"] == "externa"


@pytest.mark.asyncio
async def test_guardar_una_contrasena_exige_el_segundo_factor_antes_de_tocar_auth(client, world, monkeypatch):
    """PUT /secret con apply_to_account cambia la contraseña de una cuenta REAL. Un rechazo
    tiene que dejar Auth intacto: sin este orden quedaría la cuenta con la contraseña nueva y
    la operación denegada."""
    env = totp_env(monkeypatch)
    factor = enroll_real_factor(env, ADMIN_ID)

    async with client as ac:
        denegado = await _put_secret(ac, "cred-int-1", password="Nueva#Clave77", apply_to_account=True)
        assert denegado.status_code == 403
        _sin_efectos(world, cid="cred-int-1")
        assert _denegados(world) == [("guardar_secreto_denegado", "totp_invalido")]

        bueno = await ac.put(
            SECRET_INT, json={"password": "Nueva#Clave77", "apply_to_account": True},
            headers={TOTP: factor.code()},
        )

    assert bueno.status_code == 200
    world.admin.auth.admin.update_user_by_id.assert_called_once_with(
        WORKER_USER_ID, {"password": "Nueva#Clave77"}
    )
    assert world.sealed[0]["password"] == "Nueva#Clave77"


@pytest.mark.asyncio
async def test_guardar_sin_aplicar_a_la_cuenta_tambien_exige_el_segundo_factor(client, world, monkeypatch):
    """Guardar una contraseña nueva ES rotar (es lo único que apaga rotation_required), así
    que no basta con gatear el caso de la cuenta interna."""
    env = totp_env(monkeypatch)
    enroll_real_factor(env, ADMIN_ID)

    async with client as ac:
        response = await _put_secret(ac, "cred-ext-1", password="Nueva#Clave88")

    assert response.status_code == 403
    _sin_efectos(world, cid="cred-ext-1")
    assert _denegados(world) == [("guardar_secreto_denegado", "totp_invalido")]


@pytest.mark.asyncio
async def test_las_guardas_responden_antes_de_pedir_el_segundo_factor(client, world, monkeypatch):
    """Un 400/404 no consume un código TOTP (uno cada 30 s) ni deja un denegado en la
    auditoría: la petición igual iba a fallar. Nadie está enrolado, así que cualquier llamada
    que llegara al factor daría 403."""
    totp_env(monkeypatch)
    world.credentials["cred-int-2"] = _credential(
        id="cred-int-2", type="interna", supabase_user_id="w2", status="revocada"
    )

    async with client as ac:
        respuestas = {
            "revocar una externa": await ac.post("/api/v1/dashboard/credentials/cred-ext-1/revoke", json={}),
            "revocar una ya revocada": await ac.post("/api/v1/dashboard/credentials/cred-int-2/revoke", json={}),
            "revocar una inexistente": await ac.post("/api/v1/dashboard/credentials/nada/revoke", json={}),
            "sugerir una interna": await ac.post("/api/v1/dashboard/credentials/cred-int-1/suggest", json={}),
            "aplicar a una externa": await _put_secret(
                ac, "cred-ext-1", password="Nueva#Clave99", apply_to_account=True
            ),
            "guardar en una inexistente": await _put_secret(ac, "nada", password="Nueva#Clave99"),
        }

    assert {k: r.status_code for k, r in respuestas.items()} == {
        "revocar una externa": 400, "revocar una ya revocada": 400, "revocar una inexistente": 404,
        "sugerir una interna": 400, "aplicar a una externa": 400, "guardar en una inexistente": 404,
    }
    assert world.audit == []


# --------------------------------------------------------------------------- «vía /passwords/generate»


def test_la_rotacion_y_el_endpoint_de_generar_comparten_la_misma_funcion():
    """HU18: «genera una credencial nueva vía /passwords/generate». Es LA MISMA función, no una
    copia paralela; y vive en servicios, no en una ruta que otra ruta importa."""
    assert (
        dashboard.generate_password_core
        is passwords.generate_password_core
        is password_factory.generate_password_core
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("url, credential", [(REVOKE, "cred-int-1"), (SUGGEST, "cred-ext-1")])
async def test_revocar_y_sugerir_generan_con_generate_password_core_en_modo_random(
    client, world, monkeypatch, url, credential
):
    pedidos = []

    async def espia(request):
        pedidos.append(request)
        return PasswordGenerateResponse(
            generated_password="Espia#Generada99aA", explanation="x", entropy_bits=104.0
        )

    monkeypatch.setattr(dashboard, "generate_password_core", espia)

    async with client as ac:
        response = await ac.post(url, json={})

    body = response.json()
    assert response.status_code == 200
    assert (body.get("applied_password") or body.get("suggested_password")) == "Espia#Generada99aA"
    assert len(pedidos) == 1
    assert (pedidos[0].mode, pedidos[0].length) == ("random", 16)
    assert all((pedidos[0].use_upper, pedidos[0].use_lower, pedidos[0].use_digits, pedidos[0].use_symbols))


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [REVOKE, SUGGEST])
async def test_la_rotacion_no_depende_de_que_la_ia_este_arriba(client, world, monkeypatch, url):
    """Revocar a alguien que se va no puede terminar en un 502 porque Ollama esté caído:
    mode='random' es el único camino de generate_password_core que no llama a la IA."""
    async def ia_caida(**kwargs):
        raise RuntimeError("Ollama caído")

    monkeypatch.setattr(ai_engine, "generate_password", ia_caida)

    async with client as ac:
        response = await ac.post(url, json={})

    assert response.status_code == 200
    body = response.json()
    assert len(body.get("applied_password") or body.get("suggested_password")) == 16


@pytest.mark.asyncio
async def test_la_contrasena_que_fija_el_admin_no_pasa_por_el_generador(client, world, monkeypatch):
    llamadas = []

    async def espia(request):
        llamadas.append(request)
        raise AssertionError("no debería generarse nada")

    monkeypatch.setattr(dashboard, "generate_password_core", espia)

    async with client as ac:
        response = await ac.post(REVOKE, json={"new_password": "LaQueFijoElAdmin#1"})

    assert response.status_code == 200 and response.json()["applied_password"] == "LaQueFijoElAdmin#1"
    assert llamadas == []
