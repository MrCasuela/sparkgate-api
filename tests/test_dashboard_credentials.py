"""Credenciales propias de la organización (HU21 etapa C): registrar, guardar y revelar
la contraseña, reasignar al reemplazo, y sugerir rotación.

Un "mundo" en memoria reemplaza los repositorios y el cifrado, para que cada test se
lea como una regla de negocio y no como cableado de mocks. La pieza clave es el último
test: ninguna contraseña llega jamás a ningún payload de auditoría, por ningún camino.
"""

import json
from copy import deepcopy
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.api import dependencies
from app.api.dependencies import verify_token
from app.api.routes import dashboard
from app.main import app
from app.services import dashboard_repo, secret_access, vault_crypto
from tests.totp_fakes import enroll_real_factor, totp_env

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
