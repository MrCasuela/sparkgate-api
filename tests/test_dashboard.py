import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api import dependencies
from app.api.dependencies import verify_token
from app.api.routes import dashboard
from app.services import secret_access

NOW = datetime.now(timezone.utc).isoformat()

ORG_ID = "org-1"
OTHER_ORG_ID = "org-2"

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
def sin_segundo_factor(monkeypatch):
    """Estos tests miden qué hacen revoke/suggest con Auth y la base, no el factor: se anula el
    verificador. Que esas rutas LO EXIGEN de verdad lo miden test_dashboard_credentials.py y
    test_secret_access.py, con la cadena real."""
    monkeypatch.setattr(secret_access, "_verify_step_up", lambda caller, scope, code: None)


@pytest.fixture(autouse=True)
def override_auth():
    # Sobrescribe verify_token (no el guard) para que require_enterprise corra
    # de verdad. El dict viene ya aplanado, como lo devuelve verify_token.
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
    """require_enterprise resuelve la organización contra la tabla en cada
    request; sin este stub los tests pegarían contra Supabase de verdad."""
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
    """revoke, suggest y el alta de trabajador guardan ahora la contraseña cifrada.
    Se reemplazan el cifrado y el repositorio del sobre para que los tests no toquen
    Supabase ni dependan de que haya una clave maestra en el entorno, y se devuelve lo
    que llegó a cada uno para poder asertar sobre ello."""
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
    # Sin otras credenciales que rotar: el caso de rotación tiene sus propios tests.
    monkeypatch.setattr(
        dashboard.dashboard_repo, "list_member_credentials", lambda member_id, org_id: []
    )
    monkeypatch.setattr(
        dashboard.dashboard_repo,
        "get_member",
        lambda member_id, org_id: {"id": member_id, "full_name": "Integrante de prueba"},
    )
    return calls


def credential_lookup_returning(*rows):
    """Returns each row in order on successive calls, regardless of id — simulates
    the handler's own get_credential(before) ... get_credential(after) sequence
    against a row whose status changed in between."""
    queue = list(rows)

    def _get(cid, org_id):
        return queue.pop(0)

    return _get


@pytest.mark.asyncio
async def test_members_endpoint_requires_enterprise(client):
    app.dependency_overrides[verify_token] = lambda: {
        "id": "user-1",
        "email": "user@example.com",
        "type_account": "personal",
        "claimed_org_id": None,
        "user_metadata": {},
    }
    async with client as ac:
        response = await ac.get("/api/v1/dashboard/members")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_enterprise_sin_organizacion_es_rechazado(client, monkeypatch):
    """type_account dice enterprise pero no hay fila en organizations: el guard
    se planta, porque la tabla es la fuente de verdad, no el claim."""
    monkeypatch.setattr(
        dependencies.org_repo, "get_organization_by_owner", lambda owner_user_id: None
    )
    async with client as ac:
        response = await ac.get("/api/v1/dashboard/members")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_org_id_sale_de_la_tabla_no_del_claim(client, monkeypatch):
    """Regresión de R-HU21-3: el claim del token puede estar desactualizado o
    adulterado, así que el filtro de tenencia tiene que usar el org_id de la
    tabla, no el que viene en user_metadata."""
    app.dependency_overrides[verify_token] = lambda: {
        "id": "admin-1",
        "email": "admin@pyme-demo.sparkgate.test",
        "type_account": "enterprise",
        "claimed_org_id": OTHER_ORG_ID,  # claim mentiroso
        "user_metadata": {"type_account": "enterprise", "org_id": OTHER_ORG_ID},
    }
    received = {}

    def _list(org_id):
        received["org_id"] = org_id
        return []

    monkeypatch.setattr(dashboard.dashboard_repo, "list_members_with_credentials", _list)

    async with client as ac:
        response = await ac.get("/api/v1/dashboard/members")

    assert response.status_code == 200
    assert received["org_id"] == ORG_ID


@pytest.mark.asyncio
async def test_credencial_de_otra_organizacion_responde_404(client, monkeypatch):
    """AC3: el repo filtra por org_id, así que una credencial ajena devuelve
    None y el handler responde 404 — nunca 403, que confirmaría que el id
    existe."""
    received = {}

    def _get(cid, org_id):
        received["org_id"] = org_id
        return None

    monkeypatch.setattr(dashboard.dashboard_repo, "get_credential", _get)

    async with client as ac:
        response = await ac.post(
            "/api/v1/dashboard/credentials/cred-de-otra-org/revoke", json={}
        )

    assert response.status_code == 404
    assert received["org_id"] == ORG_ID


@pytest.mark.asyncio
async def test_revoke_rejects_external_credential(client, monkeypatch):
    monkeypatch.setattr(dashboard.dashboard_repo, "get_credential", lambda cid, org_id: ACTIVE_EXTERNAL_CREDENTIAL)
    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{ACTIVE_EXTERNAL_CREDENTIAL['id']}/revoke",
            json={"new_password": NEW_PASSWORD},
        )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_suggest_rejects_internal_credential(client, monkeypatch):
    monkeypatch.setattr(dashboard.dashboard_repo, "get_credential", lambda cid, org_id: ACTIVE_INTERNAL_CREDENTIAL)
    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{ACTIVE_INTERNAL_CREDENTIAL['id']}/suggest",
            json={"new_password": NEW_PASSWORD},
        )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_revoke_rejects_own_admin_account(client, monkeypatch):
    own_credential = dict(ACTIVE_INTERNAL_CREDENTIAL, supabase_user_id="admin-1")
    monkeypatch.setattr(dashboard.dashboard_repo, "get_credential", lambda cid, org_id: own_credential)
    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{own_credential['id']}/revoke",
            json={"new_password": NEW_PASSWORD},
        )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_revoke_rejects_short_password(client, monkeypatch):
    monkeypatch.setattr(dashboard.dashboard_repo, "get_credential", lambda cid, org_id: dict(ACTIVE_INTERNAL_CREDENTIAL))
    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{ACTIVE_INTERNAL_CREDENTIAL['id']}/revoke",
            json={"new_password": "short"},
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_revoke_internal_applies_password_and_bans(client, monkeypatch, secret_storage):
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
    # Igualdad EXACTA, no subset: es lo que hace hermética la garantía de que el
    # payload de auditoría no lleva la contraseña.
    assert audit_calls == [
        {
            "org_id": ORG_ID,
            "actor_user_id": "admin-1",
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
        assert NEW_PASSWORD not in json.dumps(call)

    # La contraseña que Auth aceptó vuelve en la respuesta y se guardó cifrada. El AAD
    # es la ORGANIZACIÓN, no el integrante: por eso reasignar o borrar la cuenta del
    # trabajador no puede destruir un secreto de la empresa.
    assert body["applied_password"] == NEW_PASSWORD
    assert body["secret_stored"] is True
    assert secret_storage["sealed"] == [{"subject_id": ORG_ID, "password": NEW_PASSWORD}]
    assert [c["credential_id"] for c in secret_storage["upserts"]] == [
        ACTIVE_INTERNAL_CREDENTIAL["id"]
    ]
    # Lo que llega al repositorio es el sobre cifrado, nunca el texto.
    assert set(secret_storage["upserts"][0]["envelope"]) == set(FAKE_ENVELOPE)
    assert NEW_PASSWORD not in json.dumps(secret_storage["upserts"])


@pytest.mark.asyncio
async def test_suggest_external_does_not_call_admin_api(client, monkeypatch, secret_storage):
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
        assert NEW_PASSWORD not in json.dumps(call)
    # La sugerencia vuelve en la respuesta: antes se descartaba y el panel mostraba la
    # que él mismo había generado.
    assert body["suggested_password"] == NEW_PASSWORD


@pytest.mark.asyncio
async def test_restore_rejects_already_active(client, monkeypatch):
    monkeypatch.setattr(dashboard.dashboard_repo, "get_credential", lambda cid, org_id: dict(ACTIVE_INTERNAL_CREDENTIAL))
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
    monkeypatch.setattr(dashboard.dashboard_repo, "list_audit_log", lambda org_id: [entry])

    async with client as ac:
        response = await ac.get("/api/v1/dashboard/audit-log")

    assert response.status_code == 200
    assert response.json()[0]["action"] == "revocar_interna"


@pytest.mark.asyncio
async def test_revoke_internal_generates_password_server_side(client, monkeypatch):
    """No new_password body → the backend generates it and never writes it to audit.
    Y ahora esa contraseña vuelve en la respuesta: antes era inobservable, que era el bug."""
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
    # La que el backend generó es la que devuelve: el cliente ya no tiene que inventarla.
    assert response.json()["applied_password"] == "SrvGen#Clave#99aA"
    assert audit_calls[0]["action"] == "revocar_interna"
    for call in audit_calls:
        assert "password" not in call
        assert "new_password" not in call
        assert "SrvGen#Clave#99aA" not in json.dumps(call)


@pytest.mark.asyncio
async def test_suggest_external_genera_y_guarda_el_secreto_cifrado(
    client, monkeypatch, secret_storage
):
    """Antes: test_suggest_external_generates_but_does_not_persist_password.

    Se invirtió A PROPÓSITO la mitad del invariante que decía que la contraseña
    sugerida no se persiste: para poder entregársela a un empleado o a su reemplazo, la
    organización tiene que poder volver a verla, así que se guarda cifrada.

    La otra mitad NO se tocó y es lo que sostiene AC4: ningún payload de auditoría lleva
    la contraseña. Los bucles de abajo son lo único que sobrevive del test original.
    """
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
    assert response.json()["suggested_password"] == "SrvGen#Externa#77zZ"
    # Mitad invertida: SÍ se persiste, cifrada, con la organización como dueña del dato.
    assert secret_storage["sealed"] == [{"subject_id": ORG_ID, "password": "SrvGen#Externa#77zZ"}]
    assert len(secret_storage["upserts"]) == 1
    assert "SrvGen#Externa#77zZ" not in json.dumps(secret_storage["upserts"])
    # Mitad intacta: la auditoría nunca lleva la contraseña.
    assert audit_calls[0]["action"] == "sugerir_externa"
    for call in audit_calls:
        assert "password" not in call
        assert "new_password" not in call
        assert "SrvGen#Externa#77zZ" not in json.dumps(call)


@pytest.mark.asyncio
async def test_revoke_rejects_already_revoked(client, monkeypatch):
    monkeypatch.setattr(
        dashboard.dashboard_repo, "get_credential", lambda cid, org_id: dict(REVOKED_INTERNAL_CREDENTIAL)
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
        lambda cid, org_id: dict(PENDING_EXTERNAL_CREDENTIAL),
    )
    async with client as ac:
        response = await ac.post(
            f"/api/v1/dashboard/credentials/{PENDING_EXTERNAL_CREDENTIAL['id']}/suggest",
            json={"new_password": NEW_PASSWORD},
        )
    assert response.status_code == 400
