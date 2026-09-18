from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.dependencies import verify_token
from app.api.routes import vault

NOW = datetime.now(timezone.utc).isoformat()
USER_ID = "user-1"
OTHER_USER_ID = "user-2"

ENCRYPTED_SECRET = {
    "ciphertext": "cipher==",
    "nonce": "nonce==",
    "wrapped_dek": "wrapped==",
    "dek_nonce": "deknonce==",
    "kek_version": 1,
}

STORED_ITEM = {
    "id": "item-1",
    "user_id": USER_ID,
    "service_name": "GitHub",
    "username": "mrcasuela",
    "created_at": NOW,
    "updated_at": NOW,
    **ENCRYPTED_SECRET,
}


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[verify_token] = lambda: {
        "id": USER_ID,
        "email": "user@example.com",
        "user_metadata": {},
    }
    yield
    app.dependency_overrides.clear()


def _audit_recorder(monkeypatch):
    calls = []
    monkeypatch.setattr(vault.vault_repo, "insert_audit", lambda **kwargs: calls.append(kwargs))
    return calls


@pytest.mark.asyncio
async def test_save_item_requires_auth(client):
    app.dependency_overrides[verify_token] = lambda: None
    async with client as ac:
        response = await ac.post("/api/v1/vault/items", json={"service_name": "GitHub", "password": "x"})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_save_item_encrypts_before_persisting(client, monkeypatch):
    monkeypatch.setattr(vault.vault_crypto, "is_available", lambda: True)
    monkeypatch.setattr(vault.vault_crypto, "encrypt_secret", lambda payload, aad: dict(ENCRYPTED_SECRET))
    insert_calls = []

    def fake_insert_item(**kwargs):
        insert_calls.append(kwargs)
        return dict(STORED_ITEM)

    monkeypatch.setattr(vault.vault_repo, "insert_item", fake_insert_item)
    audit_calls = _audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.post(
            "/api/v1/vault/items",
            json={"service_name": "GitHub", "username": "mrcasuela", "password": "hunter2", "notes": "n"},
        )

    assert response.status_code == 201
    assert insert_calls[0]["user_id"] == USER_ID
    assert insert_calls[0]["secret"] == ENCRYPTED_SECRET
    # the plaintext password must never reach the insert as a top-level field
    assert "password" not in insert_calls[0]
    assert audit_calls == [{"user_id": USER_ID, "item_id": "item-1", "action": "guardar", "result": "ok"}]


@pytest.mark.asyncio
async def test_save_item_rejected_without_kek_and_does_not_persist(client, monkeypatch):
    monkeypatch.setattr(vault.vault_crypto, "is_available", lambda: False)
    insert_item = MagicMock()
    monkeypatch.setattr(vault.vault_repo, "insert_item", insert_item)

    async with client as ac:
        response = await ac.post(
            "/api/v1/vault/items", json={"service_name": "GitHub", "password": "hunter2"}
        )

    assert response.status_code == 503
    insert_item.assert_not_called()


@pytest.mark.asyncio
async def test_get_item_not_owned_returns_404_and_logs_denial(client, monkeypatch):
    monkeypatch.setattr(vault.vault_crypto, "is_available", lambda: True)
    monkeypatch.setattr(vault.vault_repo, "get_item", lambda item_id, user_id: None)
    audit_calls = _audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.get(f"/api/v1/vault/items/{STORED_ITEM['id']}")

    assert response.status_code == 404
    assert audit_calls == [
        {"user_id": USER_ID, "item_id": STORED_ITEM["id"], "action": "consultar_denegado", "result": "denegado"}
    ]


@pytest.mark.asyncio
async def test_get_item_owned_returns_decrypted_secret(client, monkeypatch):
    monkeypatch.setattr(vault.vault_crypto, "is_available", lambda: True)

    received_args = {}

    def fake_get_item(item_id, user_id):
        received_args["item_id"], received_args["user_id"] = item_id, user_id
        return dict(STORED_ITEM)

    monkeypatch.setattr(vault.vault_repo, "get_item", fake_get_item)
    monkeypatch.setattr(
        vault.vault_crypto, "decrypt_secret", lambda row, aad: {"password": "hunter2", "notes": "n"}
    )
    audit_calls = _audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.get(f"/api/v1/vault/items/{STORED_ITEM['id']}")

    assert response.status_code == 200
    body = response.json()
    assert body["password"] == "hunter2"
    assert received_args == {"item_id": STORED_ITEM["id"], "user_id": USER_ID}
    assert audit_calls == [
        {"user_id": USER_ID, "item_id": STORED_ITEM["id"], "action": "consultar", "result": "ok"}
    ]


@pytest.mark.asyncio
async def test_get_item_blocked_without_kek(client, monkeypatch):
    monkeypatch.setattr(vault.vault_crypto, "is_available", lambda: False)
    get_item = MagicMock()
    monkeypatch.setattr(vault.vault_repo, "get_item", get_item)

    async with client as ac:
        response = await ac.get(f"/api/v1/vault/items/{STORED_ITEM['id']}")

    assert response.status_code == 503
    get_item.assert_not_called()


@pytest.mark.asyncio
async def test_list_items_never_decrypts(client, monkeypatch):
    monkeypatch.setattr(vault.vault_repo, "list_items", lambda user_id: [STORED_ITEM])
    decrypt = MagicMock()
    monkeypatch.setattr(vault.vault_crypto, "decrypt_secret", decrypt)
    _audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.get("/api/v1/vault/items")

    assert response.status_code == 200
    assert response.json()[0]["service_name"] == "GitHub"
    decrypt.assert_not_called()


@pytest.mark.asyncio
async def test_delete_item_not_owned_returns_404(client, monkeypatch):
    monkeypatch.setattr(vault.vault_repo, "delete_item", lambda item_id, user_id: False)
    audit_calls = _audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.delete(f"/api/v1/vault/items/{STORED_ITEM['id']}")

    assert response.status_code == 404
    assert audit_calls[0]["action"] == "eliminar_denegado"


@pytest.mark.asyncio
async def test_delete_item_owned_returns_204(client, monkeypatch):
    monkeypatch.setattr(vault.vault_repo, "delete_item", lambda item_id, user_id: True)
    audit_calls = _audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.delete(f"/api/v1/vault/items/{STORED_ITEM['id']}")

    assert response.status_code == 204
    assert audit_calls[0]["action"] == "eliminar"


@pytest.mark.asyncio
async def test_delete_item_does_not_require_kek(client, monkeypatch):
    """Deletion is not gated on is_available() — losing the KEK must never block erasure."""
    monkeypatch.setattr(vault.vault_crypto, "is_available", lambda: False)
    monkeypatch.setattr(vault.vault_repo, "delete_item", lambda item_id, user_id: True)
    _audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.delete(f"/api/v1/vault/items/{STORED_ITEM['id']}")

    assert response.status_code == 204


@pytest.mark.asyncio
async def test_purge_items_returns_deleted_count(client, monkeypatch):
    monkeypatch.setattr(vault.vault_repo, "delete_all_items", lambda user_id: 3)
    audit_calls = _audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.delete("/api/v1/vault/items")

    assert response.status_code == 200
    assert response.json() == {"deleted_count": 3}
    assert audit_calls[0] == {
        "user_id": USER_ID,
        "item_id": None,
        "action": "eliminar_todo",
        "result": "ok",
        "deleted_count": 3,
    }


@pytest.mark.asyncio
async def test_fallo_de_integridad_responde_503_y_audita_error(client, monkeypatch):
    """Si el tag GCM no cuadra (fila movida, adulterada, o KEK rotada) el
    usuario recibe 503, no un 500 sin traza. No es 404: esconder una
    adulteración es justo lo que el tag existe para evitar."""
    from app.services import vault_crypto as vault_crypto_module

    monkeypatch.setattr(vault.vault_crypto, "is_available", lambda: True)
    monkeypatch.setattr(vault.vault_repo, "get_item", lambda item_id, user_id: dict(STORED_ITEM))

    def _explode(row, aad):
        raise vault_crypto_module.InvalidTag()

    monkeypatch.setattr(vault.vault_crypto, "decrypt_secret", _explode)
    audit_calls = _audit_recorder(monkeypatch)

    async with client as ac:
        response = await ac.get("/api/v1/vault/items/item-1")

    assert response.status_code == 503
    assert audit_calls == [
        {"user_id": USER_ID, "item_id": "item-1", "action": "consultar", "result": "error"}
    ]
