import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import require_user
from app.core.exceptions import ServiceUnavailableError
from app.schemas.vault import (
    VaultAuditEntryOut,
    VaultItemCreate,
    VaultItemOut,
    VaultPurgeResponse,
    VaultSecretOut,
)
from app.services import vault_crypto, vault_repo

logger = logging.getLogger("sparkgate.vault")
router = APIRouter(prefix="/api/v1/vault", tags=["vault"])


def _require_available() -> None:
    if not vault_crypto.is_available():
        raise ServiceUnavailableError(
            "Vault",
            detail="El módulo de bóveda no está operativo: falta la clave maestra.",
        )


@router.post("/items", response_model=VaultItemOut, status_code=status.HTTP_201_CREATED)
async def save_item(body: VaultItemCreate, user: dict = Depends(require_user)):
    _require_available()
    user_id = user["id"]

    secret = vault_crypto.encrypt_secret(
        {"password": body.password, "notes": body.notes}, aad=user_id
    )
    item = vault_repo.insert_item(
        user_id=user_id,
        service_name=body.service_name,
        username=body.username,
        secret=secret,
    )
    vault_repo.insert_audit(
        user_id=user_id, item_id=item["id"], action="guardar", result="ok"
    )
    logger.info("Vault item %s saved for user %s (service=%s)", item["id"], user_id, body.service_name)
    return item


@router.get("/items", response_model=list[VaultItemOut])
async def list_items(user: dict = Depends(require_user)):
    user_id = user["id"]
    items = vault_repo.list_items(user_id)
    vault_repo.insert_audit(user_id=user_id, item_id=None, action="listar", result="ok")
    return items


@router.get("/items/{item_id}", response_model=VaultSecretOut)
async def get_item(item_id: str, user: dict = Depends(require_user)):
    _require_available()
    user_id = user["id"]

    item = vault_repo.get_item(item_id, user_id)
    if item is None:
        vault_repo.insert_audit(
            user_id=user_id, item_id=item_id, action="consultar_denegado", result="denegado"
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada")

    try:
        secret = vault_crypto.decrypt_secret(item, aad=user_id)
    except vault_crypto.InvalidTag:
        # El tag GCM no cuadra: la fila fue movida, adulterada, o la KEK cambió.
        # No es un 404 (esconder una adulteración es justo lo que el tag existe
        # para evitar) ni un 500: desde el cliente, el módulo no puede servir
        # este ítem, igual que cuando falta la clave maestra.
        vault_repo.insert_audit(
            user_id=user_id, item_id=item_id, action="consultar", result="error"
        )
        logger.error(
            "Vault item %s: fallo de integridad al descifrar (kek_version=%s)",
            item_id,
            item.get("kek_version"),
        )
        raise ServiceUnavailableError(
            "Vault",
            detail="No se pudo descifrar la credencial: el registro no supera "
            "la verificación de integridad.",
        )

    vault_repo.insert_audit(user_id=user_id, item_id=item_id, action="consultar", result="ok")
    logger.info("Vault item %s decrypted for user %s", item_id, user_id)
    return VaultSecretOut(
        id=item["id"],
        service_name=item["service_name"],
        username=item.get("username"),
        password=secret["password"],
        notes=secret.get("notes"),
    )


@router.delete("/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_item(item_id: str, user: dict = Depends(require_user)):
    user_id = user["id"]
    deleted = vault_repo.delete_item(item_id, user_id)
    if not deleted:
        vault_repo.insert_audit(
            user_id=user_id, item_id=item_id, action="eliminar_denegado", result="denegado"
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada")

    vault_repo.insert_audit(user_id=user_id, item_id=item_id, action="eliminar", result="ok")
    logger.info("Vault item %s deleted for user %s", item_id, user_id)


@router.delete("/items", response_model=VaultPurgeResponse)
async def purge_items(user: dict = Depends(require_user)):
    user_id = user["id"]
    deleted_count = vault_repo.delete_all_items(user_id)
    vault_repo.insert_audit(
        user_id=user_id,
        item_id=None,
        action="eliminar_todo",
        result="ok",
        deleted_count=deleted_count,
    )
    logger.info("Vault purged for user %s (deleted_count=%s)", user_id, deleted_count)
    return VaultPurgeResponse(deleted_count=deleted_count)


@router.get("/audit", response_model=list[VaultAuditEntryOut])
async def get_audit_log(user: dict = Depends(require_user)):
    return vault_repo.list_audit(user["id"])
