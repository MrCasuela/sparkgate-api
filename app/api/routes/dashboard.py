import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import require_enterprise
from app.core.exceptions import ServiceUnavailableError
from app.schemas.dashboard import (
    AuditLogEntryOut,
    CreateMemberRequest,
    CreateMemberResponse,
    CredentialActionRequest,
    CredentialActionResponse,
    MemberOut,
)
from app.schemas.vault import VaultItemOut, VaultSecretOut
from app.services import dashboard_repo, random_generator, vault_crypto, vault_repo
from app.services.db_client import get_supabase_admin

logger = logging.getLogger("sparkgate.dashboard")
router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


def _resolve_password(body: CredentialActionRequest) -> str:
    """Server-side generation unless the admin explicitly overrides. The generated
    value is used to rotate/propose a credential but is NEVER written to the audit
    log (AC4)."""
    if body.new_password:
        return body.new_password
    generated = random_generator.generate(
        length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True
    )
    logger.info("Dashboard generated a new credential password server-side.")
    return generated


@router.get("/members", response_model=list[MemberOut])
async def list_members(caller: dict = Depends(require_enterprise)):
    return dashboard_repo.list_members_with_credentials(caller["org_id"])


@router.post("/members", response_model=CreateMemberResponse, status_code=status.HTTP_201_CREATED)
async def create_member(
    body: CreateMemberRequest,
    caller: dict = Depends(require_enterprise),
):
    """Provisiona la cuenta de un trabajador (HU21 AC2).

    Usa la Admin API y no el sign_up público: no manda mail de confirmación, así
    que no choca con el rate limit de Supabase, y la cuenta queda vinculada a la
    organización en el acto.
    """
    org_id = caller["org_id"]
    temporary_password = random_generator.generate(
        length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True
    )

    try:
        created = get_supabase_admin().auth.admin.create_user(
            {
                "email": body.email,
                "password": temporary_password,
                "email_confirm": True,
                "user_metadata": {
                    "premium": False,
                    "plan": "Gratuito",
                    "type_account": "personal",
                    "org_id": org_id,
                },
            }
        )
    except Exception as e:
        if "already registered" in str(e).lower() or "already exists" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Ya existe una cuenta con este correo.",
            )
        logger.error("No se pudo crear el usuario del trabajador: %s", e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No se pudo crear la cuenta del trabajador.",
        )

    new_user_id = created.user.id
    try:
        member = dashboard_repo.create_member(
            org_id=org_id,
            full_name=body.full_name,
            email=body.email,
            role_title=body.role_title,
            supabase_user_id=new_user_id,
        )
        dashboard_repo.create_internal_credential(
            member_id=member["id"],
            service_name="SparkGate (cuenta interna)",
            supabase_user_id=new_user_id,
        )
    except Exception as e:
        # Compensación: un usuario de Auth sin fila de gobernanza es invisible
        # para el panel y no se puede administrar. Mismo criterio que el borrado
        # de cuenta, donde delete_user va último para no dejar datos huérfanos.
        logger.error("Alta de trabajador fallida tras crear el usuario %s: %s", new_user_id, e)
        get_supabase_admin().auth.admin.delete_user(new_user_id)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No se pudo registrar al trabajador en el panel. No se creó ninguna cuenta.",
        )

    dashboard_repo.insert_audit_log(
        org_id=org_id,
        actor_email=caller.get("email", "unknown"),
        member_id=member["id"],
        action="crear_trabajador",
    )
    logger.info("Trabajador %s dado de alta en la organización %s", member["id"], org_id)

    member["credentials"] = []
    return CreateMemberResponse(member=member, temporary_password=temporary_password)


@router.get("/audit-log", response_model=list[AuditLogEntryOut])
async def get_audit_log(caller: dict = Depends(require_enterprise)):
    return dashboard_repo.list_audit_log(caller["org_id"])


@router.post("/credentials/{credential_id}/revoke", response_model=CredentialActionResponse)
async def revoke_internal_credential(
    credential_id: str,
    body: CredentialActionRequest,
    caller: dict = Depends(require_enterprise),
):
    credential = dashboard_repo.get_credential(credential_id, caller["org_id"])
    if credential is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada")
    if credential["type"] != "interna":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Esta acción solo aplica a cuentas internas gestionadas por SparkGate.",
        )
    if credential.get("supabase_user_id") == caller.get("id"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No podés revocar tu propia cuenta de administrador desde este panel.",
        )
    if credential.get("status") == "revocada":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Esta credencial interna ya está revocada.",
        )

    # auth.admin.sign_out(jwt, scope) revokes a *specific session by its own JWT* —
    # we only have the member's user_id (their JWT isn't ours to hold). update_user_by_id
    # is the only Admin API mechanism that can act on a user_id: one call both bans the
    # account (blocks future logins/refreshes immediately, matches AC6 — an access token
    # already issued stays valid until it naturally expires) and rotates its real password,
    # so a later "restore" hands back an account with a password the departed employee
    # never knew, not their old one.
    admin_api_success = False
    supabase_user_id = credential.get("supabase_user_id")
    if supabase_user_id:
        try:
            new_password = _resolve_password(body)
            get_supabase_admin().auth.admin.update_user_by_id(
                supabase_user_id, {"password": new_password, "ban_duration": "87600h"}
            )
            admin_api_success = True
        except Exception as e:
            logger.error("Revoke failed for user %s: %s", supabase_user_id, e)

    dashboard_repo.update_credential_status(credential_id, "revocada")
    dashboard_repo.insert_audit_log(
        org_id=caller["org_id"],
        actor_email=caller.get("email", "unknown"),
        member_id=credential["member_id"],
        credential_id=credential_id,
        credential_type="interna",
        action="revocar_interna",
    )
    logger.info("Revoked internal credential %s (admin_api_success=%s)", credential_id, admin_api_success)

    updated = dashboard_repo.get_credential(credential_id, caller["org_id"])
    return CredentialActionResponse(credential=updated, admin_api_success=admin_api_success)


@router.post("/credentials/{credential_id}/suggest", response_model=CredentialActionResponse)
async def suggest_external_credential(
    credential_id: str,
    body: CredentialActionRequest,
    caller: dict = Depends(require_enterprise),
):
    credential = dashboard_repo.get_credential(credential_id, caller["org_id"])
    if credential is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada")
    if credential["type"] != "externa":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Esta acción solo aplica a cuentas externas, fuera del control de SparkGate.",
        )
    if credential.get("status") == "pendiente_aplicacion_manual":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Esta credencial externa ya tiene una contraseña pendiente de aplicación manual.",
        )

    # Generate a proposed password server-side (AC3). It is returned to the caller
    # for manual application on the external service; SparkGate makes no promise to
    # change anything on the remote service.
    _resolve_password(body)
    dashboard_repo.update_credential_status(credential_id, "pendiente_aplicacion_manual")
    dashboard_repo.insert_audit_log(
        org_id=caller["org_id"],
        actor_email=caller.get("email", "unknown"),
        member_id=credential["member_id"],
        credential_id=credential_id,
        credential_type="externa",
        action="sugerir_externa",
    )
    logger.info("Suggested password for external credential %s", credential_id)

    updated = dashboard_repo.get_credential(credential_id, caller["org_id"])
    return CredentialActionResponse(credential=updated, admin_api_success=True)


@router.post("/credentials/{credential_id}/restore", response_model=CredentialActionResponse)
async def restore_credential(
    credential_id: str,
    caller: dict = Depends(require_enterprise),
):
    credential = dashboard_repo.get_credential(credential_id, caller["org_id"])
    if credential is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada")
    if credential["status"] == "activa":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Esta credencial ya está activa.",
        )

    admin_api_success = True
    supabase_user_id = credential.get("supabase_user_id")
    if credential["type"] == "interna" and supabase_user_id:
        admin_api_success = False
        try:
            get_supabase_admin().auth.admin.update_user_by_id(
                supabase_user_id, {"ban_duration": "none"}
            )
            admin_api_success = True
        except Exception as e:
            logger.error("Restore failed for user %s: %s", supabase_user_id, e)

    dashboard_repo.update_credential_status(credential_id, "activa")
    action = "restaurar_interna" if credential["type"] == "interna" else "restaurar_externa"
    dashboard_repo.insert_audit_log(
        org_id=caller["org_id"],
        actor_email=caller.get("email", "unknown"),
        member_id=credential["member_id"],
        credential_id=credential_id,
        credential_type=credential["type"],
        action=action,
    )
    logger.info("Restored credential %s (admin_api_success=%s)", credential_id, admin_api_success)

    updated = dashboard_repo.get_credential(credential_id, caller["org_id"])
    return CredentialActionResponse(credential=updated, admin_api_success=admin_api_success)


def _resolve_member_owner(member_id: str, org_id: str) -> str | None:
    """Valida que el integrante sea de MI organización y devuelve el user_id de
    su cuenta SparkGate (None si no tiene ninguna vinculada).

    Un integrante de otra organización responde 404 y no 403: mismo criterio
    anti-enumeración que el vault personal, inexistente y ajeno se ven igual.
    """
    member = dashboard_repo.get_member(member_id, org_id)
    if member is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Integrante no encontrado"
        )
    return member.get("supabase_user_id")


@router.get("/members/{member_id}/vault", response_model=list[VaultItemOut])
async def list_member_vault(
    member_id: str,
    caller: dict = Depends(require_enterprise),
):
    """Metadata de la bóveda de un trabajador (HU21 AC5).

    No llama a _require_available() a propósito: listar metadata no descifra
    nada, así que sigue funcionando con la clave maestra caída (AC8). Es el
    mismo criterio que GET /api/v1/vault/items.
    """
    org_id = caller["org_id"]
    owner_id = _resolve_member_owner(member_id, org_id)

    if owner_id is None:
        # Integrante sin cuenta SparkGate vinculada (contratista externo, o
        # alguien que ya borró su cuenta): no tiene bóveda que listar.
        return []

    items = vault_repo.list_items(owner_id)
    vault_repo.insert_audit(
        user_id=owner_id,
        item_id=None,
        action="listar_admin",
        result="ok",
        actor_user_id=caller["id"],
    )
    dashboard_repo.insert_audit_log(
        org_id=org_id,
        actor_email=caller.get("email", "unknown"),
        member_id=member_id,
        action="listar_vault_miembro",
    )
    logger.info(
        "Bóveda del integrante %s listada por %s (%s ítems)", member_id, caller["id"], len(items)
    )
    return items


@router.post(
    "/members/{member_id}/vault/{item_id}/reveal",
    response_model=VaultSecretOut,
)
async def reveal_member_vault_item(
    member_id: str,
    item_id: str,
    caller: dict = Depends(require_enterprise),
):
    """Descifra una credencial del trabajador y la devuelve (HU21 AC6).

    Es POST y no GET a propósito: escribe auditoría, no debe quedar en el
    historial del navegador ni ser precargable.
    """
    if not vault_crypto.is_available():
        raise ServiceUnavailableError(
            "Vault",
            detail="El módulo de bóveda no está operativo: falta la clave maestra.",
        )

    org_id = caller["org_id"]
    actor_id = caller["id"]
    actor_email = caller.get("email", "unknown")
    owner_id = _resolve_member_owner(member_id, org_id)

    if owner_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada"
        )

    item = vault_repo.get_item(item_id, owner_id)
    if item is None:
        vault_repo.insert_audit(
            user_id=owner_id,
            item_id=item_id,
            action="consultar_admin_denegado",
            result="denegado",
            actor_user_id=actor_id,
        )
        dashboard_repo.insert_audit_log(
            org_id=org_id,
            actor_email=actor_email,
            member_id=member_id,
            action="consultar_vault_miembro_denegado",
            vault_item_id=item_id,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada"
        )

    # El AAD sigue siendo el user_id del DUEÑO, no el del caller: identifica de
    # quién es el dato, no quién pregunta. Por eso el acceso de la empresa no
    # obliga a tocar vault_crypto ni debilita el cifrado — mover una fila a otro
    # user_id sigue rompiendo el tag GCM.
    try:
        secret = vault_crypto.decrypt_secret(item, aad=owner_id)
    except vault_crypto.InvalidTag:
        vault_repo.insert_audit(
            user_id=owner_id,
            item_id=item_id,
            action="consultar_admin",
            result="error",
            actor_user_id=actor_id,
        )
        dashboard_repo.insert_audit_log(
            org_id=org_id,
            actor_email=actor_email,
            member_id=member_id,
            action="consultar_vault_miembro",
            vault_item_id=item_id,
        )
        logger.error(
            "Reveal del ítem %s: fallo de integridad al descifrar (kek_version=%s)",
            item_id,
            item.get("kek_version"),
        )
        raise ServiceUnavailableError(
            "Vault",
            detail="No se pudo descifrar la credencial: el registro no supera "
            "la verificación de integridad.",
        )

    # Doble auditoría (AC7). La entrada del vault es la que ve el propio
    # trabajador en GET /api/v1/vault/audit: es la mitigación de privacidad de
    # esta historia, no un detalle de implementación.
    vault_repo.insert_audit(
        user_id=owner_id,
        item_id=item_id,
        action="consultar_admin",
        result="ok",
        actor_user_id=actor_id,
    )
    dashboard_repo.insert_audit_log(
        org_id=org_id,
        actor_email=actor_email,
        member_id=member_id,
        action="consultar_vault_miembro",
        vault_item_id=item_id,
    )
    logger.info(
        "Ítem %s del integrante %s revelado a %s", item_id, member_id, actor_id
    )
    return VaultSecretOut(
        id=item["id"],
        service_name=item["service_name"],
        username=item.get("username"),
        password=secret["password"],
        notes=secret.get("notes"),
    )
