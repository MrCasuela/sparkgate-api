import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import optional_step_up_code, require_enterprise
from app.schemas.dashboard import (
    AuditLogEntryOut,
    CreateCredentialRequest,
    CreateMemberRequest,
    CreateMemberResponse,
    CredentialActionRequest,
    CredentialActionResponse,
    CredentialOut,
    CredentialSecretOut,
    CredentialSecretRequest,
    CredentialSecretSaveResponse,
    MemberOut,
    ReassignCredentialRequest,
    ReassignCredentialResponse,
    RotationSuggestion,
)
from app.schemas.vault import VaultItemOut, VaultSecretOut
from app.services import (
    credential_secret_repo,
    dashboard_repo,
    random_generator,
    secret_access,
    vault_repo,
)
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


def _audit(caller: dict, *, member_id: str | None, action: str, **fields) -> None:
    """Entrada de auditoría del panel. Org y autor salen SIEMPRE del caller ya
    resuelto por require_enterprise, nunca de un argumento: así ninguna ruta puede
    auditar a nombre de otra organización o de otro usuario por descuido."""
    dashboard_repo.insert_audit_log(
        org_id=caller["org_id"],
        actor_user_id=caller["id"],
        actor_email=caller.get("email"),
        member_id=member_id,
        action=action,
        **fields,
    )


def _flag_rotation(org_id: str, credentials: list[dict], member_name: str | None) -> list[dict]:
    """Marca para rotar y devuelve las sugerencias que el panel muestra.

    Es una SUGERENCIA, no una acción: rotar una contraseña externa es trabajo manual
    (SparkGate no controla el proveedor), y una interna se rota con revoke o con PUT
    /secret. La bandera queda persistida en la credencial y solo se apaga rotando.
    """
    dashboard_repo.set_rotation_required([c["id"] for c in credentials], org_id)
    return [
        RotationSuggestion(
            credential_id=c["id"],
            service_name=c["service_name"],
            type=c["type"],
            member_name=member_name,
        ).model_dump()
        for c in credentials
    ]


def _try_store_secret(
    caller: dict, credential: dict, *, password: str, notes: str | None = None
) -> bool:
    """Guarda cifrada la contraseña que una acción principal acaba de producir.

    Es best-effort A PROPÓSITO y nunca lanza: revocar a alguien que se va no puede
    depender de que la clave maestra esté arriba, y dar de alta un trabajador tampoco.
    Si falla devuelve False, y la ruta se lo dice al panel: en ese caso la respuesta
    es la única copia de la contraseña y el usuario tiene que saberlo.

    El subject del AAD es la organización, no el integrante: por eso reasignar la
    credencial o borrar la cuenta del trabajador no tocan este sobre.
    """
    org_id = caller["org_id"]
    try:
        envelope = secret_access.seal_secret(subject_id=org_id, password=password, notes=notes)
        credential_secret_repo.upsert_secret(
            credential_id=credential["id"], org_id=org_id, envelope=envelope
        )
        dashboard_repo.mark_secret_saved(credential["id"], org_id)
        return True
    except Exception as e:
        # Solo el tipo de error: el mensaje de un fallo de base podría repetir el
        # payload, y acá el payload es un sobre con material sensible.
        logger.error(
            "No se pudo guardar el secreto de la credencial %s (%s)",
            credential["id"],
            type(e).__name__,
        )
        try:
            _audit(
                caller,
                member_id=credential.get("member_id"),
                credential_id=credential["id"],
                credential_type=credential.get("type"),
                action="guardar_secreto_fallido",
            )
        except Exception:
            logger.error("Tampoco se pudo auditar el fallo de guardado de %s", credential["id"])
        return False


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
        internal_credential = dashboard_repo.create_internal_credential(
            org_id=org_id,
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

    _audit(
        caller,
        member_id=member["id"],
        action="crear_trabajador",
    )
    logger.info("Trabajador %s dado de alta en la organización %s", member["id"], org_id)

    # La temporal es la contraseña vigente de esa cuenta hasta que el trabajador la
    # cambie: se guarda para que la empresa pueda volver a verla si se le pierde.
    secret_stored = _try_store_secret(caller, internal_credential, password=temporary_password)

    member["credentials"] = []
    return CreateMemberResponse(
        member=member, temporary_password=temporary_password, secret_stored=secret_stored
    )


@router.get("/credentials", response_model=list[CredentialOut])
async def list_credentials(
    assigned: bool | None = None,
    caller: dict = Depends(require_enterprise),
):
    """Credenciales de la organización. `assigned=false` devuelve el pool sin
    asignar, que no aparece en GET /members y que el panel necesita para mostrar y
    etiquetar esas credenciales."""
    return dashboard_repo.list_credentials(caller["org_id"], assigned=assigned)


@router.post("/credentials", response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
async def create_credential(
    body: CreateCredentialRequest,
    caller: dict = Depends(require_enterprise),
):
    """Registra una cuenta externa de la organización (Google Workspace, Dropbox...).

    Siempre es `externa`: las internas solo las crea el alta de trabajador, porque
    son cuentas de Supabase Auth atadas a una persona. Si viene `password`, se guarda
    cifrada junto con el alta.
    """
    org_id = caller["org_id"]
    if body.password is not None:
        # Sin clave maestra no se persiste nada, y no se toca la base para saberlo.
        secret_access.require_available()
    if body.member_id is not None:
        # Un integrante de otra organización responde igual que uno inexistente.
        if dashboard_repo.get_member(body.member_id, org_id) is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Integrante no encontrado"
            )

    credential = dashboard_repo.create_external_credential(
        org_id=org_id,
        member_id=body.member_id,
        service_name=body.service_name,
        username=body.username,
    )

    if body.password is not None:
        try:
            envelope = secret_access.seal_secret(
                subject_id=org_id, password=body.password, notes=body.notes
            )
            credential_secret_repo.upsert_secret(
                credential_id=credential["id"], org_id=org_id, envelope=envelope
            )
            dashboard_repo.mark_secret_saved(credential["id"], org_id)
        except Exception as e:
            # Compensación: una credencial que el usuario cree guardada con su
            # contraseña y no lo está es peor que no tenerla. Mismo criterio que el
            # alta de trabajador: no dejar una fila a medias que parece completa.
            logger.error(
                "Alta de credencial %s fallida al guardar el secreto (%s)",
                credential["id"],
                type(e).__name__,
            )
            dashboard_repo.delete_credential(credential["id"], org_id)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="No se pudo guardar la contraseña. No se registró la cuenta.",
            )

    _audit(
        caller,
        member_id=body.member_id,
        credential_id=credential["id"],
        credential_type="externa",
        action="crear_credencial_externa",
    )
    logger.info("Credencial externa %s registrada en la organización %s", credential["id"], org_id)
    return dashboard_repo.get_credential(credential["id"], org_id)


@router.post("/credentials/{credential_id}/reassign", response_model=ReassignCredentialResponse)
async def reassign_credential(
    credential_id: str,
    body: ReassignCredentialRequest,
    caller: dict = Depends(require_enterprise),
):
    """Pasa una credencial externa de un integrante a otro (el reemplazo), o de
    vuelta al pool. No re-cifra nada: el secreto es de la organización, que no
    cambia. Cruzar organizaciones es imposible por construcción, porque las dos
    consultas van filtradas por el mismo org_id del caller."""
    org_id = caller["org_id"]
    credential = dashboard_repo.get_credential(credential_id, org_id)
    if credential is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada")
    if credential["type"] != "externa":
        # Una interna es una cuenta de Supabase Auth atada a una persona: pasársela
        # al reemplazo sería darle la identidad del anterior. El reemplazo obtiene su
        # propia cuenta interna con el alta de trabajador.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Solo se pueden reasignar cuentas externas. Una cuenta interna es "
            "personal: el reemplazo obtiene la suya con el alta de trabajador.",
        )
    if body.member_id is not None and dashboard_repo.get_member(body.member_id, org_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integrante no encontrado")
    if credential.get("member_id") == body.member_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La credencial ya está asignada a ese integrante.",
        )

    previous_member_id = credential.get("member_id")
    dashboard_repo.reassign_credential(credential_id, org_id, body.member_id)
    _audit(
        caller,
        member_id=previous_member_id,
        target_member_id=body.member_id,
        credential_id=credential_id,
        credential_type="externa",
        action="reasignar_credencial",
    )
    logger.info(
        "Credencial %s reasignada de %s a %s", credential_id, previous_member_id, body.member_id
    )

    # La que cambia de manos es la que hay que rotar: quien la tenía ya conoce su
    # contraseña. (No las OTRAS credenciales del integrante anterior: seguir teniéndolas
    # es lo normal hasta que se reasignen una a una.)
    previous = (
        dashboard_repo.get_member(previous_member_id, org_id) if previous_member_id else None
    )
    rotation_suggested = _flag_rotation(
        org_id, [credential], previous["full_name"] if previous else None
    )
    return ReassignCredentialResponse(
        credential=dashboard_repo.get_credential(credential_id, org_id),
        rotation_suggested=rotation_suggested,
    )


@router.put("/credentials/{credential_id}/secret", response_model=CredentialSecretSaveResponse)
async def save_credential_secret(
    credential_id: str,
    body: CredentialSecretRequest,
    caller: dict = Depends(require_enterprise),
):
    """Guarda o reemplaza la contraseña de una credencial de la organización.

    PUT porque es el reemplazo idempotente de un sub-recurso. NUNCA devuelve el
    plaintext: el cliente ya lo tiene, y verlo de nuevo es el reveal, que audita.
    """
    # Antes de tocar la base: sin clave maestra no se persiste nada (AC5 / AC8).
    secret_access.require_available()
    org_id = caller["org_id"]

    credential = dashboard_repo.get_credential(credential_id, org_id)
    if credential is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada")

    applied = False
    if body.apply_to_account:
        if credential["type"] != "interna":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Solo una cuenta interna se puede aplicar desde SparkGate: una "
                "externa está fuera de su control.",
            )
        supabase_user_id = credential.get("supabase_user_id")
        if not supabase_user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Esta credencial no tiene una cuenta SparkGate vinculada.",
            )
        # Auth primero: lo guardado tiene que ser la contraseña VIGENTE, no una
        # anotación que no coincide con la cuenta.
        try:
            get_supabase_admin().auth.admin.update_user_by_id(
                supabase_user_id, {"password": body.password}
            )
            applied = True
        except Exception as e:
            logger.error("No se pudo aplicar la contraseña a la cuenta %s: %s", supabase_user_id, e)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="No se pudo aplicar la contraseña a la cuenta. No se guardó nada.",
            )

    try:
        envelope = secret_access.seal_secret(
            subject_id=org_id, password=body.password, notes=body.notes
        )
        credential_secret_repo.upsert_secret(
            credential_id=credential_id, org_id=org_id, envelope=envelope
        )
        dashboard_repo.mark_secret_saved(credential_id, org_id, username=body.username)
    except Exception as e:
        logger.error(
            "No se pudo guardar el secreto de la credencial %s (%s)", credential_id, type(e).__name__
        )
        _audit(
            caller,
            member_id=credential.get("member_id"),
            credential_id=credential_id,
            credential_type=credential["type"],
            action="guardar_secreto_fallido",
        )
        # El caso peligroso: la cuenta ya cambió de contraseña y el sobre no se
        # guardó. El cliente todavía tiene el plaintext, y hay que decírselo.
        detail = (
            "La contraseña se aplicó a la cuenta pero no se pudo guardar cifrada. "
            "Guardala de nuevo antes de cerrar."
            if applied
            else "No se pudo guardar la contraseña."
        )
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail)

    _audit(
        caller,
        member_id=credential.get("member_id"),
        credential_id=credential_id,
        credential_type=credential["type"],
        action="guardar_secreto",
    )
    logger.info("Secreto de la credencial %s guardado (applied=%s)", credential_id, applied)
    return CredentialSecretSaveResponse(
        credential=dashboard_repo.get_credential(credential_id, org_id),
        admin_api_success=applied or not body.apply_to_account,
        secret_stored=True,
    )


@router.post(
    "/credentials/{credential_id}/secret/reveal",
    response_model=CredentialSecretOut,
)
async def reveal_credential_secret(
    credential_id: str,
    caller: dict = Depends(require_enterprise),
    step_up_code: str | None = Depends(optional_step_up_code),
):
    """Descifra la contraseña de una credencial de la organización.

    POST y no GET, igual que el reveal de la bóveda del trabajador: escribe
    auditoría, no debe quedar en el historial del navegador ni ser precargable.
    """
    secret_access.require_available()
    org_id = caller["org_id"]

    credential = dashboard_repo.get_credential(credential_id, org_id)
    if credential is None:
        _audit(
            caller,
            member_id=None,
            credential_id=credential_id,
            action="consultar_secreto_denegado",
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada")

    envelope = credential_secret_repo.get_envelope(credential_id, org_id)
    if envelope is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Esta credencial no tiene una contraseña guardada.",
        )

    def on_denied(reason: str) -> None:
        _audit(
            caller,
            member_id=credential.get("member_id"),
            credential_id=credential_id,
            credential_type=credential["type"],
            action="consultar_secreto_denegado",
        )

    # El subject es el org_id leído de la MISMA fila que el criptograma, no el del
    # caller: el AAD dice de quién es el dato, no quién lo pide.
    secret = secret_access.read_foreign_secret(
        caller=caller,
        scope="org_credential",
        subject_id=envelope["org_id"],
        target_id=credential_id,
        envelope=envelope,
        step_up_code=step_up_code,
        on_denied=on_denied,
    )

    _audit(
        caller,
        member_id=credential.get("member_id"),
        credential_id=credential_id,
        credential_type=credential["type"],
        action="consultar_secreto",
    )

    # Mitigación compensatoria de la suplantación (R-HU21-5). Revelar la contraseña
    # vigente de la cuenta SparkGate de un trabajador le permite a la empresa entrar
    # como él, y esa sesión queda registrada a su nombre. Lo mínimo que se le debe es
    # poder ver, en SU propia auditoría, que la empresa retiró la contraseña.
    # Va antes del return: si la entrada falla, el plaintext no sale (falla cerrada).
    #
    # Hace visible la ENTREGA, no el USO: si la empresa inicia sesión con ella, la
    # sesión es indistinguible y la auditoría del trabajador le atribuye cada acción
    # a él. Eso no lo arregla esta entrada. Decisión aceptada, ver la ADR de la etapa.
    if credential["type"] == "interna" and credential.get("supabase_user_id"):
        vault_repo.insert_audit(
            user_id=credential["supabase_user_id"],
            item_id=None,
            action="consultar_credencial_interna_admin",
            result="ok",
            actor_user_id=caller["id"],
        )

    logger.info("Secreto de la credencial %s revelado a %s", credential_id, caller["id"])
    return CredentialSecretOut(
        id=credential["id"],
        service_name=credential["service_name"],
        type=credential["type"],
        username=credential.get("username"),
        password=secret["password"],
        notes=secret.get("notes"),
        secret_updated_at=credential.get("secret_updated_at"),
    )


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
    # account (blocks logins/refreshes immediately, matches AC6) and rotates its real
    # password, so a later "restore" hands back an account with a password the departed
    # employee never knew, not their old one. An already-issued access token does NOT
    # outlive this: verify_token asks Auth on every request, so the next call is a 401
    # (measured against real Supabase, E2E step 21b0 — an earlier comment here claimed a
    # ~1h window that doesn't exist on this route).
    admin_api_success = False
    applied_password: str | None = None
    supabase_user_id = credential.get("supabase_user_id")
    if supabase_user_id:
        try:
            new_password = _resolve_password(body)
            get_supabase_admin().auth.admin.update_user_by_id(
                supabase_user_id, {"password": new_password, "ban_duration": "87600h"}
            )
            admin_api_success = True
            # Solo se devuelve si Auth la aceptó: una contraseña que no llegó a
            # aplicarse no es la de la cuenta y mostrarla sería engañoso.
            applied_password = new_password
        except Exception as e:
            logger.error("Revoke failed for user %s: %s", supabase_user_id, e)

    # Auth -> sobre -> estado. La contraseña que Auth acaba de aceptar es la vigente de
    # la cuenta: se guarda para que la empresa pueda entregársela a un reemplazo o
    # recuperarla. Si el sobre falla, la respuesta es la única copia.
    secret_stored = False
    if applied_password is not None:
        secret_stored = _try_store_secret(caller, credential, password=applied_password)

    dashboard_repo.update_credential_status(credential_id, "revocada")
    _audit(
        caller,
        member_id=credential["member_id"],
        credential_id=credential_id,
        credential_type="interna",
        action="revocar_interna",
    )
    logger.info("Revoked internal credential %s (admin_api_success=%s)", credential_id, admin_api_success)

    # Bloquear a alguien no cambia las contraseñas que ya conocía: sugerir rotar sus
    # otras credenciales todavía activas. La interna que se acaba de revocar ya se
    # rotó, y una ya revocada o pendiente no es una cuenta viva.
    rotation_suggested: list[dict] = []
    revoked_member_id = credential.get("member_id")
    if revoked_member_id is not None:
        others = [
            c
            for c in dashboard_repo.list_member_credentials(revoked_member_id, caller["org_id"])
            if c["id"] != credential_id and c["status"] == "activa"
        ]
        member = dashboard_repo.get_member(revoked_member_id, caller["org_id"])
        rotation_suggested = _flag_rotation(
            caller["org_id"], others, member["full_name"] if member else None
        )

    updated = dashboard_repo.get_credential(credential_id, caller["org_id"])
    return CredentialActionResponse(
        credential=updated,
        admin_api_success=admin_api_success,
        applied_password=applied_password,
        secret_stored=secret_stored,
        rotation_suggested=rotation_suggested,
    )


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
    # change anything on the remote service. (Este comentario era falso hasta ahora:
    # el valor se descartaba y el caller solo veía el que él mismo había enviado.)
    suggested_password = _resolve_password(body)
    # Se guarda cifrada como la contraseña que la empresa va a aplicar en el servicio:
    # así no depende de que alguien la anote. Sigue pendiente hasta que se aplique.
    secret_stored = _try_store_secret(caller, credential, password=suggested_password)
    dashboard_repo.update_credential_status(credential_id, "pendiente_aplicacion_manual")
    _audit(
        caller,
        member_id=credential["member_id"],
        credential_id=credential_id,
        credential_type="externa",
        action="sugerir_externa",
    )
    logger.info("Suggested password for external credential %s", credential_id)

    updated = dashboard_repo.get_credential(credential_id, caller["org_id"])
    return CredentialActionResponse(
        credential=updated,
        admin_api_success=True,
        suggested_password=suggested_password,
        secret_stored=secret_stored,
    )


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
    _audit(
        caller,
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
    _audit(
        caller,
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
    step_up_code: str | None = Depends(optional_step_up_code),
):
    """Descifra una credencial del trabajador y la devuelve (HU21 AC6).

    Es POST y no GET a propósito: escribe auditoría, no debe quedar en el
    historial del navegador ni ser precargable.
    """
    # Antes de tocar la base: sin clave maestra no se consulta nada (AC8).
    secret_access.require_available()

    actor_id = caller["id"]
    owner_id = _resolve_member_owner(member_id, caller["org_id"])

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
        _audit(
            caller,
            member_id=member_id,
            action="consultar_vault_miembro_denegado",
            vault_item_id=item_id,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada"
        )

    def on_denied(reason: str) -> None:
        # Cada log tiene su propio vocabulario de "denegado"; por eso lo escribe la
        # ruta y no el punto de paso.
        if reason == secret_access.DENIED_STEP_UP:
            vault_action, vault_result = "consultar_admin_denegado", "denegado"
            panel_action = "consultar_vault_miembro_denegado"
        else:
            # Fallo de integridad: no es un rechazo del usuario sino un ítem que no
            # supera la verificación, y se registra como error.
            vault_action, vault_result = "consultar_admin", "error"
            panel_action = "consultar_vault_miembro"
        vault_repo.insert_audit(
            user_id=owner_id,
            item_id=item_id,
            action=vault_action,
            result=vault_result,
            actor_user_id=actor_id,
        )
        _audit(caller, member_id=member_id, action=panel_action, vault_item_id=item_id)

    # El AAD es el user_id del DUEÑO, no el del caller: identifica de quién es el
    # dato, no quién pregunta. Por eso el acceso de la empresa no obliga a tocar
    # vault_crypto ni debilita el cifrado.
    secret = secret_access.read_foreign_secret(
        caller=caller,
        scope="vault_item",
        subject_id=owner_id,
        target_id=item_id,
        envelope=item,
        step_up_code=step_up_code,
        on_denied=on_denied,
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
    _audit(
        caller,
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
