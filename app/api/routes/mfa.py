"""Enrolamiento del segundo factor TOTP (HU18).

Router propio bajo /me y con require_user, no bajo /dashboard: el segundo factor lo necesita
CUALQUIER persona que lea un secreto ajeno (la empresa, pero también el trabajador que retira
la credencial que le asignaron), y el router de /dashboard entero cuelga de require_enterprise.
Tampoco va dentro de me.py, que tiene declarado el contrato de «solo lectura de lo que la
organización asignó»: esto es seguridad de la cuenta.

El código viaja en el header X-SparkGate-TOTP, igual que en las demás operaciones sensibles
(un solo helper en el cliente), y no en el body: un DELETE con body lo descartan algunos
proxies.

Auditoría en vault_audit_log y no en dashboard_audit_log: el enrolamiento es de la PERSONA,
una cuenta personal no tiene org_id, y además el propio usuario lo ve en GET /vault/audit.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.api.dependencies import optional_step_up_code, require_user
from app.core.exceptions import ServiceUnavailableError, StepUpRequired
from app.schemas.mfa import MfaEnrollResponse, MfaStatusOut
from app.services import totp_service, vault_repo

logger = logging.getLogger("sparkgate.mfa")
router = APIRouter(prefix="/api/v1/me/mfa", tags=["mfa"])


def _audit(user: dict, action: str, result: str = "ok") -> None:
    # El actor ES el dueño, así que actor_user_id va nulo. Nunca lleva el secreto ni el
    # código: el payload de vault_audit_log solo admite UUIDs y enums.
    vault_repo.insert_audit(
        user_id=user["id"], item_id=None, action=action, result=result, actor_user_id=None
    )


def _unavailable() -> ServiceUnavailableError:
    return ServiceUnavailableError(
        "Segundo factor",
        detail="El segundo factor no está disponible en este momento. Se rechaza en vez de omitirlo.",
    )


@router.get("", response_model=MfaStatusOut)
async def mfa_status(user: dict = Depends(require_user)):
    """No audita: consultar el propio estado no es un evento de seguridad."""
    return MfaStatusOut(**totp_service.get_status(user["id"]))


@router.post("/enroll", response_model=MfaEnrollResponse, status_code=status.HTTP_201_CREATED)
async def enroll(user: dict = Depends(require_user)):
    """Genera un secreto NUEVO y lo deja pendiente. No habilita nada hasta /confirm.

    Sobre un factor ya confirmado responde 409: un JWT robado no puede pisar el factor de la
    víctima por uno propio. Sobre uno pendiente lo reemplaza (reintentar es normal).
    """
    account_name = user.get("email") or user["id"]
    try:
        enrollment = totp_service.start_enrollment(user["id"], account_name)
    except totp_service.TotpAlreadyEnrolled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ya tenés un segundo factor activo. Desactivalo con un código vigente antes de configurar otro.",
        )
    except totp_service.TotpUnavailable:
        logger.error("Enrolamiento imposible: TOTP_MASTER_KEY ausente o mal formada")
        raise _unavailable()

    _audit(user, "mfa_enrolar")
    logger.info("Enrolamiento TOTP iniciado para el usuario %s", user["id"])
    return enrollment


@router.post("/confirm", response_model=MfaStatusOut)
async def confirm(
    user: dict = Depends(require_user),
    code: str | None = Depends(optional_step_up_code),
):
    """El primer código correcto activa el factor."""
    try:
        totp_service.confirm_enrollment(user["id"], code)
    except totp_service.TotpDenied as denied:
        _audit(user, "mfa_denegado", result="denegado")
        raise StepUpRequired(code=denied.code) from None
    except totp_service.TotpUnavailable:
        raise _unavailable()

    _audit(user, "mfa_activar")
    logger.info("Segundo factor activado para el usuario %s", user["id"])
    return MfaStatusOut(**totp_service.get_status(user["id"]))


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def disable(
    user: dict = Depends(require_user),
    code: str | None = Depends(optional_step_up_code),
):
    """Desactiva el factor. Exige un código vigente: sin eso, un JWT robado apagaría el
    segundo factor y después leería todo."""
    try:
        totp_service.disable(user["id"], code)
    except totp_service.TotpDenied as denied:
        _audit(user, "mfa_denegado", result="denegado")
        raise StepUpRequired(code=denied.code) from None
    except totp_service.TotpUnavailable:
        raise _unavailable()

    _audit(user, "mfa_desactivar")
    logger.info("Segundo factor desactivado para el usuario %s", user["id"])
    return Response(status_code=status.HTTP_204_NO_CONTENT)
