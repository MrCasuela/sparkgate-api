"""Lo que la organización le asignó al usuario que está logueado (HU21 etapa C).

Router propio, con require_user, y NO dentro de /dashboard: ese router entero cuelga de
require_enterprise, y un endpoint de trabajador ahí quedaría a un Depends mal escrito de
ser un agujero de tenencia.

Solo lectura: el trabajador ve y retira lo que se le asignó; no edita ni borra nada.

require_user no publica org_id (eso lo hace require_enterprise): acá se deriva de la fila
de la credencial, que lleva el suyo.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import optional_step_up_code, require_user
from app.schemas.dashboard import CredentialSecretOut
from app.schemas.me import AssignedCredentialOut
from app.services import credential_secret_repo, dashboard_repo, org_repo, secret_access

logger = logging.getLogger("sparkgate.me")
router = APIRouter(prefix="/api/v1/me", tags=["me"])


@router.get("/credentials", response_model=list[AssignedCredentialOut])
async def list_my_credentials(user: dict = Depends(require_user)):
    """Credenciales externas que la empresa le asignó a este usuario.

    No audita: listar lo propio no es un evento de privacidad, y auditarlo metería una
    escritura de cadena en cada carga de pantalla.
    """
    credentials = dashboard_repo.list_assigned_credentials(user["id"])

    organization_names: dict[str, str] = {}
    result = []
    for credential in credentials:
        org_id = credential["org_id"]
        if org_id not in organization_names:
            organization = org_repo.get_organization(org_id)
            organization_names[org_id] = organization["name"] if organization else ""
        result.append({**credential, "organization_name": organization_names[org_id]})
    return result


@router.post("/credentials/{credential_id}/reveal", response_model=CredentialSecretOut)
async def reveal_my_credential(
    credential_id: str,
    user: dict = Depends(require_user),
    step_up_code: str | None = Depends(optional_step_up_code),
):
    """El trabajador retira la contraseña de una credencial que se le asignó.

    Pasa por el mismo punto de paso único que el reveal de la empresa, así que el
    segundo factor de HU18 lo cubre sin tocar esta ruta.
    """
    secret_access.require_available()

    credential = dashboard_repo.get_assigned_credential(credential_id, user["id"])
    if credential is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credencial no encontrada")

    # Guardas de estado. No son cosméticas: revocar a un trabajador banea sus logins
    # futuros, pero su access token ya emitido sigue vivo ~1 hora (V10). Sin esto, un
    # trabajador recién revocado podría retirar todas las credenciales de la empresa
    # durante esa hora. Se mira el estado de SU cuenta interna, no el de la credencial
    # externa: la externa sigue "activa" aunque él ya no pertenezca a la empresa.
    if dashboard_repo.has_revoked_internal(credential["member_id"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tu acceso a la organización fue revocado.",
        )
    if credential["status"] != "activa":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Esta credencial está pendiente de actualización. Consultá con tu empresa.",
        )

    envelope = credential_secret_repo.get_envelope(credential_id, credential["org_id"])
    if envelope is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Esta credencial no tiene una contraseña guardada.",
        )

    def audit(action: str) -> None:
        # La empresa ve en su propia cadena quién retiró qué. El autor es el
        # trabajador, no un administrador.
        dashboard_repo.insert_audit_log(
            org_id=credential["org_id"],
            actor_user_id=user["id"],
            actor_email=user.get("email"),
            member_id=credential["member_id"],
            credential_id=credential_id,
            credential_type=credential["type"],
            action=action,
        )

    secret = secret_access.read_foreign_secret(
        caller=user,
        scope="org_credential",
        subject_id=envelope["org_id"],
        target_id=credential_id,
        envelope=envelope,
        step_up_code=step_up_code,
        on_denied=lambda reason: audit("consultar_secreto_denegado"),
    )

    audit("consultar_secreto_asignado")
    logger.info("Credencial %s retirada por su integrante asignado %s", credential_id, user["id"])
    return CredentialSecretOut(
        id=credential["id"],
        service_name=credential["service_name"],
        type=credential["type"],
        username=credential.get("username"),
        password=secret["password"],
        notes=secret.get("notes"),
        secret_updated_at=credential.get("secret_updated_at"),
    )
