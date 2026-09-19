from datetime import datetime

from pydantic import BaseModel, Field, computed_field, field_validator

from app.schemas.auth import EMAIL_RE


class CredentialOut(BaseModel):
    id: str
    type: str
    service_name: str
    status: str
    updated_at: datetime
    supabase_user_id: str | None = None
    # None = credencial sin asignar (pool). La credencial es de la organización; el
    # integrante es solo su portador actual.
    member_id: str | None = None
    username: str | None = None
    # Cuándo se guardó/rotó por última vez el secreto. NUNCA el secreto: el
    # criptograma vive en otra tabla y solo sale por el endpoint de reveal.
    secret_updated_at: datetime | None = None
    # Alguien que ya no debería conoce esta contraseña (se bloqueó a su portador o la
    # credencial cambió de manos). Solo se apaga guardando una contraseña nueva.
    rotation_required: bool = False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_secret(self) -> bool:
        return self.secret_updated_at is not None


class RotationSuggestion(BaseModel):
    """Una credencial cuya contraseña conviene cambiar tras bloquear o reemplazar a
    alguien. Viaja dentro de la respuesta que el panel ya recibe: no hay endpoint
    aparte que consultar."""

    credential_id: str
    service_name: str
    type: str
    # De quién es la contraseña que conoce: el integrante bloqueado o el anterior.
    member_name: str | None = None


class MemberOut(BaseModel):
    id: str
    full_name: str
    email: str
    role_title: str | None = None
    supabase_user_id: str | None = None
    credentials: list[CredentialOut] = []


class CreateMemberRequest(BaseModel):
    full_name: str = Field(..., min_length=1, max_length=120)
    email: str
    role_title: str | None = Field(None, max_length=120)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        if not EMAIL_RE.match(v):
            raise ValueError("Formato de correo electrónico inválido")
        return v


class CreateMemberResponse(BaseModel):
    member: MemberOut
    # Se devuelve al crear y se guarda cifrada como la contraseña vigente de su cuenta
    # interna, para que la empresa pueda volver a verla. NUNCA va a la auditoría.
    temporary_password: str
    # False si no se pudo guardar (clave maestra caída o falla de base): en ese caso la
    # respuesta es la única copia y el panel debe decirlo.
    secret_stored: bool = False


class CreateCredentialRequest(BaseModel):
    member_id: str | None = None
    service_name: str = Field(..., min_length=1, max_length=120)
    username: str | None = Field(None, max_length=200)
    # Opcionales: se puede registrar la cuenta ahora y guardar la contraseña después.
    password: str | None = Field(None, min_length=1, max_length=256)
    notes: str | None = Field(None, max_length=1000)


class CredentialSecretRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)
    username: str | None = Field(None, max_length=200)
    notes: str | None = Field(None, max_length=1000)
    # Solo cuentas internas: además de guardarla, aplicarla de verdad a la cuenta de
    # Auth, para que lo guardado sea la contraseña VIGENTE y no una anotación.
    apply_to_account: bool = False


class CredentialSecretSaveResponse(BaseModel):
    credential: CredentialOut
    admin_api_success: bool
    # Nunca devuelve el plaintext: el cliente ya lo tiene.
    secret_stored: bool


class CredentialSecretOut(BaseModel):
    id: str
    service_name: str
    type: str
    username: str | None = None
    password: str
    notes: str | None = None
    secret_updated_at: datetime | None = None


class ReassignCredentialRequest(BaseModel):
    # None = devolver la credencial al pool sin asignar.
    member_id: str | None = None


class ReassignCredentialResponse(BaseModel):
    credential: CredentialOut
    rotation_suggested: list[RotationSuggestion] = []


class CredentialActionRequest(BaseModel):
    new_password: str | None = Field(None, min_length=12, max_length=64)


class CredentialActionResponse(BaseModel):
    credential: CredentialOut
    admin_api_success: bool
    # La contraseña que el backend realmente usó. Antes se descartaba: el panel
    # mostraba la que la extensión había generado por su cuenta y el backend
    # nunca la tuvo, así que no había forma de guardarla ni de comprobar que era
    # la aplicada.
    #   applied_password   revoke: solo si Auth confirmó el cambio (None si falló)
    #   suggested_password suggest: la propuesta para aplicar a mano en el servicio
    applied_password: str | None = None
    suggested_password: str | None = None
    # Si esa contraseña quedó guardada cifrada. False = la respuesta es la única copia.
    secret_stored: bool = False
    # Credenciales que el integrante bloqueado también conocía y conviene rotar.
    rotation_suggested: list[RotationSuggestion] = []


class AuditLogEntryOut(BaseModel):
    id: str
    # Anulable: se guarda fuera del hash justamente para poder borrarlo por
    # supresión (Ley 21.719) sin romper la cadena.
    actor_email: str | None = None
    actor_user_id: str | None = None
    # None = credencial sin asignar (pool), o evento que no involucra a un integrante.
    member_id: str | None = None
    # Reasignación: member_id es de quién sale, target_member_id a quién pasa.
    target_member_id: str | None = None
    # Opcionales desde HU21: un evento de bóveda no tiene credencial de
    # gobernanza asociada, lleva vault_item_id.
    credential_id: str | None = None
    credential_type: str | None = None
    vault_item_id: str | None = None
    action: str
    created_at: datetime
