from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.schemas.auth import EMAIL_RE


class CredentialOut(BaseModel):
    id: str
    type: str
    service_name: str
    status: str
    updated_at: datetime
    supabase_user_id: str | None = None


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
    # Se devuelve una sola vez y no se persiste en ningún lado: ni en la tabla
    # de credenciales ni en la auditoría.
    temporary_password: str


class CredentialActionRequest(BaseModel):
    new_password: str | None = Field(None, min_length=12, max_length=64)


class CredentialActionResponse(BaseModel):
    credential: CredentialOut
    admin_api_success: bool


class AuditLogEntryOut(BaseModel):
    id: str
    actor_email: str
    member_id: str
    # Opcionales desde HU21: un evento de bóveda no tiene credencial de
    # gobernanza asociada, lleva vault_item_id.
    credential_id: str | None = None
    credential_type: str | None = None
    vault_item_id: str | None = None
    action: str
    created_at: datetime
