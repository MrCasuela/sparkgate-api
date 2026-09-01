from datetime import datetime

from pydantic import BaseModel, Field


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
    credentials: list[CredentialOut] = []


class CredentialActionRequest(BaseModel):
    new_password: str = Field(..., min_length=12, max_length=64)


class CredentialActionResponse(BaseModel):
    credential: CredentialOut
    admin_api_success: bool


class AuditLogEntryOut(BaseModel):
    id: str
    actor_email: str
    member_id: str
    credential_id: str
    credential_type: str
    action: str
    created_at: datetime
