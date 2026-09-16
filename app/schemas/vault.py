from datetime import datetime

from pydantic import BaseModel, Field


class VaultItemCreate(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=100)
    username: str | None = Field(None, max_length=200)
    password: str = Field(..., min_length=1, max_length=256)
    notes: str | None = Field(None, max_length=1000)


class VaultItemOut(BaseModel):
    id: str
    service_name: str
    username: str | None = None
    created_at: datetime
    updated_at: datetime


class VaultSecretOut(BaseModel):
    id: str
    service_name: str
    username: str | None = None
    password: str
    notes: str | None = None


class VaultPurgeResponse(BaseModel):
    deleted_count: int


class VaultAuditEntryOut(BaseModel):
    id: str
    user_id: str
    item_id: str | None = None
    action: str
    result: str
    created_at: datetime
