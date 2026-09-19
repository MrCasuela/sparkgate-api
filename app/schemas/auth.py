import re

from pydantic import BaseModel, Field, field_validator, model_validator

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ACCOUNT_TYPES = ("personal", "enterprise")


class RegisterRequest(BaseModel):
    email: str
    password: str
    type_account: str = "personal"
    organization_name: str | None = Field(default=None, min_length=2, max_length=120)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        if not EMAIL_RE.match(v):
            raise ValueError("Formato de correo electrónico inválido")
        return v

    @field_validator("type_account")
    @classmethod
    def validate_type_account(cls, v: str) -> str:
        if v not in ACCOUNT_TYPES:
            raise ValueError("El tipo de cuenta debe ser 'personal' o 'enterprise'")
        return v

    @model_validator(mode="after")
    def enterprise_requires_organization_name(self) -> "RegisterRequest":
        if self.type_account == "enterprise" and not self.organization_name:
            raise ValueError("Una cuenta de empresa necesita el nombre de la organización")
        return self


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterResponse(BaseModel):
    message: str
    user_id: str
    plan: str = Field(default="Gratuito")
    access_token: str | None = None
    type_account: str = Field(default="personal")


class LoginResponse(BaseModel):
    access_token: str
    user_id: str
    premium: bool = Field(default=False)
    # Respaldo no-JWT para que el cliente sepa qué mostrar sin decodificar el
    # token (HU21 AC4).
    type_account: str = Field(default="personal")


class DeleteAccountRequest(BaseModel):
    confirm_email: str
    password: str


class UserInfo(BaseModel):
    id: str
    email: str | None = None
    premium: bool = Field(default=False)
