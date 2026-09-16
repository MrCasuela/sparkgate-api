import re

from pydantic import BaseModel, Field, field_validator

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        if not EMAIL_RE.match(v):
            raise ValueError("Formato de correo electrónico inválido")
        return v


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterResponse(BaseModel):
    message: str
    user_id: str
    plan: str = Field(default="Gratuito")
    access_token: str | None = None


class LoginResponse(BaseModel):
    access_token: str
    user_id: str
    premium: bool = Field(default=False)


class DeleteAccountRequest(BaseModel):
    confirm_email: str
    password: str


class UserInfo(BaseModel):
    id: str
    email: str | None = None
    premium: bool = Field(default=False)
