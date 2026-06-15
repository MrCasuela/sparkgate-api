from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterResponse(BaseModel):
    message: str
    user_id: str


class LoginResponse(BaseModel):
    access_token: str
    user_id: str
    premium: bool = Field(default=False)


class UserInfo(BaseModel):
    id: str
    email: str | None = None
    premium: bool = Field(default=False)
