from datetime import datetime

from pydantic import BaseModel


class MfaStatusOut(BaseModel):
    """Estado del factor. Nunca lleva el secreto: es lo que consulta la UI para decidir si
    mostrar «Configurar» o «Listo»."""

    enrolled: bool  # True solo si está CONFIRMADO
    pending: bool  # hay un enrolamiento a medias, sin confirmar (no habilita nada)
    confirmed_at: datetime | None = None
    last_used_at: datetime | None = None
    locked_until: datetime | None = None


class MfaEnrollResponse(BaseModel):
    """Única respuesta de toda la API que devuelve el secreto TOTP en claro.

    El cliente dibuja el QR LOCALMENTE a partir de `otpauth_uri`: el backend no sirve una
    imagen, porque un PNG del secreto sería una segunda copia en un formato que el navegador
    y cualquier proxy pueden cachear. `secret` es para el ingreso manual, sin cámara.
    """

    secret: str
    otpauth_uri: str
    issuer: str
    account_name: str
    digits: int
    period: int
    algorithm: str
