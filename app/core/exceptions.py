from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


class ServiceUnavailableError(HTTPException):
    def __init__(self, service: str, detail: str | None = None):
        super().__init__(
            status_code=503,
            detail=detail or f"{service} is temporarily unavailable",
        )


class HIBPError(HTTPException):
    def __init__(self, detail: str | None = None):
        super().__init__(
            status_code=502,
            detail=detail or "Failed to check password against HIBP",
        )


class AIServiceError(HTTPException):
    def __init__(self, detail: str | None = None):
        super().__init__(
            status_code=502,
            detail=detail or "AI service is not responding",
        )


# Mensajes de los 403 de segundo factor, por `code`. Las claves son las de
# totp_service (NO_ENROLADO, INVALIDO, REUTILIZADO, BLOQUEADO); core no puede importar
# services, así que se repiten acá y un test comprueba que los dos conjuntos coinciden.
STEP_UP_DETAILS = {
    "totp_no_enrolado": "Esta operación requiere un segundo factor y tu cuenta no tiene uno configurado.",
    "totp_invalido": "El código de verificación no es válido o ya expiró.",
    "totp_reutilizado": "Ese código ya se usó. Esperá al siguiente y volvé a intentar.",
    "totp_bloqueado": "Demasiados intentos fallidos. Probá de nuevo en unos minutos.",
}


class StepUpRequired(HTTPException):
    """403: la operación exige un segundo factor vigente (HU18).

    `code` es la parte útil para el cliente: distingue "tu cuenta no tiene factor" (la UI
    debe llevar a enrolarse) de "el código está mal" (la UI debe pedirlo de nuevo). Viaja
    como clave de primer nivel de la respuesta y NO dentro de `detail`, que sigue siendo un
    string en todos los errores del proyecto: nada que hoy lea `body.detail` se rompe.
    """

    def __init__(self, code: str = "totp_invalido", detail: str | None = None):
        self.code = code
        super().__init__(status_code=403, detail=detail or STEP_UP_DETAILS[code])


async def service_unavailable_handler(request: Request, exc: ServiceUnavailableError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


async def hibp_error_handler(request: Request, exc: HIBPError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


async def ai_error_handler(request: Request, exc: AIServiceError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


async def step_up_required_handler(request: Request, exc: StepUpRequired):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "code": exc.code},
    )
