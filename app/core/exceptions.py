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
