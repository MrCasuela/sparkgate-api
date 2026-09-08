from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from app.api.dependencies import security_scheme
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
)
from app.services.db_client import get_supabase, get_supabase_admin

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse)
async def register(body: RegisterRequest):
    supabase = get_supabase()
    try:
        result = supabase.auth.sign_up({
            "email": body.email,
            "password": body.password,
            "options": {"data": {"premium": False, "plan": "Gratuito"}},
        })
    except Exception as e:
        if "already registered" in str(e).lower() or "already exists" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Este correo ya está registrado. Inicia sesión con tu cuenta existente.",
            )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Supabase returns a user with no identities (instead of raising) when the
    # email already belongs to a confirmed account, to avoid email enumeration.
    if result.user is not None and not result.user.identities:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Este correo ya está registrado. Inicia sesión con tu cuenta existente.",
        )

    return RegisterResponse(
        message="User registered",
        user_id=result.user.id,
        plan="Gratuito",
        access_token=result.session.access_token if result.session else None,
    )


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest):
    supabase = get_supabase()
    try:
        result = supabase.auth.sign_in_with_password({
            "email": body.email,
            "password": body.password,
        })
        user_metadata = result.user.user_metadata or {}
        return LoginResponse(
            access_token=result.session.access_token,
            user_id=result.user.id,
            premium=user_metadata.get("premium", False),
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post("/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
):
    """Revoke the caller's own session. Uses the Admin API sign_out on the presented
    JWT (scope='global' revokes all sessions of that user, not just this one). The
    caller must pass their own Bearer token — there is no way to revoke another user's
    session from here; offboarding members who leave is handled by the admin dashboard
    revoke endpoint (ban + password rotation via update_user_by_id)."""
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        get_supabase_admin().auth.admin.sign_out(credentials.credentials, scope="global")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return {"message": "Logged out"}
