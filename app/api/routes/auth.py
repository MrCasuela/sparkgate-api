import logging

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from app.api.dependencies import require_user, security_scheme
from app.schemas.auth import (
    DeleteAccountRequest,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
)
from app.services import dashboard_repo, vault_repo
from app.services.db_client import create_auth_client, get_supabase_admin

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

logger = logging.getLogger("sparkgate.auth")


@router.post("/register", response_model=RegisterResponse)
async def register(body: RegisterRequest):
    supabase = create_auth_client()
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
    finally:
        supabase.auth.close()

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
    supabase = create_auth_client()
    try:
        result = supabase.auth.sign_in_with_password({
            "email": body.email,
            "password": body.password,
        })
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    finally:
        supabase.auth.close()

    user_metadata = result.user.user_metadata or {}
    return LoginResponse(
        access_token=result.session.access_token,
        user_id=result.user.id,
        premium=user_metadata.get("premium", False),
    )


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
        # A GoTrue outage and a bad token both land here; only the log tells them apart.
        logger.error("Logout sign_out failed: %s", e)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return {"message": "Logged out"}


@router.delete("/account", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(body: DeleteAccountRequest, user: dict = Depends(require_user)):
    """Irreversible account + data erasure (Ley 21.719 right to erasure). Requires
    the caller to type their own email exactly (catches accidental clicks for free,
    before any network round-trip) and re-authenticate with their password (a stolen
    Bearer token alone can't destroy the account). The Supabase user is deleted last,
    so a failure partway through never leaves an account with no data behind it."""
    user_id = user["id"]
    session_email = (user.get("email") or "").strip().lower()

    if body.confirm_email.strip().lower() != session_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Debes escribir tu correo exactamente para confirmar la eliminación.",
        )

    supabase = create_auth_client()
    try:
        supabase.auth.sign_in_with_password({"email": session_email, "password": body.password})
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Contraseña incorrecta.")
    finally:
        supabase.auth.close()

    deleted_count = vault_repo.delete_all_items(user_id)
    vault_repo.insert_audit(
        user_id=user_id, item_id=None, action="eliminar_cuenta", result="ok", deleted_count=deleted_count
    )
    dashboard_repo.detach_supabase_user(user_id)

    try:
        get_supabase_admin().auth.admin.delete_user(user_id)
    except Exception as e:
        logger.error("Account deletion: delete_user failed for %s after data purge: %s", user_id, e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Tus datos fueron eliminados, pero la cuenta no pudo cerrarse. Contacta soporte.",
        )
