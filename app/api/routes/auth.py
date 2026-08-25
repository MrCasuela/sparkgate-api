from fastapi import APIRouter, HTTPException, status

from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
)
from app.services.db_client import get_supabase

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
async def logout():
    supabase = get_supabase()
    try:
        supabase.auth.sign_out()
        return {"message": "Logged out"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
