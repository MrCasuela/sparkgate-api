from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import Client

from app.services.db_client import get_supabase

security_scheme = HTTPBearer(auto_error=False)


async def verify_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    supabase: Client = Depends(get_supabase),
) -> dict | None:
    if credentials is None:
        return None
    try:
        user_response = supabase.auth.get_user(credentials.credentials)
        dumped = user_response.model_dump() if hasattr(user_response, "model_dump") else dict(user_response)
        # get_user() returns UserResponse{user: User{...}} — unwrap before flattening,
        # otherwise user_metadata (premium, is_admin) is always read as {}.
        user_data = dumped.get("user", dumped)
        user_metadata = user_data.get("user_metadata", {}) or {}
        user_data["premium"] = user_metadata.get("premium", False)
        return user_data
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


async def require_premium(
    user: dict | None = Depends(verify_token),
) -> dict:
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if not user.get("premium", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Premium subscription required",
        )
    return user


async def require_admin(
    user: dict | None = Depends(verify_token),
) -> dict:
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    user_metadata = user.get("user_metadata") or {}
    if not user_metadata.get("is_admin", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user
