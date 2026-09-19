from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import Client

from app.services import org_repo
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
        # otherwise user_metadata (premium, type_account) is always read as {}.
        user_data = dumped.get("user", dumped)
        user_metadata = user_data.get("user_metadata", {}) or {}
        user_data["premium"] = user_metadata.get("premium", False)
        user_data["type_account"] = user_metadata.get("type_account", "personal")
        # Deliberadamente NO se aplana como "org_id": el claim es cache y puede
        # estar desactualizado o adulterado. La clave "org_id" que leen los
        # handlers solo la escribe require_enterprise tras resolverla contra la
        # tabla organizations, así que un claim manipulado solo puede negar
        # acceso, nunca concederlo sobre una organización ajena.
        user_data["claimed_org_id"] = user_metadata.get("org_id")
        return user_data
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


async def require_user(
    user: dict | None = Depends(verify_token),
) -> dict:
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user


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


async def require_enterprise(
    user: dict | None = Depends(verify_token),
) -> dict:
    """Guard del panel de gobernanza: cuenta de empresa con organización propia.

    El claim type_account resuelve el rechazo sin tocar la base (barato y sin
    riesgo: un claim falso solo puede negar). La organización, en cambio, se
    resuelve siempre contra la tabla, que es la fuente de verdad, y se publica
    como user["org_id"] — la única clave que los handlers pasan a los filtros
    de tenencia del repositorio.
    """
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if user.get("type_account") != "enterprise":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Esta función es exclusiva de las cuentas de empresa.",
        )
    organization = org_repo.get_organization_by_owner(user["id"])
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tu cuenta de empresa no tiene una organización asociada.",
        )
    user["org_id"] = organization["id"]
    return user


async def optional_step_up_code(
    x_sparkgate_totp: str | None = Header(None, alias="X-SparkGate-TOTP"),
) -> str | None:
    """Código de segundo factor que el cliente adjunta a una operación sensible.

    Hoy nadie lo valida (secret_access._verify_step_up es un no-op), pero las rutas
    que leen secretos ajenos ya lo reciben y lo pasan: cuando HU18 lo implemente, el
    contrato de las rutas no cambia, solo se empieza a exigir el header.
    """
    return x_sparkgate_totp
