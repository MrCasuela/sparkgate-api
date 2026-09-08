from supabase import create_client, Client

from app.core.config import settings


_supabase_client: Client | None = None
_supabase_admin_client: Client | None = None


def get_supabase() -> Client:
    global _supabase_client
    if _supabase_client is None:
        _supabase_client = create_client(settings.supabase_url, settings.supabase_key)
    return _supabase_client


def get_supabase_admin() -> Client:
    """Service-role client for Admin API calls (session revocation, user management,
    dashboard tables). Never expose this client's key or results derived from it to
    unauthenticated or non-admin callers."""
    global _supabase_admin_client
    if _supabase_admin_client is None:
        _supabase_admin_client = create_client(
            settings.supabase_url, settings.supabase_service_role_key
        )
    return _supabase_admin_client


async def check_connection() -> bool:
    try:
        client = get_supabase()
        client.auth.get_session()
        return True
    except Exception:
        return False
