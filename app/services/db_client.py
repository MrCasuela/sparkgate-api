from supabase import create_client, Client

from app.core.config import settings


_supabase_client: Client | None = None
_supabase_admin_client: Client | None = None


def get_supabase() -> Client:
    global _supabase_client
    if _supabase_client is None:
        _supabase_client = create_client(settings.supabase_url, settings.supabase_key)
    return _supabase_client


def create_auth_client() -> Client:
    """Single-use anon client for sign_up / sign_in_with_password.

    supabase-py rewrites the client's Authorization header on SIGNED_IN, so reusing
    the singleton would leave it carrying the last caller's JWT for the life of the
    process. Callers must close it (`client.auth.close()`) when done.
    """
    return create_client(settings.supabase_url, settings.supabase_key)


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
