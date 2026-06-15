from supabase import create_client, Client

from app.core.config import settings


_supabase_client: Client | None = None


def get_supabase() -> Client:
    global _supabase_client
    if _supabase_client is None:
        _supabase_client = create_client(settings.supabase_url, settings.supabase_key)
    return _supabase_client


async def check_connection() -> bool:
    try:
        client = get_supabase()
        client.auth.get_session()
        return True
    except Exception:
        return False
