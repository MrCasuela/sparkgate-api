from fastapi import APIRouter

from app.core.config import settings
from app.schemas.common import HealthResponse
from app.services.db_client import check_connection as check_supabase

router = APIRouter(tags=["health"])


async def check_ollama() -> bool:
    import httpx
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(settings.ollama_url, timeout=5.0)
            return response.status_code == 200
    except Exception:
        return False


@router.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    ollama_ok = await check_ollama()
    supabase_ok = await check_supabase()
    status = "ok" if ollama_ok and supabase_ok else "degraded"
    return HealthResponse(status=status, ollama=ollama_ok, supabase=supabase_ok)
