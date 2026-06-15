import pytest
import respx
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.dependencies import verify_token
from app.core.config import settings


@pytest.fixture
def ollama_backend():
    old_backend = settings.ai_backend
    old_key = settings.groq_api_key
    settings.ai_backend = "ollama"
    settings.groq_api_key = ""
    yield
    settings.ai_backend = old_backend
    settings.groq_api_key = old_key


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[verify_token] = lambda: {"id": "test-user", "premium": True}
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_evaluate_returns_partial_when_hibp_down(client, ollama_backend):
    """HIBP timeout → still returns entropy + AI, compromised=false."""
    import json as _json
    hibp_url = f"{settings.hibp_api_url}/range/".rstrip("/")
    ollama_url = f"{settings.ollama_url}/api/generate"
    with respx.mock:
        respx.get(url__startswith=hibp_url).mock(
            side_effect=Exception("HIBP connection refused")
        )
        respx.post(ollama_url).respond(
            json={"response": _json.dumps({
                "ai_score": 55,
                "ai_feedback": "Contrasena de prueba.",
                "ai_suggestions": ["Mejorala un poco"],
            })},
            status_code=200,
        )
        async with client as ac:
            response = await ac.post(
                "/api/v1/passwords/evaluate",
                json={"password": "xyzzy_nonexistent_abc_123_TEST"},
            )

    assert response.status_code == 200
    data = response.json()
    assert data["entropy_bits"] > 0
    assert data["is_compromised"] is False
    assert data["pwned_count"] == 0
    assert "ai_score" in data
    assert "ai_feedback" in data


@pytest.mark.asyncio
async def test_generate_random_does_not_call_ollama(client):
    """Random mode must work without Ollama."""
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16, "mode": "random"},
        )
    assert response.status_code == 200
    data = response.json()
    assert len(data["generated_password"]) == 16
    assert data["entropy_bits"] > 60


@pytest.mark.asyncio
async def test_health_degraded_when_services_down(client):
    """Health should reflect service status."""
    async with client as ac:
        response = await ac.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("ok", "degraded")
    assert isinstance(data["ollama"], bool)
    assert isinstance(data["supabase"], bool)


@pytest.mark.asyncio
async def test_evaluate_ai_fails_returns_502(client, ollama_backend):
    """When Ollama is down, evaluate returns 502 with partial response."""
    with respx.mock:
        respx.post(f"{settings.ollama_url}/api/generate").mock(
            side_effect=Exception("Ollama not responding")
        )
        async with client as ac:
            response = await ac.post(
                "/api/v1/passwords/evaluate",
                json={"password": "Test123!"},
            )

    assert response.status_code == 502
    data = response.json()
    assert "AI service unavailable" in data["detail"]
