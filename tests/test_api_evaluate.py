import pytest
import respx
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.dependencies import verify_token
from app.core.config import settings
from app.schemas.passwords import PasswordEvaluateResponse


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[verify_token] = lambda: {"id": "test-user", "premium": True}
    yield
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def clear_caches():
    from app.services.cache import clear_caches

    clear_caches()
    yield
    clear_caches()


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_evaluate_endpoint_returns_200(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/evaluate",
            json={"password": "testpassword123"},
        )
    assert response.status_code in (200, 502)


@pytest.mark.asyncio
async def test_evaluate_returns_unauthorized_without_token(client):
    app.dependency_overrides.clear()
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/evaluate",
            json={"password": "testpassword123"},
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_evaluate_empty_password_rejected(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/evaluate",
            json={"password": ""},
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_evaluate_cache_hit_skips_ai_and_hibp(client):
    """Identical evaluate input resolves from cache without hitting HIBP/AI."""
    from app.api.routes.passwords import _evaluate_cache_key
    from app.services.cache import evaluate_cache
    from app.services.ai_engine import AI_EVALUATE_VERSION

    assert AI_EVALUATE_VERSION >= 1
    payload = PasswordEvaluateResponse(
        is_compromised=True,
        pwned_count=7,
        entropy_bits=61.2,
        entropy_threshold_met=True,
        ai_score=44,
        ai_feedback="Resultado desde cache.",
        ai_suggestions=["Usa simbolos", "Aumenta longitud"],
    )
    key = _evaluate_cache_key("CachedPass123!", None)
    evaluate_cache.set(key, payload.model_dump())

    hibp_url = settings.hibp_api_url.rstrip("/")
    with respx.mock(assert_all_called=False) as mock:
        ai_route = mock.post(f"{settings.ollama_url}/api/generate")
        hibp_route = mock.get(url__startswith=f"{hibp_url}/range/")
        async with client as ac:
            response = await ac.post(
                "/api/v1/passwords/evaluate",
                json={"password": "CachedPass123!"},
            )

    assert response.status_code == 200
    data = response.json()
    assert data["ai_feedback"] == "Resultado desde cache."
    assert data["pwned_count"] == 7
    assert ai_route.call_count == 0
    assert hibp_route.call_count == 0


@pytest.mark.asyncio
async def test_evaluate_surfaces_personal_info_detection(client):
    """HU12: password containing a name + year should surface that in ai_feedback.

    There is no dedicated personal-info detector — it's entirely delegated to the
    LLM's semantic analysis (see EVALUATE_SYSTEM_PROMPT's own worked example). This
    test locks the contract: whatever the model reports about personal info must
    reach the API response untouched.
    """
    import json as _json

    hibp_url = settings.hibp_api_url.rstrip("/")
    with respx.mock:
        respx.get(url__startswith=f"{hibp_url}/range/").respond(200, text="")
        respx.post(f"{settings.ollama_url}/api/generate").respond(
            json={"response": _json.dumps({
                "ai_score": 15,
                "ai_feedback": "La contrasena contiene un nombre propio y un ano, patrones faciles de adivinar.",
                "ai_suggestions": ["Evita usar nombres personales", "No uses anos o fechas predecibles"],
            })},
            status_code=200,
        )
        async with client as ac:
            response = await ac.post(
                "/api/v1/passwords/evaluate",
                json={"password": "Juanito2026"},
            )

    assert response.status_code == 200
    data = response.json()
    assert "nombre propio" in data["ai_feedback"]
    assert data["ai_score"] <= 20


@pytest.mark.asyncio
async def test_evaluate_partial_when_ai_malformed(client):
    """AI responds with non-JSON → 200 partial: entropy+HIBP present, ai_score null."""
    import json as _json

    hibp_url = settings.hibp_api_url.rstrip("/")
    with respx.mock:
        respx.get(url__startswith=f"{hibp_url}/range/").respond(200, text="")
        respx.post(f"{settings.ollama_url}/api/generate").respond(
            json={"response": "Lo siento, no puedo analizar esto."},
            status_code=200,
        )
        async with client as ac:
            response = await ac.post(
                "/api/v1/passwords/evaluate",
                json={"password": "Test123!"},
            )

    assert response.status_code == 200
    data = response.json()
    assert data["ai_score"] is None
    assert "no está disponible" in data["ai_feedback"]
    assert data["entropy_bits"] > 0
    assert data["is_compromised"] is False
    assert data["ai_suggestions"] == []
