import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.dependencies import verify_token


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
async def test_generate_random_returns_correct_length(client):
    async with client as ac:
        for length in [12, 16, 24, 64]:
            response = await ac.post(
                "/api/v1/passwords/generate",
                json={"length": length, "mode": "random"},
            )
            assert response.status_code == 200
            data = response.json()
            assert len(data["generated_password"]) == length
            assert data["entropy_bits"] > 0


@pytest.mark.asyncio
async def test_generate_random_always_meets_threshold(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 12, "mode": "random"},
        )
    assert response.status_code == 200
    assert response.json()["entropy_bits"] >= 60.0


@pytest.mark.asyncio
async def test_evaluate_with_context(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/evaluate",
            json={"password": "Test123!", "context": "banco"},
        )
    assert response.status_code in (200, 502)


@pytest.mark.asyncio
async def test_generate_random_excludes_lowercase(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16, "mode": "random", "use_lower": False},
        )
    assert response.status_code == 200
    pwd = response.json()["generated_password"]
    assert not any(c.islower() for c in pwd)


@pytest.mark.asyncio
async def test_generate_random_excludes_uppercase(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16, "mode": "random", "use_upper": False},
        )
    assert response.status_code == 200
    pwd = response.json()["generated_password"]
    assert not any(c.isupper() for c in pwd)


@pytest.mark.asyncio
async def test_generate_random_excludes_digits(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16, "mode": "random", "use_digits": False},
        )
    assert response.status_code == 200
    pwd = response.json()["generated_password"]
    assert not any(c.isdigit() for c in pwd)


@pytest.mark.asyncio
async def test_generate_random_excludes_symbols(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16, "mode": "random", "use_symbols": False},
        )
    assert response.status_code == 200
    pwd = response.json()["generated_password"]
    assert not any(not c.isalnum() for c in pwd)


@pytest.mark.asyncio
async def test_generate_ai_default_mode(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16},
        )
    assert response.status_code in (200, 502)


@pytest.mark.asyncio
async def test_generate_ai_with_style_passphrase(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16, "mode": "ai", "style": "passphrase", "word_count": 4},
        )
    assert response.status_code in (200, 502)


@pytest.mark.asyncio
async def test_generate_ai_with_style_pattern(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16, "mode": "ai", "style": "pattern"},
        )
    assert response.status_code in (200, 502)


@pytest.mark.asyncio
async def test_generate_ai_with_theme(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16, "mode": "ai", "theme": "animales"},
        )
    assert response.status_code in (200, 502)


@pytest.mark.asyncio
async def test_generate_ai_with_personal_words(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16, "mode": "ai", "personal_words": ["toby", "luna"]},
        )
    assert response.status_code in (200, 502)


@pytest.mark.asyncio
async def test_generate_ai_with_all_params(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={
                "length": 16, "mode": "ai", "style": "passphrase",
                "word_count": 4, "theme": "naturaleza",
                "personal_words": ["toby"],
            },
        )
    assert response.status_code in (200, 502)


@pytest.mark.asyncio
async def test_generate_invalid_style_rejected(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16, "mode": "ai", "style": "invalid"},
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_generate_invalid_word_count_rejected(client):
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/generate",
            json={"length": 16, "mode": "ai", "word_count": 10},
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_generate_ai_retry_exhaustion_returns_502(client):
    """All 3 AI attempts return low-entropy password → 502 with exhaustion message."""
    import json as _json
    import respx
    from app.core.config import settings

    low_entropy_content = _json.dumps({
        "generated_password": "abcdefghijkl",   # 12 lowercase → ~56 bits, below 60
        "explanation": "Low entropy test"
    })
    groq_response = {
        "choices": [{"message": {"content": low_entropy_content}}]
    }
    groq_url = "https://api.groq.com/openai/v1/chat/completions"

    with respx.mock:
        respx.post(groq_url).respond(json=groq_response, status_code=200)
        async with client as ac:
            response = await ac.post(
                "/api/v1/passwords/generate",
                json={"length": 14, "mode": "ai"},
            )
    assert response.status_code == 502
    data = response.json()
    assert "minimum entropy threshold" in data["detail"]
