import pytest
from httpx import AsyncClient, ASGITransport, Response as HTTPResponse

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
async def test_health_returns_degraded_when_ollama_down(client):
    import respx
    from app.core.config import settings
    with respx.mock:
        respx.get(settings.ollama_url).mock(
            side_effect=Exception("Connection refused")
        )
        async with client as ac:
            response = await ac.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["ollama"] is False


@pytest.mark.asyncio
async def test_health_returns_ok_when_ollama_up(client):
    import respx
    from app.core.config import settings
    with respx.mock:
        respx.get(settings.ollama_url).respond(status_code=200)
        async with client as ac:
            response = await ac.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["ollama"] is True
