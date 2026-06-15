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
