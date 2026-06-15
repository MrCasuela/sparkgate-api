import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.services.db_client import get_supabase


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_endpoint_returns_401_with_invalid_token(client):
    """When token is provided but invalid, should return 401 not None."""
    async with client as ac:
        response = await ac.post(
            "/api/v1/passwords/evaluate",
            json={"password": "test"},
            headers={"Authorization": "Bearer eyJinvalidtoken"},
        )
    assert response.status_code == 401
    assert "Invalid or expired token" in response.json()["detail"]
