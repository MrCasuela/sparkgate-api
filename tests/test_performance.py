import time

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.skip(reason="Performance test - run manually with services up")
@pytest.mark.asyncio
async def test_evaluate_latency(client):
    times = []
    password = "TestPassword123!"
    async with client as ac:
        for _ in range(10):
            start = time.time()
            response = await ac.post(
                "/api/v1/passwords/evaluate",
                json={"password": password},
                headers={"Authorization": "Bearer test-token"},
            )
            elapsed = time.time() - start
            times.append(elapsed)

    avg_time = sum(times) / len(times)
    assert avg_time < 5.0, f"Average latency {avg_time:.2f}s exceeds 5s threshold"


@pytest.mark.skip(reason="Performance test - run manually with services up")
@pytest.mark.asyncio
async def test_generate_latency(client):
    times = []
    async with client as ac:
        for _ in range(10):
            start = time.time()
            response = await ac.post(
                "/api/v1/passwords/generate",
                json={"length": 16, "complexity_level": "high"},
                headers={"Authorization": "Bearer test-token"},
            )
            elapsed = time.time() - start
            times.append(elapsed)

    avg_time = sum(times) / len(times)
    assert avg_time < 3.0, f"Average latency {avg_time:.2f}s exceeds 3s threshold"
