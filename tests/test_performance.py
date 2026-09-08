import os
import time

import pytest
from httpx import AsyncClient, ASGITransport

from app.api.dependencies import verify_token
from app.main import app

RUN_MANUAL = os.environ.get("SPARKGATE_RUN_MANUAL") == "1"


@pytest.fixture
def client():
    if RUN_MANUAL:
        # Measure endpoint latency against the real AI backend (Ollama/OpenRouter),
        # not against Supabase Auth: bypass verify_token with a fake user.
        app.dependency_overrides[verify_token] = lambda: {"id": "perf-user", "premium": True}
    else:
        app.dependency_overrides.pop(verify_token, None)
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.skipif(not RUN_MANUAL, reason="Performance test — run with services up and SPARKGATE_RUN_MANUAL=1")
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


@pytest.mark.skipif(not RUN_MANUAL, reason="Performance test — run with services up and SPARKGATE_RUN_MANUAL=1")
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
