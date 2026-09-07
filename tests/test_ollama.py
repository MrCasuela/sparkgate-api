import os

import pytest

RUN_MANUAL = os.environ.get("SPARKGATE_RUN_MANUAL") == "1"


@pytest.mark.skipif(not RUN_MANUAL, reason="Requires Ollama running locally — run with SPARKGATE_RUN_MANUAL=1")
@pytest.mark.asyncio
async def test_ollama_connection():
    import httpx
    async with httpx.AsyncClient() as client:
        response = await client.get("http://localhost:11434", timeout=5.0)
    assert response.status_code == 200


@pytest.mark.skipif(not RUN_MANUAL, reason="Requires Ollama running locally with llama3.2:3b — run with SPARKGATE_RUN_MANUAL=1")
@pytest.mark.asyncio
async def test_ollama_evaluate_semantic():
    import httpx
    from app.services.ai_engine import EVALUATE_NUM_PREDICT, OLLAMA_OPTIONS

    options = dict(OLLAMA_OPTIONS)
    options["num_predict"] = EVALUATE_NUM_PREDICT
    prompt = (
        'Analyze this password: "Juanito2026". '
        'Return JSON with ai_score (0-100), ai_feedback (string), ai_suggestions (array).'
    )
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:3b",
                "prompt": prompt,
                "stream": False,
                "options": options,
            },
            timeout=30.0,
        )
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    assert len(data["response"]) > 0


@pytest.mark.skipif(not RUN_MANUAL, reason="Requires Ollama running locally with llama3.2:3b — run with SPARKGATE_RUN_MANUAL=1")
@pytest.mark.asyncio
async def test_ollama_response_time():
    import time
    import httpx
    from app.services.ai_engine import GENERATE_NUM_PREDICT, OLLAMA_OPTIONS

    options = dict(OLLAMA_OPTIONS)
    options["num_predict"] = GENERATE_NUM_PREDICT
    start = time.time()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:3b",
                "prompt": 'Generate a 16-char password. Return JSON with "generated_password" and "explanation".',
                "stream": False,
                "options": options,
            },
            timeout=30.0,
        )
    elapsed = time.time() - start
    assert response.status_code == 200
    assert elapsed < 5.0, f"Ollama response took {elapsed:.2f}s, expected < 5s"
