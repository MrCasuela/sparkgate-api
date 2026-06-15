import pytest


@pytest.mark.skip(reason="Requires Ollama running locally")
@pytest.mark.asyncio
async def test_ollama_connection():
    import httpx
    async with httpx.AsyncClient() as client:
        response = await client.get("http://localhost:11434", timeout=5.0)
    assert response.status_code == 200


@pytest.mark.skip(reason="Requires Ollama running locally with llama3.2:3b")
@pytest.mark.asyncio
async def test_ollama_evaluate_semantic():
    import httpx
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
            },
            timeout=30.0,
        )
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    assert len(data["response"]) > 0


@pytest.mark.skip(reason="Requires Ollama running locally with llama3.2:3b")
@pytest.mark.asyncio
async def test_ollama_response_time():
    import time
    import httpx
    start = time.time()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:3b",
                "prompt": 'Generate a 16-char password. Return JSON with "generated_password" and "explanation".',
                "stream": False,
            },
            timeout=30.0,
        )
    elapsed = time.time() - start
    assert response.status_code == 200
    assert elapsed < 5.0, f"Ollama response took {elapsed:.2f}s, expected < 5s"
