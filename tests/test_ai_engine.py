import json

import httpx
import pytest
import respx
from httpx import Response

from app.core.config import settings
from app.services import ai_engine


@pytest.mark.asyncio
async def test_evaluate_parses_valid_ollama_response(ollama_backend):
    ollama_response = {
        "response": json.dumps({
            "ai_score": 85,
            "ai_feedback": "Contrasena fuerte y segura.",
            "ai_suggestions": ["Usa mas caracteres", "Evita patrones comunes"],
        })
    }
    with respx.mock:
        respx.post(f"{settings.ollama_url}/api/generate").respond(
            json=ollama_response, status_code=200
        )
        result = await ai_engine.evaluate_security("StrongP@ss1", False)

    assert result["ai_score"] == 85
    assert "fuerte" in result["ai_feedback"]
    assert len(result["ai_suggestions"]) == 2


@pytest.mark.asyncio
async def test_evaluate_fallback_on_malformed_json(ollama_backend):
    """When Ollama returns non-JSON, should fallback to entropy-based score."""
    ollama_response = {"response": "Lo siento, no puedo analizar esto."}
    with respx.mock:
        respx.post(f"{settings.ollama_url}/api/generate").respond(
            json=ollama_response, status_code=200
        )
        result = await ai_engine.evaluate_security("Test123!", False)

    assert result["ai_score"] >= 0
    assert result["ai_score"] <= 100
    assert "No se pudo analizar" in result["ai_feedback"]


@pytest.mark.asyncio
async def test_evaluate_raises_on_ollama_timeout(ollama_backend):
    with respx.mock:
        respx.post(f"{settings.ollama_url}/api/generate").mock(
            side_effect=Exception("Connection refused")
        )
        with pytest.raises(Exception):
            await ai_engine.evaluate_security("Test123!", False)


@pytest.mark.asyncio
async def test_generate_parses_valid_ollama_response(ollama_backend):
    ollama_response = {
        "response": json.dumps({
            "generated_password": "Casa#Azul*72!Mar",
            "explanation": "Contrasena memorable basada en escena.",
        })
    }
    with respx.mock:
        respx.post(f"{settings.ollama_url}/api/generate").respond(
            json=ollama_response, status_code=200
        )
        result = await ai_engine.generate_password(length=16)

    assert result["generated_password"] == "Casa#Azul*72!Mar"
    assert "memorable" in result["explanation"]


@pytest.mark.asyncio
async def test_generate_raises_on_invalid_response(ollama_backend):
    ollama_response = {"response": "not json at all"}
    with respx.mock:
        respx.post(f"{settings.ollama_url}/api/generate").respond(
            json=ollama_response, status_code=200
        )
        with pytest.raises(ValueError, match="invalid response"):
            await ai_engine.generate_password(length=16)


@pytest.mark.asyncio
async def test_generate_raises_on_http_error(ollama_backend):
    with respx.mock:
        respx.post(f"{settings.ollama_url}/api/generate").respond(
            status_code=503
        )
        with pytest.raises(Exception):
            await ai_engine.generate_password(length=16)


@pytest.fixture
def ollama_backend():
    old_backend = settings.ai_backend
    old_key = settings.groq_api_key
    settings.ai_backend = "ollama"
    settings.groq_api_key = ""
    yield
    settings.ai_backend = old_backend
    settings.groq_api_key = old_key


# ─── Groq backend tests ─────────────────────────────────────────────

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


@pytest.fixture
def groq_backend():
    old_backend = settings.ai_backend
    old_key = settings.groq_api_key
    settings.ai_backend = "groq"
    settings.groq_api_key = "gsk_test_key"
    yield
    settings.ai_backend = old_backend
    settings.groq_api_key = old_key


@pytest.mark.asyncio
async def test_groq_evaluate_parses_valid_response(groq_backend):
    groq_response = {
        "choices": [{
            "message": {
                "content": json.dumps({
                    "ai_score": 90,
                    "ai_feedback": "Contrasena muy segura.",
                    "ai_suggestions": ["Sigue asi"],
                })
            }
        }]
    }
    with respx.mock:
        respx.post(GROQ_API_URL).respond(json=groq_response, status_code=200)
        result = await ai_engine.evaluate_security("StrongP@ss1", False)

    assert result["ai_score"] == 90
    assert "muy segura" in result["ai_feedback"]
    assert len(result["ai_suggestions"]) == 1


@pytest.mark.asyncio
async def test_groq_evaluate_fallback_on_malformed_content(groq_backend):
    groq_response = {
        "choices": [{"message": {"content": "Esto no es JSON valido"}}]
    }
    with respx.mock:
        respx.post(GROQ_API_URL).respond(json=groq_response, status_code=200)
        result = await ai_engine.evaluate_security("Test123!", False)

    assert result["ai_score"] >= 0
    assert "No se pudo analizar" in result["ai_feedback"]


@pytest.mark.asyncio
async def test_groq_evaluate_raises_on_http_error(groq_backend):
    with respx.mock:
        respx.post(GROQ_API_URL).respond(status_code=401)
        with pytest.raises(httpx.HTTPStatusError):
            await ai_engine.evaluate_security("Test123!", False)


@pytest.mark.asyncio
async def test_groq_generate_parses_valid_response(groq_backend):
    groq_response = {
        "choices": [{
            "message": {
                "content": json.dumps({
                    "generated_password": "Casa#Azul*72!Mar",
                    "explanation": "Memorable.",
                })
            }
        }]
    }
    with respx.mock:
        respx.post(GROQ_API_URL).respond(json=groq_response, status_code=200)
        result = await ai_engine.generate_password(length=16)

    assert result["generated_password"] == "Casa#Azul*72!Mar"
    assert "Memorable" in result["explanation"]


@pytest.mark.asyncio
async def test_groq_generate_raises_on_invalid_response(groq_backend):
    groq_response = {
        "choices": [{"message": {"content": "not json at all"}}]
    }
    with respx.mock:
        respx.post(GROQ_API_URL).respond(json=groq_response, status_code=200)
        with pytest.raises(ValueError, match="invalid response"):
            await ai_engine.generate_password(length=16)


@pytest.mark.asyncio
async def test_groq_generate_raises_on_http_error(groq_backend):
    with respx.mock:
        respx.post(GROQ_API_URL).respond(status_code=503)
        with pytest.raises(httpx.HTTPStatusError):
            await ai_engine.generate_password(length=16)


@pytest.mark.asyncio
async def test_groq_generate_raises_on_timeout(groq_backend):
    with respx.mock:
        respx.post(GROQ_API_URL).mock(side_effect=httpx.ReadTimeout("timeout"))
        with pytest.raises(httpx.ReadTimeout):
            await ai_engine.generate_password(length=16)


@pytest.mark.asyncio
async def test_groq_generate_raises_on_connection_error(groq_backend):
    with respx.mock:
        respx.post(GROQ_API_URL).mock(side_effect=Exception("connection refused"))
        with pytest.raises(Exception):
            await ai_engine.generate_password(length=16)


@pytest.mark.asyncio
async def test_groq_evaluate_raises_on_timeout(groq_backend):
    with respx.mock:
        respx.post(GROQ_API_URL).mock(side_effect=httpx.ReadTimeout("timeout"))
        with pytest.raises(httpx.ReadTimeout):
            await ai_engine.evaluate_security("Test123!", False)


@pytest.mark.asyncio
async def test_groq_generate_with_context(groq_backend):
    """Call generate with context to exercise that code path."""
    groq_response = {
        "choices": [{
            "message": {
                "content": json.dumps({
                    "generated_password": "Casa#Azul*72!Mar",
                    "explanation": "Context test.",
                })
            }
        }]
    }
    with respx.mock:
        respx.post(GROQ_API_URL).respond(json=groq_response, status_code=200)
        result = await ai_engine.generate_password(length=16, context="banco")
    assert result["generated_password"] == "Casa#Azul*72!Mar"


@pytest.mark.asyncio
async def test_ollama_second_parse_fallback(ollama_backend):
    """Ollama returns text with braces but broken JSON → second parser."""
    # This content has braces but isn't valid JSON → triggers regex extraction
    ollama_response = {"response": '{"ai_score" 85 "ai_feedback" "no commas"}'}
    with respx.mock:
        respx.post(f"{settings.ollama_url}/api/generate").respond(
            json=ollama_response, status_code=200
        )
        result = await ai_engine.evaluate_security("Test123!", False)
    assert result["ai_score"] >= 0
