import pytest
from app.core.exceptions import ServiceUnavailableError, HIBPError, AIServiceError
from fastapi import Request


class TestExceptions:
    def test_service_unavailable_default(self):
        exc = ServiceUnavailableError(service="Ollama")
        assert exc.status_code == 503
        assert "Ollama" in exc.detail

    def test_service_unavailable_custom(self):
        exc = ServiceUnavailableError(service="Ollama", detail="custom msg")
        assert exc.detail == "custom msg"

    def test_hibp_error_default(self):
        exc = HIBPError()
        assert exc.status_code == 502
        assert "HIBP" in exc.detail

    def test_hibp_error_custom(self):
        exc = HIBPError(detail="custom hibp")
        assert exc.detail == "custom hibp"

    def test_ai_error_default(self):
        exc = AIServiceError()
        assert exc.status_code == 502
        assert "AI" in exc.detail

    def test_ai_error_custom(self):
        exc = AIServiceError(detail="custom ai")
        assert exc.detail == "custom ai"

    @pytest.mark.asyncio
    async def test_service_unavailable_handler_returns_json(self):
        from app.core.exceptions import service_unavailable_handler
        exc = ServiceUnavailableError(service="test")
        request = Request({"type": "http", "method": "GET", "path": "/"})
        response = await service_unavailable_handler(request, exc)
        assert response.status_code == 503
        assert response.body is not None

    @pytest.mark.asyncio
    async def test_hibp_handler_returns_json(self):
        from app.core.exceptions import hibp_error_handler
        exc = HIBPError()
        request = Request({"type": "http", "method": "GET", "path": "/"})
        response = await hibp_error_handler(request, exc)
        assert response.status_code == 502

    @pytest.mark.asyncio
    async def test_ai_handler_returns_json(self):
        from app.core.exceptions import ai_error_handler
        exc = AIServiceError()
        request = Request({"type": "http", "method": "GET", "path": "/"})
        response = await ai_error_handler(request, exc)
        assert response.status_code == 502
