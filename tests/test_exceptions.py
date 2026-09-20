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


class TestStepUpRequired:
    """403 de segundo factor (HU18). `code` va de primer nivel para que el cliente distinga
    'llevá a enrolarse' de 'pedí el código otra vez'."""

    @pytest.mark.parametrize(
        "code", ["totp_no_enrolado", "totp_invalido", "totp_reutilizado", "totp_bloqueado"]
    )
    def test_cada_codigo_es_un_403_con_su_mensaje(self, code):
        from app.core.exceptions import STEP_UP_DETAILS, StepUpRequired

        exc = StepUpRequired(code=code)
        assert exc.status_code == 403
        assert exc.code == code
        assert exc.detail == STEP_UP_DETAILS[code]

    def test_por_defecto_es_codigo_invalido(self):
        from app.core.exceptions import StepUpRequired

        assert StepUpRequired().code == "totp_invalido"

    def test_los_mensajes_son_distintos_entre_si(self):
        """Si dos códigos compartieran mensaje, la UI no podría distinguirlos ni por texto."""
        from app.core.exceptions import STEP_UP_DETAILS

        assert len(set(STEP_UP_DETAILS.values())) == len(STEP_UP_DETAILS)

    def test_un_codigo_desconocido_falla_al_construirse(self):
        """Un typo en un code no puede llegar a producción como un 403 sin mensaje."""
        from app.core.exceptions import StepUpRequired

        with pytest.raises(KeyError):
            StepUpRequired(code="totp_inventado")

    def test_core_y_totp_service_hablan_de_los_mismos_codigos(self):
        """core no puede importar services, así que los códigos se repiten: este test es lo
        que impide que una lista cambie sin la otra."""
        from app.core.exceptions import STEP_UP_DETAILS
        from app.services import totp_service

        assert set(STEP_UP_DETAILS) == {
            totp_service.NO_ENROLADO,
            totp_service.INVALIDO,
            totp_service.REUTILIZADO,
            totp_service.BLOQUEADO,
        }

    def test_secret_access_sigue_reexportandola(self):
        """Ningún import existente cambia."""
        from app.core.exceptions import StepUpRequired
        from app.services import secret_access

        assert secret_access.StepUpRequired is StepUpRequired

    @pytest.mark.asyncio
    async def test_el_handler_devuelve_detail_y_code_de_primer_nivel(self):
        import json

        from app.core.exceptions import StepUpRequired, step_up_required_handler

        exc = StepUpRequired(code="totp_no_enrolado")
        request = Request({"type": "http", "method": "POST", "path": "/"})
        response = await step_up_required_handler(request, exc)

        assert response.status_code == 403
        assert json.loads(response.body) == {"detail": exc.detail, "code": "totp_no_enrolado"}

    @pytest.mark.asyncio
    async def test_registrado_en_la_app_el_403_lleva_el_code(self):
        """Punta a punta por la app real: una ruta que levanta StepUpRequired responde con
        el code. Prueba el REGISTRO del handler en main.py, no solo la función."""
        from httpx import ASGITransport, AsyncClient

        from app.api.dependencies import verify_token
        from app.main import app
        from app.services import secret_access

        app.dependency_overrides[verify_token] = lambda: {"id": "u", "premium": True}
        app.add_api_route(
            "/__test_step_up",
            lambda: (_ for _ in ()).throw(secret_access.StepUpRequired(code="totp_reutilizado")),
            methods=["GET"],
        )
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                response = await ac.get("/__test_step_up")
        finally:
            app.router.routes = [r for r in app.router.routes if getattr(r, "path", "") != "/__test_step_up"]
            app.dependency_overrides.clear()

        assert response.status_code == 403
        assert response.json()["code"] == "totp_reutilizado"
        assert isinstance(response.json()["detail"], str)
