"""Enrolamiento del segundo factor (HU18): GET/POST/DELETE bajo /api/v1/me/mfa.

Corre el totp_service REAL contra un repositorio en memoria y un reloj controlado: nada acá
stubea al verificador, así que los códigos que se mandan son códigos TOTP de verdad.
"""

import base64
import os
import re
from urllib.parse import parse_qs, urlparse

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.dependencies import verify_token
from app.api.routes import mfa
from app.core.config import settings
from app.main import app
from app.services import totp_service
from tests.totp_fakes import FakeRepo

USER_ID = "user-mfa-1"
EMAIL = "admin@pyme.cl"
KEY = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
T0 = 1_700_000_010.0
URL = "/api/v1/me/mfa"
TOTP = "X-SparkGate-TOTP"


class World:
    def __init__(self):
        self.repo = FakeRepo()
        self.clock = {"now": T0}
        self.audit: list[dict] = []

    def advance(self, seconds=totp_service.PERIOD):
        self.clock["now"] += seconds

    def code(self, secret, steps=0):
        return totp_service._totp(secret).at(int(self.clock["now"]), counter_offset=steps)


@pytest.fixture(autouse=True)
def caller():
    app.dependency_overrides[verify_token] = lambda: {"id": USER_ID, "email": EMAIL}
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def world(monkeypatch):
    w = World()
    monkeypatch.setattr(totp_service, "totp_repo", w.repo)
    monkeypatch.setattr(totp_service, "_now", lambda: w.clock["now"])
    monkeypatch.setattr(settings, "totp_master_key", KEY)
    monkeypatch.setattr(mfa.vault_repo, "insert_audit", lambda **kw: w.audit.append(kw))
    return w


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _enroll(ac):
    response = await ac.post(f"{URL}/enroll")
    assert response.status_code == 201
    return response.json()


async def _enroll_and_confirm(ac, world):
    secret = (await _enroll(ac))["secret"]
    response = await ac.post(f"{URL}/confirm", headers={TOTP: world.code(secret)})
    assert response.status_code == 200
    world.advance()
    return secret


def _actions(world):
    return [(a["action"], a["result"]) for a in world.audit]


# --------------------------------------------------------------------------
# Autenticación
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method, path",
    [("GET", URL), ("POST", f"{URL}/enroll"), ("POST", f"{URL}/confirm"), ("DELETE", URL)],
)
async def test_sin_autenticar_los_cuatro_responden_401(client, world, method, path):
    app.dependency_overrides.clear()  # sin override: sin Bearer no hay usuario
    async with client as ac:
        response = await ac.request(method, path)
    assert response.status_code == 401
    assert world.audit == [] and world.repo.rows == {}


# --------------------------------------------------------------------------
# Estado y enrolamiento
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sin_factor_el_estado_esta_vacio(client, world):
    async with client as ac:
        body = (await ac.get(URL)).json()

    assert (body["enrolled"], body["pending"]) == (False, False)
    assert world.audit == []  # consultar el propio estado no es un evento de seguridad


@pytest.mark.asyncio
async def test_enroll_devuelve_lo_que_la_extension_necesita_para_dibujar_el_qr(client, world):
    async with client as ac:
        body = await _enroll(ac)

    uri = urlparse(body["otpauth_uri"])
    query = parse_qs(uri.query)
    assert (uri.scheme, uri.netloc) == ("otpauth", "totp")
    assert query["secret"] == [body["secret"]] and query["issuer"] == ["SparkGate"]
    assert re.fullmatch(r"[A-Z2-7]{32}", body["secret"])
    assert (body["digits"], body["period"], body["algorithm"]) == (6, 30, "SHA1")
    assert body["issuer"] == "SparkGate" and body["account_name"] == EMAIL
    assert _actions(world) == [("mfa_enrolar", "ok")]


@pytest.mark.asyncio
async def test_un_factor_sin_confirmar_no_cuenta_como_enrolado(client, world):
    async with client as ac:
        await _enroll(ac)
        body = (await ac.get(URL)).json()

    assert (body["enrolled"], body["pending"]) == (False, True)
    assert totp_service.is_enrolled(USER_ID) is False


@pytest.mark.asyncio
async def test_reenrolar_un_factor_pendiente_lo_reemplaza(client, world):
    async with client as ac:
        first = (await _enroll(ac))["secret"]
        second = (await _enroll(ac))["secret"]
        viejo = await ac.post(f"{URL}/confirm", headers={TOTP: world.code(first)})
        nuevo = await ac.post(f"{URL}/confirm", headers={TOTP: world.code(second)})

    assert first != second
    assert (viejo.status_code, nuevo.status_code) == (403, 200)


@pytest.mark.asyncio
async def test_enrolar_sobre_un_factor_confirmado_da_409_y_no_lo_pisa(client, world):
    async with client as ac:
        secret = await _enroll_and_confirm(ac, world)
        before = dict(world.repo.rows[USER_ID])
        response = await ac.post(f"{URL}/enroll")
        # Se compara ANTES de usar el factor: desactivarlo borra la fila.
        intacto = world.repo.rows[USER_ID]["secret_envelope"] == before["secret_envelope"]
        still_works = await ac.delete(URL, headers={TOTP: world.code(secret)})

    assert response.status_code == 409
    assert intacto
    assert still_works.status_code == 204  # el factor original seguía siendo el válido


# --------------------------------------------------------------------------
# Confirmar
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirmar_con_un_codigo_valido_activa_el_factor(client, world):
    async with client as ac:
        secret = (await _enroll(ac))["secret"]
        response = await ac.post(f"{URL}/confirm", headers={TOTP: world.code(secret)})

    body = response.json()
    assert response.status_code == 200
    assert (body["enrolled"], body["pending"]) == (True, False)
    assert body["confirmed_at"] is not None
    assert _actions(world) == [("mfa_enrolar", "ok"), ("mfa_activar", "ok")]


@pytest.mark.asyncio
async def test_confirmar_con_un_codigo_malo_da_403_con_code_y_lo_deja_pendiente(client, world):
    async with client as ac:
        secret = (await _enroll(ac))["secret"]
        wrong = next(c for c in (f"{n:06d}" for n in range(100000, 100100))
                     if c not in {world.code(secret, s) for s in (-1, 0, 1)})
        response = await ac.post(f"{URL}/confirm", headers={TOTP: wrong})

    assert response.status_code == 403
    assert response.json()["code"] == "totp_invalido"
    assert totp_service.is_enrolled(USER_ID) is False
    assert _actions(world)[-1] == ("mfa_denegado", "denegado")


@pytest.mark.asyncio
async def test_confirmar_sin_header_es_403_invalido(client, world):
    async with client as ac:
        await _enroll(ac)
        response = await ac.post(f"{URL}/confirm")

    assert response.status_code == 403 and response.json()["code"] == "totp_invalido"


@pytest.mark.asyncio
async def test_confirmar_sin_haber_enrolado_es_no_enrolado(client, world):
    async with client as ac:
        response = await ac.post(f"{URL}/confirm", headers={TOTP: "123456"})

    assert response.status_code == 403
    assert response.json()["code"] == "totp_no_enrolado"


# --------------------------------------------------------------------------
# Desactivar
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_desactivar_con_un_codigo_malo_da_403_y_la_fila_sigue_existiendo(client, world):
    """La aserción es sobre el repositorio, no solo sobre el status."""
    async with client as ac:
        await _enroll_and_confirm(ac, world)
        response = await ac.delete(URL, headers={TOTP: "000000"})

    assert response.status_code == 403
    assert USER_ID in world.repo.rows
    assert totp_service.is_enrolled(USER_ID) is True
    assert _actions(world)[-1] == ("mfa_denegado", "denegado")


@pytest.mark.asyncio
async def test_desactivar_sin_codigo_no_apaga_el_factor(client, world):
    """Un JWT robado sin el teléfono no puede apagar el segundo factor."""
    async with client as ac:
        await _enroll_and_confirm(ac, world)
        response = await ac.delete(URL)

    assert response.status_code == 403
    assert totp_service.is_enrolled(USER_ID) is True


@pytest.mark.asyncio
async def test_desactivar_con_un_codigo_vigente_elimina_el_factor(client, world):
    async with client as ac:
        secret = await _enroll_and_confirm(ac, world)
        response = await ac.delete(URL, headers={TOTP: world.code(secret)})
        estado = (await ac.get(URL)).json()

    assert response.status_code == 204 and response.content == b""
    assert USER_ID not in world.repo.rows
    assert (estado["enrolled"], estado["pending"]) == (False, False)
    assert _actions(world)[-1] == ("mfa_desactivar", "ok")


@pytest.mark.asyncio
async def test_desactivar_sin_factor_es_no_enrolado(client, world):
    async with client as ac:
        response = await ac.delete(URL, headers={TOTP: "123456"})

    assert response.status_code == 403 and response.json()["code"] == "totp_no_enrolado"


# --------------------------------------------------------------------------
# Falla cerrado y nada secreto en la auditoría
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sin_clave_del_factor_enrolar_da_503_y_no_deja_nada(client, world, monkeypatch):
    monkeypatch.setattr(settings, "totp_master_key", "")
    async with client as ac:
        response = await ac.post(f"{URL}/enroll")

    assert response.status_code == 503
    assert world.repo.rows == {} and world.audit == []


@pytest.mark.asyncio
async def test_sin_clave_del_factor_confirmar_da_503_no_403(client, world, monkeypatch):
    async with client as ac:
        secret = (await _enroll(ac))["secret"]
        monkeypatch.setattr(settings, "totp_master_key", "")
        response = await ac.post(f"{URL}/confirm", headers={TOTP: world.code(secret)})

    assert response.status_code == 503  # no se puede verificar: no es un «código inválido»
    assert totp_service.is_enrolled(USER_ID) is False


@pytest.mark.asyncio
async def test_ninguna_entrada_de_auditoria_lleva_el_secreto_ni_un_codigo(client, world):
    async with client as ac:
        secret = (await _enroll(ac))["secret"]
        good = world.code(secret)
        await ac.post(f"{URL}/confirm", headers={TOTP: "000000"})
        await ac.post(f"{URL}/confirm", headers={TOTP: good})
        world.advance()
        await ac.delete(URL, headers={TOTP: world.code(secret)})

    assert len(world.audit) == 4
    dump = repr(world.audit)
    assert secret not in dump and good not in dump and "000000" not in dump
    # Y sólo claves de vault_repo.insert_audit: UUIDs y enums, nada más.
    assert all(set(a) <= {"user_id", "item_id", "action", "result", "actor_user_id"} for a in world.audit)
    assert all(a["actor_user_id"] is None and a["item_id"] is None for a in world.audit)


@pytest.mark.asyncio
async def test_el_estado_no_expone_ningun_secreto(client, world):
    async with client as ac:
        await _enroll_and_confirm(ac, world)
        body = (await ac.get(URL)).json()

    assert set(body) == {"enrolled", "pending", "confirmed_at", "last_used_at", "locked_until"}
