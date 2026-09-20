"""Segundo factor TOTP (HU18): la primitiva, la ventana, el anti-replay y el bloqueo.

El repositorio se reemplaza por uno en memoria que replica la semántica CONDICIONAL de los
UPDATE reales (mark_used solo gana si el paso es mayor al último). Su cuerpo real solo corre
contra un Supabase de verdad: lo cubre scripts/e2e_hu18_check.py.

Regla de honestidad: nada acá stubea totp_service.verify y luego afirma cumplir un AC de
verificación. Lo que stubea al verificador solo prueba cableado.
"""

import base64
import copy
import json
import logging
import os
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import pytest
from cryptography.exceptions import InvalidTag

from app.core.config import settings
from app.services import totp_service, vault_crypto

USER = "user-1"
OTHER_USER = "user-2"
KEY = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
T0 = 1_700_000_010.0  # un instante cualquiera, alejado de un borde de paso


# --------------------------------------------------------------------------
# La primitiva: vectores de prueba de RFC 6238, Apéndice B (SHA-1, 8 dígitos)
# --------------------------------------------------------------------------

RFC_SEED = base64.b32encode(b"12345678901234567890").decode("ascii")  # GEZDGNBV...


@pytest.mark.parametrize(
    "unix_time, expected",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_vectores_del_rfc_6238(unix_time, expected):
    """Pasan por el MISMO constructor que usa verify(): si alguien cambia ALGORITHM o PERIOD,
    dejan de dar. Prueban nuestra configuración contra el estándar, no 'lo que hace pyotp'."""
    assert totp_service._totp(RFC_SEED, digits=8).at(unix_time) == expected


def test_los_parametros_de_produccion_estan_anclados():
    """Cambiar cualquiera invalida TODOS los factores ya enrolados: las apps de autenticación
    siguen generando 6 dígitos/30 s/SHA-1 con el secreto que escanearon."""
    assert (totp_service.DIGITS, totp_service.PERIOD, totp_service.ALGORITHM) == (6, 30, "SHA1")
    assert totp_service.VALID_WINDOW == 1


# --------------------------------------------------------------------------
# Andamiaje
# --------------------------------------------------------------------------


class FakeRepo:
    """totp_repo en memoria, con la misma semántica condicional que los UPDATE reales."""

    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.envelopes_sealed: list[dict] = []

    def get_factor(self, user_id):
        return copy.deepcopy(self.rows.get(user_id))

    def upsert_pending_factor(self, *, user_id, envelope):
        self.envelopes_sealed.append(envelope)
        self.rows[user_id] = {
            "user_id": user_id, "secret_envelope": envelope, "confirmed_at": None,
            "last_time_step": None, "last_used_at": None, "failed_attempts": 0, "locked_until": None,
        }

    def confirm_factor(self, *, user_id, time_step):
        row = self.rows.get(user_id)
        if row is None or row["confirmed_at"]:
            return False
        row.update(confirmed_at="2026-01-01T00:00:00+00:00", last_time_step=time_step,
                   failed_attempts=0, locked_until=None)
        return True

    def mark_used(self, *, user_id, time_step):
        row = self.rows.get(user_id)
        if row is None:
            return False
        last = row["last_time_step"]
        if last is not None and last >= time_step:
            return False
        row.update(last_time_step=time_step, failed_attempts=0, locked_until=None,
                   last_used_at="2026-01-01T00:00:00+00:00")
        return True

    def mark_failure(self, *, user_id, failed_attempts, locked_until):
        self.rows[user_id].update(failed_attempts=failed_attempts, locked_until=locked_until)

    def delete_factor(self, user_id):
        return self.rows.pop(user_id, None) is not None


class World:
    def __init__(self, repo: FakeRepo, clock: dict):
        self.repo = repo
        self.clock = clock

    def advance(self, seconds: float):
        self.clock["now"] += seconds

    def code(self, secret: str, steps: int = 0) -> str:
        """Código válido `steps` pasos respecto del reloj actual."""
        return totp_service._totp(secret).at(int(self.clock["now"]), counter_offset=steps)

    def enroll_and_confirm(self, user_id=USER) -> str:
        """Enrola y confirma; devuelve el secreto. Deja el reloj UN paso adelante, porque
        confirmar consume el paso actual (anti-replay) y el siguiente código ya es distinto."""
        secret = totp_service.start_enrollment(user_id, f"{user_id}@pyme.cl")["secret"]
        totp_service.confirm_enrollment(user_id, self.code(secret))
        self.advance(totp_service.PERIOD)
        return secret

    def denied(self, fn, *args) -> str:
        with pytest.raises(totp_service.TotpDenied) as exc:
            fn(*args)
        return exc.value.code


@pytest.fixture
def world(monkeypatch):
    repo = FakeRepo()
    clock = {"now": T0}
    monkeypatch.setattr(totp_service, "totp_repo", repo)
    monkeypatch.setattr(totp_service, "_now", lambda: clock["now"])
    monkeypatch.setattr(settings, "totp_master_key", KEY)
    return World(repo, clock)


# --------------------------------------------------------------------------
# No enrolado / pendiente (lo que hace verificable la decisión de los dos 403)
# --------------------------------------------------------------------------


def test_sin_factor_es_no_enrolado_y_no_invalido(world):
    assert world.denied(totp_service.verify, USER, "123456") == totp_service.NO_ENROLADO


def test_un_factor_sin_confirmar_no_cuenta_como_enrolado(world):
    """Aunque el código sea VÁLIDO para el secreto pendiente, no habilita nada: sin esta regla,
    abandonar el enrolamiento a mitad dejaría a la persona sin salida."""
    secret = totp_service.start_enrollment(USER, "a@pyme.cl")["secret"]

    assert totp_service.is_enrolled(USER) is False
    assert totp_service.get_status(USER)["pending"] is True
    assert world.denied(totp_service.verify, USER, world.code(secret)) == totp_service.NO_ENROLADO


def test_sin_clave_del_factor_y_sin_factor_sigue_siendo_no_enrolado(world, monkeypatch):
    """Quien nunca se enroló recibe 'no enrolado' (403 que lleva a enrolarse) y no un 503 por
    una clave que ni siquiera hace falta para decidirlo."""
    monkeypatch.setattr(settings, "totp_master_key", "")
    assert world.denied(totp_service.verify, USER, "123456") == totp_service.NO_ENROLADO


# --------------------------------------------------------------------------
# Verificación, ventana y anti-replay
# --------------------------------------------------------------------------


def test_un_codigo_vigente_se_acepta(world):
    secret = world.enroll_and_confirm()
    totp_service.verify(USER, world.code(secret))


def test_el_codigo_admite_los_espacios_que_muestran_las_apps(world):
    secret = world.enroll_and_confirm()
    code = world.code(secret)
    totp_service.verify(USER, f"{code[:3]} {code[3:]}")


def _sin_la_capa_de_la_base(world, monkeypatch):
    """El anti-replay tiene DOS capas: el chequeo del servicio y el UPDATE condicional de
    mark_used. La segunda tapa a la primera, así que un test que las deje activas a las dos
    no detecta que se rompa una sola (una mutación '<=' -> '==' pasaba toda la suite). Acá se
    neutraliza la de la base para que estos tests midan la del servicio; la de la base la mide
    test_perder_la_carrera_de_mark_used_es_reutilizado. Sigue ESCRIBIENDO el paso (el
    chequeo del servicio lo lee), solo que sin la condición."""

    def incondicional(*, user_id, time_step):
        world.repo.rows[user_id].update(last_time_step=time_step, failed_attempts=0, locked_until=None)
        return True

    monkeypatch.setattr(world.repo, "mark_used", incondicional)


def test_reusar_un_codigo_aceptado_es_reutilizado_y_no_suma_fallos(world, monkeypatch):
    secret = world.enroll_and_confirm()
    _sin_la_capa_de_la_base(world, monkeypatch)
    code = world.code(secret)
    totp_service.verify(USER, code)

    assert world.denied(totp_service.verify, USER, code) == totp_service.REUTILIZADO
    # El código era válido: quien lo reusa casi siempre es un doble clic, no un ataque.
    assert world.repo.rows[USER]["failed_attempts"] == 0


def test_un_paso_anterior_al_ultimo_aceptado_tambien_es_reutilizado(world, monkeypatch):
    """<= y no ==: cierra el reenvío de un código capturado hace 30 s."""
    secret = world.enroll_and_confirm()
    anterior = world.code(secret, steps=-1)
    totp_service.verify(USER, world.code(secret))
    _sin_la_capa_de_la_base(world, monkeypatch)

    assert world.denied(totp_service.verify, USER, anterior) == totp_service.REUTILIZADO


def test_el_codigo_de_la_confirmacion_no_sirve_luego_como_segundo_factor(world):
    secret = totp_service.start_enrollment(USER, "a@pyme.cl")["secret"]
    code = world.code(secret)
    totp_service.confirm_enrollment(USER, code)

    assert world.denied(totp_service.verify, USER, code) == totp_service.REUTILIZADO


def test_la_ventana_acepta_mas_menos_un_paso_y_rechaza_dos(world):
    for steps, esperado in [(-1, None), (1, None), (-2, totp_service.INVALIDO), (2, totp_service.INVALIDO)]:
        secret = world.enroll_and_confirm(user_id=f"u{steps}")
        # Confirmar consumió el paso S y el reloj quedó en S+1: ahí "T-1" es S, que el
        # anti-replay rechaza a propósito. Un paso más para medir la ventana sobre pasos
        # que nadie consumió.
        world.advance(totp_service.PERIOD)
        code = world.code(secret, steps=steps)
        if esperado is None:
            totp_service.verify(f"u{steps}", code)
        else:
            assert world.denied(totp_service.verify, f"u{steps}", code) == esperado


def test_perder_la_carrera_de_mark_used_es_reutilizado(world, monkeypatch):
    """Dos peticiones simultáneas con el mismo código leen el mismo last_time_step; solo una
    gana el UPDATE condicional. La otra tiene que ser rechazada aunque su lectura pasó."""
    secret = world.enroll_and_confirm()
    monkeypatch.setattr(world.repo, "mark_used", lambda **kw: False)

    assert world.denied(totp_service.verify, USER, world.code(secret)) == totp_service.REUTILIZADO


@pytest.mark.parametrize("code", [None, "", "   ", "12345", "1234567", "abcdef", "12 34"])
def test_un_codigo_ausente_o_mal_formado_es_invalido_y_no_suma_fallos(world, code):
    """No es una adivinanza. Si sumara, sondear '¿esto pide segundo factor?' sin código
    quemaría el bloqueo del usuario legítimo."""
    world.enroll_and_confirm()

    assert world.denied(totp_service.verify, USER, code) == totp_service.INVALIDO
    assert world.repo.rows[USER]["failed_attempts"] == 0


# --------------------------------------------------------------------------
# Bloqueo
# --------------------------------------------------------------------------


def _wrong(secret, world):
    """Un código de formato válido que NO corresponde a ninguno de los tres pasos de la ventana."""
    valid = {world.code(secret, s) for s in (-1, 0, 1)}
    return next(c for c in (f"{n:06d}" for n in range(100000, 100100)) if c not in valid)


def test_cinco_fallos_bloquean_y_el_codigo_correcto_tampoco_pasa_bloqueado(world):
    secret = world.enroll_and_confirm()
    wrong = _wrong(secret, world)

    for _ in range(totp_service.MAX_FAILED - 1):
        assert world.denied(totp_service.verify, USER, wrong) == totp_service.INVALIDO
    assert world.denied(totp_service.verify, USER, wrong) == totp_service.BLOQUEADO

    # Ni el código CORRECTO pasa durante el bloqueo: si pasara, la fuerza bruta seguiría.
    assert world.denied(totp_service.verify, USER, world.code(secret)) == totp_service.BLOQUEADO


def test_pasado_el_bloqueo_hay_cinco_intentos_nuevos_y_no_uno(world):
    secret = world.enroll_and_confirm()
    wrong = _wrong(secret, world)
    for _ in range(totp_service.MAX_FAILED):
        with pytest.raises(totp_service.TotpDenied):
            totp_service.verify(USER, wrong)

    world.advance(totp_service.LOCKOUT_SECONDS + 1)
    assert world.repo.rows[USER]["failed_attempts"] == 0
    assert world.denied(totp_service.verify, USER, _wrong(secret, world)) == totp_service.INVALIDO
    totp_service.verify(USER, world.code(secret))


def test_un_acierto_reinicia_el_contador(world):
    secret = world.enroll_and_confirm()
    for _ in range(totp_service.MAX_FAILED - 1):
        with pytest.raises(totp_service.TotpDenied):
            totp_service.verify(USER, _wrong(secret, world))

    totp_service.verify(USER, world.code(secret))
    assert world.repo.rows[USER]["failed_attempts"] == 0


# --------------------------------------------------------------------------
# Enrolamiento y desactivación
# --------------------------------------------------------------------------


def test_el_uri_otpauth_lleva_los_parametros_que_esperan_las_apps(world):
    enrollment = totp_service.start_enrollment(USER, "admin@pyme.cl")
    parsed = urlparse(enrollment["otpauth_uri"])
    query = parse_qs(parsed.query)

    assert (parsed.scheme, parsed.netloc) == ("otpauth", "totp")
    assert unquote(parsed.path) == "/SparkGate:admin@pyme.cl"
    assert query["secret"] == [enrollment["secret"]]
    assert query["issuer"] == ["SparkGate"]
    assert (query["digits"], query["period"], query["algorithm"]) == (["6"], ["30"], ["SHA1"])
    assert re.fullmatch(r"[A-Z2-7]{32}", enrollment["secret"])  # base32 de 160 bits


def test_el_secreto_se_guarda_cifrado_con_el_aad_del_dueno(world, monkeypatch):
    captured = {}
    real = vault_crypto.encrypt_secret

    def spy(payload, aad, *, key_b64=None):
        captured.update(aad=aad, key=key_b64)
        return real(payload, aad=aad, key_b64=key_b64)

    monkeypatch.setattr(totp_service.vault_crypto, "encrypt_secret", spy)
    secret = totp_service.start_enrollment(USER, "a@pyme.cl")["secret"]

    assert captured == {"aad": USER, "key": KEY}  # AAD = el dueño, clave = la del FACTOR
    assert secret not in json.dumps(world.repo.rows[USER]["secret_envelope"])


def test_una_fila_movida_a_otro_usuario_no_abre(world):
    """AAD = user_id: el sobre de un usuario copiado a la fila de otro rompe el tag GCM aunque
    se conozca la clave. Y eso no es un 'código inválido': es un fallo de integridad (503)."""
    secret = world.enroll_and_confirm()
    world.repo.rows[OTHER_USER] = copy.deepcopy(world.repo.rows[USER])

    with pytest.raises(totp_service.TotpUnavailable):
        totp_service.verify(OTHER_USER, world.code(secret))


def test_la_kek_de_la_boveda_no_abre_el_factor():
    """El factor NO está bajo la KEK: dos claves, dos fallos descorrelacionados."""
    other = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    sealed = vault_crypto.encrypt_secret({"totp_secret": "X"}, aad=USER, key_b64=KEY)
    with pytest.raises(InvalidTag):
        vault_crypto.decrypt_secret(sealed, aad=USER, key_b64=other)


def test_sin_clave_del_factor_no_se_puede_verificar_ni_enrolar(world, monkeypatch):
    """Falla CERRADO: nunca se deja pasar sin segundo factor por no poder verificarlo."""
    secret = world.enroll_and_confirm()
    monkeypatch.setattr(settings, "totp_master_key", "")

    with pytest.raises(totp_service.TotpUnavailable):
        totp_service.verify(USER, world.code(secret))
    with pytest.raises(totp_service.TotpUnavailable):
        totp_service.start_enrollment(OTHER_USER, "b@pyme.cl")


def test_enrolar_sobre_un_factor_confirmado_no_lo_pisa(world):
    """Un JWT robado no puede reemplazar el factor de la víctima por uno propio."""
    secret = world.enroll_and_confirm()
    before = copy.deepcopy(world.repo.rows[USER])

    with pytest.raises(totp_service.TotpAlreadyEnrolled):
        totp_service.start_enrollment(USER, "a@pyme.cl")
    assert world.repo.rows[USER] == before
    totp_service.verify(USER, world.code(secret))  # el original sigue funcionando


def test_reintentar_un_enrolamiento_pendiente_lo_reemplaza(world):
    first = totp_service.start_enrollment(USER, "a@pyme.cl")["secret"]
    second = totp_service.start_enrollment(USER, "a@pyme.cl")["secret"]

    assert first != second
    assert world.denied(totp_service.confirm_enrollment, USER, world.code(first)) == totp_service.INVALIDO
    totp_service.confirm_enrollment(USER, world.code(second))
    assert totp_service.is_enrolled(USER) is True


def test_confirmar_con_un_codigo_malo_deja_el_factor_pendiente(world):
    secret = totp_service.start_enrollment(USER, "a@pyme.cl")["secret"]

    assert world.denied(totp_service.confirm_enrollment, USER, _wrong(secret, world)) == totp_service.INVALIDO
    assert totp_service.is_enrolled(USER) is False


def test_confirmar_sin_enrolamiento_pendiente_es_no_enrolado(world):
    assert world.denied(totp_service.confirm_enrollment, USER, "123456") == totp_service.NO_ENROLADO


def test_desactivar_con_un_codigo_malo_deja_la_fila(world):
    secret = world.enroll_and_confirm()

    assert world.denied(totp_service.disable, USER, _wrong(secret, world)) == totp_service.INVALIDO
    assert USER in world.repo.rows  # la aserción es sobre el repo, no sobre el status


def test_desactivar_con_un_codigo_vigente_elimina_el_factor(world):
    secret = world.enroll_and_confirm()
    totp_service.disable(USER, world.code(secret))

    assert USER not in world.repo.rows
    assert world.denied(totp_service.verify, USER, "123456") == totp_service.NO_ENROLADO


def test_el_estado_no_expone_el_secreto(world):
    world.enroll_and_confirm()
    status = totp_service.get_status(USER)

    assert set(status) == {"enrolled", "pending", "confirmed_at", "last_used_at", "locked_until"}
    assert status["enrolled"] is True and status["pending"] is False


# --------------------------------------------------------------------------
# Herméticos
# --------------------------------------------------------------------------


def test_el_codigo_se_compara_en_tiempo_constante():
    source = (Path(__file__).resolve().parent.parent / "app" / "services" / "totp_service.py").read_text(
        encoding="utf-8"
    )
    assert "hmac.compare_digest" in source
    assert not re.search(r"==\s*normalized|normalized\s*==|==\s*code\b|\bcode\s*==", source)


def test_nada_secreto_llega_a_un_log(world, caplog):
    """Ni el secreto ni ningún código aparecen en un solo record, en ningún camino: enrolar,
    confirmar, verificar, fallar hasta el bloqueo, replay."""
    caplog.set_level(logging.DEBUG)
    enrollment = totp_service.start_enrollment(USER, "a@pyme.cl")
    secret = enrollment["secret"]
    good = world.code(secret)
    totp_service.confirm_enrollment(USER, good)
    world.advance(totp_service.PERIOD)
    good2 = world.code(secret)
    totp_service.verify(USER, good2)
    with pytest.raises(totp_service.TotpDenied):
        totp_service.verify(USER, good2)  # replay
    wrong = _wrong(secret, world)
    for _ in range(totp_service.MAX_FAILED):
        with pytest.raises(totp_service.TotpDenied):
            totp_service.verify(USER, wrong)

    text = "\n".join(r.getMessage() for r in caplog.records)
    for forbidden in (secret, good, good2, wrong, enrollment["otpauth_uri"]):
        assert forbidden not in text
