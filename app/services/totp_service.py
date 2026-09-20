"""Segundo factor TOTP (RFC 6238). HU18.

El secreto se guarda CIFRADO con vault_crypto bajo TOTP_MASTER_KEY (no bajo la KEK de la
bóveda: ver el docstring de vault_crypto) y con AAD = el user_id del dueño, leído de la
misma fila. Mover la fila a otro user_id rompe el tag GCM aunque se conozca la clave. Es el
único caso del sistema donde el dueño del dato y quien lo lee son la misma persona, así que
acá el AAD SÍ coincide con el caller; no es una regla general.

NO importa secret_access: es secret_access quien importa este módulo (_verify_step_up).
Invertirlo sería un ciclo. Tampoco conoce HTTP: levanta excepciones propias y la capa de
arriba decide el status.

Ningún logger de este archivo imprime el secreto, el código ni el URI otpauth://.
"""

import hashlib
import hmac
import logging
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

import pyotp

from app.core.config import settings
from app.services import totp_repo, vault_crypto

logger = logging.getLogger("sparkgate.totp")

ISSUER = "SparkGate"
DIGITS = 6
PERIOD = 30  # RFC 6238 §5.2 y lo que asumen Google/Microsoft Authenticator
ALGORITHM = "SHA1"  # el default del RFC y el único que toda app de autenticación soporta
VALID_WINDOW = 1  # ±1 paso = ±30 s de deriva de reloj; seguro porque el anti-replay lo compensa
MAX_FAILED = 5
LOCKOUT_SECONDS = 900

NO_ENROLADO = "totp_no_enrolado"
INVALIDO = "totp_invalido"
REUTILIZADO = "totp_reutilizado"
BLOQUEADO = "totp_bloqueado"

_DIGITS_RE = re.compile(rf"\d{{{DIGITS}}}")
# Orden de prueba: el paso actual primero, que es el caso normal.
_DRIFTS = tuple(dict.fromkeys((0, *range(-VALID_WINDOW, VALID_WINDOW + 1))))


class TotpDenied(Exception):
    """Motivo por el que se negó el factor. `code` es uno de los cuatro de arriba."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class TotpUnavailable(Exception):
    """El factor no se puede verificar (falta TOTP_MASTER_KEY o el sobre no abre). Falla
    CERRADO: la capa de arriba responde 503, nunca deja pasar sin segundo factor."""


class TotpAlreadyEnrolled(Exception):
    """Ya hay un factor CONFIRMADO. Hay que desactivarlo con un código válido primero."""


def _now() -> float:
    """Reloj inyectable: los tests lo reemplazan para probar ventana y anti-replay."""
    return time.time()


def _utc(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _totp(secret_b32: str, *, digits: int = DIGITS) -> pyotp.TOTP:
    """Único constructor de TOTP del módulo. Lo usan verify y los vectores del RFC 6238:
    si alguien cambia ALGORITHM o PERIOD, los vectores dejan de dar y la suite se cae."""
    return pyotp.TOTP(secret_b32, digits=digits, interval=PERIOD, digest=getattr(hashlib, ALGORITHM.lower()))


def _key() -> str:
    key = settings.totp_master_key
    if not vault_crypto.is_available(key):
        raise TotpUnavailable("TOTP_MASTER_KEY ausente o mal formada")
    return key


def _seal(user_id: str, secret_b32: str) -> dict:
    return vault_crypto.encrypt_secret({"totp_secret": secret_b32}, aad=user_id, key_b64=_key())


def _open(user_id: str, row: dict) -> str:
    try:
        payload = vault_crypto.decrypt_secret(row["secret_envelope"], aad=user_id, key_b64=_key())
    except vault_crypto.InvalidTag:
        # Clave distinta a la que selló, sobre adulterado o fila movida de dueño. No es un
        # "código inválido": es un fallo de integridad y se dice como tal (503, no 403).
        logger.error("El sobre del factor no abre (user=%s): clave, AAD o contenido no coinciden", user_id)
        raise TotpUnavailable("el sobre del factor no abre") from None
    return payload["totp_secret"]


def _is_locked(row: dict) -> bool:
    locked_until = row.get("locked_until")
    return bool(locked_until) and datetime.fromisoformat(locked_until) > _utc(_now())


def _register_failure(user_id: str, row: dict) -> None:
    failed = int(row.get("failed_attempts") or 0) + 1
    if failed >= MAX_FAILED:
        # Al bloquear, el contador vuelve a cero: pasado el bloqueo hay 5 intentos nuevos,
        # no uno solo que volvería a bloquear al primer error.
        until = _utc(_now() + LOCKOUT_SECONDS).isoformat()
        totp_repo.mark_failure(user_id=user_id, failed_attempts=0, locked_until=until)
        logger.warning("Factor bloqueado por %d intentos fallidos (user=%s)", MAX_FAILED, user_id)
        raise TotpDenied(BLOQUEADO)
    totp_repo.mark_failure(user_id=user_id, failed_attempts=failed, locked_until=None)
    raise TotpDenied(INVALIDO)


def _matched_step(secret_b32: str, code: str) -> int | None:
    """Paso de 30 s cuyo código coincide, o None. pyotp.verify devuelve un bool y no dice
    QUÉ paso coincidió, que es justo lo que el anti-replay necesita: se resuelve a mano.
    Comparación en tiempo constante."""
    now = int(_now())
    counter = now // PERIOD
    totp = _totp(secret_b32)
    for drift in _DRIFTS:
        if hmac.compare_digest(totp.at(now, counter_offset=drift), code):
            return counter + drift
    return None


def _check_code(user_id: str, row: dict, code: str | None) -> int:
    """Valida un código contra el factor de `row` y devuelve el paso aceptado. Común a
    verify, confirm y disable: un solo lugar donde se decide bloqueo, fallo y replay."""
    normalized = (code or "").strip().replace(" ", "")
    if not _DIGITS_RE.fullmatch(normalized):
        # Ausente o mal formado: no es una adivinanza, así que no suma fallos. Si sumara,
        # sondear "¿esto pide segundo factor?" sin código quemaría el bloqueo.
        raise TotpDenied(INVALIDO)

    # El bloqueo va ANTES de comparar: un código correcto durante el bloqueo también se
    # rechaza, o la fuerza bruta seguiría durante toda la ventana.
    if _is_locked(row):
        raise TotpDenied(BLOQUEADO)

    secret = _open(user_id, row)
    step = _matched_step(secret, normalized)
    if step is None:
        _register_failure(user_id, row)  # siempre levanta

    last = row.get("last_time_step")
    if last is not None and step <= int(last):
        # <= y no ==: también se rechaza un paso ANTERIOR, que cierra el reenvío de un
        # código capturado hace 30 s. No suma fallos: el código era válido, y quien lo
        # reusa casi siempre es el usuario legítimo con un doble clic.
        raise TotpDenied(REUTILIZADO)
    return step


def is_enrolled(user_id: str) -> bool:
    row = totp_repo.get_factor(user_id)
    return bool(row and row.get("confirmed_at"))


def get_status(user_id: str) -> dict:
    """Estado del factor SIN el secreto: es lo que consulta la UI."""
    row = totp_repo.get_factor(user_id)
    if row is None:
        return {"enrolled": False, "pending": False, "confirmed_at": None,
                "last_used_at": None, "locked_until": None}
    confirmed = bool(row.get("confirmed_at"))
    return {
        "enrolled": confirmed,
        "pending": not confirmed,
        "confirmed_at": row.get("confirmed_at"),
        "last_used_at": row.get("last_used_at"),
        "locked_until": row.get("locked_until") if _is_locked(row) else None,
    }


def start_enrollment(user_id: str, account_name: str) -> dict:
    """Genera un secreto nuevo y lo deja PENDIENTE. Un factor sin confirmar no habilita
    nada: si contara, abandonar el enrolamiento dejaría a la persona con un código
    inválido permanente y sin forma de volver a entrar.

    Sobre un factor ya CONFIRMADO no se reemplaza (TotpAlreadyEnrolled): un JWT robado no
    puede pisar el factor de la víctima; hay que desactivarlo con un código válido.
    """
    row = totp_repo.get_factor(user_id)
    if row and row.get("confirmed_at"):
        raise TotpAlreadyEnrolled()

    secret = pyotp.random_base32()  # 160 bits
    totp_repo.upsert_pending_factor(user_id=user_id, envelope=_seal(user_id, secret))

    label = quote(f"{ISSUER}:{account_name}", safe="")
    query = urlencode(
        {"secret": secret, "issuer": ISSUER, "algorithm": ALGORITHM, "digits": DIGITS, "period": PERIOD}
    )
    return {
        "secret": secret,
        "otpauth_uri": f"otpauth://totp/{label}?{query}",
        "issuer": ISSUER,
        "account_name": account_name,
        "digits": DIGITS,
        "period": PERIOD,
        "algorithm": ALGORITHM,
    }


def confirm_enrollment(user_id: str, code: str | None) -> None:
    """El primer código correcto activa el factor. Sin un enrolamiento pendiente no hay
    nada que confirmar (NO_ENROLADO)."""
    row = totp_repo.get_factor(user_id)
    if row is None or row.get("confirmed_at"):
        raise TotpDenied(NO_ENROLADO)
    step = _check_code(user_id, row, code)
    if not totp_repo.confirm_factor(user_id=user_id, time_step=step):
        raise TotpDenied(REUTILIZADO)  # otro request lo confirmó primero


def verify(user_id: str, code: str | None) -> None:
    """Lo que usa secret_access._verify_step_up. Levanta TotpDenied / TotpUnavailable.

    Un factor sin confirmar cuenta como NO enrolado.
    """
    row = totp_repo.get_factor(user_id)
    if row is None or not row.get("confirmed_at"):
        raise TotpDenied(NO_ENROLADO)
    step = _check_code(user_id, row, code)
    if not totp_repo.mark_used(user_id=user_id, time_step=step):
        raise TotpDenied(REUTILIZADO)  # lo consumió una petición concurrente


def disable(user_id: str, code: str | None) -> None:
    """Elimina el factor. Exige un código vigente: sin eso, un JWT robado apagaría el
    segundo factor y después leería todo."""
    row = totp_repo.get_factor(user_id)
    if row is None or not row.get("confirmed_at"):
        raise TotpDenied(NO_ENROLADO)
    _check_code(user_id, row, code)
    totp_repo.delete_factor(user_id)
