"""Repositorio del factor TOTP en memoria, compartido por los tests de HU18.

Replica la semántica CONDICIONAL de los UPDATE reales de totp_repo (mark_used solo gana si el
paso es mayor al último; confirm_factor solo si sigue pendiente). Los cuerpos reales de
totp_repo solo corren contra un Supabase de verdad: los cubre scripts/e2e_hu18_check.py.
"""

import copy


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


# --------------------------------------------------------------------------
# Cadena REAL del segundo factor para los tests de cableado de las rutas
#
# Los tests de ruta miden la ruta, no el factor: por defecto anulan _verify_step_up (ver
# el fixture `sin_segundo_factor` de cada archivo). Los tests que necesitan comprobar que
# UNA RUTA exige el factor de verdad usan esto: la ruta -> _verify_step_up real ->
# totp_service real -> este repo en memoria, con un reloj controlado.
# --------------------------------------------------------------------------

import base64
import os

from app.core.config import settings
from app.services import secret_access, totp_service, vault_crypto

# Capturados al importar, ANTES de que ningún fixture los reemplace.
REAL_VERIFY_STEP_UP = secret_access._verify_step_up
_REAL_IS_AVAILABLE = vault_crypto.is_available
_REAL_ENCRYPT = vault_crypto.encrypt_secret
_REAL_DECRYPT = vault_crypto.decrypt_secret

KEY = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
T0 = 1_700_000_010.0


class TotpEnv:
    """Repo en memoria + reloj controlado, ya instalados en totp_service."""

    def __init__(self, repo: FakeRepo, clock: dict):
        self.repo = repo
        self.clock = clock

    def tick(self):
        """Avanza un paso de 30 s: el código anterior ya no sirve (anti-replay)."""
        self.clock["now"] += totp_service.PERIOD


class Factor:
    def __init__(self, env: TotpEnv, secret: str):
        self.env, self.secret = env, secret

    def code(self, steps: int = 0) -> str:
        return totp_service._totp(self.secret).at(int(self.env.clock["now"]), counter_offset=steps)

    def tick(self):
        self.env.tick()


def totp_env(monkeypatch) -> TotpEnv:
    """Instala el repo en memoria, el reloj y TOTP_MASTER_KEY, y vuelve a poner el
    verificador REAL en lugar del stub del fixture autouse. Nadie está enrolado todavía."""
    env = TotpEnv(FakeRepo(), {"now": T0})
    monkeypatch.setattr(totp_service, "totp_repo", env.repo)
    monkeypatch.setattr(totp_service, "_now", lambda: env.clock["now"])
    monkeypatch.setattr(settings, "totp_master_key", KEY)
    monkeypatch.setattr(secret_access, "_verify_step_up", REAL_VERIFY_STEP_UP)
    _keep_totp_crypto_working(monkeypatch)
    return env


def enroll_real_factor(env: TotpEnv, user_id: str) -> Factor:
    """Enrola y confirma de verdad. Deja el reloj un paso adelante: confirmar consume el
    paso actual, y el siguiente código ya es distinto."""
    secret = totp_service.start_enrollment(user_id, f"{user_id}@pyme.cl")["secret"]
    factor = Factor(env, secret)
    totp_service.confirm_enrollment(user_id, factor.code())
    factor.tick()
    return factor


def _keep_totp_crypto_working(monkeypatch) -> None:
    """Los tests de ruta reemplazan vault_crypto.is_available/encrypt/decrypt con stubs de la
    KEK que ignoran `key_b64`, y totp_service usa esos MISMOS nombres del módulo. Se envuelve
    lo que esté parcheado: sin key_b64 (la KEK de la bóveda) va al stub del test; con key_b64
    (el factor) va al real."""
    cur_available = vault_crypto.is_available
    cur_encrypt = vault_crypto.encrypt_secret
    cur_decrypt = vault_crypto.decrypt_secret

    def is_available(key_b64=None):
        return cur_available() if key_b64 is None else _REAL_IS_AVAILABLE(key_b64)

    def encrypt_secret(payload, aad, *, key_b64=None):
        if key_b64 is None:
            return cur_encrypt(payload, aad)
        return _REAL_ENCRYPT(payload, aad=aad, key_b64=key_b64)

    def decrypt_secret(row, aad, *, key_b64=None):
        if key_b64 is None:
            return cur_decrypt(row, aad=aad)
        return _REAL_DECRYPT(row, aad=aad, key_b64=key_b64)

    monkeypatch.setattr(vault_crypto, "is_available", is_available)
    monkeypatch.setattr(vault_crypto, "encrypt_secret", encrypt_secret)
    monkeypatch.setattr(vault_crypto, "decrypt_secret", decrypt_secret)
