import base64
import os

import pytest
from cryptography.exceptions import InvalidTag

from app.core.config import settings
from app.services import vault_crypto

VALID_KEK = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
OTHER_KEK = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


@pytest.fixture(autouse=True)
def valid_kek(monkeypatch):
    monkeypatch.setattr(settings, "vault_master_key", VALID_KEK)
    yield


def test_round_trip():
    payload = {"password": "hunter2", "notes": "cuenta personal"}
    secret = vault_crypto.encrypt_secret(payload, aad="user-1")
    decrypted = vault_crypto.decrypt_secret(secret, aad="user-1")
    assert decrypted == payload


def test_same_plaintext_yields_different_ciphertext():
    payload = {"password": "hunter2", "notes": None}
    a = vault_crypto.encrypt_secret(payload, aad="user-1")
    b = vault_crypto.encrypt_secret(payload, aad="user-1")
    assert a["ciphertext"] != b["ciphertext"]
    assert a["nonce"] != b["nonce"]


def test_tampered_ciphertext_fails():
    secret = vault_crypto.encrypt_secret({"password": "hunter2", "notes": None}, aad="user-1")
    tampered = dict(secret, ciphertext=secret["ciphertext"][:-4] + "AAAA")
    with pytest.raises(InvalidTag):
        vault_crypto.decrypt_secret(tampered, aad="user-1")


def test_wrong_aad_fails():
    """AC3 at the crypto layer: a ciphertext bound to one user's id can't be
    decrypted under another user's id, even with the correct KEK."""
    secret = vault_crypto.encrypt_secret({"password": "hunter2", "notes": None}, aad="user-1")
    with pytest.raises(InvalidTag):
        vault_crypto.decrypt_secret(secret, aad="user-2")


def test_is_available_true_with_valid_kek():
    assert vault_crypto.is_available() is True


def test_is_available_false_with_empty_kek(monkeypatch):
    monkeypatch.setattr(settings, "vault_master_key", "")
    assert vault_crypto.is_available() is False


def test_is_available_false_with_invalid_base64(monkeypatch):
    monkeypatch.setattr(settings, "vault_master_key", "not-valid-base64!!!")
    assert vault_crypto.is_available() is False


def test_is_available_false_with_wrong_length(monkeypatch):
    short_key = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")
    monkeypatch.setattr(settings, "vault_master_key", short_key)
    assert vault_crypto.is_available() is False


def test_encrypt_raises_without_kek(monkeypatch):
    monkeypatch.setattr(settings, "vault_master_key", "")
    with pytest.raises(RuntimeError):
        vault_crypto.encrypt_secret({"password": "x", "notes": None}, aad="user-1")


# --------------------------------------------------------------------------
# Clave alternativa (HU18): el factor TOTP se sella con TOTP_MASTER_KEY, no con la KEK
# --------------------------------------------------------------------------


def test_una_clave_explicita_reemplaza_a_la_kek_no_se_suma_a_ella():
    """Sellado con la clave del factor, la KEK de la bóveda NO lo abre y viceversa. Si las
    dos fueran intercambiables, perder una arrastraría a la otra, que es justo lo que se
    evita con dos claves."""
    payload = {"totp_secret": "JBSWY3DPEHPK3PXP"}
    sealed = vault_crypto.encrypt_secret(payload, aad="user-1", key_b64=OTHER_KEK)

    assert vault_crypto.decrypt_secret(sealed, aad="user-1", key_b64=OTHER_KEK) == payload
    with pytest.raises(InvalidTag):
        vault_crypto.decrypt_secret(sealed, aad="user-1")  # con la KEK de la bóveda


def test_la_clave_explicita_no_depende_de_que_la_kek_este_arriba(monkeypatch):
    """La propiedad que motivó tener dos claves: con la KEK caída, el factor sigue
    sellándose y abriéndose."""
    monkeypatch.setattr(settings, "vault_master_key", "")
    sealed = vault_crypto.encrypt_secret({"totp_secret": "X"}, aad="user-1", key_b64=OTHER_KEK)
    assert vault_crypto.decrypt_secret(sealed, aad="user-1", key_b64=OTHER_KEK) == {"totp_secret": "X"}
    assert vault_crypto.is_available() is False
    assert vault_crypto.is_available(OTHER_KEK) is True


def test_una_clave_explicita_vacia_no_cae_a_la_kek():
    """"" no es None: una TOTP_MASTER_KEY sin configurar debe leerse como NO disponible, no
    como «cifrá el segundo factor con la clave de la bóveda» (que anularía la separación)."""
    assert vault_crypto.is_available("") is False
    with pytest.raises(RuntimeError):
        vault_crypto.encrypt_secret({"totp_secret": "X"}, aad="user-1", key_b64="")


def test_el_aad_tambien_ata_al_sobre_del_factor():
    sealed = vault_crypto.encrypt_secret({"totp_secret": "X"}, aad="user-1", key_b64=OTHER_KEK)
    with pytest.raises(InvalidTag):
        vault_crypto.decrypt_secret(sealed, aad="user-2", key_b64=OTHER_KEK)
