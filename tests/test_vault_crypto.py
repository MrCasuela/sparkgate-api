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
