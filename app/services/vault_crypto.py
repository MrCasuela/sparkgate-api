"""Envelope encryption for the Vault module (HU17 / CU07).

Each secret is encrypted with a random per-item Data Encryption Key (DEK) under
AES-256-GCM. The DEK itself is then wrapped (encrypted) with the Key Encryption
Key (KEK), which lives outside the database in `settings.vault_master_key`. This
is the standard envelope-encryption scheme described in NIST SP 800-38D.

AAD (Additional Authenticated Data) is always the owning user's id. This binds
the ciphertext to its owner cryptographically: moving a row to another user_id,
or decrypting it on behalf of someone else, fails the GCM tag check even if the
KEK is known. This is defense in depth on top of the application-level
`.eq("user_id", ...)` ownership filter (AC3).

Not zero-knowledge by design (informe L413): the KEK is held by the backend, so
an operator with server access can decrypt. This lets an admin role recover or
rotate a departed member's credential later (CU08), which a strict
zero-knowledge scheme would forbid.
"""

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

KEK_VERSION = 1
_KEY_LEN = 32  # AES-256
_NONCE_LEN = 12  # 96-bit GCM nonce, per NIST SP 800-38D


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def _load_kek() -> bytes | None:
    raw = settings.vault_master_key
    if not raw:
        return None
    try:
        key = _b64d(raw)
    except Exception:
        return None
    if len(key) != _KEY_LEN:
        return None
    return key


def is_available() -> bool:
    """True only if a well-formed 32-byte KEK is configured (AC5)."""
    return _load_kek() is not None


def encrypt_secret(payload: dict, aad: str) -> dict:
    """Encrypt {password, notes} under a fresh DEK, then wrap the DEK with the KEK.

    Raises RuntimeError if called without checking is_available() first — callers
    must check is_available() and reject the request (503) before ever reaching
    here, so no plaintext is persisted (AC5).
    """
    kek = _load_kek()
    if kek is None:
        raise RuntimeError("vault_crypto.encrypt_secret called without an available KEK")

    dek = os.urandom(_KEY_LEN)
    nonce = os.urandom(_NONCE_LEN)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad.encode("utf-8"))

    dek_nonce = os.urandom(_NONCE_LEN)
    wrapped_dek = AESGCM(kek).encrypt(dek_nonce, dek, aad.encode("utf-8"))

    return {
        "ciphertext": _b64e(ciphertext),
        "nonce": _b64e(nonce),
        "wrapped_dek": _b64e(wrapped_dek),
        "dek_nonce": _b64e(dek_nonce),
        "kek_version": KEK_VERSION,
    }


def decrypt_secret(row: dict, aad: str) -> dict:
    """Unwrap the DEK with the KEK, then decrypt the payload. Raises InvalidTag
    if the AAD (owner) doesn't match or the ciphertext/wrapped_dek was tampered.
    """
    kek = _load_kek()
    if kek is None:
        raise RuntimeError("vault_crypto.decrypt_secret called without an available KEK")

    dek = AESGCM(kek).decrypt(
        _b64d(row["dek_nonce"]), _b64d(row["wrapped_dek"]), aad.encode("utf-8")
    )
    plaintext = AESGCM(dek).decrypt(
        _b64d(row["nonce"]), _b64d(row["ciphertext"]), aad.encode("utf-8")
    )
    return json.loads(plaintext.decode("utf-8"))


__all__ = ["is_available", "encrypt_secret", "decrypt_secret", "InvalidTag", "KEK_VERSION"]
