"""
AES-256-GCM Encryption
=======================
Encrypts uploaded files and sensitive database records at rest.

Key management
--------------
Set AEROA_ENCRYPTION_KEY env var to a base64-encoded 32-byte key.
Generate one with:  python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"

If the key is missing in development, a random ephemeral key is used
and a loud warning is emitted.  In production, startup fails if missing.
"""

import os
import json
import base64
import hashlib
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)

_NONCE_LEN = 12   # 96-bit GCM nonce (NIST recommended)
_KEY_LEN   = 32   # 256-bit key


def _get_master_key() -> bytes:
    """Load encryption key from environment. Fails loudly in production."""
    b64 = os.environ.get("AEROA_ENCRYPTION_KEY", "")
    if b64:
        key = base64.b64decode(b64)
        if len(key) != _KEY_LEN:
            raise RuntimeError(
                f"AEROA_ENCRYPTION_KEY must be {_KEY_LEN} bytes "
                f"(got {len(key)}). Regenerate with the command in encryption.py."
            )
        return key

    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError(
            "AEROA_ENCRYPTION_KEY is required in production. "
            "Set it in your Railway environment variables."
        )

    # Dev fallback: deterministic key derived from secret_key so data survives restarts
    secret = os.environ.get("FLASK_SECRET_KEY", "dev-only-insecure")
    key = hashlib.sha256(secret.encode()).digest()
    log.warning(
        "⚠️  No AEROA_ENCRYPTION_KEY set — using derived dev key. "
        "DO NOT use this in production."
    )
    return key


# ── Core primitives ────────────────────────────────────────────────────────────

def encrypt_bytes(plaintext: bytes) -> bytes:
    """
    AES-256-GCM encrypt.
    Returns:  [12-byte nonce] + [ciphertext + 16-byte GCM tag]
    The nonce is randomly generated per encryption call.
    """
    key   = _get_master_key()
    nonce = os.urandom(_NONCE_LEN)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_bytes(blob: bytes) -> bytes:
    """
    AES-256-GCM decrypt.
    Expects the blob format produced by encrypt_bytes.
    Raises cryptography.exceptions.InvalidTag if tampered.
    """
    key    = _get_master_key()
    nonce  = blob[:_NONCE_LEN]
    ct     = blob[_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, None)


def encrypt_b64(plaintext: bytes) -> str:
    """Encrypt and return as URL-safe base64 string for DB storage."""
    return base64.urlsafe_b64encode(encrypt_bytes(plaintext)).decode()


def decrypt_b64(b64_str: str) -> bytes:
    """Decrypt a URL-safe base64 string produced by encrypt_b64."""
    return decrypt_bytes(base64.urlsafe_b64decode(b64_str))


def encrypt_json(obj: dict) -> str:
    """Encrypt a JSON-serialisable object → base64 string."""
    return encrypt_b64(json.dumps(obj, separators=(",", ":")).encode())


def decrypt_json(b64_str: str) -> dict:
    """Decrypt a JSON object encrypted with encrypt_json."""
    return json.loads(decrypt_b64(b64_str).decode())


# ── File helpers ───────────────────────────────────────────────────────────────

def file_sha256(data: bytes) -> str:
    """SHA-256 hex digest of raw (pre-encryption) file bytes for integrity tracking."""
    return hashlib.sha256(data).hexdigest()


def encrypt_file(file_bytes: bytes) -> tuple[bytes, str]:
    """
    Encrypt a file for storage.
    Returns:  (encrypted_blob, sha256_of_original)
    """
    digest   = file_sha256(file_bytes)
    blob     = encrypt_bytes(file_bytes)
    return blob, digest


def decrypt_file(blob: bytes) -> bytes:
    """Decrypt a file blob produced by encrypt_file."""
    return decrypt_bytes(blob)
