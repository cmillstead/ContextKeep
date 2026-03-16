"""Optional Fernet encryption for memory content at rest.

Encryption is enabled when CONTEXTKEEP_SECRET env var is set.
When disabled, encrypt/decrypt are no-ops (passthrough).
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_SALT = b"contextkeep-v1-static-salt"


def _derive_key(secret: str) -> bytes:
    """Derive a Fernet key from a passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))


def is_encryption_enabled() -> bool:
    """True if CONTEXTKEEP_SECRET env var is set."""
    return bool(os.environ.get("CONTEXTKEEP_SECRET"))


def encrypt(plaintext: str) -> str:
    """Encrypt text. Returns base64 Fernet token. No-op if CONTEXTKEEP_SECRET not set."""
    secret = os.environ.get("CONTEXTKEEP_SECRET")
    if not secret:
        return plaintext
    key = _derive_key(secret)
    f = Fernet(key)
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt Fernet token. No-op if CONTEXTKEEP_SECRET not set."""
    secret = os.environ.get("CONTEXTKEEP_SECRET")
    if not secret:
        return ciphertext
    key = _derive_key(secret)
    f = Fernet(key)
    return f.decrypt(ciphertext.encode()).decode()
