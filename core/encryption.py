"""Optional Fernet encryption for memory content at rest.

Encryption is enabled when CONTEXTKEEP_SECRET env var is set.
When disabled, encrypt/decrypt are no-ops (passthrough).

Salt handling:
- A random 16-byte salt is generated once and persisted to
  ``<PROJECT_ROOT>/.contextkeep_salt``.
- ``_STATIC_SALT`` is kept for backward-compat decryption of
  tokens that were encrypted before the random-salt migration.
"""

import os
import base64
import pathlib
from typing import Dict, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# Project root & salt helpers
# ---------------------------------------------------------------------------

PROJECT_ROOT: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent

_STATIC_SALT: bytes = b"contextkeep-v1-static-salt"


def _get_salt_path() -> pathlib.Path:
    """Return the path to the persisted random salt file."""
    return PROJECT_ROOT / ".contextkeep_salt"


def _load_or_create_salt() -> bytes:
    """Load the random salt from disk, or create & persist a new one.

    Uses O_EXCL for race-free creation and sets 0o600 permissions.
    """
    salt_path = _get_salt_path()
    if salt_path.exists():
        return salt_path.read_bytes()
    salt = os.urandom(16)
    salt_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(salt_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, salt)
        finally:
            os.close(fd)
    except FileExistsError:
        # Race condition: another process created it first
        return salt_path.read_bytes()
    return salt


def check_salt_permissions() -> bool:
    """Check that the salt file has safe permissions (0o600).

    Returns True if the file doesn't exist or has correct permissions.
    Returns False and logs a warning if permissions are too open.
    """
    import logging
    import stat
    salt_path = _get_salt_path()
    if not salt_path.exists():
        return True
    mode = stat.S_IMODE(os.stat(salt_path).st_mode)
    if mode != 0o600:
        logging.getLogger("contextkeep.encryption").warning(
            "Salt file %s has permissions %o (expected 0600). Run: chmod 600 %s",
            salt_path, mode, salt_path,
        )
        return False
    return True


# ---------------------------------------------------------------------------
# Key derivation & Fernet cache
# ---------------------------------------------------------------------------

_fernet_cache: Dict[Tuple[str, bytes], Fernet] = {}


def _derive_key(secret: str, salt: bytes) -> bytes:
    """Derive a Fernet key from a passphrase and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))


def _get_fernet(secret: str, salt: bytes) -> Fernet:
    """Return a cached Fernet instance for the given (secret, salt) pair."""
    cache_key = (secret, salt)
    if cache_key not in _fernet_cache:
        key = _derive_key(secret, salt)
        _fernet_cache[cache_key] = Fernet(key)
    return _fernet_cache[cache_key]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_encryption_enabled() -> bool:
    """True if CONTEXTKEEP_SECRET env var is set."""
    return bool(os.environ.get("CONTEXTKEEP_SECRET"))


def encrypt(plaintext: str) -> str:
    """Encrypt text. Returns base64 Fernet token. No-op if CONTEXTKEEP_SECRET not set."""
    secret = os.environ.get("CONTEXTKEEP_SECRET")
    if not secret:
        return plaintext
    salt = _load_or_create_salt()
    f = _get_fernet(secret, salt)
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt Fernet token. No-op if CONTEXTKEEP_SECRET not set.

    Tries the random salt first; falls back to the legacy static salt
    for backward compatibility with tokens encrypted before the migration.
    """
    secret = os.environ.get("CONTEXTKEEP_SECRET")
    if not secret:
        return ciphertext

    salt = _load_or_create_salt()
    f = _get_fernet(secret, salt)
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        pass

    # Fallback: try static salt for pre-migration tokens
    f_static = _get_fernet(secret, _STATIC_SALT)
    return f_static.decrypt(ciphertext.encode()).decode()
