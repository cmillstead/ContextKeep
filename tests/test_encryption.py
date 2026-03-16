import os
import pathlib
import stat
import pytest
from unittest.mock import patch

import core.encryption as enc
from core.encryption import encrypt, decrypt, is_encryption_enabled


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def salt_dir(tmp_path):
    """Redirect PROJECT_ROOT to a temporary directory so each test gets
    its own salt file, and clear the Fernet cache between tests."""
    enc._get_fernet.cache_clear()
    enc._salt_checked = False
    with patch.object(enc, "PROJECT_ROOT", tmp_path):
        yield tmp_path
    enc._get_fernet.cache_clear()
    enc._salt_checked = False


# ---------------------------------------------------------------------------
# Original tests (updated for salt_dir fixture)
# ---------------------------------------------------------------------------


def test_encryption_disabled_by_default():
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("CONTEXTKEEP_SECRET", None)
        assert is_encryption_enabled() is False


def test_encrypt_passthrough_when_disabled():
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("CONTEXTKEEP_SECRET", None)
        plaintext = "Hello, world!"
        assert encrypt(plaintext) == plaintext


def test_decrypt_passthrough_when_disabled():
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("CONTEXTKEEP_SECRET", None)
        text = "Hello, world!"
        assert decrypt(text) == text


def test_encryption_enabled_with_secret():
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "my-test-secret"}):
        assert is_encryption_enabled() is True


def test_encrypt_produces_different_output():
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "my-test-secret"}):
        plaintext = "Sensitive memory content"
        ciphertext = encrypt(plaintext)
        assert ciphertext != plaintext
        assert len(ciphertext) > 0


def test_roundtrip_encrypt_decrypt():
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "my-test-secret"}):
        plaintext = "Project API key: sk-12345"
        ciphertext = encrypt(plaintext)
        decrypted = decrypt(ciphertext)
        assert decrypted == plaintext


def test_different_secrets_produce_different_ciphertext():
    plaintext = "Same content"
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "secret-one"}):
        ct1 = encrypt(plaintext)
    enc._get_fernet.cache_clear()
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "secret-two"}):
        ct2 = encrypt(plaintext)
    assert ct1 != ct2


def test_wrong_secret_fails_decrypt(salt_dir):
    from core.encryption import DecryptionError
    plaintext = "Sensitive data"
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "correct-secret"}):
        ciphertext = encrypt(plaintext)
    enc._get_fernet.cache_clear()
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "wrong-secret"}):
        with pytest.raises(DecryptionError):
            decrypt(ciphertext)


def test_unicode_content():
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-secret"}):
        plaintext = "Unicode content: caf\u00e9 \U0001f600 \u4e16\u754c"
        assert decrypt(encrypt(plaintext)) == plaintext


def test_empty_string():
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-secret"}):
        assert decrypt(encrypt("")) == ""


# ---------------------------------------------------------------------------
# TestSaltFile
# ---------------------------------------------------------------------------


class TestSaltFile:
    """Tests for salt file creation, loading, and persistence."""

    def test_salt_file_created_on_first_encrypt(self, salt_dir):
        salt_path = salt_dir / ".contextkeep_salt"
        assert not salt_path.exists()
        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-secret"}):
            encrypt("hello")
        assert salt_path.exists()

    def test_salt_file_is_16_bytes(self, salt_dir):
        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-secret"}):
            encrypt("hello")
        salt_path = salt_dir / ".contextkeep_salt"
        assert len(salt_path.read_bytes()) == 16

    def test_salt_file_reused_across_calls(self, salt_dir):
        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-secret"}):
            encrypt("first")
            salt_after_first = (salt_dir / ".contextkeep_salt").read_bytes()
            enc._get_fernet.cache_clear()
            encrypt("second")
            salt_after_second = (salt_dir / ".contextkeep_salt").read_bytes()
        assert salt_after_first == salt_after_second

    def test_get_salt_path_uses_project_root(self, salt_dir):
        expected = salt_dir / ".contextkeep_salt"
        assert enc._get_salt_path() == expected


# ---------------------------------------------------------------------------
# TestFernetCache
# ---------------------------------------------------------------------------


class TestFernetCache:
    """Tests for the Fernet instance cache."""

    def test_cache_returns_same_fernet_instance(self, salt_dir):
        salt = enc._load_or_create_salt()
        f1 = enc._get_fernet("secret", salt)
        f2 = enc._get_fernet("secret", salt)
        assert f1 is f2

    def test_cache_different_keys_different_instances(self, salt_dir):
        salt = enc._load_or_create_salt()
        f1 = enc._get_fernet("secret-a", salt)
        f2 = enc._get_fernet("secret-b", salt)
        assert f1 is not f2


# ---------------------------------------------------------------------------
# TestBackwardCompatDecrypt
# ---------------------------------------------------------------------------


class TestBackwardCompatDecrypt:
    """Verify decrypt falls back to _STATIC_SALT for legacy tokens."""

    def test_decrypt_legacy_static_salt_token(self, salt_dir):
        secret = "my-secret"
        plaintext = "legacy data"

        # Encrypt with the old static salt directly
        from cryptography.fernet import Fernet as F
        key = enc._derive_key(secret, enc._STATIC_SALT)
        legacy_token = F(key).encrypt(plaintext.encode()).decode()

        # Ensure the random salt exists (different from static)
        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": secret}):
            # Trigger salt file creation with random salt
            encrypt("trigger")
            enc._get_fernet.cache_clear()

            # decrypt should fall back to static salt and succeed
            result = decrypt(legacy_token)
            assert result == plaintext


# ---------------------------------------------------------------------------
# TestSaltFilePermissions
# ---------------------------------------------------------------------------


class TestSaltFilePermissions:
    """Tests for salt file permission security."""

    def test_salt_file_created_with_0600(self, salt_dir):
        """Salt file must have 0o600 permissions after creation."""
        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-secret"}):
            encrypt("trigger salt creation")
        salt_path = salt_dir / ".contextkeep_salt"
        mode = stat.S_IMODE(os.stat(salt_path).st_mode)
        assert mode == 0o600

    def test_existing_salt_file_not_recreated(self, salt_dir):
        """If salt file already exists, _load_or_create_salt should read it, not recreate."""
        salt_path = salt_dir / ".contextkeep_salt"
        original_salt = os.urandom(16)
        # Write with restricted perms
        fd = os.open(str(salt_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, original_salt)
        finally:
            os.close(fd)

        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-secret"}):
            loaded_salt = enc._load_or_create_salt()
        assert loaded_salt == original_salt

    def test_check_salt_permissions_warns_on_open_perms(self, salt_dir):
        """check_salt_permissions should return False if salt file is world-readable."""
        salt_path = salt_dir / ".contextkeep_salt"
        salt_path.write_bytes(os.urandom(16))
        os.chmod(salt_path, 0o644)
        assert enc.check_salt_permissions() is False

    def test_check_salt_permissions_ok_on_correct_perms(self, salt_dir):
        """check_salt_permissions should return True if salt file is 0o600."""
        salt_path = salt_dir / ".contextkeep_salt"
        salt_path.write_bytes(os.urandom(16))
        os.chmod(salt_path, 0o600)
        assert enc.check_salt_permissions() is True

    def test_check_salt_permissions_ok_when_no_file(self, salt_dir):
        """check_salt_permissions should return True if salt file doesn't exist yet."""
        assert enc.check_salt_permissions() is True


# ---------------------------------------------------------------------------
# TestDecryptionError
# ---------------------------------------------------------------------------


class TestDecryptionError:
    def test_decrypt_invalid_token_raises_decryption_error(self, salt_dir):
        """decrypt() with a bad token should raise DecryptionError, not InvalidToken."""
        from core.encryption import DecryptionError
        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-secret"}):
            encrypt("trigger salt")
            enc._get_fernet.cache_clear()
            with pytest.raises(DecryptionError):
                decrypt("not-a-valid-fernet-token")

    def test_decrypt_wrong_key_raises_decryption_error(self, salt_dir):
        """decrypt() with wrong key should raise DecryptionError."""
        from core.encryption import DecryptionError
        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "correct-key"}):
            ct = encrypt("secret")
        enc._get_fernet.cache_clear()
        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "wrong-key"}):
            with pytest.raises(DecryptionError):
                decrypt(ct)

    def test_decryption_error_is_value_error_subclass(self):
        """DecryptionError should be a ValueError subclass."""
        from core.encryption import DecryptionError
        assert issubclass(DecryptionError, ValueError)


# ---------------------------------------------------------------------------
# TestSaltPermissionsOnLoad (Task 1.2)
# ---------------------------------------------------------------------------


class TestSaltPermissionsOnLoad:
    """check_salt_permissions is called once when loading an existing salt."""

    def test_load_salt_calls_check_permissions(self, salt_dir):
        """_load_or_create_salt should call check_salt_permissions on existing salt."""
        salt_path = salt_dir / ".contextkeep_salt"
        salt_path.write_bytes(os.urandom(16))
        os.chmod(salt_path, 0o644)

        import logging
        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-secret"}):
            with patch("core.encryption.check_salt_permissions", wraps=enc.check_salt_permissions) as mock_check:
                enc._load_or_create_salt()
                assert mock_check.call_count == 1

    def test_load_salt_warns_on_bad_permissions(self, salt_dir):
        """Loading salt with 0o644 should log a warning."""
        import logging
        salt_path = salt_dir / ".contextkeep_salt"
        salt_path.write_bytes(os.urandom(16))
        os.chmod(salt_path, 0o644)

        logger = logging.getLogger("contextkeep.encryption")
        with patch.object(logger, "warning") as mock_warn:
            enc._load_or_create_salt()
            assert mock_warn.call_count == 1

    def test_salt_check_only_once(self, salt_dir):
        """check_salt_permissions should only be called once (cached flag)."""
        salt_path = salt_dir / ".contextkeep_salt"
        salt_path.write_bytes(os.urandom(16))
        os.chmod(salt_path, 0o600)

        with patch("core.encryption.check_salt_permissions", wraps=enc.check_salt_permissions) as mock_check:
            enc._load_or_create_salt()
            enc._load_or_create_salt()
            enc._load_or_create_salt()
            assert mock_check.call_count == 1


# ---------------------------------------------------------------------------
# TestLRUFernetCache (Task 1.3)
# ---------------------------------------------------------------------------


class TestLRUFernetCache:
    """Fernet cache is an LRU cache with maxsize=4."""

    def test_cache_maxsize_is_4(self, salt_dir):
        assert enc._get_fernet.cache_info().maxsize == 4

    def test_cache_hits_on_repeated_calls(self, salt_dir):
        salt = enc._load_or_create_salt()
        enc._get_fernet.cache_clear()
        enc._get_fernet("secret", salt)
        enc._get_fernet("secret", salt)
        info = enc._get_fernet.cache_info()
        assert info.hits >= 1
        assert info.misses >= 1

    def test_cache_evicts_beyond_maxsize(self, salt_dir):
        """After 5 distinct entries, the first should be evicted."""
        enc._get_fernet.cache_clear()
        salts = [os.urandom(16) for _ in range(5)]
        for s in salts:
            enc._get_fernet("secret", s)
        info = enc._get_fernet.cache_info()
        assert info.currsize == 4  # maxsize=4, so oldest evicted
