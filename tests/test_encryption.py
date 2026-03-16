import os
import pytest
from unittest.mock import patch
from core.encryption import encrypt, decrypt, is_encryption_enabled


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
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "secret-two"}):
        ct2 = encrypt(plaintext)
    assert ct1 != ct2


def test_wrong_secret_fails_decrypt():
    plaintext = "Sensitive data"
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "correct-secret"}):
        ciphertext = encrypt(plaintext)
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "wrong-secret"}):
        with pytest.raises(Exception):
            decrypt(ciphertext)


def test_unicode_content():
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-secret"}):
        plaintext = "Unicode content: caf\u00e9 \U0001f600 \u4e16\u754c"
        assert decrypt(encrypt(plaintext)) == plaintext


def test_empty_string():
    with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-secret"}):
        assert decrypt(encrypt("")) == ""
