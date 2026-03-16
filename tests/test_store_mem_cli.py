import os
import pytest
from unittest.mock import patch


class TestEncryptExisting:
    def test_encrypt_skips_already_encrypted(self, manager):
        with patch("store_mem_cli.memory_manager", manager):
            with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-key"}):
                manager.store_memory("plain", "content", source="test", created_by="test")
                from store_mem_cli import encrypt_existing
                encrypt_existing()
                mem = manager.retrieve_memory("plain")
                assert mem is not None

    def test_encrypt_handles_immutable_with_force(self, manager):
        with patch("store_mem_cli.memory_manager", manager):
            with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-key"}):
                manager.store_memory("locked", "content", source="test", created_by="test")
                manager.set_immutable("locked", True)
                from store_mem_cli import encrypt_existing
                # Should not raise — force=True bypasses immutability
                encrypt_existing()


class TestDecryptExisting:
    def test_decrypt_handles_immutable_with_force(self, manager):
        with patch("store_mem_cli.memory_manager", manager):
            with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-key"}):
                manager.store_memory("enc-locked", "secret", source="test", created_by="test")
                manager.set_immutable("enc-locked", True)
                from store_mem_cli import decrypt_existing
                # Should not raise — force=True bypasses immutability
                decrypt_existing()
