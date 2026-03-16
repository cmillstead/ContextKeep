import json
import os
import stat
import hashlib
import pytest
from pathlib import Path
from unittest.mock import patch
from core.memory_manager import MemoryManager


@pytest.fixture
def manager(tmp_path):
    """Create a MemoryManager with a temp data directory."""
    data_dir = tmp_path / "data" / "memories"
    data_dir.mkdir(parents=True)
    mgr = MemoryManager()
    mgr.cache_dir = data_dir
    return mgr


class TestSHA256Migration:
    def test_new_memory_uses_sha256_filename(self, manager):
        manager.store_memory("test-key", "content", source="cli", created_by="test")
        expected_hash = hashlib.sha256("test-key".encode()).hexdigest()
        assert (manager.cache_dir / f"{expected_hash}.json").exists()

    def test_md5_file_migrated_on_read(self, manager):
        key = "legacy-key"
        md5_hash = hashlib.md5(key.encode()).hexdigest()
        sha256_hash = hashlib.sha256(key.encode()).hexdigest()
        md5_path = manager.cache_dir / f"{md5_hash}.json"
        data = {"key": key, "content": "old data", "title": key,
                "tags": [], "created_at": "2025-01-01", "updated_at": "2025-01-01",
                "lines": 1, "chars": 8}
        md5_path.write_text(json.dumps(data))
        result = manager.retrieve_memory(key)
        assert result is not None
        assert result["content"] == "old data"
        assert not md5_path.exists()
        assert (manager.cache_dir / f"{sha256_hash}.json").exists()

    def test_sha256_file_preferred_over_md5(self, manager):
        key = "dual-key"
        md5_hash = hashlib.md5(key.encode()).hexdigest()
        sha256_hash = hashlib.sha256(key.encode()).hexdigest()
        old_data = {"key": key, "content": "old", "title": key,
                    "tags": [], "created_at": "2025-01-01", "updated_at": "2025-01-01",
                    "lines": 1, "chars": 3}
        new_data = {"key": key, "content": "new", "title": key,
                    "tags": [], "created_at": "2025-01-01", "updated_at": "2025-01-01",
                    "lines": 1, "chars": 3}
        (manager.cache_dir / f"{md5_hash}.json").write_text(json.dumps(old_data))
        (manager.cache_dir / f"{sha256_hash}.json").write_text(json.dumps(new_data))
        result = manager.retrieve_memory(key)
        assert result["content"] == "new"


class TestFilePermissions:
    def test_written_file_has_0600_permissions(self, manager):
        manager.store_memory("perm-test", "secret", source="test", created_by="test")
        sha = hashlib.sha256("perm-test".encode()).hexdigest()
        file_path = manager.cache_dir / f"{sha}.json"
        mode = stat.S_IMODE(os.stat(file_path).st_mode)
        assert mode == 0o600


class TestSchemaFields:
    def test_new_fields_stored(self, manager):
        manager.store_memory("schema-test", "content",
                             source="mcp", created_by="mcp-tool")
        result = manager.retrieve_memory("schema-test")
        assert result["source"] == "mcp"
        assert result["created_by"] == "mcp-tool"
        assert result["immutable"] is False
        assert result["suspicious"] is False
        assert result["matched_patterns"] == []
        assert result["encrypted"] is False

    def test_source_preserved_on_update(self, manager):
        manager.store_memory("provenance", "v1", source="mcp", created_by="mcp-tool")
        manager.store_memory("provenance", "v2", source="human", created_by="webui")
        result = manager.retrieve_memory("provenance")
        assert result["content"] == "v2"
        assert result["source"] == "mcp"
        assert result["created_by"] == "mcp-tool"

    def test_legacy_memory_gets_defaults(self, manager):
        sha = hashlib.sha256("legacy".encode()).hexdigest()
        old_data = {"key": "legacy", "content": "old", "title": "legacy",
                    "tags": [], "created_at": "2025-01-01", "updated_at": "2025-01-01",
                    "lines": 1, "chars": 3}
        (manager.cache_dir / f"{sha}.json").write_text(json.dumps(old_data))
        result = manager.retrieve_memory("legacy")
        assert result["source"] == "unknown"
        assert result["created_by"] == "unknown"
        assert result["immutable"] is False
        assert result["suspicious"] is False

    def test_immutable_field_roundtrip(self, manager):
        manager.store_memory("lock-test", "content", source="human", created_by="webui")
        result = manager.retrieve_memory("lock-test")
        result["immutable"] = True
        sha = hashlib.sha256("lock-test".encode()).hexdigest()
        with open(manager.cache_dir / f"{sha}.json", "w") as f:
            json.dump(result, f)
        result2 = manager.retrieve_memory("lock-test")
        assert result2["immutable"] is True


class TestEncryptionIntegration:
    def test_content_encrypted_when_enabled(self, manager):
        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-key"}):
            manager.store_memory("enc-test", "secret content", source="test", created_by="test")
            sha = hashlib.sha256("enc-test".encode()).hexdigest()
            with open(manager.cache_dir / f"{sha}.json") as f:
                raw = json.load(f)
            assert raw["encrypted"] is True
            assert raw["content"] != "secret content"
            result = manager.retrieve_memory("enc-test")
            assert result["content"] == "secret content"

    def test_unencrypted_memory_readable_when_encryption_enabled(self, manager):
        sha = hashlib.sha256("plain".encode()).hexdigest()
        data = {"key": "plain", "content": "plain text", "title": "plain",
                "tags": [], "created_at": "2025-01-01", "updated_at": "2025-01-01",
                "lines": 1, "chars": 10, "encrypted": False}
        (manager.cache_dir / f"{sha}.json").write_text(json.dumps(data))
        with patch.dict(os.environ, {"CONTEXTKEEP_SECRET": "test-key"}):
            result = manager.retrieve_memory("plain")
            assert result["content"] == "plain text"


class TestErrorHandling:
    def test_corrupt_json_returns_none(self, manager):
        sha = hashlib.sha256("corrupt".encode()).hexdigest()
        (manager.cache_dir / f"{sha}.json").write_text("not json{{{")
        result = manager.retrieve_memory("corrupt")
        assert result is None

    def test_corrupt_json_skipped_in_list(self, manager):
        sha = hashlib.sha256("bad".encode()).hexdigest()
        (manager.cache_dir / f"{sha}.json").write_text("broken")
        manager.store_memory("good", "valid", source="test", created_by="test")
        memories = manager.list_memories()
        assert len(memories) == 1
        assert memories[0]["key"] == "good"

    def test_no_dead_code_in_retrieve(self, manager):
        manager.store_memory("alive", "test", source="test", created_by="test")
        result = manager.retrieve_memory("alive")
        assert result["content"] == "test"
        assert manager.retrieve_memory("nonexistent") is None
