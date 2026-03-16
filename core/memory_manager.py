import json
import os
import hashlib
import threading
import unicodedata
from pathlib import Path
from typing import Dict, List, Optional, Any
from core.encryption import encrypt, decrypt, is_encryption_enabled, DecryptionError
from core.utils import now_timestamp

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent
DEFAULT_CACHE_DIR = PROJECT_ROOT / "data" / "memories"

# Schema defaults for legacy memories missing new fields
_SCHEMA_DEFAULTS = {
    "source": "unknown",
    "created_by": "unknown",
    "last_modified_by": "unknown",
    "immutable": False,
    "suspicious": False,
    "matched_patterns": [],
    "encrypted": False,
}


class MemoryManager:
    def __init__(self, cache_dir: Optional[Path] = None, max_content_size: int = 100 * 1024):
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.cache_dir, 0o700)
        self.max_content_size = max_content_size
        self._locks: Dict[str, threading.Lock] = {}
        self._locks_lock = threading.Lock()

    def _get_key_lock(self, key: str) -> threading.Lock:
        """Return a per-key lock, creating one if needed."""
        with self._locks_lock:
            if key not in self._locks:
                self._locks[key] = threading.Lock()
            return self._locks[key]

    def _get_file_path(self, key: str) -> Path:
        """Get the SHA-256 file path for a given memory key."""
        key = unicodedata.normalize("NFC", key)
        safe_key = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{safe_key}.json"

    def _get_legacy_file_path(self, key: str) -> Path:
        """Get the legacy MD5 file path for backward compatibility."""
        key = unicodedata.normalize("NFC", key)
        safe_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{safe_key}.json"

    def _migrate_if_needed(self, key: str) -> Optional[Path]:
        """If a SHA-256 file exists, return it. Otherwise migrate from MD5 if present."""
        sha_path = self._get_file_path(key)
        if sha_path.exists():
            return sha_path

        md5_path = self._get_legacy_file_path(key)
        if md5_path.exists():
            # Migrate: read from MD5, write to SHA-256, delete MD5
            try:
                with open(md5_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._write_json(sha_path, data)
                md5_path.unlink()
                return sha_path
            except (json.JSONDecodeError, OSError):
                return None

        return None

    def _write_json(self, file_path: Path, data: Dict[str, Any]) -> None:
        """Write JSON data to file atomically with 0o600 permissions.

        Writes to a temp file in the same directory, then atomically replaces
        the target. Uses os.fdopen for proper file object handling.
        """
        import tempfile
        content = json.dumps(data, indent=2, ensure_ascii=False)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(file_path.parent), prefix=".tmp_", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, str(file_path))
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _apply_schema_defaults(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add missing schema fields with safe defaults for legacy memories."""
        for field, default in _SCHEMA_DEFAULTS.items():
            if field not in data:
                # Use a copy for mutable defaults
                data[field] = default if not isinstance(default, list) else list(default)
        if "title" not in data:
            data["title"] = data.get("key", "")
        return data

    def store_memory(
        self,
        key: str,
        content: str,
        tags: Optional[List[str]] = None,
        title: Optional[str] = None,
        source: str = "unknown",
        created_by: str = "unknown",
        suspicious: bool = False,
        matched_patterns: Optional[List[str]] = None,
        audit_entry: Optional[str] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """Store a new memory or overwrite an existing one.

        Raises ValueError if the memory is immutable and force=False.
        """
        with self._get_key_lock(key):
            file_path = self._get_file_path(key)
            now = now_timestamp()

            memory_data = {
                "key": key,
                "title": title or key,
                "content": content,
                "tags": tags or [],
                "created_at": now,
                "updated_at": now,
                "lines": len(content.splitlines()),
                "chars": len(content),
                "source": source,
                "created_by": created_by,
                "last_modified_by": created_by,
                "immutable": False,
                "suspicious": suspicious,
                "matched_patterns": matched_patterns or [],
                "encrypted": False,
            }

            # Append audit entry if provided
            if audit_entry:
                content = f"{content}\n\n---\n**{now} | {audit_entry}**"
                memory_data["content"] = content
                memory_data["chars"] = len(content)
                memory_data["lines"] = len(content.splitlines())

            # Check content size (including audit trail)
            if len(memory_data["content"].encode("utf-8")) > self.max_content_size:
                raise ValueError(
                    "Content with audit trail exceeds max size (%d bytes)" % self.max_content_size
                )

            # If updating, preserve fields AND check immutability (COMBINED)
            existing_path = self._migrate_if_needed(key)
            if existing_path and existing_path.exists():
                try:
                    with open(existing_path, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                    # Defense-in-depth: check immutability at the core layer
                    if not force and existing.get("immutable"):
                        raise ValueError(
                            f"Memory '{key}' is immutable. Use force=True to override."
                        )
                    memory_data["created_at"] = existing.get("created_at", now)
                    if not title:
                        memory_data["title"] = existing.get("title", key)
                    # Preserve provenance from original write
                    memory_data["source"] = existing.get("source", source)
                    memory_data["created_by"] = existing.get("created_by", created_by)
                    memory_data["immutable"] = existing.get("immutable", False)
                except (json.JSONDecodeError, OSError):
                    pass  # Overwrite if corrupt

            # Encrypt content if encryption is enabled
            if is_encryption_enabled():
                memory_data["content"] = encrypt(content)
                memory_data["encrypted"] = True

            self._write_json(file_path, memory_data)
            return memory_data

    def retrieve_memory(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve a memory by key."""
        file_path = self._migrate_if_needed(key)
        if file_path is None:
            return None

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

        data = self._apply_schema_defaults(data)

        # Decrypt content if it was encrypted
        if data.get("encrypted"):
            try:
                data["content"] = decrypt(data["content"])
            except DecryptionError:
                data["content"] = "[DECRYPTION FAILED] Content cannot be decrypted. The encryption key may have changed."
                data["decryption_failed"] = True

        return data

    def list_memories(self, decrypt_content: bool = True) -> List[Dict[str, Any]]:
        """List all memories with metadata."""
        memories = []
        for file_path in self.cache_dir.glob("*.json"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data = self._apply_schema_defaults(data)
                # Decrypt content for search/snippet
                if decrypt_content and data.get("encrypted"):
                    try:
                        data["content"] = decrypt(data["content"])
                    except DecryptionError:
                        data["content"] = "[DECRYPTION FAILED] Content cannot be decrypted."
                        data["decryption_failed"] = True
                # Add a snippet for display
                data["snippet"] = (
                    data["content"][:100] + "..."
                    if len(data["content"]) > 100
                    else data["content"]
                )
                memories.append(data)
            except (json.JSONDecodeError, OSError):
                continue

        # Sort by updated_at descending
        return sorted(memories, key=lambda x: x.get("updated_at", ""), reverse=True)

    def search_memories(self, query: str) -> List[Dict[str, Any]]:
        """Search memories by key, title, or content."""
        query_lower = query.lower()
        results = []
        # First pass: search key/title without decrypting content
        all_memories = self.list_memories(decrypt_content=False)
        needs_content_search = []
        for mem in all_memories:
            if (
                query_lower in mem["key"].lower()
                or query_lower in mem.get("title", "").lower()
            ):
                # Match on key/title — decrypt content for the result
                if mem.get("encrypted"):
                    try:
                        mem["content"] = decrypt(mem["content"])
                    except DecryptionError:
                        mem["content"] = "[DECRYPTION FAILED] Content cannot be decrypted."
                        mem["decryption_failed"] = True
                    mem["snippet"] = (
                        mem["content"][:100] + "..."
                        if len(mem["content"]) > 100
                        else mem["content"]
                    )
                results.append(mem)
            else:
                needs_content_search.append(mem)

        # Second pass: decrypt and search content only for non-matches
        for mem in needs_content_search:
            if mem.get("encrypted"):
                try:
                    mem["content"] = decrypt(mem["content"])
                except DecryptionError:
                    mem["content"] = "[DECRYPTION FAILED] Content cannot be decrypted."
                    mem["decryption_failed"] = True
                    mem["snippet"] = mem["content"]
                    continue
                mem["snippet"] = (
                    mem["content"][:100] + "..."
                    if len(mem["content"]) > 100
                    else mem["content"]
                )
            if query_lower in mem["content"].lower():
                results.append(mem)

        return results

    def delete_memory(self, key: str, force: bool = False) -> bool:
        """Delete a memory by key.

        Raises ValueError if the memory is immutable and force=False.
        """
        with self._get_key_lock(key):
            # Defense-in-depth: check immutability at the core layer
            if not force:
                check_path = self._migrate_if_needed(key)
                if check_path is None:
                    check_path = self._get_file_path(key)
                if check_path.exists():
                    try:
                        with open(check_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        if data.get("immutable"):
                            raise ValueError(
                                f"Memory '{key}' is immutable. Use force=True to override."
                            )
                    except (json.JSONDecodeError, OSError):
                        pass
            file_path = self._get_file_path(key)
            if file_path.exists():
                file_path.unlink()
                # Clean up per-key lock
                with self._locks_lock:
                    self._locks.pop(key, None)
                return True
            # Check legacy MD5 path
            legacy_path = self._get_legacy_file_path(key)
            if legacy_path.exists():
                legacy_path.unlink()
                # Clean up per-key lock
                with self._locks_lock:
                    self._locks.pop(key, None)
                return True
            return False

    def set_immutable(self, key: str, value: bool = True) -> Optional[Dict]:
        """Set the immutable flag on a memory. Returns updated data or None if not found."""
        with self._get_key_lock(key):
            file_path = self._migrate_if_needed(key)
            if file_path is None:
                file_path = self._get_file_path(key)
            if not file_path.exists():
                return None
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                return None
            data = self._apply_schema_defaults(data)
            data["immutable"] = bool(value)
            self._write_json(file_path, data)
            return data

    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        memories = self.list_memories()
        return {
            "total_count": len(memories),
            "total_chars": sum(m["chars"] for m in memories),
            "storage_path": str(self.cache_dir),
        }


# Global instance
memory_manager = MemoryManager()
