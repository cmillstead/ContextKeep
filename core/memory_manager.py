import json
import os
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.encryption import encrypt, decrypt, is_encryption_enabled
from core.utils import now_timestamp

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent
CACHE_DIR = PROJECT_ROOT / "data" / "memories"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
os.chmod(CACHE_DIR, 0o700)

# Schema defaults for legacy memories missing new fields
_SCHEMA_DEFAULTS = {
    "source": "unknown",
    "created_by": "unknown",
    "immutable": False,
    "suspicious": False,
    "matched_patterns": [],
    "encrypted": False,
}


class MemoryManager:
    def __init__(self):
        self.cache_dir = CACHE_DIR

    def _get_file_path(self, key: str) -> Path:
        """Get the SHA-256 file path for a given memory key."""
        safe_key = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{safe_key}.json"

    def _get_legacy_file_path(self, key: str) -> Path:
        """Get the legacy MD5 file path for backward compatibility."""
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
        """Write JSON data to file with 0o600 permissions."""
        content = json.dumps(data, indent=2, ensure_ascii=False)
        # Open with restricted permissions from the start
        fd = os.open(str(file_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
        # Ensure permissions are correct even if umask interfered
        os.chmod(file_path, 0o600)

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
    ) -> Dict[str, Any]:
        """Store a new memory or overwrite an existing one."""
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
            "immutable": False,
            "suspicious": suspicious,
            "matched_patterns": matched_patterns or [],
            "encrypted": False,
        }

        # Append audit entry if provided
        if audit_entry:
            timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
            content = f"{content}\n\n---\n**{timestamp} | {audit_entry}**"
            memory_data["content"] = content
            memory_data["chars"] = len(content)
            memory_data["lines"] = len(content.splitlines())

        # If updating, preserve created_at, title, source, created_by, immutable
        existing_path = self._migrate_if_needed(key)
        if existing_path and existing_path.exists():
            try:
                with open(existing_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
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
            data["content"] = decrypt(data["content"])

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
                    data["content"] = decrypt(data["content"])
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
        query = query.lower()
        results = []
        all_memories = self.list_memories()

        for mem in all_memories:
            if (
                query in mem["key"].lower()
                or query in mem.get("title", "").lower()
                or query in mem["content"].lower()
            ):
                results.append(mem)

        return results

    def delete_memory(self, key: str) -> bool:
        """Delete a memory by key."""
        file_path = self._get_file_path(key)
        if file_path.exists():
            file_path.unlink()
            return True
        # Check legacy MD5 path
        legacy_path = self._get_legacy_file_path(key)
        if legacy_path.exists():
            legacy_path.unlink()
            return True
        return False

    def set_immutable(self, key: str, value: bool = True) -> Optional[Dict]:
        """Set the immutable flag on a memory. Returns updated data or None if not found."""
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
