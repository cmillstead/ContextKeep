# ContextKeep Code Scan Implementation Plan — 2026-03-16

**Total tasks**: 19 findings (3 CRIT, 4 HIGH, 6 MED, 6 LOW)
**Total tests to add**: ~18 new tests across 4 phases
**Vault reference**: `ContextKeep Code Scan 2026-03-16.md`

---

## Phase 1: CRIT Fixes (3 tasks, ~6 new tests)

### Task 1.1: Random salt for PBKDF2 (SEC-CRIT-1)
- **Files**: `core/encryption.py`
- **Fix**: Generate random 16-byte salt on first use, persist in `data/.salt`. Fall back to static salt for backward compat.
- **Tests** (2):
  - Different salts produce different keys
  - Existing static-salt data still decrypts after migration

### Task 1.2: Cache Fernet key derivation (DATA-CRIT-2)
- **Files**: `core/encryption.py`
- **Fix**: Cache `Fernet` instance after first derivation. Invalidate if `CONTEXTKEEP_SECRET` changes.
- **Tests** (2):
  - `_derive_key` called exactly once across multiple encrypt/decrypt calls
  - Benchmark: 50 encrypted memories list in under 1 second

### Task 1.3: Lazy content loading in list_memories (DATA-CRIT-3)
- **Files**: `core/memory_manager.py`
- **Fix**: Read only metadata + truncated content for list/search operations.
- **Tests** (2):
  - Snippets correct with truncated loading
  - Peak memory reasonable with 10x50KB memories

---

## Phase 2: HIGH Fixes (4 tasks, ~6 new tests)

### Task 2.1: WebUI immutability checks on delete (SEC-HIGH-4)
- **Files**: `webui.py`
- **Fix**: Add immutability check before `memory_manager.delete_memory()`.
- **Tests** (1): Lock memory, attempt DELETE via WebUI, assert 403

### Task 2.2: WebUI immutability checks on update (SEC-HIGH-5)
- **Files**: `webui.py`
- **Fix**: Check immutable flag before `store_memory()` call.
- **Tests** (1): Lock memory, attempt PUT, assert 403

### Task 2.3: Add MemoryManager.set_immutable() method (CODE-HIGH-6 + CODE-MED-12)
- **Files**: `core/memory_manager.py`, `server.py`, `webui.py`
- **Fix**: New `set_immutable(key, value)` method. Refactor server.py `mark_immutable` and webui.py toggle to use it.
- **Tests** (3): set_immutable on existing, on non-existent key, idempotent call

### Task 2.4: Fix store_memory type hints (CODE-HIGH-7)
- **Files**: `core/memory_manager.py`
- **Fix**: `Optional[List[str]]` for tags and matched_patterns params.
- **Tests** (1): Existing tests sufficient, verify mypy passes

---

## Phase 3: MED Fixes (6 tasks, ~5 new tests)

### Task 3.1: Centralize timestamp generation (CODE-MED-9)
- **Files**: `core/utils.py` (new), `server.py`, `webui.py`, `core/memory_manager.py`
- **Fix**: Create `now_timestamp()`, use everywhere.
- **Tests** (1): Verify returns parseable ISO string

### Task 3.2: Move audit log to MemoryManager (CODE-MED-10)
- **Files**: `core/memory_manager.py`, `server.py`, `webui.py`
- **Fix**: Add `action` parameter to `store_memory()`, append audit trail in manager.
- **Tests** (1): Store + update, verify audit log format

### Task 3.3: Add content scanning to WebUI create (SEC-MED-11)
- **Files**: `webui.py`
- **Fix**: Call `scan_content()` on POST, null check for `request.json`.
- **Tests** (1): POST injection payload, verify suspicious flag

### Task 3.4: Fix double content encoding (CODE-MED-13)
- **Files**: `server.py`
- **Fix**: Store byte length in variable.
- **Tests** (0): Existing tests cover

### Task 3.5: Document or fix async lock (CODE-MED-14)
- **Files**: `server.py`
- **Fix**: Add comment documenting threading.Lock choice, or switch to asyncio.Lock.
- **Tests** (1): Concurrent async allow() calls

### Task 3.6: CSRF token acknowledged (SEC-MED-15)
- No change needed.

---

## Phase 4: LOW Fixes (6 tasks, ~1 new test)

### Task 4.1: Fix install.py version string (CODE-LOW-16)
- **Files**: `install.py`
- **Fix**: V1.0 -> V1.2

### Task 4.2: Remove unused shutil import (CODE-LOW-17)
- **Files**: `install.py`
- **Fix**: Remove `import shutil`

### Task 4.3: Package project properly (CODE-LOW-18)
- **Files**: `pyproject.toml` (new), `webui.py`, `store_mem_cli.py`
- **Fix**: Create pyproject.toml, remove sys.path hacks

### Task 4.4: Add utility script tests (TEST-LOW-19)
- **Files**: `tests/test_cli.py` (new)
- **Tests** (1): encrypt/decrypt roundtrip

### Task 4.5: Expand WebUI test coverage (TEST-LOW-20)
- **Files**: `tests/test_webui.py`
- **Tests**: Search endpoint, PUT change tracking, list with data, 413

### Task 4.6: Adopt pytest-asyncio (TEST-LOW-21)
- **Files**: `tests/test_server.py`
- **Fix**: Convert to async def tests
