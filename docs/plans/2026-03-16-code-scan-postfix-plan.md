# ContextKeep Post-Fix Code Scan Plan — 2026-03-16

**Total tasks**: 12 findings (0 CRIT, 2 HIGH, 4 MED, 6 LOW)
**Vault reference**: `ContextKeep Code Scan 2026-03-16 Post-Fix.md`

---

## Phase 1: HIGH Fixes (2 tasks)

### Task 1.1: Fix double-read TOCTOU in store_memory() (CODE-HIGH-1)
- **Files**: `core/memory_manager.py`
- **Fix**: Combine immutability check and update path into a single file read. Read once, check immutability, use that data for provenance preservation.
- **Tests** (1): Verify `_migrate_if_needed` called once per `store_memory()` on existing key

### Task 1.2: Fix store_mem_cli.py immutability bypass (SEC-HIGH-2)
- **Files**: `store_mem_cli.py`
- **Fix**: Pass `force=True` to `store_memory()` in `encrypt_existing()` and `decrypt_existing()`. Use context manager for env var manipulation in `decrypt_existing()`.
- **Tests** (2): Create `tests/test_store_mem_cli.py` with encrypt/decrypt + immutable memory tests

---

## Phase 2: MED Fixes (4 tasks)

### Task 2.1: Fix delete_memory() legacy path immutability gap (CODE-MED-3)
- **Files**: `core/memory_manager.py`
- **Fix**: Use `_migrate_if_needed()` for immutability check in `delete_memory()`.
- **Tests** (1): Immutable memory at MD5 path, verify ValueError raised

### Task 2.2: Standardize timestamp formats (CODE-MED-4)
- **Files**: `core/memory_manager.py`
- **Fix**: Use consistent format for audit entry timestamps.
- **Tests** (1): Assert audit timestamp format matches pattern

### Task 2.3: Optimize search_memories() decryption (PERF-MED-5)
- **Files**: `core/memory_manager.py`
- **Fix**: Two-pass search: key/title first without decryption, then content with decryption.
- **Tests** (1): Verify search by key doesn't trigger decryption

### Task 2.4: Fix WebUI test isolation (TEST-MED-6)
- **Files**: `tests/test_webui.py`
- **Fix**: Add fixture patching `memory_manager.cache_dir` to `tmp_path`.
- **Tests** (0): Infrastructure fix

---

## Phase 3: LOW Fixes (6 tasks)

### Task 3.1: Remove dead check_timezone.py (CODE-LOW-7)
### Task 3.2: Move module-level side effects to __init__ (CODE-LOW-8)
### Task 3.3: Create conftest.py with shared fixtures (CODE-LOW-9)
### Task 3.4: Add pyproject.toml, remove sys.path hacks (CODE-LOW-10)
### Task 3.5: Add store_mem_cli.py tests (TEST-LOW-11)
### Task 3.6: Consider StoreRequest dataclass (CODE-LOW-12)
