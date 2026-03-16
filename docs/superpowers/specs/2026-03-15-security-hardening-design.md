# ContextKeep Security Hardening — Design Spec

**Date:** 2026-03-15
**Status:** Approved
**Scope:** All 23 scan findings + AI attack hardening + optional encryption + self-hosted fonts

---

## 1. Traditional Security Fixes

### server.py
- Remove all `print(f"DEBUG: ...")` statements (13 in server.py + 2 in dead code block of memory_manager.py)
- Replace with `logging` module writing to stderr (level INFO by default)
- Add `--debug` CLI flag to enable DEBUG-level logging
- Default SSE host: `0.0.0.0` -> `127.0.0.1`
- Add new `delete_memory` MCP tool (does not currently exist — new tool with confirmation gate)

### webui.py
- Bind to `127.0.0.1`, `debug=False`
- Replace `str(e)` in all 6 except blocks with generic error messages; log real errors via `logging.exception()`
- Add security headers via `@app.after_request`:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy: default-src 'self'; font-src 'self'; style-src 'self' 'unsafe-inline'`
- Add CSRF protection:
  - Generate token via `secrets.token_hex(32)`, store in module-level variable (regenerates on restart, acceptable for local tool)
  - Render token into `index.html` via Jinja2 `{{ csrf_token }}` in a `<meta>` tag
  - JavaScript reads token from `<meta name="csrf-token">` and adds `X-CSRF-Token` header to all fetch requests
  - `@app.before_request` validates token on POST/PUT/DELETE, returns 403 JSON if invalid
- Set `app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024` (10MB)
- Add `@app.errorhandler(413)` returning JSON `{"success": false, "error": "Request too large"}` (Flask default returns HTML)
- Keep `sys.path.insert(0, str(Path(__file__).parent))` — it is needed for `from core.memory_manager import ...` when running `python webui.py` directly
- Set `app.secret_key = os.urandom(32)` (regenerates on restart — acceptable for local tool with no persistent sessions)

### core/memory_manager.py
- `hashlib.md5` -> `hashlib.sha256` with backward-compat migration:
  - On read: try SHA256 filename first, fall back to MD5 filename, auto-rename to SHA256 using `os.replace()` (atomic on POSIX, handles race conditions)
  - On write: always use SHA256
  - Note: migration is one-way. Recommend backup of `data/memories/` before upgrading. Wrap rename in try/except FileNotFoundError for concurrent process safety.
- Delete dead code (lines 77-85, unreachable second try block)
- Replace bare `except:` with `except (json.JSONDecodeError, OSError):`
- Set file permissions `0o600` on written JSON files via `os.open()` + `os.fdopen()`
- Set directory permissions `0o700` on `data/memories/` at startup

### contextkeep-server.service
- `--host 0.0.0.0` -> `--host 127.0.0.1`

### install_services.sh
- Validate `$SUDO_USER` with `id "$SUDO_USER"` or exit
- Use `mktemp` for temp service files instead of writing to CWD
- Print `localhost` URLs instead of LAN IPs

### store_mem_cli.py
- `sys.path.append(os.getcwd())` -> `sys.path.append(str(Path(__file__).parent))`
- Replace hardcoded Valheim project data with generic placeholder example

### requirements.txt
- Pin: `flask==3.1.3`, `fastmcp==3.1.1`, `cryptography>=46.0.0`

---

## 2. AI Attack Hardening

### New file: core/content_scanner.py

Regex-based prompt injection detector. Single function:

```python
def scan_content(text: str) -> dict:
    """Returns {"suspicious": bool, "matched_patterns": [str]}"""
```

Pattern list as module constant:
```python
INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?previous\s+instructions", "ignore-previous"),
    (r"you\s+are\s+now\s+in\s+.+\s+mode", "mode-switch"),
    (r"\[?\s*system\s*(override|prompt|instruction)", "system-override"),
    (r"disregard\s+(your|all|prior)", "disregard"),
    (r"forget\s+(everything|all|your\s+instructions)", "forget-instructions"),
    (r"new\s+instructions?\s*:", "new-instructions"),
    (r"do\s+not\s+follow\s+(your|the)\s+(previous|original)", "dont-follow"),
    (r"act\s+as\s+(if\s+you\s+are|a)\s+", "act-as"),
    (r"pretend\s+(you\s+are|to\s+be)", "pretend"),
    (r"override\s+(safety|security|content)\s+(filter|policy|restriction)", "override-safety"),
    (r"jailbreak", "jailbreak"),
    (r"DAN\s+mode", "dan-mode"),
    (r"ignore\s+(safety|content)\s+(guidelines|rules|policies)", "ignore-safety"),
]
```

Called only on the write path (store_memory). Non-blocking: memory is still stored, just flagged.

### Memory schema changes

New fields added to JSON (backward-compatible defaults on read):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `source` | string | `"unknown"` | `"mcp"`, `"human"`, `"cli"`, `"unknown"` |
| `created_by` | string | `"unknown"` | `"mcp-tool"`, `"webui"`, `"cli"`, `"unknown"` |
| `immutable` | bool | `false` | If true, MCP tools cannot overwrite or delete |
| `suspicious` | bool | `false` | Set by content scanner |
| `matched_patterns` | list | `[]` | Pattern names that triggered |
| `encrypted` | bool | `false` | Whether content field is encrypted |

### Enforced gates (server.py MCP tools)

**store_memory:**
- Refuses to overwrite keys where `immutable: true` — returns descriptive error
- Runs content scanner on content, sets `suspicious` + `matched_patterns`
- Sets `source: "mcp"`, `created_by: "mcp-tool"`
- Content size cap: 100KB default, configurable via `CONTEXTKEEP_MAX_SIZE` env var

**delete_memory (NEW MCP tool — does not currently exist):**
- Parameters: `key` (str), `confirm` (str)
- `confirm` must equal first 8 chars of `sha256(key)` — e.g., `confirm="a1b2c3d4"`
- Returns the expected confirmation value in the error message so the AI can retry correctly
- Note: confirmation is a deliberate speed bump, not a secret — it prevents casual/injected deletions by requiring a two-step flow
- Refuses to delete keys where `immutable: true`

**Rate limiting:**
- 20 writes/minute sliding window (in-memory counter, resets on restart)
- Applies to `store_memory` only
- Uses `threading.Lock` for thread safety (Flask default server is threaded)
- Returns error with retry-after hint when exceeded

**New tool: mark_immutable(key)**
- Sets `immutable: true` on the specified memory
- One-way via MCP — only WebUI can toggle off
- Returns confirmation message

### Provenance tracking
- `source` tracks original creation only (never overwritten on update)
- `created_by` tracks original creator (never overwritten on update)
- On update, the existing `source` and `created_by` are preserved from the stored JSON
- Immutability enforcement lives in the MCP tool layer ONLY (server.py), never in memory_manager.py — this keeps the WebUI bypass implicit and clean

### WebUI changes
- WebUI bypasses immutability gate (human override — calls memory_manager directly, which has no immutability check)
- WebUI sets `source: "human"`, `created_by: "webui"` on new memories only
- PUT `/api/memories/<key>` accepts optional `immutable` boolean field to toggle lock
- Display badges on memory cards:
  - Yellow warning badge for `suspicious: true`
  - Lock icon for `immutable: true`
  - Source indicator showing provenance (mcp/human/cli)
- Immutability toggle in edit modal (checkbox)

---

## 3. Encryption at Rest

### New file: core/encryption.py

Uses `cryptography.Fernet`. Key derived from `CONTEXTKEEP_SECRET` env var via PBKDF2 with a static salt.

```python
def encrypt(plaintext: str) -> str:
    """Encrypts text. Returns base64 Fernet token. No-op if CONTEXTKEEP_SECRET not set."""

def decrypt(ciphertext: str) -> str:
    """Decrypts Fernet token. No-op if CONTEXTKEEP_SECRET not set."""

def is_encryption_enabled() -> bool:
    """True if CONTEXTKEEP_SECRET env var is set."""
```

### Integration
- On write: if encryption enabled, encrypt `content` field only. Key, title, tags, timestamps remain plaintext (search/listing works without decryption).
- On read: check `"encrypted": true`, decrypt content if present.
- Unencrypted memories read normally even when encryption is enabled (gradual migration).
- `store_mem_cli.py --encrypt-existing` batch command to encrypt all unencrypted memories.
- `store_mem_cli.py --decrypt-existing` batch command to decrypt all encrypted memories (for key rotation or disabling encryption).
- WARNING: if `CONTEXTKEEP_SECRET` is lost, encrypted memories are permanently unreadable. Document this and recommend key backup.

---

## 4. Self-Hosted Fonts

- Download Space Grotesk (weights 300-700) and JetBrains Mono (weights 400, 500) as woff2 files into `static/fonts/`
- Replace `<link>` tags in `templates/index.html` (lines 8-10) with nothing
- Replace `@import url(...)` in `static/css/style.css` (line 4) with local `@font-face` declarations
- Result: zero external network requests from the WebUI

---

## File Change Summary

| File | Action |
|------|--------|
| `server.py` | Major rewrite: logging, gates, rate limiting, new tool |
| `webui.py` | Moderate: security headers, CSRF, generic errors, badges |
| `core/memory_manager.py` | Major: SHA256 migration, permissions, schema fields, encryption |
| `core/content_scanner.py` | New file |
| `core/encryption.py` | New file |
| `store_mem_cli.py` | Fix sys.path, placeholder data, add --encrypt-existing |
| `requirements.txt` | Pin versions, add cryptography |
| `contextkeep-server.service` | One-line fix (host) |
| `install_services.sh` | Validate user, mktemp, localhost URLs |
| `templates/index.html` | Remove Google Fonts links |
| `static/css/style.css` | Replace @import with @font-face |
| `static/js/app.js` | Add CSRF token header, badge rendering |
| `static/fonts/` | New directory with woff2 files |

## Out of Scope
- WebUI authentication (explicitly excluded per user request)
- Content scanning via LLM (too slow, too fragile)
- Log rotation config (OS-level concern, not app-level)
