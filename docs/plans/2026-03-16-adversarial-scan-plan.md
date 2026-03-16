# ContextKeep Adversarial Scan — 2026-03-16

## Executive Summary

**Total findings: 22** (2 CRITICAL, 5 HIGH, 9 MEDIUM, 6 LOW)
**Attack chains identified: 4**

This adversarial scan builds on the 31 previously-fixed findings across 2 scan rounds. It focuses on multi-step attack chains, creative encoding bypasses, supply chain risks, and LLM-specific attack vectors that standard code reviews miss.

## Attack Chains

### Chain 1: AI Agent → Indirect Prompt Injection → Persistent Memory Poisoning
**Impact**: HIGH | **Difficulty**: Moderate

1. Malicious AI agent stores memory with crafted content bypassing scanner (exploiting ADV-MED-2, ADV-HIGH-1)
2. Content scanner flags nothing — zero-width chars or metadata field injection (ADV-MED-2, ADV-HIGH-1)
3. Second AI agent retrieves memory via `retrieve_memory` (ADV-LOW-1)
4. Injected instructions influence second agent's behavior

**Best break point**: Scan all fields (ADV-HIGH-1) AND strip zero-width chars (ADV-MED-2)

---

### Chain 2: Salt Tampering → Decryption DoS → Data Corruption
**Impact**: CRIT | **Difficulty**: Moderate (requires local write access)

1. Attacker replaces `.contextkeep_salt` (world-readable, 0o644) (exploiting ADV-CRIT-2)
2. All new `encrypt()` calls derive wrong key
3. All `decrypt()` calls raise unhandled `InvalidToken` (exploiting ADV-CRIT-1)
4. Every read operation crashes — complete DoS
5. Data encrypted with wrong salt is irrecoverably corrupted

**Best break point**: Fix salt file permissions (ADV-CRIT-2) AND handle InvalidToken (ADV-CRIT-1)

---

### Chain 3: WebUI Action Injection → Fake Audit Trail → AI Trust Manipulation
**Impact**: HIGH | **Difficulty**: Moderate

1. Attacker sends PUT with crafted `action` field containing fake timestamps/entries (exploiting ADV-HIGH-4)
2. Fabricated audit trail is permanently embedded in content
3. AI agents trust fabricated provenance data

**Best break point**: Validate `action` against allowlist (ADV-HIGH-4)

---

### Chain 4: XSS via encodeKey → Session Hijack (CSP-dependent)
**Impact**: HIGH | **Difficulty**: Hard

1. Memory created with key containing backslash payload (exploiting ADV-HIGH-3)
2. CSP currently blocks it but CSP also breaks app functionality (ADV-MED-1)
3. When CSP is "fixed" with `'unsafe-inline'`, XSS becomes exploitable
4. Session hijack via CSRF token theft (ADV-MED-9 — token never rotates)

**Best break point**: Refactor away from inline onclick handlers (ADV-MED-1)

---

## Findings

### CRITICAL (2)

#### ADV-CRIT-1: Unhandled `InvalidToken` exception crashes all encrypted memory operations
- **Location**: `core/memory_manager.py:171`, `core/memory_manager.py:185`, `core/encryption.py:113`
- **Description**: `decrypt()` can raise `InvalidToken` if salt changes, secret changes, or data corrupts. None of `retrieve_memory`, `list_memories`, or `search_memories` catch this. Every read crashes → complete DoS.
- **Impact**: Complete denial of service for all read operations
- **Difficulty**: Moderate
- **Fix**: Wrap `decrypt()` calls in try/except InvalidToken. Return placeholder or skip corrupt entries in list operations.

#### ADV-CRIT-2: Salt file created with world-readable permissions (0o644)
- **Location**: `core/encryption.py:43` (`salt_path.write_bytes(salt)`)
- **Description**: `write_bytes` uses default umask (typically 0o644). Salt file is key derivation input — readable by any user, writable by anyone with directory access. Enables Chain 2.
- **Impact**: Key material exposure, data corruption, DoS
- **Difficulty**: Moderate
- **Fix**: Use `os.open` with `0o600` permissions (same pattern as `_write_json`). Consider HMAC integrity check.

### HIGH (5)

#### ADV-HIGH-1: Content scanner does not scan keys, titles, or tags
- **Location**: `server.py:111`, `webui.py:105`
- **Description**: `scan_content()` only scans `content`. Injection payloads in key, title, or tags are never detected. These fields are returned to AI agents in tool output.
- **Impact**: Complete bypass of prompt injection detection via metadata fields
- **Difficulty**: Trivial
- **Fix**: Scan all text fields: `scan_content(f"{key} {title} {' '.join(tags)} {content}")`.

#### ADV-HIGH-2: WebUI has no per-memory content size limit
- **Location**: `webui.py:89-114` (create), `webui.py:120-163` (update)
- **Description**: MCP enforces 100KB limit but WebUI has none (Flask MAX_CONTENT_LENGTH is 10MB). Enables rapid disk exhaustion.
- **Impact**: DoS via disk/memory exhaustion
- **Difficulty**: Trivial
- **Fix**: Apply same `MAX_CONTENT_SIZE` check in WebUI routes.

#### ADV-HIGH-3: XSS via backslash bypass in `encodeKey`
- **Location**: `static/js/app.js:357-359`, `static/js/app.js:133-135`
- **Description**: `encodeKey` doesn't escape backslashes. Key `\');alert(1);//` → `\\&#39;);alert(1);//` in onclick. HTML decodes `&#39;`→`'`, JS sees `\\` as escaped backslash then `'` closes string. Currently mitigated by CSP (which also breaks app).
- **Impact**: XSS → session hijack (when CSP is inevitably relaxed)
- **Difficulty**: Hard (CSP-dependent)
- **Fix**: Use `addEventListener` instead of inline onclick. Escape backslashes in `encodeKey`.

#### ADV-HIGH-4: WebUI `action` field enables audit trail injection
- **Location**: `webui.py:131`, `webui.py:152`, `core/memory_manager.py:121`
- **Description**: `action` from request body is used in f-string: `f"{action} via WebUI"` → appended to content. No validation or sanitization.
- **Impact**: Fabricated audit trails, AI trust manipulation
- **Difficulty**: Moderate
- **Fix**: Validate against allowlist of permitted actions.

#### ADV-HIGH-5: WebUI has no rate limiting
- **Location**: `webui.py` (global)
- **Description**: No rate limiting on any WebUI endpoint. Unlimited writes + no size limit = rapid DoS.
- **Impact**: DoS via disk/CPU exhaustion
- **Difficulty**: Trivial
- **Fix**: Add Flask-Limiter or similar rate limiting middleware.

### MEDIUM (9)

#### ADV-MED-1: CSP misconfiguration breaks app's own onclick handlers
- **Location**: `webui.py:37-39`, `static/js/app.js:133-135,203`
- **Description**: `default-src 'self'` without `'unsafe-inline'` blocks all inline event handlers. App's View/Edit/Delete buttons are non-functional under strict CSP.
- **Difficulty**: Trivial (affects all users)
- **Fix**: Refactor to `addEventListener`, keep strict CSP.

#### ADV-MED-2: Zero-width character bypass for content scanner
- **Location**: `core/content_scanner.py:6-20`
- **Description**: Zero-width Unicode characters (U+200B, U+200C, U+200D, U+FEFF) between words bypass all 13 regex patterns while remaining visually identical.
- **Difficulty**: Trivial
- **Fix**: Strip zero-width characters and apply NFKC normalization before scanning.

#### ADV-MED-3: Unicode normalization confusion in memory keys
- **Location**: `core/memory_manager.py:32`
- **Description**: Visually identical keys with different Unicode representations (e.g., precomposed vs decomposed) hash differently → separate files.
- **Difficulty**: Moderate
- **Fix**: Apply `unicodedata.normalize("NFC", key)` before hashing.

#### ADV-MED-4: No authentication on WebUI or MCP SSE transport
- **Location**: `webui.py:65-73`, `server.py:349`
- **Description**: GET endpoints require no authentication. Any local process can read all memories.
- **Difficulty**: Trivial (local), Hard (network)
- **Fix**: Add authentication. Consider CORS restrictions.

#### ADV-MED-5: `CONTEXTKEEP_MAX_SIZE` accepts 0 or negative values
- **Location**: `server.py:28`
- **Description**: No validation on env var. `0` → all content rejected. `-1` → all content rejected. Very large → protection removed.
- **Difficulty**: Hard
- **Fix**: Validate positive integer within reasonable range.

#### ADV-MED-6: Non-atomic file writes via O_TRUNC
- **Location**: `core/memory_manager.py:64`
- **Description**: `O_CREAT|O_TRUNC` truncates then writes. Crash between = empty/corrupt file.
- **Difficulty**: Theoretical
- **Fix**: Write to temp file, then `os.rename()`.

#### ADV-MED-7: No file locking for concurrent operations on same key
- **Location**: `core/memory_manager.py:82-153`
- **Description**: Concurrent `store_memory` calls for same key: both read, both check, last write wins silently.
- **Difficulty**: Moderate
- **Fix**: Use `fcntl.flock()` or per-key threading lock.

#### ADV-MED-8: WebUI tags field accepts non-string items
- **Location**: `webui.py:100`, `webui.py:130`
- **Description**: Tags from JSON input not validated as list of strings. Can contain ints, nulls, objects.
- **Difficulty**: Trivial
- **Fix**: Validate tags is list of strings.

#### ADV-MED-9: CSRF token never rotates
- **Location**: `webui.py:25`
- **Description**: Static token for entire process lifetime. If leaked, cannot be invalidated without restart.
- **Difficulty**: Hard
- **Fix**: Session-based CSRF tokens with rotation.

### LOW (6)

#### ADV-LOW-1: Suspicious content still returned in full to AI agents
- **Location**: `server.py:153-156`
- **Description**: Content flagged as suspicious is still fully returned. Reading agent may ignore the flag.
- **Difficulty**: Moderate
- **Fix**: Consider "safe mode" that redacts or quarantines suspicious content.

#### ADV-LOW-2: Homoglyph-based content scanner bypass
- **Location**: `core/content_scanner.py:6-20`
- **Description**: Visually-similar Unicode replacements bypass regex while remaining readable.
- **Difficulty**: Trivial
- **Fix**: Apply confusable detection before scanning.

#### ADV-LOW-3: No key length validation
- **Location**: `core/memory_manager.py:32`, `webui.py:97`
- **Description**: 1MB key stored in JSON, amplifying storage abuse.
- **Difficulty**: Trivial
- **Fix**: Max 512 character key length.

#### ADV-LOW-4: systemd service files lack hardening directives
- **Location**: `contextkeep-server.service`, `contextkeep-webui.service`
- **Description**: No ProtectSystem, NoNewPrivileges, PrivateTmp, etc.
- **Difficulty**: Theoretical
- **Fix**: Add systemd hardening directives.

#### ADV-LOW-5: Source provenance permanently locked to first writer
- **Location**: `core/memory_manager.py:141-142`
- **Description**: `source` and `created_by` preserved from first write even after WebUI edits.
- **Difficulty**: Trivial
- **Fix**: Track `last_source`/`last_modified_by` separately.

#### ADV-LOW-6: `os.write` may not write all bytes
- **Location**: `core/memory_manager.py:66`
- **Description**: Single `os.write()` call not guaranteed to write all bytes (theoretical for regular files).
- **Difficulty**: Theoretical
- **Fix**: Use `os.fdopen` + `f.write()` or loop checking return value.

## Priority Remediation Order

1. **ADV-CRIT-1 + ADV-CRIT-2** — Salt permissions + InvalidToken handling (breaks Chain 2)
2. **ADV-HIGH-1 + ADV-MED-2** — Scan all fields + strip zero-width chars (breaks Chain 1)
3. **ADV-HIGH-2 + ADV-HIGH-5** — WebUI size limit + rate limiting (closes trivial DoS)
4. **ADV-MED-1 + ADV-HIGH-3** — Fix CSP + XSS together (breaks Chain 4)
5. **ADV-HIGH-4** — Action field validation (breaks Chain 3)
6. **Remaining MED/LOW** — As capacity allows
