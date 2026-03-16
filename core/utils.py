"""Shared utility functions for ContextKeep."""

import os
import re
import threading
import time
import unicodedata
from datetime import datetime


# ---------------------------------------------------------------------------
# Validation constants & helpers
# ---------------------------------------------------------------------------
MAX_KEY_LENGTH = 256
MAX_TITLE_LENGTH = 500
MAX_TAGS = 20
MAX_TAG_LENGTH = 50
_TAG_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9 _-]*$')


def validate_key(key: str) -> str | None:
    """Validate memory key. Returns error string or None if valid."""
    if not key:
        return "Key is required"
    if len(key) > MAX_KEY_LENGTH:
        return "Key too long (max %d chars)" % MAX_KEY_LENGTH
    return None


def validate_title(title: str) -> str | None:
    """Validate memory title. Returns error string or None if valid."""
    if len(title) > MAX_TITLE_LENGTH:
        return "Title too long (max %d chars)" % MAX_TITLE_LENGTH
    return None


def validate_tags(tags: list) -> str | None:
    """Validate tags list. Returns error string or None if valid."""
    if not isinstance(tags, list):
        return "Tags must be a list"
    if len(tags) > MAX_TAGS:
        return "Too many tags (max %d)" % MAX_TAGS
    for tag in tags:
        if not isinstance(tag, str):
            return "Each tag must be a string"
        if len(tag) > MAX_TAG_LENGTH:
            return "Tag too long (max %d chars)" % MAX_TAG_LENGTH
        if tag and not _TAG_PATTERN.match(tag):
            return "Tag contains invalid characters"
    return None


def now_timestamp() -> str:
    """Return the current time as an ISO-8601 string with timezone."""
    return datetime.now().astimezone().isoformat()


class RateLimiter:
    """Thread-safe sliding-window rate limiter.

    Note: This is a global (not per-IP) rate limiter. All clients share
    the same counter. This is intentional for ContextKeep's single-user,
    localhost deployment model. For multi-user deployments, switch to
    per-client rate limiting.
    """

    def __init__(self, max_calls: int = 20, window: float = 60):
        self.max_calls = max_calls
        self.window = window
        self._timestamps: list = []
        self._lock = threading.Lock()

    def allow(self) -> bool:
        """Return True if the call is within the rate limit, and record it."""
        now = time.monotonic()
        with self._lock:
            cutoff = now - self.window
            self._timestamps = [t for t in self._timestamps if t > cutoff]
            if len(self._timestamps) >= self.max_calls:
                return False
            self._timestamps.append(now)
            return True


def _parse_max_size() -> int:
    """Parse CONTEXTKEEP_MAX_SIZE env var with validation and clamping."""
    raw = os.environ.get("CONTEXTKEEP_MAX_SIZE", str(100 * 1024))
    try:
        val = int(raw)
    except ValueError:
        val = 100 * 1024
    return max(1024, min(val, 10 * 1024 * 1024))
