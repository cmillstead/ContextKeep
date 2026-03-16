"""Shared utility functions for ContextKeep."""

import os
import threading
import time
from datetime import datetime


def now_timestamp() -> str:
    """Return the current time as an ISO-8601 string with timezone."""
    return datetime.now().astimezone().isoformat()


class RateLimiter:
    """Thread-safe sliding-window rate limiter."""

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
