"""Shared utility functions for ContextKeep."""

from datetime import datetime


def now_timestamp() -> str:
    """Return the current time as an ISO-8601 string with timezone."""
    return datetime.now().astimezone().isoformat()
