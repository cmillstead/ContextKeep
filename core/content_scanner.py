"""Regex-based prompt injection detector for memory content."""

import re
from typing import Dict, List, Tuple

INJECTION_PATTERNS: List[Tuple[str, str]] = [
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

_COMPILED_PATTERNS = [(re.compile(pattern, re.IGNORECASE), name) for pattern, name in INJECTION_PATTERNS]


def scan_content(text: str) -> Dict[str, object]:
    """Scan text for prompt injection patterns.

    Returns {"suspicious": bool, "matched_patterns": [str]}
    Called on the write path only. Non-blocking: content is still stored, just flagged.
    """
    matched = []
    for compiled_re, name in _COMPILED_PATTERNS:
        if compiled_re.search(text):
            matched.append(name)
    return {
        "suspicious": len(matched) > 0,
        "matched_patterns": matched,
    }
