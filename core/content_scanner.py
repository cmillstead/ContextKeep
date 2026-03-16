"""Regex-based prompt injection detector for memory content."""

import re
import unicodedata
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

# Zero-width and invisible characters to strip
_INVISIBLE_CHARS = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u2061\u2062\u2063\u2064\u180e]"
)

# Common homoglyph mappings (Cyrillic/Greek → ASCII)
_HOMOGLYPHS: Dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
    "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
    "\u03a5": "Y", "\u03a7": "X",
}


def _normalize_for_scan(text: str) -> str:
    """Normalize text for scanning: NFKC normalize, strip invisible chars, map homoglyphs."""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE_CHARS.sub("", text)
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def scan_content(text: str) -> Dict[str, object]:
    """Scan text for prompt injection patterns.

    Returns {"suspicious": bool, "matched_patterns": [str]}
    Called on the write path only. Non-blocking: content is still stored, just flagged.
    """
    normalized = _normalize_for_scan(text)
    matched = []
    for compiled_re, name in _COMPILED_PATTERNS:
        if compiled_re.search(normalized):
            matched.append(name)
    return {
        "suspicious": len(matched) > 0,
        "matched_patterns": matched,
    }


def scan_all_fields(key: str = "", title: str = "", tags: List[str] = None, content: str = "") -> Dict[str, object]:
    """Scan all memory fields for injection patterns."""
    if tags is None:
        tags = []
    combined = "\n".join([key, title, " ".join(str(t) for t in tags), content])
    return scan_content(combined)
