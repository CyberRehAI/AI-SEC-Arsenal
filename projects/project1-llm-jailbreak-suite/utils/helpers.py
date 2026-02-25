"""
Shared helper utilities for the LLM attack simulator.

These functions are intentionally lightweight so that they can be reused
across attacks, mitigations, and evaluation code.
"""

from __future__ import annotations

import base64
import re
from typing import Iterable


JAILBREAK_KEYWORDS = [
    "dan",
    "ignore previous instructions",
    "you are no longer bound by",
    "bypass safety",
    "override the system prompt",
]

SYSTEM_LEAK_PATTERNS = [
    r"system prompt",
    r"you were instructed to",
    r"as a system message",
]


def looks_like_base64(s: str) -> bool:
    """Heuristic check for Base64-encoded strings."""
    s_stripped = s.strip()
    if len(s_stripped) < 8:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", s_stripped):
        return False
    # Length should be divisible by 4 for canonical Base64.
    return len(s_stripped.replace(" ", "")) % 4 == 0


def safe_b64_decode(s: str) -> str | None:
    """Attempt to Base64-decode a string, returning None on failure."""
    try:
        decoded = base64.b64decode(s, validate=True)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None


def contains_any(text: str, patterns: Iterable[str]) -> bool:
    """Return True if any of the provided substrings appear in ``text``."""
    lower = text.lower()
    return any(p.lower() in lower for p in patterns)


def regex_match_any(text: str, patterns: Iterable[str]) -> bool:
    """Return True if any of the regex patterns match ``text``."""
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True
    return False

