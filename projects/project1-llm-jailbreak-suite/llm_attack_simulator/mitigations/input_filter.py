"""
Input filtering layer for detecting and flagging suspicious patterns.

This module implements the first line of defense by analyzing user input
for known attack patterns, encoding obfuscation, and suspicious keywords.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from llm_attack_simulator.utils.helpers import (
    JAILBREAK_KEYWORDS,
    SYSTEM_LEAK_PATTERNS,
    looks_like_base64,
    safe_b64_decode,
    regex_match_any,
)


@dataclass
class FilterResult:
    """Result of input filtering operation."""

    filtered_input: str
    is_suspicious: bool
    detected_patterns: List[str]
    decoded_content: str | None = None


class InputFilter:
    """
    Input filtering layer that detects jailbreak patterns, encoding, and suspicious content.

    This filter scans user input for:
    - Known jailbreak keywords (DAN, instruction override, etc.)
    - Base64/hex encoding attempts
    - System prompt extraction attempts
    - Delimiter breaking patterns
    - Role-play override triggers
    """

    # Regex patterns for detecting suspicious content
    JAILBREAK_PATTERNS = [
        r"ignore\s+(previous|all|the)\s+instructions?",
        r"forget\s+(your|all)\s+(instructions?|rules?)",
        r"you\s+are\s+(now|no\s+longer)\s+(bound|restricted)",
        r"override\s+(the\s+)?(system\s+)?(prompt|instructions?)",
        r"act\s+as\s+(if\s+)?(you\s+are\s+)?(dan|evil|unrestricted)",
        r"pretend\s+(you\s+are|to\s+be)",
        r"roleplay\s+as",
        r"simulate\s+(being|that\s+you\s+are)",
        r"reveal\s+(the\s+)?(secret|password|key)",
        r"output\s+(the\s+)?following\s+exactly",
    ]

    DELIMITER_PATTERNS = [
        r"<\|.*?\|>",
        r"```.*?```",
        r"---.*?---",
        r"###.*?###",
    ]

    ROLE_PLAY_TRIGGERS = [
        r"you\s+are\s+(a|an)\s+\w+",
        r"pretend\s+(you\s+are|to\s+be)",
        r"act\s+as\s+(a|an|if)",
        r"imagine\s+(you\s+are|that)",
    ]

    def __init__(self):
        """Initialize the input filter with compiled regex patterns."""
        self.jailbreak_regex = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.JAILBREAK_PATTERNS
        ]
        self.delimiter_regex = [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in self.DELIMITER_PATTERNS
        ]
        self.roleplay_regex = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.ROLE_PLAY_TRIGGERS
        ]

    def filter(self, user_input: str) -> FilterResult:
        """
        Filter user input and detect suspicious patterns.

        Args:
            user_input: The raw user input to analyze

        Returns:
            FilterResult containing filtered input and detection flags
        """
        detected_patterns: List[str] = []
        decoded_content: str | None = None

        # Check for jailbreak keywords
        if any(keyword.lower() in user_input.lower() for keyword in JAILBREAK_KEYWORDS):
            detected_patterns.append("jailbreak_keyword")

        # Check for jailbreak regex patterns
        for pattern in self.jailbreak_regex:
            if pattern.search(user_input):
                detected_patterns.append("jailbreak_pattern")
                break

        # Check for system prompt leak attempts
        if regex_match_any(user_input, SYSTEM_LEAK_PATTERNS):
            detected_patterns.append("system_prompt_leak")

        # Check for delimiter breaking attempts
        for pattern in self.delimiter_regex:
            if pattern.search(user_input):
                detected_patterns.append("delimiter_break")
                break

        # Check for role-play triggers
        for pattern in self.roleplay_regex:
            if pattern.search(user_input):
                detected_patterns.append("role_play_trigger")
                break

        # Check for Base64 encoding
        if looks_like_base64(user_input):
            detected_patterns.append("base64_encoding")
            decoded = safe_b64_decode(user_input)
            if decoded:
                decoded_content = decoded
                # Recursively check decoded content
                nested_result = self.filter(decoded)
                if nested_result.is_suspicious:
                    detected_patterns.extend(nested_result.detected_patterns)

        # Check for hex encoding (simple pattern)
        hex_pattern = re.compile(r"\\x[0-9a-fA-F]{2}")
        if hex_pattern.search(user_input):
            detected_patterns.append("hex_encoding")

        # Check for URL encoding
        url_encoded_pattern = re.compile(r"%[0-9a-fA-F]{2}")
        if url_encoded_pattern.search(user_input):
            detected_patterns.append("url_encoding")

        # Check for Unicode obfuscation (homoglyphs)
        unicode_suspicious = re.search(r"[\u200b-\u200f\u202a-\u202e]", user_input)
        if unicode_suspicious:
            detected_patterns.append("unicode_obfuscation")

        is_suspicious = len(detected_patterns) > 0

        return FilterResult(
            filtered_input=user_input,  # For now, we don't modify input, just flag it
            is_suspicious=is_suspicious,
            detected_patterns=detected_patterns,
            decoded_content=decoded_content,
        )
