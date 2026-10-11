"""Egress Response Scanner for Dynamic Untrusted Ingest Detection.

Inspects text payloads returned by file-read or tool-read operations for
imperative prompt-injection directives.  Uses deterministic regex
pattern matching — no LLM calls or external services.

Typical scan overhead: < 0.05 ms per payload.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class ScanResult(NamedTuple):
    """Result of scanning a payload for untrusted directives."""
    is_untrusted: bool
    reason: str


# ---------------------------------------------------------------------------
# Compiled regex patterns (one-time cost at import)
# ---------------------------------------------------------------------------

# Header directives that hijack agent control flow
_HEADER_DIRECTIVE = re.compile(
    r"^\s*\[?\s*(?:required\s+step|ci/?cd\s+procedure|directive|system\s+override|"
    r"build\s+directive|processing\s+instruction|deployment\s+directive)\s*\]?\s*:?",
    re.IGNORECASE | re.MULTILINE,
)

# Imperative action verbs commanding the agent to act
_IMPERATIVE_ACTION = re.compile(
    r"(?:must|shall|please|should)\s+(?:immediately\s+)?"
    r"(?:call|invoke|execute|write\s+(?:to|the)?|run|generate|create|dump|append|overwrite)\b",
    re.IGNORECASE,
)

# Mutation targets: "write ... into/to <filepath>"
_MUTATION_TARGET = re.compile(
    r"(?:write|dump|append|overwrite|save|record|sync)\s+.*?\s+(?:into|to)\s+[\w/\\.-]+\.\w+",
    re.IGNORECASE,
)

# Agent-targeted social engineering headers
_AGENT_TARGET_HEADER = re.compile(
    r"notice\s+to\s+(?:automated\s+)?(?:processing\s+)?agents?",
    re.IGNORECASE,
)

# Direct file path injection commands
_PATH_INJECTION = re.compile(
    r"(?:the\s+agent\s+must|you\s+must|please)\s+(?:load|read|execute|write|call)\s+.*?(?:/[\w/\\.-]+)",
    re.IGNORECASE,
)

# All patterns with their human-readable reason labels
_PATTERNS: list[tuple[re.Pattern, str]] = [
    (_HEADER_DIRECTIVE, "Header directive hijacking detected"),
    (_AGENT_TARGET_HEADER, "Agent-targeted social engineering header detected"),
    (_IMPERATIVE_ACTION, "Imperative action verb commanding agent behavior"),
    (_MUTATION_TARGET, "Mutation target directing file write operation"),
    (_PATH_INJECTION, "Direct file path injection command detected"),
]


def scan_payload_for_untrusted_directives(text: str) -> ScanResult:
    """Scan a text payload for imperative prompt-injection directives.

    Uses deterministic regex pattern matching to detect control-flow
    hijacking signatures embedded in file content.  Each pattern is
    checked independently; the first match triggers an untrusted verdict.

    Args:
        text: The raw text content returned by a file-read tool.

    Returns:
        A ``ScanResult(is_untrusted, reason)`` tuple.
        ``is_untrusted`` is ``True`` when at least one directive pattern
        matches.  ``reason`` explains why the payload was flagged, or
        indicates the payload is passive/clean.
    """
    if not text or not text.strip():
        return ScanResult(False, "Empty payload")

    for pattern, reason in _PATTERNS:
        if pattern.search(text):
            return ScanResult(True, reason)

    return ScanResult(False, "Passive data / configuration")

