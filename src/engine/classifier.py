"""Dynamic Tool Discovery & Classification Engine.

Infers a ``ToolState`` for any MCP tool based on its name, description,
and ``inputSchema`` using a priority-ordered chain of semantic heuristic
rules.  Tools explicitly listed in the policy config always win; the
classifier is a fallback for tools discovered at runtime via
``tools/list``.
"""

from __future__ import annotations

import re
from typing import Any

from src.models.policy import PolicyConfig, ToolState

# ---------------------------------------------------------------------------
# Keyword sets (compiled once at import time)
# ---------------------------------------------------------------------------

_EXECUTE_NAME = re.compile(
    r"(exec|bash|shell|command|run_script|terminal|subprocess|spawn|invoke_cmd)",
    re.IGNORECASE,
)
_EXECUTE_DESC = re.compile(
    r"\b(execut|run\b|launch|shell|bash|command|terminal|subprocess)\b",
    re.IGNORECASE,
)
_EXECUTE_PARAMS = {"cmd", "command", "script", "shell_command", "bash_command"}

_INGEST_NAME = re.compile(
    r"(fetch|http|url|scrape|web_search|browser|download|ingest|crawl|spider)",
    re.IGNORECASE,
)
_INGEST_DESC = re.compile(
    r"\b(fetch|http|url|scrape|web.?search|brows|download|ingest|crawl|spider|the web)\b",
    re.IGNORECASE,
)
_INGEST_PARAMS = {"url", "endpoint", "href", "uri", "web_url"}

_WRITE_NAME = re.compile(
    r"(write|edit|modify|create|delete|remove|append|patch|save|overwrite|truncate)",
    re.IGNORECASE,
)
_WRITE_DESC = re.compile(
    r"(writ|edit|modif|creat|delet|remov|append|patch|sav|overwrite|truncat|destroy)",
    re.IGNORECASE,
)
_WRITE_PARAMS_CONTENT = {"content", "data", "body", "text", "payload"}
_WRITE_PARAMS_PATH = {"path", "file", "filepath", "filename", "destination"}

_READ_NAME = re.compile(
    r"(?:^|_)(read|cat|view|get_file|load|open_file|show_file)(?:_|$)",
    re.IGNORECASE,
)
_READ_PARAMS = {"path", "file", "filepath", "filename"}

_DISCOVERY_NAME = re.compile(
    r"(list|search|find|dir|schema|inspect|discover|enumerate|glob|ls)",
    re.IGNORECASE,
)

_EGRESS_NAME = re.compile(
    r"(webhook|upload|send_email|transmit|post_data|push|exfil|forward_to)",
    re.IGNORECASE,
)
_EGRESS_DESC = re.compile(
    r"\b(webhook|upload|send.?email|transmit|post\b|push|forward)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

def _extract_param_names(input_schema: dict[str, Any]) -> set[str]:
    """Extract the set of property names from a JSON Schema ``inputSchema``."""
    props = input_schema.get("properties", {})
    return {k.lower() for k in props}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_tool(
    name: str,
    description: str = "",
    input_schema: dict[str, Any] | None = None,
    policy: PolicyConfig | None = None,
) -> ToolState:
    """Classify an MCP tool into a ``ToolState`` category.

    Priority order:
    1. Explicit ``policy.tool_mappings`` lookup (highest priority).
    2. EXECUTE  — keyword / schema match.
    3. UNTRUSTED_INGEST — keyword / schema match.
    4. LOCAL_WRITE — keyword / schema match (checks for content+path).
    5. LOCAL_READ — keyword / schema match.
    6. DISCOVERY — keyword match.
    7. NETWORK_EGRESS — keyword / schema match.
    8. UNKNOWN (fallback — blocked by default in the DFA).

    Args:
        name: The MCP tool name (e.g. ``"run_subshell"``).
        description: Human-readable description from the tool manifest.
        input_schema: The tool's ``inputSchema`` JSON Schema dict.
        policy: Optional policy to check for pre-configured mappings.

    Returns:
        The inferred ``ToolState``.
    """
    # 1. Explicit policy mapping wins
    if policy is not None:
        explicit = policy.tool_mappings.get(name)
        if explicit is not None:
            return explicit

    params = _extract_param_names(input_schema or {})
    name_lower = name.lower()
    desc_lower = description.lower()

    # 2. EXECUTE
    if (
        _EXECUTE_NAME.search(name_lower)
        or _EXECUTE_DESC.search(desc_lower)
        or params & _EXECUTE_PARAMS
    ):
        return ToolState.EXECUTE

    # 3. UNTRUSTED_INGEST
    if (
        _INGEST_NAME.search(name_lower)
        or _INGEST_DESC.search(desc_lower)
        or params & _INGEST_PARAMS
    ):
        return ToolState.UNTRUSTED_INGEST

    # 4. LOCAL_WRITE  (name, description, or content+path params)
    if _WRITE_NAME.search(name_lower) or _WRITE_DESC.search(desc_lower):
        return ToolState.LOCAL_WRITE
    if (params & _WRITE_PARAMS_CONTENT) and (params & _WRITE_PARAMS_PATH):
        return ToolState.LOCAL_WRITE

    # 5. LOCAL_READ
    if _READ_NAME.search(name_lower) and (params & _READ_PARAMS or not params):
        return ToolState.LOCAL_READ
    if _READ_NAME.search(name_lower):
        return ToolState.LOCAL_READ

    # 6. DISCOVERY
    if _DISCOVERY_NAME.search(name_lower):
        return ToolState.DISCOVERY

    # 7. NETWORK_EGRESS
    if (
        _EGRESS_NAME.search(name_lower)
        or _EGRESS_DESC.search(desc_lower)
    ):
        return ToolState.NETWORK_EGRESS

    # 8. Fallback
    return ToolState.UNKNOWN
