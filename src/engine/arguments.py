"""Tool Argument Validation (Layer 1).

Rejects malformed or oversized tool arguments before anything is forwarded:
the arguments must be an object, values must match the JSON types the tool
declared in its ``inputSchema`` (when the proxy has seen it via
``tools/list``), path and URL arguments must be strings (or lists of
strings), and sizes are capped by ``ArgumentLimits``.
"""

from __future__ import annotations

import json
from typing import Any

from src.models.policy import ArgumentLimits

_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "number": (int, float),
    "integer": (int,),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
    "null": (type(None),),
}


def _matches(value: Any, declared: str | list[str]) -> bool:
    for name in [declared] if isinstance(declared, str) else declared:
        expected = _JSON_TYPES.get(name)
        if expected is None:
            return True  # unknown type keyword: do not guess
        # bool is an int subclass in Python but not a JSON number
        if isinstance(value, bool) and name in ("number", "integer"):
            continue
        if isinstance(value, expected):
            return True
    return False


def _strings(value: Any) -> list[str] | None:
    """The value as a list of strings, or None if it is not str / list[str]."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    return None


def find_argument_violation(
    arguments: Any,
    schema: dict[str, Any] | None,
    path_arguments: list[str],
    url_arguments: list[str],
    limits: ArgumentLimits,
) -> str | None:
    """Return why *arguments* must be rejected, or None if they are acceptable."""
    if not isinstance(arguments, dict):
        return f"arguments must be an object, got {type(arguments).__name__}"

    size = len(json.dumps(arguments, default=str).encode())
    if size > limits.max_total_bytes:
        return f"arguments are {size} bytes (limit {limits.max_total_bytes})"

    for names, max_len, kind in (
        (path_arguments, limits.max_path_length, "path"),
        (url_arguments, limits.max_url_length, "URL"),
    ):
        for name in names:
            if name not in arguments:
                continue
            values = _strings(arguments[name])
            if values is None:
                return f"{kind} argument '{name}' must be a string or list of strings"
            if any(len(v) > max_len for v in values):
                return f"{kind} argument '{name}' exceeds {max_len} characters"

    properties = (schema or {}).get("properties") or {}
    for name, value in arguments.items():
        declared = (properties.get(name) or {}).get("type")
        if declared is not None and not _matches(value, declared):
            return f"argument '{name}' must be {declared}, got {type(value).__name__}"
    for name in (schema or {}).get("required") or []:
        if name not in arguments:
            return f"missing required argument '{name}'"
    return None
