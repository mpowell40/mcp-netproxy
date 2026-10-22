"""Provenance labels for information flow control.

A session's labels say *where* the data it has seen came from, never what
that data says.  ``untrusted`` (integrity) marks content an attacker may
control; ``secret`` (confidentiality) marks content that must not leave.
Labels are declared per source in the policy's ``labels:`` section, by tool
name and by path glob, and only ever accumulate on a session.
"""

from __future__ import annotations

import functools
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from src.engine.paths import path_forms
from src.models.policy import PolicyConfig, ToolState

# Argument names that identify what a tool read, in priority order
_SOURCE_ARGUMENTS = ("path", "url", "uri", "paths", "source", "query")


def describe_source(tool_name: str, arguments: dict[str, Any] | None) -> str:
    """Render ``tool:target`` for label attribution (``fs__read_file:notes.txt``)."""
    for key in _SOURCE_ARGUMENTS:
        value = (arguments or {}).get(key)
        if value:
            return f"{tool_name}:{value}"
    return tool_name


@dataclass(frozen=True)
class LabelOrigin:
    """Why a session (or file) carries a label.

    Attributes:
        label: The label, e.g. ``"untrusted"``.
        source: Tool and target that delivered the data,
            e.g. ``"web__fetch:https://example.org/"``.
        rule: The policy rule that assigned it: ``"tool:web__fetch"``,
            ``"path:**/secrets/**"``, or ``"file:<path>"`` for a label a
            file inherited from the session that wrote it.
    """

    label: str
    source: str
    rule: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "source": self.source, "rule": self.rule, "timestamp": self.timestamp}


# ---------------------------------------------------------------------------
# Globs
# ---------------------------------------------------------------------------

def _segment_regex(segment: str) -> str:
    out = []
    for ch in segment:
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
    return "".join(out)


@functools.lru_cache(maxsize=256)
def glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile a path glob to a regex over absolute POSIX paths.

    ``**`` matches zero or more whole segments; ``*`` and ``?`` never cross
    a ``/``.  A pattern without a leading ``/`` is anchored anywhere, as if
    it began with ``**/``.
    """
    parts = [p for p in pattern.replace("\\", "/").split("/") if p]
    if not pattern.startswith("/") and (not parts or parts[0] != "**"):
        parts.insert(0, "**")
    regex = "".join("(?:/[^/]+)*" if part == "**" else "/" + _segment_regex(part) for part in parts)
    return re.compile(regex or "/")


def glob_match(pattern: str, path: str) -> bool:
    """Whether the absolute POSIX *path* matches *pattern*."""
    return glob_regex(pattern).fullmatch(path) is not None


# ---------------------------------------------------------------------------
# Source labels
# ---------------------------------------------------------------------------

def path_values(arguments: dict[str, Any] | None, names: list[str]) -> list[str]:
    """String values of the named path arguments (lists are flattened)."""
    out: list[str] = []
    for name in names:
        value = (arguments or {}).get(name)
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str) and item:
                out.append(item)
    return out


class LabelResolver:
    """Decides which labels a call's response carries, from policy alone."""

    def __init__(self, policy: PolicyConfig) -> None:
        self._policy = policy

    @property
    def enabled(self) -> bool:
        return bool(self._policy.labels.sources)

    def path_labels(self, path: str) -> list[tuple[str, str]]:
        """``(label, glob)`` pairs whose glob matches any form of *path*."""
        forms = path_forms(path)
        hits: list[tuple[str, str]] = []
        for label, source in self._policy.labels.sources.items():
            for pattern in source.paths:
                if any(glob_match(pattern, form) for form in forms):
                    hits.append((label, pattern))
                    break
        return hits

    def source_labels(
        self, tool_name: str, state: ToolState, arguments: dict[str, Any] | None
    ) -> list[LabelOrigin]:
        """Labels the response to this call carries.

        Tool labels apply to every response of the tool.  Path labels apply
        to calls in ``path_label_states`` whose path arguments match a glob.
        """
        labels_cfg = self._policy.labels
        origins: list[LabelOrigin] = []
        described = describe_source(tool_name, arguments)
        for label, source in labels_cfg.sources.items():
            if tool_name in source.tools:
                origins.append(LabelOrigin(label, described, f"tool:{tool_name}"))
        if state in labels_cfg.path_label_states:
            for path in path_values(arguments, self._policy.path_arguments_for(tool_name)):
                for label, pattern in self.path_labels(path):
                    origins.append(LabelOrigin(label, f"{tool_name}:{path}", f"path:{pattern}"))
        return origins


# ---------------------------------------------------------------------------
# Value tracking (secondary defense)
# ---------------------------------------------------------------------------
#
# When a response comes from a source whose labels are value-tracked
# (``secret`` by default), fixed-length fragments of its secret-looking
# values are remembered per session, and a later call into a tracked sink
# whose arguments contain any fragment is refused.
#
# This is a best-effort backstop, NOT the guarantee.  It is evaded by any
# transformation of the value before it leaves: base64/hex or other
# encodings, reversal, case changes, interleaving characters, splitting
# into pieces shorter than the fragment length, paraphrase or summary, and
# values the extractor below does not recognize as secret-looking.  The
# sticky ``secret`` label and its sink rule are what actually stop
# exfiltration; value tracking only matters where a sink rule is relaxed.

# KEY=VALUE / KEY: VALUE / export KEY=VALUE (dotenv, ini, yaml)
_ASSIGNMENT = re.compile(r"""^\s*(?:export\s+)?["']?[A-Za-z_][\w.-]*["']?\s*[=:]\s*(.+?)\s*,?\s*$""")
# Credential-shaped tokens: long runs of token characters
_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-.~]+")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def _looks_secret(token: str) -> bool:
    """A token mixing letters with digits or symbols (keys, passwords, IDs)."""
    has_alpha = any(c.isalpha() for c in token)
    has_other = any(c.isdigit() or not c.isalnum() for c in token)
    return has_alpha and has_other


def extract_secret_values(text: str, min_length: int) -> set[str]:
    """Secret-looking values in *text*.

    Every assigned value (``KEY=VALUE``) of at least *min_length*
    characters, plus every credential-shaped token of that length.
    Comment lines are skipped; a leading URL scheme is dropped so that
    ``https://`` is never remembered as part of a secret.
    """
    values: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", ";")):
            continue
        match = _ASSIGNMENT.match(line)
        if match:
            value = _SCHEME.sub("", match.group(1).strip().strip("\"'"))
            if len(value) >= min_length:
                values.add(value)
        for token in _TOKEN.findall(stripped):
            token = _SCHEME.sub("", token)
            if len(token) >= min_length and _looks_secret(token):
                values.add(token)
    return values


def fragments_of(value: str, length: int) -> set[str]:
    """Every window of *length* characters in *value* (or the value itself if shorter)."""
    if len(value) <= length:
        return {value}
    return {value[i:i + length] for i in range(len(value) - length + 1)}


def _argument_strings(value: Any):
    if isinstance(value, dict):
        for item in value.values():
            yield from _argument_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _argument_strings(item)
    elif value is not None:
        text = str(value)
        yield text
        decoded = urllib.parse.unquote_plus(text)
        if decoded != text:
            yield decoded


def find_tracked_fragment(arguments: Any, fragments: set[str], length: int) -> bool:
    """Whether any argument value (raw or URL-decoded) contains a tracked fragment."""
    if not fragments:
        return False
    for text in _argument_strings(arguments):
        if len(text) < length:
            if text in fragments:
                return True
            continue
        if not fragments.isdisjoint(text[i:i + length] for i in range(len(text) - length + 1)):
            return True
    return False
