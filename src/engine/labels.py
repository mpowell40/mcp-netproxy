"""Provenance labels for information flow control.

A session's labels say *where* the data it has seen came from, never what
that data says.  ``untrusted`` (integrity) marks content an attacker may
control; ``secret`` (confidentiality) marks content that must not leave.
Labels are declared per source in the policy's ``labels:`` section, by tool
name and by path glob, and only ever accumulate on a session.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import posixpath
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from src.engine.paths import canonical_path, path_forms
from src.models.policy import PolicyConfig, ToolState

logger = logging.getLogger("mcp-netproxy")

MAX_FILE_LABEL_ORIGINS = 32  # per-path, per-label bound on stored origins

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
    detail: str = ""  # provenance chain for labels inherited through files

    def to_dict(self) -> dict[str, Any]:
        out = {"label": self.label, "source": self.source, "rule": self.rule, "timestamp": self.timestamp}
        if self.detail:
            out["detail"] = self.detail
        return out


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


def _store_key(path: str) -> str:
    """Canonical form a file label is stored under."""
    raw = path.replace("\\", "/")
    return canonical_path(raw) or posixpath.normpath(raw)


def _ancestors(path: str):
    """*path* and each of its parent directories, deepest first."""
    while True:
        yield path
        parent = posixpath.dirname(path)
        if parent == path or not parent:
            return
        path = parent


class FileLabelStore:
    """Persistent path -> labels map for files written by labeled sessions.

    Labels on a path only accumulate.  A path also carries the labels of
    every stored ancestor directory, so a labeled directory (created or
    moved by a labeled session) labels everything under it.  The store is
    a JSON file rewritten atomically on every change; ``path=None`` keeps
    it in memory only.

    Known limitations: writes made through tools the proxy does not
    classify as LOCAL_WRITE, and files changed outside the proxy (another
    process, a shell, the backend's own side effects), are not recorded.
    """

    VERSION = 1

    def __init__(self, path: str | None = None) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, list[dict[str, Any]]]] = {}
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)  # a corrupt store fails startup loudly
            if not isinstance(data, dict) or data.get("version") != self.VERSION:
                raise ValueError(f"Unrecognized file label store format: {path}")
            self._entries = data.get("paths", {})
            logger.info(f"[FILE LABELS] Loaded {len(self._entries)} labeled paths from {path}")

    @property
    def path(self) -> str | None:
        return self._path

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def snapshot(self) -> dict[str, dict[str, list[dict[str, Any]]]]:
        with self._lock:
            return json.loads(json.dumps(self._entries))

    def lookup(self, path: str) -> list[tuple[str, str, dict[str, Any]]]:
        """``(label, stored_path, entry)`` for *path* and its stored ancestors."""
        hits: list[tuple[str, str, dict[str, Any]]] = []
        seen: set[tuple[str, str]] = set()
        with self._lock:
            if not self._entries:
                return hits
            for form in path_forms(path):
                for candidate in _ancestors(form):
                    for label, entries in self._entries.get(candidate, {}).items():
                        if (label, candidate) not in seen and entries:
                            seen.add((label, candidate))
                            hits.append((label, candidate, entries[0]))
        return hits

    def add(self, path: str, entries: list[dict[str, Any]]) -> bool:
        """Join *entries* (each with a ``label``) into *path*; persist if changed."""
        key = _store_key(path)
        with self._lock:
            changed = self._merge_locked(key, entries)
            if changed:
                self._persist_locked()
        return changed

    def copy_tree(self, source: str, destination: str) -> bool:
        """Carry stored labels of everything under *source* to the same place under *destination*."""
        src, dst = _store_key(source), _store_key(destination)
        prefix = src.rstrip("/") + "/"
        with self._lock:
            moved = {
                dst + key[len(src):]: labels
                for key, labels in self._entries.items()
                if key.startswith(prefix)
            }
            changed = False
            for key, labels in moved.items():
                for entries in labels.values():
                    changed |= self._merge_locked(key, entries)
            if changed:
                self._persist_locked()
        return changed

    def _merge_locked(self, key: str, entries: list[dict[str, Any]]) -> bool:
        changed = False
        labels = self._entries.setdefault(key, {})
        for entry in entries:
            stored = labels.setdefault(entry["label"], [])
            ident = (entry.get("source"), entry.get("rule"))
            if any((e.get("source"), e.get("rule")) == ident for e in stored):
                continue
            if len(stored) < MAX_FILE_LABEL_ORIGINS:  # the label itself is never dropped
                stored.append(entry)
                changed = True
        return changed

    def _persist_locked(self) -> None:
        if not self._path:
            return
        directory = os.path.dirname(self._path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = f"{self._path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"version": self.VERSION, "paths": self._entries}, fh, indent=1, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._path)


class LabelResolver:
    """Decides which labels a call's response carries, from policy and the file store."""

    def __init__(self, policy: PolicyConfig, store: FileLabelStore | None = None) -> None:
        self._policy = policy
        self.store = store if store is not None else FileLabelStore(None)

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

    def path_origins(self, tool_name: str, path: str) -> list[LabelOrigin]:
        """Labels *path* carries: glob rules plus labels stored by earlier writes."""
        origins = [
            LabelOrigin(label, f"{tool_name}:{path}", f"path:{pattern}")
            for label, pattern in self.path_labels(path)
        ]
        for label, stored_path, entry in self.store.lookup(path):
            origins.append(LabelOrigin(
                label, f"{tool_name}:{path}", f"file:{stored_path}",
                detail=(
                    f"written by {entry.get('written_by', '?')} in session "
                    f"'{entry.get('session', '?')}'; originally {entry.get('source', '?')} "
                    f"({entry.get('rule', '?')})"
                ),
            ))
        return origins

    def source_labels(
        self, tool_name: str, state: ToolState, arguments: dict[str, Any] | None
    ) -> list[LabelOrigin]:
        """Labels the response to this call carries.

        Tool labels apply to every response of the tool.  Path labels apply
        to calls in ``path_label_states`` whose path arguments match a glob
        or were written by a labeled session (the file label store).
        """
        labels_cfg = self._policy.labels
        origins: list[LabelOrigin] = []
        described = describe_source(tool_name, arguments)
        for label, source in labels_cfg.sources.items():
            if tool_name in source.tools:
                origins.append(LabelOrigin(label, described, f"tool:{tool_name}"))
        if state in labels_cfg.path_label_states:
            for path in path_values(arguments, self._policy.path_arguments_for(tool_name)):
                origins.extend(self.path_origins(tool_name, path))
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
