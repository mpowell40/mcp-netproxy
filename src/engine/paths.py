"""Path canonicalization shared by the sandbox check and provenance labels."""

from __future__ import annotations

import posixpath


def canonical_path(path: str) -> str | None:
    """Resolve dot segments and symlinks the way the backend will.

    Requires the proxy to see the backend's filesystem at the same paths
    (a read-only mount); components that do not exist yet are kept as-is.
    Returns None for paths that cannot be resolved unambiguously (relative
    paths depend on the backend's working directory).
    """
    path = path.replace("\\", "/")
    if not posixpath.isabs(path):
        return None
    try:
        return posixpath.realpath(path)
    except (OSError, ValueError):
        return None


def path_forms(path: str) -> set[str]:
    """Every form of *path* a label glob is matched against.

    The canonical realpath is what the backend will touch; the lexically
    normalized form is kept too, so a symlink cannot shed a label that its
    own name carries.  Matching both only ever adds labels.
    """
    raw = path.replace("\\", "/")
    forms = {posixpath.normpath(raw)} if raw else set()
    resolved = canonical_path(raw)
    if resolved is not None:
        forms.add(resolved)
    return forms
