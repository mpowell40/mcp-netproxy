"""Proxy-issued session tokens (MCP ``Mcp-Session-Id``).

The proxy mints an unguessable token on every ``initialize`` and returns it
in the ``Mcp-Session-Id`` response header.  Every later request on that
connection must carry it; the token is the only way to address a session, so
a client can no longer choose, share or switch session IDs to shed a taint
latch or reach another client's session.

Each token maps to a *public id* (``sess-<hash prefix>``).  The public id is
what the DFA, telemetry, logs and ``/session/{id}`` endpoints use; the raw
token never leaves the ``initialize`` response, so the unauthenticated
inspection endpoints cannot leak a usable credential.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

SESSION_HEADER = "Mcp-Session-Id"
PUBLIC_ID_HEADER = "X-Proxy-Session"


@dataclass
class TokenRecord:
    public_id: str
    client_name: str
    created_at: float
    last_seen: float


def public_id_for(token: str) -> str:
    """Stable, non-reversible identifier for *token*."""
    return "sess-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


class SessionTokenStore:
    """Thread-safe token -> session registry with idle expiry.

    ``on_expire(public_id)`` runs for every token that expires or is revoked,
    so the caller can drop the matching DFA session.
    """

    def __init__(
        self,
        *,
        ttl: float | None,
        clock: Callable[[], float] = time.monotonic,
        on_expire: Callable[[str], None] | None = None,
    ) -> None:
        self._ttl = ttl or None
        self._clock = clock
        self._on_expire = on_expire
        self._records: dict[str, TokenRecord] = {}
        self._lock = threading.Lock()
        self._last_sweep = clock()

    def mint(self, client_info: Any = None) -> tuple[str, str]:
        """Issue a new token; return ``(token, public_id)``."""
        name = ""
        if isinstance(client_info, dict):
            name = str(client_info.get("name", ""))[:100]
        now = self._clock()
        with self._lock:
            expired = self._sweep_locked(now)
            token = secrets.token_urlsafe(32)
            while token in self._records:  # pragma: no cover - astronomically unlikely
                token = secrets.token_urlsafe(32)
            record = TokenRecord(public_id_for(token), name, now, now)
            self._records[token] = record
        self._notify(expired)
        return token, record.public_id

    def resolve(self, token: str | None) -> str | None:
        """Public id for a live *token* (refreshing its idle timer), else None."""
        if not token:
            return None
        now = self._clock()
        expired: list[str] = []
        with self._lock:
            expired = self._sweep_locked(now)
            record = self._records.get(token)
            if record is not None and self._is_expired(record, now):
                del self._records[token]
                expired.append(record.public_id)
                record = None
            if record is not None:
                record.last_seen = now
        self._notify(expired)
        return record.public_id if record is not None else None

    def revoke(self, token: str | None) -> str | None:
        """Invalidate *token*; return its public id if it was live."""
        if not token:
            return None
        with self._lock:
            record = self._records.pop(token, None)
        if record is None:
            return None
        self._notify([record.public_id])
        return record.public_id

    def list(self) -> list[dict[str, Any]]:
        """Snapshot of live sessions (public ids only, never tokens)."""
        now = self._clock()
        with self._lock:
            expired = self._sweep_locked(now, force=True)
            rows = [
                {
                    "session_id": r.public_id,
                    "client_name": r.client_name,
                    "created_at": r.created_at,
                    "idle_seconds": round(now - r.last_seen, 3),
                }
                for r in self._records.values()
            ]
        self._notify(expired)
        return rows

    # -- internals -------------------------------------------------------

    def _is_expired(self, record: TokenRecord, now: float) -> bool:
        return self._ttl is not None and now - record.last_seen > self._ttl

    def _sweep_locked(self, now: float, force: bool = False) -> list[str]:
        """Drop expired tokens (at most once per min(ttl, 60s) unless forced)."""
        if self._ttl is None:
            return []
        if not force and now - self._last_sweep < min(self._ttl, 60.0):
            return []
        self._last_sweep = now
        dead = [t for t, r in self._records.items() if self._is_expired(r, now)]
        return [self._records.pop(t).public_id for t in dead]

    def _notify(self, public_ids: list[str]) -> None:
        if self._on_expire is None:
            return
        for public_id in public_ids:
            self._on_expire(public_id)
