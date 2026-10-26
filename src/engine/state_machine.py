"""Behavioral Graph & Session State Engine.

Maintains per-session DFA state, evaluates transitions against the
declarative PolicyConfig, records an audit trail, and exports
Mermaid.js diagrams for forensic analysis.

Each session is an isolated ``SessionState`` keyed by session_id, guarded
by its own lock.  The PolicyConfig transition graph is shared read-only;
nothing a session does is written back into it.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, NamedTuple

from src.models.policy import ForbiddenInvariant, PolicyConfig, ToolState

logger = logging.getLogger("mcp-netproxy")

DEFAULT_SESSION_TTL = 3600.0  # seconds of inactivity before a session is evicted
DEFAULT_MAX_HISTORY = 1024  # per-session bound on transition / trajectory records
MAX_TAINT_ORIGINS = 32  # per-session bound on recorded taint origins

# Argument names that identify what a tool read, in priority order
_SOURCE_ARGUMENTS = ("path", "url", "uri", "paths", "source", "query")


@dataclass
class TransitionRecord:
    """An immutable record of a single state transition attempt."""

    timestamp: float
    tool_name: str
    from_state: ToolState
    to_state: ToolState
    status: str  # "ALLOWED" | "BLOCKED_TRANSITION" | "BLOCKED_INVARIANT" | "BLOCKED_UNKNOWN"
    reason: str = ""


class StateHistoryEntry(NamedTuple):
    """One step of a session's actual trajectory through the DFA."""

    timestamp: float
    state: ToolState
    tool_invoked: str


@dataclass(frozen=True)
class TaintOrigin:
    """Where a session's taint came from.

    Attributes:
        taint_source: Tool and target that delivered the content,
            e.g. ``"fs__read_file:/sandbox/notes.txt"``.
        trigger_pattern: Detector that fired, e.g. ``"HEADER_DIRECTIVE"``,
            or ``"STATIC_POLICY_MAPPING"`` for tools mapped to UNTRUSTED_INGEST.
    """

    taint_source: str
    trigger_pattern: str
    reason: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class SessionState:
    """Mutable state for a single agent session."""

    session_id: str = ""
    current_state: ToolState = ToolState.START
    history: deque[TransitionRecord] = field(
        default_factory=lambda: deque(maxlen=DEFAULT_MAX_HISTORY)
    )
    state_history: deque[StateHistoryEntry] = field(
        default_factory=lambda: deque(maxlen=DEFAULT_MAX_HISTORY)
    )
    # Unbounded by design: invariants depend on every state ever visited,
    # and the set can hold at most len(ToolState) members.
    visited_states: set[ToolState] = field(default_factory=lambda: {ToolState.START})
    taint_vector: list[TaintOrigin] = field(default_factory=list)
    taint_origins_dropped: int = 0
    created_at: float = field(default_factory=time.time)
    last_seen: float = 0.0  # engine clock (monotonic), used for TTL expiry

    @property
    def is_tainted(self) -> bool:
        """Sticky latch: True once any taint origin has been recorded."""
        return bool(self.taint_vector)

    def add_taint(self, origin: TaintOrigin) -> None:
        # Keep the earliest origins (the root cause) and count the overflow;
        # the latch itself never depends on the bound.
        if len(self.taint_vector) < MAX_TAINT_ORIGINS:
            self.taint_vector.append(origin)
        else:
            self.taint_origins_dropped += 1


def describe_source(tool_name: str, arguments: dict[str, Any] | None) -> str:
    """Render ``tool:target`` for taint attribution (``fs__read_file:notes.txt``)."""
    for key in _SOURCE_ARGUMENTS:
        value = (arguments or {}).get(key)
        if value:
            return f"{tool_name}:{value}"
    return tool_name


class SessionGraphManager:
    """Thread-safe session state engine backed by a PolicyConfig DFA.

    Each unique session_id gets its own SessionState. Transitions are
    evaluated atomically under a per-session lock.  Sessions idle for
    longer than ``session_ttl`` seconds are evicted (``None`` or ``0``
    disables expiry).
    """

    def __init__(
        self,
        policy: PolicyConfig,
        *,
        session_ttl: float | None = DEFAULT_SESSION_TTL,
        max_history: int = DEFAULT_MAX_HISTORY,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._policy = policy
        self._sessions: dict[str, SessionState] = {}
        self._lock = threading.Lock()  # Protects _sessions dict creation
        self._session_locks: dict[str, threading.Lock] = {}
        self._session_ttl = session_ttl or None
        self._max_history = max_history
        self._clock = clock
        self._last_sweep = clock()

    # -- internal helpers ------------------------------------------------

    def _get_session(self, session_id: str) -> tuple[SessionState, threading.Lock]:
        """Return (session, lock), creating both atomically if needed."""
        with self._lock:
            now = self._clock()
            self._sweep_expired_locked(now)
            session = self._sessions.get(session_id)
            if session is not None and self._is_expired(session, now):
                self._evict_locked(session_id)
                session = None
            if session is None:
                session = SessionState(
                    session_id=session_id,
                    history=deque(maxlen=self._max_history),
                    state_history=deque(maxlen=self._max_history),
                )
                session.state_history.append(
                    StateHistoryEntry(time.time(), ToolState.START, "[session_start]")
                )
                self._sessions[session_id] = session
                self._session_locks[session_id] = threading.Lock()
            session.last_seen = now
            return session, self._session_locks[session_id]

    def _is_expired(self, session: SessionState, now: float) -> bool:
        return self._session_ttl is not None and now - session.last_seen > self._session_ttl

    def _evict_locked(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        self._session_locks.pop(session_id, None)
        if session is not None and session.is_tainted:
            logger.info(f"[SESSION EXPIRY] Evicted tainted session '{session_id}' after TTL")

    def _sweep_expired_locked(self, now: float) -> None:
        """Evict every expired session; runs at most once per min(ttl, 60s)."""
        if self._session_ttl is None or now - self._last_sweep < min(self._session_ttl, 60.0):
            return
        self._last_sweep = now
        for sid in [s for s, sess in self._sessions.items() if self._is_expired(sess, now)]:
            self._evict_locked(sid)

    @staticmethod
    def _record(
        session: SessionState,
        tool_name: str,
        from_state: ToolState,
        to_state: ToolState,
        status: str,
        reason: str,
    ) -> TransitionRecord:
        record = TransitionRecord(
            timestamp=time.time(),
            tool_name=tool_name,
            from_state=from_state,
            to_state=to_state,
            status=status,
            reason=reason,
        )
        session.history.append(record)
        if status == "ALLOWED":
            session.state_history.append(
                StateHistoryEntry(record.timestamp, to_state, tool_name)
            )
        return record

    # -- public API ------------------------------------------------------

    def evaluate_transition(
        self, session_id: str, tool_name: str, arguments: dict[str, Any] | None = None
    ) -> tuple[bool, str, dict[str, Any]]:
        """Evaluate whether *tool_name* is legal for *session_id*.

        Returns:
            (allowed, reason, metadata) where *allowed* is True when the
            tool call may proceed, *reason* is a human-readable verdict,
            and *metadata* contains forensic context for logging/response.
        """
        session, slock = self._get_session(session_id)

        with slock:
            from_state = session.current_state
            to_state = self._policy.resolve_state(tool_name, arguments)

            meta: dict[str, Any] = {
                "session_id": session_id,
                "tool_name": tool_name,
                "from_state": from_state.value,
                "to_state": to_state.value,
            }

            # 1. Unknown tool → block by default
            if to_state is ToolState.UNKNOWN:
                reason = f"Unknown tool '{tool_name}' is not mapped in policy"
                record = self._record(
                    session, tool_name, from_state, to_state, "BLOCKED_UNKNOWN", reason
                )
                meta["status"] = record.status
                return False, reason, meta

            # 2. Sticky taint latch check:
            # If session is tainted, mutating or egress actions are strictly forbidden
            if session.is_tainted and to_state in (
                ToolState.LOCAL_WRITE,
                ToolState.EXECUTE,
                ToolState.NETWORK_EGRESS,
            ):
                reason = (
                    "Session taint persistent latch: Untrusted ingestion cannot "
                    "directly mutate local files or trigger privileged egress "
                    "(mitigating indirect prompt injection)."
                )
                record = self._record(
                    session, tool_name, from_state, to_state, "BLOCKED_INVARIANT", reason
                )
                meta["status"] = record.status
                meta["invariant_rule"] = {
                    "from": from_state.value,
                    "to": to_state.value,
                }
                meta["taint_vector"] = [o.taint_source for o in session.taint_vector]
                return False, reason, meta

            # 3. Check forbidden invariants (takes priority over allowed)
            violated: ForbiddenInvariant | None = self._policy.check_invariants(
                from_state, to_state, session.visited_states
            )
            if violated is not None:
                reason = violated.reason
                record = self._record(
                    session, tool_name, from_state, to_state, "BLOCKED_INVARIANT", reason
                )
                meta["status"] = record.status
                meta["invariant_rule"] = {
                    "from": violated.from_state.value,
                    "to": violated.to_state.value,
                }
                return False, reason, meta

            # 4. Check allowed transitions
            if not self._policy.is_transition_allowed(from_state, to_state):
                reason = (
                    f"Transition {from_state.value} -> {to_state.value} "
                    f"is not in the allowed transition graph"
                )
                record = self._record(
                    session, tool_name, from_state, to_state, "BLOCKED_TRANSITION", reason
                )
                meta["status"] = record.status
                return False, reason, meta

            # 5. Valid: advance state
            session.current_state = to_state
            session.visited_states.add(to_state)
            if to_state is ToolState.UNTRUSTED_INGEST:
                session.add_taint(
                    TaintOrigin(
                        taint_source=describe_source(tool_name, arguments),
                        trigger_pattern="STATIC_POLICY_MAPPING",
                        reason=f"'{tool_name}' is mapped to UNTRUSTED_INGEST",
                    )
                )
            reason = "Allowed"
            record = self._record(session, tool_name, from_state, to_state, "ALLOWED", reason)
            meta["status"] = record.status
            return True, reason, meta

    def get_session_history(
        self, session_id: str
    ) -> list[TransitionRecord]:
        """Return a copy of the transition history for a session."""
        session, slock = self._get_session(session_id)
        with slock:
            return list(session.history)

    def peek_state(self, session_id: str) -> ToolState:
        """Current DFA state without creating or refreshing the session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or self._is_expired(session, self._clock()):
                return ToolState.START
            return session.current_state

    def get_session_context(self, session_id: str) -> dict[str, Any] | None:
        """JSON-serializable snapshot of a live session, or None if absent."""
        with self._lock:
            session = self._sessions.get(session_id)
            slock = self._session_locks.get(session_id)
            if session is None or self._is_expired(session, self._clock()):
                return None
        with slock:
            return {
                "session_id": session.session_id,
                "current_state": session.current_state.value,
                "is_tainted": session.is_tainted,
                "taint_vector": [
                    {
                        "taint_source": o.taint_source,
                        "trigger_pattern": o.trigger_pattern,
                        "reason": o.reason,
                        "timestamp": o.timestamp,
                    }
                    for o in session.taint_vector
                ],
                "taint_origins_dropped": session.taint_origins_dropped,
                "state_history": [
                    {"timestamp": e.timestamp, "state": e.state.value, "tool_invoked": e.tool_invoked}
                    for e in session.state_history
                ],
                "visited_states": sorted(s.value for s in session.visited_states),
                "created_at": session.created_at,
                "session_ttl": self._session_ttl,
            }

    def taint_session(
        self,
        session_id: str,
        taint_state: ToolState = ToolState.UNTRUSTED_INGEST,
        *,
        taint_source: str = "[dynamic_ingest_scan]",
        trigger_pattern: str = "UNSPECIFIED",
        reason: str = "Session tainted by dynamic response scanner",
    ) -> None:
        """Retroactively taint a session's current state with a persistent sticky latch.

        Used by the dynamic ingest scanner to override the DFA state when
        response content analysis reveals untrusted directives. Once tainted,
        session.is_tainted remains True persistently for the session lifetime,
        blocking any subsequent mutating or egress actions even if intermediate
        benign reads occur.  Each call appends a TaintOrigin to the session's
        taint_vector for attribution.
        """
        session, slock = self._get_session(session_id)
        with slock:
            from_state = session.current_state
            session.add_taint(TaintOrigin(taint_source, trigger_pattern, reason))
            session.current_state = taint_state
            session.visited_states.add(taint_state)
            self._record(
                session, "[dynamic_ingest_scan]", from_state, taint_state, "ALLOWED", reason
            )

    def reset_session(self, session_id: str) -> None:
        """Reset a session back to START state."""
        with self._lock:
            self._sessions.pop(session_id, None)
            self._session_locks.pop(session_id, None)

    def purge_expired(self) -> int:
        """Evict all sessions past their TTL now; return how many were removed."""
        with self._lock:
            before = len(self._sessions)
            self._last_sweep = float("-inf")
            self._sweep_expired_locked(self._clock())
            return before - len(self._sessions)

    def export_mermaid_graph(self, session_id: str) -> str:
        """Generate a Mermaid.js state diagram for a session's trajectory.

        Allowed transitions render as green arrows; blocked transitions
        render as red dashed arrows with the blocked node highlighted.
        """
        history = self.get_session_history(session_id)

        lines: list[str] = ["stateDiagram-v2"]
        blocked_states: set[str] = set()

        for rec in history:
            src = rec.from_state.value
            dst = rec.to_state.value

            if rec.status == "ALLOWED":
                lines.append(f"    {src} --> {dst} : {rec.tool_name} ✅")
            else:
                lines.append(f"    {src} --> {dst} : {rec.tool_name} ❌ BLOCKED")
                blocked_states.add(dst)

        # Style blocked nodes in red
        if blocked_states:
            lines.append(f'    classDef blocked fill:#ff4444,color:#fff,stroke:#cc0000')
            for bs in blocked_states:
                lines.append(f"    class {bs} blocked")

        if not history:
            lines.append("    [*] --> START")

        return "\n".join(lines)
