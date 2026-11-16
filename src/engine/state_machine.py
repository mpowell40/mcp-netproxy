"""Behavioral Graph & Session State Engine.

Maintains per-session DFA state, evaluates transitions against the
declarative PolicyConfig, records an audit trail, and exports
Mermaid.js diagrams for forensic analysis.

Each session is an isolated ``SessionState`` keyed by session_id, guarded
by its own lock.  The PolicyConfig transition graph is shared read-only;
nothing a session does is written back into it.

Before the transition graph, every call is checked against the session's
provenance labels: the policy's ``labels.sinks`` rules name the DFA states
each label may not reach (e.g. ``untrusted`` -> LOCAL_WRITE).
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, NamedTuple

from src.engine.labels import (
    FileLabelStore,
    LabelOrigin,
    LabelResolver,
    describe_source,
    extract_secret_values,
    find_tracked_fragment,
    fragments_of,
    path_values,
)
from src.models.policy import ForbiddenInvariant, PolicyConfig, SinkRule, ToolState

logger = logging.getLogger("mcp-netproxy")

DEFAULT_SESSION_TTL = 3600.0  # seconds of inactivity before a session is evicted
DEFAULT_MAX_HISTORY = 1024  # per-session bound on transition / trajectory records
# Overrides labels.file_labels.store_path (tests, alternate deployments)
FILE_LABEL_STORE_ENV = "MCP_FILE_LABEL_STORE"
MAX_LABEL_ORIGINS = 32  # per-session, per-label bound on recorded label origins
MAX_ALERTS = 32  # per-session bound on recorded scanner alerts

__all__ = ["SessionGraphManager", "SessionState", "describe_source", "DEFAULT_SESSION_TTL"]


@dataclass
class TransitionRecord:
    """An immutable record of a single state transition attempt."""

    timestamp: float
    tool_name: str
    from_state: ToolState
    to_state: ToolState
    status: str  # "ALLOWED" | "BLOCKED_LABEL" | "BLOCKED_VALUE" | "BLOCKED_TRANSITION" | "BLOCKED_INVARIANT" | "BLOCKED_UNKNOWN"
    reason: str = ""


class StateHistoryEntry(NamedTuple):
    """One step of a session's actual trajectory through the DFA."""

    timestamp: float
    state: ToolState
    tool_invoked: str


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
    # Provenance labels: label -> origins.  Sticky: entries are never removed;
    # the label set is the key set, so the origin bound never clears a label.
    labels: dict[str, list[LabelOrigin]] = field(default_factory=dict)
    label_origins_dropped: int = 0
    # Value tracking: fragments of secret values this session has read.
    tracked_fragments: set[str] = field(default_factory=set)
    tracked_fragments_dropped: int = 0
    # Ingest scanner alerts: telemetry only, never an input to enforcement.
    alerts: list[dict[str, Any]] = field(default_factory=list)
    alerts_dropped: int = 0
    created_at: float = field(default_factory=time.time)
    last_seen: float = 0.0  # engine clock (monotonic), used for TTL expiry

    @property
    def is_tainted(self) -> bool:
        """True once the session carries any provenance label."""
        return bool(self.labels)


    @property
    def label_set(self) -> frozenset[str]:
        """Labels the session carries (the join of every source it has read)."""
        return frozenset(self.labels)

    def add_label(self, origin: LabelOrigin) -> bool:
        """Join *origin*'s label into the session; False if already recorded."""
        origins = self.labels.setdefault(origin.label, [])
        key = (origin.source, origin.rule)
        if any((o.source, o.rule) == key for o in origins):
            return False
        if len(origins) < MAX_LABEL_ORIGINS:
            origins.append(origin)
        else:
            self.label_origins_dropped += 1
        return True

    def labels_dict(self) -> dict[str, list[dict[str, Any]]]:
        return {label: [o.to_dict() for o in origins] for label, origins in sorted(self.labels.items())}


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
        file_label_store: FileLabelStore | None = None,
    ) -> None:
        self._policy = policy
        if file_label_store is None:
            file_label_store = FileLabelStore(
                os.getenv(FILE_LABEL_STORE_ENV) or policy.labels.file_labels.store_path
            )
        self._labels = LabelResolver(policy, file_label_store)
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
                meta["check"] = "unknown_tool"
                return False, reason, meta

            # 2. Label sink policy (sticky provenance labels):
            # a session carrying a label may never reach that label's sinks.
            violated_sinks = self._sink_violations(session, to_state)
            if violated_sinks:
                reason = violated_sinks[0].reason
                record = self._record(
                    session, tool_name, from_state, to_state, "BLOCKED_LABEL", reason
                )
                meta["status"] = record.status
                meta["check"] = "label_sink"
                meta["sink_rules"] = [
                    {"label": r.label, "block": [b.value for b in r.block]} for r in violated_sinks
                ]
                meta["labels"] = session.labels_dict()
                return False, reason, meta

            # 2b. Value tracking (secondary defense; see labels.py for what
            # evades it).  Outbound arguments carrying a fragment of a value
            # read from a value-tracked source are refused.
            tracking = self._policy.labels.value_tracking
            if (
                tracking.enabled
                and to_state in tracking.sinks
                and find_tracked_fragment(arguments, session.tracked_fragments, tracking.fragment_length)
            ):
                reason = (
                    "Arguments contain a value read from a "
                    f"{'/'.join(tracking.labels)}-labeled source (value tracking)."
                )
                record = self._record(
                    session, tool_name, from_state, to_state, "BLOCKED_VALUE", reason
                )
                meta["status"] = record.status
                meta["check"] = "value_tracking"
                meta["labels"] = session.labels_dict()
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
                meta["check"] = "forbidden_invariant"
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
                meta["check"] = "transition_graph"
                return False, reason, meta

            # 5. Valid: advance state.  Labels are applied by record_source()
            # once the backend has answered, not here.
            session.current_state = to_state
            session.visited_states.add(to_state)
            reason = "Allowed"
            record = self._record(session, tool_name, from_state, to_state, "ALLOWED", reason)
            meta["status"] = record.status
            return True, reason, meta

    def _sink_violations(self, session: SessionState, to_state: ToolState) -> list[SinkRule]:
        """Sink rules whose label the session carries and whose sinks include *to_state*."""
        return [
            rule for rule in self._policy.labels.sinks
            if rule.label in session.labels and to_state in rule.block
        ]

    def record_source(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        response_text: str = "",
    ) -> list[LabelOrigin]:
        """Apply the labels of the source this call read from.

        Called once the backend has answered (successfully or not): labels
        are decided by the policy's source rules for this tool and its path
        arguments, never by the response content.  If the source carries a
        value-tracked label, fragments of *response_text*'s secret-looking
        values are remembered for the outbound check.  Returns the origins
        that were new to the session.
        """
        origins = self._labels.source_labels(
            tool_name, self._policy.resolve_state(tool_name, arguments), arguments
        )
        applied = self.apply_labels(session_id, origins)
        tracking = self._policy.labels.value_tracking
        if (
            tracking.enabled
            and response_text
            and any(o.label in tracking.labels for o in origins)
        ):
            self._track_values(session_id, response_text)
        return applied

    @property
    def file_labels(self) -> FileLabelStore:
        return self._labels.store

    def record_write(
        self, session_id: str, tool_name: str, arguments: dict[str, Any] | None = None
    ) -> list[str]:
        """Propagate labels to the files a LOCAL_WRITE call is about to change.

        Every destination path gets the session's current labels, plus the
        labels of the call's source paths (``move_file``'s ``source``: glob
        and stored labels, including those stored under it).  Called after
        the call has passed every check and *before* it is forwarded, so a
        write the backend performs but never confirms is still recorded;
        over-labeling a write that then fails is the safe direction.
        Raises OSError if the store cannot be persisted (callers fail closed).
        Returns the destination paths that gained labels.
        """
        if self._policy.resolve_state(tool_name, arguments) is not ToolState.LOCAL_WRITE:
            return []
        cfg = self._policy.labels.file_labels
        path_args = self._policy.path_arguments_for(tool_name)
        sources = path_values(arguments, [a for a in path_args if a in cfg.source_arguments])
        destinations = path_values(arguments, [a for a in path_args if a not in cfg.source_arguments])
        if not destinations:
            return []

        session, slock = self._get_session(session_id)
        with slock:
            session_origins = [o for origins in session.labels.values() for o in origins]
        carried = [o for src in sources for o in self._labels.path_origins(tool_name, src)]

        changed: list[str] = []
        store = self._labels.store
        for dest in destinations:
            entries = [
                {
                    "label": o.label,
                    "source": o.source,
                    "rule": o.rule,
                    "written_by": f"{tool_name}:{dest}",
                    "session": session_id,
                    "timestamp": time.time(),
                }
                for o in session_origins + carried
            ]
            touched = store.add(dest, entries) if entries else False
            for src in sources:
                touched |= store.copy_tree(src, dest)
            if touched:
                changed.append(dest)
                logger.info(f"[FILE LABELS] '{dest}' labeled by '{tool_name}' in session '{session_id}'")
        return changed

    def _track_values(self, session_id: str, text: str) -> None:
        tracking = self._policy.labels.value_tracking
        new: set[str] = set()
        for value in extract_secret_values(text, tracking.min_value_length):
            new |= fragments_of(value, tracking.fragment_length)
        session, slock = self._get_session(session_id)
        with slock:
            new -= session.tracked_fragments
            room = tracking.max_fragments_per_session - len(session.tracked_fragments)
            if len(new) > room:
                session.tracked_fragments_dropped += len(new) - max(room, 0)
                new = set(sorted(new)[:max(room, 0)])
            session.tracked_fragments |= new

    def apply_labels(self, session_id: str, origins: list[LabelOrigin]) -> list[LabelOrigin]:
        """Join *origins* into the session's labels; return those not seen before."""
        if not origins:
            return []
        session, slock = self._get_session(session_id)
        with slock:
            return [o for o in origins if session.add_label(o)]

    def label(
        self, session_id: str, label: str, *, source: str = "[manual]", rule: str = "manual"
    ) -> None:
        """Label a session directly (operators and tests)."""
        self.apply_labels(session_id, [LabelOrigin(label, source, rule)])

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
                "labels": session.labels_dict(),
                "label_origins_dropped": session.label_origins_dropped,
                # Fragments themselves are secret; only their count is exposed
                "tracked_fragments": len(session.tracked_fragments),
                "tracked_fragments_dropped": session.tracked_fragments_dropped,
                "alerts": list(session.alerts),
                "alerts_dropped": session.alerts_dropped,
                "state_history": [
                    {"timestamp": e.timestamp, "state": e.state.value, "tool_invoked": e.tool_invoked}
                    for e in session.state_history
                ],
                "visited_states": sorted(s.value for s in session.visited_states),
                "created_at": session.created_at,
                "session_ttl": self._session_ttl,
            }

    def record_alert(self, session_id: str, alert: dict[str, Any]) -> None:
        """Record an ingest-scanner alert for operators.

        Alerts are telemetry: they never change the session's labels or
        DFA state.
        """
        session, slock = self._get_session(session_id)
        with slock:
            if len(session.alerts) < MAX_ALERTS:
                session.alerts.append({**alert, "timestamp": time.time()})
            else:
                session.alerts_dropped += 1

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
