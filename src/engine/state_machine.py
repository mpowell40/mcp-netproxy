"""Behavioral Graph & Session State Engine.

Maintains per-session DFA state, evaluates transitions against the
declarative PolicyConfig, records an audit trail, and exports
Mermaid.js diagrams for forensic analysis.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from src.models.policy import ForbiddenInvariant, PolicyConfig, ToolState


@dataclass
class TransitionRecord:
    """An immutable record of a single state transition attempt."""

    timestamp: float
    tool_name: str
    from_state: ToolState
    to_state: ToolState
    status: str  # "ALLOWED" | "BLOCKED_TRANSITION" | "BLOCKED_INVARIANT" | "BLOCKED_UNKNOWN"
    reason: str = ""


@dataclass
class SessionState:
    """Mutable state for a single agent session."""

    current_state: ToolState = ToolState.START
    history: list[TransitionRecord] = field(default_factory=list)
    visited_states: set[ToolState] = field(default_factory=lambda: {ToolState.START})


class SessionGraphManager:
    """Thread-safe session state engine backed by a PolicyConfig DFA.

    Each unique session_id gets its own SessionState. Transitions are
    evaluated atomically under a per-session lock.
    """

    def __init__(self, policy: PolicyConfig) -> None:
        self._policy = policy
        self._sessions: dict[str, SessionState] = {}
        self._lock = threading.Lock()  # Protects _sessions dict creation
        self._session_locks: dict[str, threading.Lock] = {}

    # -- internal helpers ------------------------------------------------

    def _get_session(self, session_id: str) -> tuple[SessionState, threading.Lock]:
        """Return (session, lock), creating both atomically if needed."""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState()
                self._session_locks[session_id] = threading.Lock()
            return self._sessions[session_id], self._session_locks[session_id]

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
                record = TransitionRecord(
                    timestamp=time.time(),
                    tool_name=tool_name,
                    from_state=from_state,
                    to_state=to_state,
                    status="BLOCKED_UNKNOWN",
                    reason=reason,
                )
                session.history.append(record)
                meta["status"] = record.status
                return False, reason, meta

            # 2. Check forbidden invariants (takes priority over allowed)
            violated: ForbiddenInvariant | None = self._policy.check_invariants(
                from_state, to_state, session.visited_states
            )
            if violated is not None:
                reason = violated.reason
                record = TransitionRecord(
                    timestamp=time.time(),
                    tool_name=tool_name,
                    from_state=from_state,
                    to_state=to_state,
                    status="BLOCKED_INVARIANT",
                    reason=reason,
                )
                session.history.append(record)
                meta["status"] = record.status
                meta["invariant_rule"] = {
                    "from": violated.from_state.value,
                    "to": violated.to_state.value,
                }
                return False, reason, meta

            # 3. Check allowed transitions
            if not self._policy.is_transition_allowed(from_state, to_state):
                reason = (
                    f"Transition {from_state.value} -> {to_state.value} "
                    f"is not in the allowed transition graph"
                )
                record = TransitionRecord(
                    timestamp=time.time(),
                    tool_name=tool_name,
                    from_state=from_state,
                    to_state=to_state,
                    status="BLOCKED_TRANSITION",
                    reason=reason,
                )
                session.history.append(record)
                meta["status"] = record.status
                return False, reason, meta

            # 4. Valid: advance state
            session.current_state = to_state
            session.visited_states.add(to_state)
            reason = "Allowed"
            record = TransitionRecord(
                timestamp=time.time(),
                tool_name=tool_name,
                from_state=from_state,
                to_state=to_state,
                status="ALLOWED",
                reason=reason,
            )
            session.history.append(record)
            meta["status"] = record.status
            return True, reason, meta

    def get_session_history(
        self, session_id: str
    ) -> list[TransitionRecord]:
        """Return a copy of the transition history for a session."""
        session, _ = self._get_session(session_id)
        return list(session.history)

    def reset_session(self, session_id: str) -> None:
        """Reset a session back to START state."""
        with self._lock:
            self._sessions.pop(session_id, None)
            self._session_locks.pop(session_id, None)

    def export_mermaid_graph(self, session_id: str) -> str:
        """Generate a Mermaid.js state diagram for a session's trajectory.

        Allowed transitions render as green arrows; blocked transitions
        render as red dashed arrows with the blocked node highlighted.
        """
        session, _ = self._get_session(session_id)
        history = session.history

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
