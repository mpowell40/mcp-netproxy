"""Structured Checkpoint Telemetry for the Proxy Event Lifecycle.

Every JSON-RPC frame that crosses the proxy passes through one or more
checkpoints.  Each checkpoint emits an immutable ``ProxyEvent`` recording
the session, tool, DFA state, and the proxy's decision, so a session's
full trajectory can be reconstructed independently of the DFA history.

    tools/list:  BEFORE_TOOL_LIST  ->  (fan-out)  ->  AFTER_TOOL_LIST (per tool)
    tools/call:  BEFORE_TOOL_CALL  ->  (forward)  ->  AFTER_TOOL_CALL
"""

from __future__ import annotations

import enum
import json
import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger("mcp-netproxy.events")


class Checkpoint(str, enum.Enum):
    """Points in the frame lifecycle where the proxy inspects traffic."""

    BEFORE_TOOL_LIST = "BEFORE_TOOL_LIST"  # tools/list request, before fan-out
    AFTER_TOOL_LIST = "AFTER_TOOL_LIST"  # each advertised tool schema & description
    BEFORE_TOOL_CALL = "BEFORE_TOOL_CALL"  # parameters + DFA transition check
    AFTER_TOOL_CALL = "AFTER_TOOL_CALL"  # response payload via the ingest scanner


class Decision(str, enum.Enum):
    """What the proxy did with the frame at a checkpoint.

    ALLOW:  frame forwarded unchanged.
    BLOCK:  frame rejected (or, for a listed tool, every call to it will be).
    MUTATE: frame forwarded with proxy rewrites (e.g. namespaced tool names).
    """

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    MUTATE = "MUTATE"


@dataclass(frozen=True)
class ProxyEvent:
    """A single checkpoint telemetry record."""

    session_id: str
    event_type: Checkpoint
    tool_name: str | None
    current_state: str
    decision: Decision
    timestamp: float = field(default_factory=time.time)
    request_id: Any = None
    details: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "event_type": self.event_type.value,
            "tool_name": self.tool_name,
            "current_state": self.current_state,
            "decision": self.decision.value,
            "timestamp": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "request_id": self.request_id,
            "details": self.details,
        }


EventSink = Callable[[ProxyEvent], None]


class EventCollector:
    """Thread-safe bounded store and fan-out point for ProxyEvents.

    Events are kept in a ring buffer (oldest evicted first) and pushed to
    every registered sink.  A failing sink is logged and never interrupts
    enforcement.
    """

    def __init__(self, max_events: int = 10_000, log_events: bool = True) -> None:
        self._events: deque[ProxyEvent] = deque(maxlen=max_events)
        self._sinks: list[EventSink] = []
        self._lock = threading.Lock()
        self._log_events = log_events

    def add_sink(self, sink: EventSink) -> None:
        with self._lock:
            self._sinks.append(sink)

    def emit(self, event: ProxyEvent) -> ProxyEvent:
        with self._lock:
            self._events.append(event)
            sinks = list(self._sinks)
        if self._log_events:
            logger.info(json.dumps(event.to_dict(), default=str))
        for sink in sinks:
            try:
                sink(event)
            except Exception:
                logger.exception("[TELEMETRY] Event sink failed")
        return event

    def events(self, session_id: str | None = None) -> list[ProxyEvent]:
        """Return a snapshot of stored events, optionally for one session."""
        with self._lock:
            snapshot = list(self._events)
        if session_id is None:
            return snapshot
        return [e for e in snapshot if e.session_id == session_id]
