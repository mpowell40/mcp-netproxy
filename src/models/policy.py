"""Declarative Policy Schema for Behavioral State-Machine Invariant Enforcement.

Defines the DFA state space, tool-to-state mappings, legal transitions,
and forbidden invariants loaded from a YAML configuration file.
"""

from __future__ import annotations

import enum
import pathlib
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator


class ToolState(str, enum.Enum):
    """Abstract states in the behavioral DFA.

    Each tool invocation is mapped to exactly one ToolState.
    The proxy evaluates whether the transition from the session's
    current state to the target state is legal before forwarding.
    """

    START = "START"
    DISCOVERY = "DISCOVERY"
    LOCAL_READ = "LOCAL_READ"
    LOCAL_WRITE = "LOCAL_WRITE"
    UNTRUSTED_INGEST = "UNTRUSTED_INGEST"
    EXECUTE = "EXECUTE"
    NETWORK_EGRESS = "NETWORK_EGRESS"
    UNKNOWN = "UNKNOWN"


class ForbiddenInvariant(BaseModel):
    """A single forbidden invariant rule.

    If a session attempts to transition from `from_state` to `to_state`
    without having visited all states in `unless_visited` first, the
    transition is blocked with the given `reason`.
    """

    from_state: ToolState
    to_state: ToolState
    reason: str
    unless_visited: list[ToolState] = Field(default_factory=list)


class PolicyConfig(BaseModel):
    """Root policy configuration loaded from YAML.

    Attributes:
        tool_mappings: Maps concrete tool names to their abstract ToolState.
        allowed_transitions: Adjacency list of legal directed edges in the DFA.
        forbidden_invariants: Explicit security invariants that override
            allowed_transitions and trigger fatal violations.
    """

    tool_mappings: dict[str, ToolState]
    allowed_transitions: dict[ToolState, list[ToolState]]
    forbidden_invariants: list[ForbiddenInvariant] = Field(default_factory=list)
    untrusted_paths: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _coerce_yaml_keys(cls, values: dict[str, Any]) -> dict[str, Any]:
        """Coerce YAML string keys into ToolState enum members."""
        raw_transitions = values.get("allowed_transitions", {})
        coerced: dict[ToolState, list[ToolState]] = {}
        for key, targets in raw_transitions.items():
            state_key = ToolState(key) if isinstance(key, str) else key
            coerced[state_key] = [
                ToolState(t) if isinstance(t, str) else t for t in targets
            ]
        values["allowed_transitions"] = coerced
        return values

    @classmethod
    def from_yaml(cls, path: str | pathlib.Path) -> PolicyConfig:
        """Load a PolicyConfig from a YAML file on disk."""
        path = pathlib.Path(path)
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        return cls.model_validate(raw)

    def resolve_state(
        self, tool_name: str, arguments: dict[str, Any] | None = None
    ) -> ToolState:
        """Map a concrete tool name (and optional arguments) to its abstract ToolState.

        If arguments target a path matching untrusted_paths for a read tool,
        resolves to ToolState.UNTRUSTED_INGEST.
        Returns ToolState.UNKNOWN for unmapped tools.
        """
        base_state = self.tool_mappings.get(tool_name, ToolState.UNKNOWN)
        if arguments and self.untrusted_paths and base_state == ToolState.LOCAL_READ:
            path_val = str(
                arguments.get("path")
                or arguments.get("file")
                or arguments.get("filepath")
                or ""
            )
            if path_val:
                import fnmatch
                for pattern in self.untrusted_paths:
                    if (
                        fnmatch.fnmatch(path_val.lower(), pattern.lower())
                        or fnmatch.fnmatch(pathlib.Path(path_val).name.lower(), pattern.lower())
                    ):
                        return ToolState.UNTRUSTED_INGEST

        return base_state

    def is_transition_allowed(self, from_state: ToolState, to_state: ToolState) -> bool:
        """Check whether a directed edge exists in allowed_transitions."""
        return to_state in self.allowed_transitions.get(from_state, [])

    def check_invariants(
        self,
        from_state: ToolState,
        to_state: ToolState,
        visited_states: set[ToolState],
    ) -> ForbiddenInvariant | None:
        """Return the first violated ForbiddenInvariant, or None if clean."""
        for inv in self.forbidden_invariants:
            if inv.from_state == from_state and inv.to_state == to_state:
                # Check if all 'unless_visited' states have been seen
                if inv.unless_visited and inv.unless_visited <= visited_states:
                    continue  # Exception satisfied
                return inv
        return None
