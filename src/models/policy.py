"""Declarative Policy Schema for Behavioral State-Machine Invariant Enforcement.

Defines the DFA state space, tool-to-state mappings, legal transitions,
and forbidden invariants loaded from a YAML configuration file.
"""

from __future__ import annotations

import enum
import pathlib
import re
from typing import Any

import yaml
from pydantic import BaseModel, Field, PrivateAttr, model_validator

# Separator between a backend namespace and its upstream tool name
# (e.g. ``fs__read_file``).  Namespaces may not contain underscores, so the
# first occurrence of the separator always splits deterministically.
NAMESPACE_SEPARATOR = "__"
_NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9]*$")


def namespaced(namespace: str, tool_name: str) -> str:
    """Build the client-facing, namespaced name for a backend tool."""
    return f"{namespace}{NAMESPACE_SEPARATOR}{tool_name}"


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


class BackendConfig(BaseModel):
    """A downstream MCP server registered behind the proxy.

    Attributes:
        url: JSON-RPC endpoint of the backend.
        url_env: Optional environment variable that overrides ``url``.
        capabilities: DFA states this backend is permitted to expose.
            Dynamically discovered tools classified outside this set are
            quarantined as UNKNOWN.  ``None`` means unrestricted.
        sandbox_roots: Path prefixes that path-like arguments must stay
            within.  Empty disables the boundary check for this backend.
        path_arguments: Argument names (string or list of strings) that are
            checked against ``sandbox_roots``.
        scan_responses: Run the ingest scanner over LOCAL_READ /
            UNTRUSTED_INGEST responses from this backend.
        tools: Explicit upstream-tool-name -> ToolState mappings.
    """

    url: str
    url_env: str | None = None
    capabilities: list[ToolState] | None = None
    sandbox_roots: list[str] = Field(default_factory=list)
    path_arguments: list[str] = Field(default_factory=lambda: ["path"])
    scan_responses: bool = False
    tools: dict[str, ToolState] = Field(default_factory=dict)


class PolicyConfig(BaseModel):
    """Root policy configuration loaded from YAML.

    Attributes:
        tool_mappings: Maps concrete tool names to their abstract ToolState.
            Top-level entries are global (un-namespaced) mappings.  Backend
            tools are added under their namespaced name, plus a bare-name
            alias while exactly one backend serves that name.
        allowed_transitions: Adjacency list of legal directed edges in the DFA.
        forbidden_invariants: Explicit security invariants that override
            allowed_transitions and trigger fatal violations.
        backends: Registered downstream MCP servers, keyed by namespace.
        default_backend: Namespace that receives non-``tools/call`` traffic
            and tools that no registered backend serves.
    """

    tool_mappings: dict[str, ToolState]
    allowed_transitions: dict[ToolState, list[ToolState]]
    forbidden_invariants: list[ForbiddenInvariant] = Field(default_factory=list)
    backends: dict[str, BackendConfig] = Field(default_factory=dict)
    default_backend: str | None = None

    # Names declared at the top level of ``tool_mappings``; never replaced
    # or withdrawn by backend aliasing.
    _global_names: set[str] = PrivateAttr(default_factory=set)
    # Bare upstream tool name -> namespaces that serve it.
    _alias_owners: dict[str, set[str]] = PrivateAttr(default_factory=dict)

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

    def model_post_init(self, __context: Any) -> None:
        """Validate the backend registry and register declared backend tools."""
        self._global_names = set(self.tool_mappings)
        if self.default_backend is not None and self.default_backend not in self.backends:
            raise ValueError(f"default_backend '{self.default_backend}' is not a registered backend")
        backends, self.backends = self.backends, {}
        for namespace, backend in backends.items():
            self.add_backend(namespace, backend)

    # -- backend registry ----------------------------------------------------

    def add_backend(self, namespace: str, backend: BackendConfig) -> None:
        """Register a backend and its declared tools under ``namespace``."""
        if not _NAMESPACE_RE.match(namespace):
            raise ValueError(
                f"Backend namespace '{namespace}' must match {_NAMESPACE_RE.pattern}"
            )
        if namespace in self.backends:
            raise ValueError(f"Backend namespace '{namespace}' is already registered")
        if backend.capabilities is not None:
            for tool_name, state in backend.tools.items():
                if state not in backend.capabilities:
                    raise ValueError(
                        f"Backend '{namespace}' declares tool '{tool_name}' as "
                        f"{state.value}, outside its capabilities"
                    )
        self.backends[namespace] = backend
        for tool_name, state in backend.tools.items():
            self.register_backend_tool(namespace, tool_name, state)

    def register_backend_tool(self, namespace: str, tool_name: str, state: ToolState) -> str:
        """Map ``namespace__tool_name`` to ``state`` and maintain the bare alias.

        The bare name stays resolvable only while a single backend serves
        it; once a second backend exposes the same name the alias is
        withdrawn, so the bare name falls back to UNKNOWN (blocked).
        """
        key = namespaced(namespace, tool_name)
        self.tool_mappings[key] = state
        owners = self._alias_owners.setdefault(tool_name, set())
        owners.add(namespace)
        if tool_name not in self._global_names:
            if len(owners) == 1:
                self.tool_mappings[tool_name] = state
            else:
                self.tool_mappings.pop(tool_name, None)
        return key

    def split_namespaced(self, name: str) -> tuple[str, str] | None:
        """Return ``(namespace, tool_name)`` if *name* targets a registered backend."""
        namespace, sep, tool_name = name.partition(NAMESPACE_SEPARATOR)
        if sep and tool_name and namespace in self.backends:
            return namespace, tool_name
        return None

    def backends_serving(self, tool_name: str) -> list[str]:
        """Namespaces whose backends serve the bare upstream *tool_name*."""
        return sorted(self._alias_owners.get(tool_name, ()))

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
        """Map a concrete tool name to its abstract ToolState.

        The ``arguments`` parameter is accepted for API compatibility
        but is no longer used for filename-based taint detection.
        Content-based taint detection is now handled by the ingest scanner.

        Returns ToolState.UNKNOWN for unmapped tools.
        """
        return self.tool_mappings.get(tool_name, ToolState.UNKNOWN)

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

