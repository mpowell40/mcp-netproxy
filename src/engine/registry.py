"""Multi-Backend Registry & Tool Namespace Router.

Resolves client-facing tool names to a downstream MCP backend, namespaces
tools aggregated from ``tools/list`` (``fs__read_file``, ``web__fetch``),
quarantines discovered tools that exceed a backend's declared capabilities,
and applies each backend's sandbox boundary to path-like arguments.
"""

from __future__ import annotations

import functools
import logging
import os
from dataclasses import dataclass
from typing import Any

from src.engine.arguments import find_argument_violation
from src.engine.classifier import classify_tool
from src.engine.egress import EgressPolicy
from src.engine.paths import canonical_path as _canonical
from src.models.policy import BackendConfig, PolicyConfig, ToolState, namespaced

logger = logging.getLogger("mcp-netproxy")

# DFA states whose responses carry ingested content worth scanning
# (NETWORK_EGRESS: an outbound request returns external content)
_SCANNED_STATES = {ToolState.LOCAL_READ, ToolState.UNTRUSTED_INGEST, ToolState.NETWORK_EGRESS}


class ToolResolutionError(Exception):
    """A tool name cannot be routed to exactly one backend."""

    def __init__(self, message: str, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.data = data or {}


@dataclass(frozen=True)
class ResolvedTool:
    """Routing decision for a single ``tools/call``.

    Attributes:
        requested: Name exactly as sent by the client.
        canonical: Name evaluated by the DFA (namespaced when backend-owned).
        upstream: Name forwarded to the backend.
        namespace: Target backend namespace, or None if unroutable.
    """

    requested: str
    canonical: str
    upstream: str
    namespace: str | None


class BackendRegistry:
    """Runtime view of ``PolicyConfig.backends`` with resolved endpoint URLs."""

    def __init__(self, policy: PolicyConfig, url_overrides: dict[str, str] | None = None) -> None:
        self._policy = policy
        overrides = url_overrides or {}
        self._urls: dict[str, str] = {}
        self._egress: dict[str, EgressPolicy | None] = {}
        self._schemas: dict[str, dict[str, Any]] = {}  # namespaced tool -> inputSchema
        for namespace, backend in policy.backends.items():
            env_url = os.getenv(backend.url_env) if backend.url_env else None
            self._urls[namespace] = overrides.get(namespace) or env_url or backend.url

    # -- lookup ----------------------------------------------------------

    @property
    def namespaces(self) -> list[str]:
        return list(self._policy.backends)

    @property
    def default_namespace(self) -> str | None:
        if self._policy.default_backend:
            return self._policy.default_backend
        return next(iter(self._policy.backends), None)

    def backend(self, namespace: str) -> BackendConfig:
        return self._policy.backends[namespace]

    def url(self, namespace: str) -> str:
        return self._urls[namespace]

    def resolve(self, tool_name: str) -> ResolvedTool:
        """Route *tool_name* to a backend.

        Namespaced names route directly.  Bare names route to the single
        backend serving them; a bare name served by several backends is
        rejected as ambiguous.  Names no backend serves fall back to the
        default backend under their bare (global) policy mapping.
        """
        split = self._policy.split_namespaced(tool_name)
        if split is not None:
            namespace, upstream = split
            return ResolvedTool(tool_name, tool_name, upstream, namespace)

        owners = self._policy.backends_serving(tool_name)
        if len(owners) > 1:
            raise ToolResolutionError(
                f"Ambiguous tool name '{tool_name}' is served by multiple backends; "
                f"call one of: {', '.join(namespaced(ns, tool_name) for ns in owners)}",
                data={"candidates": [namespaced(ns, tool_name) for ns in owners]},
            )
        if owners:
            return ResolvedTool(tool_name, namespaced(owners[0], tool_name), tool_name, owners[0])
        return ResolvedTool(tool_name, tool_name, tool_name, self.default_namespace)

    def resolve_state(self, tool_name: str) -> ToolState:
        """DFA state the policy currently assigns to *tool_name*."""
        return self._policy.resolve_state(tool_name)

    # -- discovery -------------------------------------------------------

    def register_discovered(self, namespace: str, tool: dict[str, Any]) -> dict[str, Any]:
        """Classify a tool advertised by *namespace* and return its namespaced schema.

        Explicit mappings are never overwritten.  A tool classified into a
        state outside the backend's ``capabilities`` is quarantined as
        UNKNOWN, so the DFA blocks it by default.
        """
        tool_name = tool["name"]
        key = namespaced(namespace, tool_name)
        schema = tool.get("inputSchema")
        if isinstance(schema, dict):
            self._schemas[key] = schema
        if key not in self._policy.tool_mappings:
            state = classify_tool(
                name=tool_name,
                description=tool.get("description", ""),
                input_schema=tool.get("inputSchema", {}),
                policy=None,
            )
            capabilities = self.backend(namespace).capabilities
            if capabilities is not None and state is not ToolState.UNKNOWN and state not in capabilities:
                logger.warning(
                    f"[DYNAMIC DISCOVERY] Quarantined '{key}': classified as {state.value}, "
                    f"outside backend '{namespace}' capabilities"
                )
                state = ToolState.UNKNOWN
            self._policy.register_backend_tool(namespace, tool_name, state)
            logger.info(f"[DYNAMIC DISCOVERY] Classified new tool '{key}' as {state.value}")
        return {**tool, "name": key}

    # -- enforcement helpers --------------------------------------------

    def find_argument_violation(self, resolved: ResolvedTool, arguments: Any) -> str | None:
        """Return why the call's arguments are malformed or oversized, if they are."""
        backend = self.backend(resolved.namespace) if resolved.namespace is not None else None
        return find_argument_violation(
            arguments,
            self._schemas.get(resolved.canonical),
            backend.path_arguments if backend else [],
            backend.url_arguments if backend and backend.egress is not None else [],
            self._policy.argument_limits,
        )

    def find_sandbox_violation(self, resolved: ResolvedTool, arguments: dict[str, Any]) -> str | None:
        """Return the first path argument outside the backend sandbox, if any."""
        if resolved.namespace is None:
            return None
        backend = self.backend(resolved.namespace)
        if not backend.sandbox_roots:
            return None
        for arg_name in backend.path_arguments:
            value = arguments.get(arg_name)
            candidates = value if isinstance(value, list) else [value]
            for candidate in candidates:
                if candidate is None or candidate == "":
                    continue
                if not _within_roots(str(candidate), backend.sandbox_roots):
                    return str(candidate)
        return None

    def egress_policy(self, namespace: str) -> EgressPolicy | None:
        """The backend's outbound URL policy, or None if it has none."""
        if namespace not in self._egress:
            config = self.backend(namespace).egress
            self._egress[namespace] = EgressPolicy(config) if config is not None else None
        return self._egress[namespace]

    async def find_egress_violation(self, resolved: ResolvedTool, arguments: dict[str, Any]) -> str | None:
        """Return why a URL argument may not be fetched, if any."""
        if resolved.namespace is None:
            return None
        policy = self.egress_policy(resolved.namespace)
        if policy is None:
            return None
        for arg_name in self.backend(resolved.namespace).url_arguments:
            if arg_name in arguments:
                verdict = await policy.check(arguments[arg_name])
                if not verdict.allowed:
                    return verdict.reason
        return None

    def should_scan(self, resolved: ResolvedTool, state: ToolState) -> bool:
        """Whether the response to this call goes through the (alert-only) ingest scanner."""
        if resolved.namespace is None:
            return False
        return self.backend(resolved.namespace).scan_responses and state in _SCANNED_STATES


def _within_roots(path: str, roots: list[str]) -> bool:
    """Canonicalize *path* and check it equals or sits under one of *roots*.

    Fails closed: a path that cannot be canonicalized is outside.
    """
    resolved = _canonical(path)
    if resolved is None:
        return False
    return any(
        resolved == root or resolved.startswith(f"{root}/")
        for root in (_canonical_root(r) for r in roots)
    )


@functools.lru_cache(maxsize=64)
def _canonical_root(root: str) -> str | None:
    """Sandbox roots are fixed for the proxy's lifetime; resolve each once."""
    return _canonical(root)
