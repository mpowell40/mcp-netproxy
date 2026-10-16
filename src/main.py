"""mcp-netproxy: Zero Trust Policy Enforcement Point for MCP tool calls.

Combines regex-based heuristic inspection with Behavioral State-Machine
Invariant Enforcement and Egress Response Scanning across multiple
downstream MCP backends declared in the ``backends:`` registry of
``config/policy.yaml`` (e.g., Filesystem MCP as ``fs``, Fetch MCP as ``web``).

Incoming JSON-RPC 2.0 ``tools/call`` requests are evaluated against the
DFA *before* any downstream forwarding occurs.  Additionally intercepts
``tools/list`` to multiplex tool schemas from every registered backend,
namespacing each tool (``fs__read_file``) and dynamically classifying
previously-unseen tools.

Every frame emits structured ``ProxyEvent`` telemetry at the
BEFORE/AFTER_TOOL_LIST and BEFORE/AFTER_TOOL_CALL checkpoints.  Calls
within one session are serialized end-to-end (DFA check -> forward ->
response scan) so a call cannot slip past a taint that an in-flight
response is about to latch.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import pathlib
import re
import sys
import weakref
from typing import Any, Callable

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response

from src.engine.egress import EgressGuard
from src.engine.events import Checkpoint, Decision, EventCollector, ProxyEvent
from src.engine.ingest_scanner import scan_payload_for_untrusted_directives
from src.engine.registry import BackendRegistry, ToolResolutionError
from src.engine.state_machine import DEFAULT_SESSION_TTL, SessionGraphManager, describe_source
from src.models.policy import PolicyConfig, ToolState

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logger = logging.getLogger("mcp-netproxy")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s - [%(name)s] - %(levelname)s - %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Default paths / env
# ---------------------------------------------------------------------------
_DEFAULT_POLICY = pathlib.Path(__file__).resolve().parent.parent / "config" / "policy.yaml"

# Heuristic inspection patterns (Layer 1).  Path traversal is decided by the
# canonicalizing sandbox check, not by matching "../" in the raw arguments.
SENSITIVE_PATH_PATTERN = r"(/etc/|~/\.ssh|~/\.env)"
SHELL_INJECTION = r"(;|\||\&\&|\bcurl\b|\bbash\b)"
AWS_KEY_PATTERN = r"(AKIA[0-9A-Z]{16})"

# Namespace that ``fetch_downstream_url`` overrides (legacy create_app kwarg)
_FETCH_NAMESPACE = "web"


def create_app(
    policy_config: PolicyConfig | None = None,
    graph_manager: SessionGraphManager | None = None,
    downstream_url: str | None = None,
    fetch_downstream_url: str | None = None,
    backend_urls: dict[str, str] | None = None,
    event_collector: EventCollector | None = None,
) -> FastAPI:
    """Factory function for the FastAPI application.

    Accepts optional pre-built policy/engine instances for testability.
    Backend endpoints come from the policy's ``backends:`` registry;
    ``backend_urls`` overrides them per namespace.  ``downstream_url`` and
    ``fetch_downstream_url`` are kept as shorthands for overriding the
    default backend and the ``web`` backend respectively.
    """
    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        # Egress guard: forward proxy that the fetch backend sends every
        # request through (--proxy-url), so redirects are re-validated too.
        guard_port = os.getenv("EGRESS_GUARD_PORT")
        guard_ns = os.getenv("EGRESS_GUARD_BACKEND", _FETCH_NAMESPACE)
        server = None
        if guard_port and guard_ns in _policy.backends:
            egress = _registry.egress_policy(guard_ns)
            if egress is None:
                raise RuntimeError(f"EGRESS_GUARD_PORT set but backend '{guard_ns}' has no egress policy")
            server = await EgressGuard(egress).start("0.0.0.0", int(guard_port))
            logger.info(f"[EGRESS GUARD] Enforcing '{guard_ns}' egress policy on port {guard_port}")
        try:
            yield
        finally:
            if server is not None:
                server.close()
                await server.wait_closed()

    app = FastAPI(title="MCP Enforcement Proxy (Multi-Backend Behavioral DFA)", lifespan=lifespan)

    # Resolve configuration
    policy_path = os.getenv("POLICY_PATH", str(_DEFAULT_POLICY))
    _policy = policy_config or PolicyConfig.from_yaml(policy_path)
    _engine = graph_manager or SessionGraphManager(
        _policy,
        session_ttl=float(os.getenv("SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL)),
    )
    _events = event_collector or EventCollector()

    url_overrides = dict(backend_urls or {})
    if downstream_url and _policy.default_backend:
        url_overrides.setdefault(_policy.default_backend, downstream_url)
    if fetch_downstream_url and _FETCH_NAMESPACE in _policy.backends:
        url_overrides.setdefault(_FETCH_NAMESPACE, fetch_downstream_url)
    _registry = BackendRegistry(_policy, url_overrides)

    # Store on app.state for access in tests / introspection
    app.state.policy = _policy
    app.state.engine = _engine
    app.state.registry = _registry
    app.state.events = _events

    # One asyncio.Lock per in-flight session; entries vanish once unused.
    _session_gates: weakref.WeakValueDictionary[str, asyncio.Lock] = weakref.WeakValueDictionary()

    def _session_gate(session_id: str) -> asyncio.Lock:
        gate = _session_gates.get(session_id)
        if gate is None:
            gate = asyncio.Lock()
            _session_gates[session_id] = gate
        return gate

    def _emit(
        checkpoint: Checkpoint,
        session_id: str,
        tool_name: str | None,
        decision: Decision,
        request_id: Any,
        current_state: str | None = None,
        **details: Any,
    ) -> None:
        _events.emit(
            ProxyEvent(
                session_id=session_id,
                event_type=checkpoint,
                tool_name=tool_name,
                current_state=current_state or _engine.peek_state(session_id).value,
                decision=decision,
                request_id=request_id,
                details=details,
            )
        )

    # -----------------------------------------------------------------------
    # POST /mcp  –  main enforcement endpoint
    # -----------------------------------------------------------------------
    @app.post("/mcp")
    async def enforce_mcp(request: Request) -> Response:
        """Intercept, evaluate, and conditionally forward MCP tool calls."""

        # -- Parse JSON-RPC payload -----------------------------------
        try:
            payload: dict[str, Any] = await request.json()
        except Exception:
            return _jsonrpc_error(None, -32700, "Parse error: Invalid JSON payload", status=400)

        request_id = payload.get("id")
        method = payload.get("method", "")
        session_id = _session_id(request)

        # -- tools/list: multiplex across backends & auto-classify ---------
        if method == "tools/list":
            _emit(Checkpoint.BEFORE_TOOL_LIST, session_id, None, Decision.ALLOW, request_id)
            return await _handle_tools_list(payload, _registry, session_id, _emit)

        # -- Non-tool-call requests pass through to the default backend ----
        if method != "tools/call":
            default_ns = _registry.default_namespace
            if default_ns is None:
                return _jsonrpc_error(request_id, -32601, "No backend registered", status=200)
            return await _forward(payload, _registry.url(default_ns))

        # -- Serialize this session's calls across check -> forward -> scan --
        # Without this, a second call evaluated while a scanned response is
        # still in flight would miss the taint that response is about to latch.
        async with _session_gate(session_id):
            return await _handle_tool_call(payload, session_id)

    async def _handle_tool_call(payload: dict[str, Any], session_id: str) -> Response:
        """Run one ``tools/call`` through the BEFORE/AFTER_TOOL_CALL checkpoints."""
        request_id = payload.get("id")
        params = payload.get("params", {})
        tool_name: str = params.get("name", "")
        arguments: Any = params.get("arguments", {})

        def block(layer: str, reason: str, tool: str = tool_name, **details: Any) -> None:
            _emit(
                Checkpoint.BEFORE_TOOL_CALL, session_id, tool, Decision.BLOCK, request_id,
                layer=layer, reason=reason, **details,
            )

        # -- Resolve namespaced / bare tool name to a backend --------------
        try:
            resolved = _registry.resolve(tool_name)
        except ToolResolutionError as exc:
            logger.warning(
                f"[SECURITY BLOCKED - ROUTING] Session '{session_id}' called ambiguous tool '{tool_name}'"
            )
            block("routing", str(exc))
            return _jsonrpc_error(request_id, -32602, str(exc), data=exc.data, status=200)

        # -- Layer 1: Argument validation (types and size limits) -----------
        argument_violation = _registry.find_argument_violation(resolved, arguments)
        if argument_violation is not None:
            logger.warning(
                f"[SECURITY BLOCKED - INPUT] Intercepted '{resolved.canonical}' ({argument_violation}) from session '{session_id}'"
            )
            block("heuristic", f"Invalid arguments: {argument_violation}", resolved.canonical)
            return _jsonrpc_error(
                request_id,
                -32602,
                f"Policy Violation: Invalid arguments: {argument_violation} blocked by proxy",
                status=200,
            )
        arg_string = " ".join(str(v) for v in arguments.values())

        # -- Layer 1: Heuristic & Scope Boundary inspection -------------
        is_sensitive_path = bool(re.search(SENSITIVE_PATH_PATTERN, arg_string))
        is_shell = bool(re.search(SHELL_INJECTION, arg_string))
        is_aws_key = bool(re.search(AWS_KEY_PATTERN, arg_string))

        # Scope boundary check: path arguments must stay inside the backend sandbox
        is_out_of_sandbox = _registry.find_sandbox_violation(resolved, arguments) is not None

        # Egress check: URL arguments must satisfy the backend's URL policy
        egress_violation = await _registry.find_egress_violation(resolved, arguments)
        if egress_violation is not None:
            logger.warning(
                f"[SECURITY BLOCKED - EGRESS] Intercepted '{resolved.canonical}' ({egress_violation}) from session '{session_id}'"
            )
            block("heuristic", f"Egress policy: {egress_violation}", resolved.canonical)
            return _jsonrpc_error(
                request_id,
                -32602,
                f"Policy Violation: Egress policy: {egress_violation} blocked by proxy",
                status=200,
            )

        if is_sensitive_path or is_shell or is_aws_key or is_out_of_sandbox:
            reason = (
                "Malicious pattern detected"
                if (is_sensitive_path or is_shell or is_aws_key)
                else "Path outside sandbox boundary"
            )
            logger.warning(
                f"[SECURITY BLOCKED - HEURISTIC] Intercepted '{resolved.canonical}' ({reason}) with args {arguments} from session '{session_id}'"
            )
            block("heuristic", reason, resolved.canonical)
            return _jsonrpc_error(
                request_id,
                -32602,
                f"Policy Violation: {reason} blocked by proxy",
                status=200,
            )

        # -- Layer 2: Behavioral DFA enforcement -------------------------
        allowed, reason, meta = _engine.evaluate_transition(session_id, resolved.canonical, arguments)

        if not allowed:
            logger.warning(
                f"[SECURITY BLOCKED - DFA INVARIANT] Session '{session_id}' denied transition: "
                f"tool='{resolved.canonical}', state='{meta['from_state']}' -> '{meta['to_state']}', reason='{reason}'"
            )
            block(
                "dfa", reason, resolved.canonical,
                current_state=meta["from_state"], target_state=meta["to_state"], status=meta["status"],
            )
            return _jsonrpc_error(
                request_id,
                -32001,
                "Security Invariant Violation",
                data={
                    "current_state": meta["from_state"],
                    "attempted_tool": resolved.canonical,
                    "target_state": meta["to_state"],
                    "reason": reason,
                },
                status=200,
            )

        # -- Dispatch to the owning backend under its upstream tool name ---
        if resolved.namespace is None:
            block("routing", f"No backend serves tool '{tool_name}'", resolved.canonical)
            return _jsonrpc_error(
                request_id, -32601, f"No backend serves tool '{tool_name}'", status=200
            )
        target_backend = _registry.url(resolved.namespace)
        _emit(
            Checkpoint.BEFORE_TOOL_CALL,
            session_id,
            resolved.canonical,
            Decision.MUTATE if resolved.upstream != tool_name else Decision.ALLOW,
            request_id,
            current_state=meta["from_state"],
            target_state=meta["to_state"],
            backend=resolved.namespace,
            upstream_tool=resolved.upstream,
        )
        logger.info(
            f"[MULTI-BACKEND DISPATCH] Routing tool='{resolved.canonical}' for session='{session_id}' "
            f"-> {resolved.namespace} ({target_backend})"
        )
        upstream_payload = {**payload, "params": {**params, "name": resolved.upstream}}
        response = await _forward(upstream_payload, target_backend)

        # -- Layer 3: Dynamic Ingest Scanner (response inspection) --------
        # For content-returning tools on backends with scan_responses enabled,
        # scan the response payload for imperative prompt-injection directives.
        after: dict[str, Any] = {"scanned": False, "tainted": False, "status_code": response.status_code}
        if _registry.should_scan(resolved, ToolState(meta["to_state"])):
            after["scanned"] = True
            try:
                resp_body = json.loads(response.body)
                # Extract text from MCP result.content[].text
                result = resp_body.get("result", {})
                content_blocks = result.get("content", [])
                extracted_texts = [
                    block.get("text", "")
                    for block in content_blocks
                    if isinstance(block, dict) and block.get("type") == "text"
                ]
                full_text = "\n".join(extracted_texts)

                if full_text.strip():
                    scan_result = scan_payload_for_untrusted_directives(full_text)
                    if scan_result.is_untrusted:
                        # Retroactively taint the session with sticky latch
                        taint_source = describe_source(resolved.canonical, arguments)
                        _engine.taint_session(
                            session_id,
                            ToolState.UNTRUSTED_INGEST,
                            taint_source=taint_source,
                            trigger_pattern=scan_result.pattern_id,
                            reason=scan_result.reason,
                        )
                        after.update(
                            tainted=True,
                            taint_source=taint_source,
                            trigger_pattern=scan_result.pattern_id,
                            reason=scan_result.reason,
                        )
                        logger.warning(
                            f"[DYNAMIC INGEST SCANNER] Session '{session_id}' tainted "
                            f"with UNTRUSTED_INGEST from tool '{resolved.canonical}'. Reason: {scan_result.reason}"
                        )
            except Exception as exc:
                # Non-parseable response — leave session state as-is
                after["scan_error"] = type(exc).__name__

        _emit(Checkpoint.AFTER_TOOL_CALL, session_id, resolved.canonical, Decision.ALLOW, request_id, **after)
        return response

    # -----------------------------------------------------------------------
    # GET /session/{session_id}  –  session context (trajectory & taint vector)
    # -----------------------------------------------------------------------
    @app.get("/session/{session_id}")
    async def session_context(session_id: str) -> Response:
        """Return the session's state history and taint attribution."""
        context = _engine.get_session_context(session_id)
        if context is None:
            return Response(
                content=json.dumps({"error": f"Unknown or expired session '{session_id}'"}),
                status_code=404,
                media_type="application/json",
            )
        return Response(content=json.dumps(context), media_type="application/json")

    # -----------------------------------------------------------------------
    # GET /session/{session_id}/events  –  checkpoint telemetry
    # -----------------------------------------------------------------------
    @app.get("/session/{session_id}/events")
    async def session_events(session_id: str) -> dict:
        """Return the checkpoint events recorded for a session."""
        return {
            "session_id": session_id,
            "events": [e.to_dict() for e in _events.events(session_id)],
        }

    # -----------------------------------------------------------------------
    # GET /session/{session_id}/graph  –  Mermaid diagram export
    # -----------------------------------------------------------------------
    @app.get("/session/{session_id}/graph")
    async def session_graph(session_id: str) -> dict:
        """Return the Mermaid state-diagram for a session."""
        diagram = _engine.export_mermaid_graph(session_id)
        return {"session_id": session_id, "mermaid": diagram}

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _session_id(request: Request) -> str:
    """Session key: X-Session-ID, else the client host.

    The host (not host:port) is deliberate: keying on the ephemeral port
    would let a client shed its taint latch simply by reconnecting.
    """
    return request.headers.get(
        "X-Session-ID", request.client.host if request.client else "unknown"
    )


def _jsonrpc_error(
    request_id: Any,
    code: int,
    message: str,
    data: dict | None = None,
    status: int = 200,
) -> Response:
    """Build a compliant JSON-RPC 2.0 error response."""
    body: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
    if data is not None:
        body["error"]["data"] = data
    return Response(
        content=json.dumps(body),
        status_code=status,
        media_type="application/json",
    )


async def _forward(payload: dict, downstream_url: str) -> Response:
    """Forward a JSON-RPC payload to the specified downstream MCP server."""
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post(downstream_url, json=payload, timeout=10.0)
            return Response(
                content=res.content,
                status_code=res.status_code,
                media_type="application/json",
            )
        except Exception as exc:
            return _jsonrpc_error(
                payload.get("id"),
                -32000,
                f"Downstream connection error: {exc}",
                status=502,
            )


async def _handle_tools_list(
    payload: dict,
    registry: BackendRegistry,
    session_id: str,
    emit: Callable[..., None],
) -> Response:
    """Multiplex ``tools/list`` across all registered backends and auto-classify.

    Queries every backend concurrently, namespaces each advertised tool as
    ``<namespace>__<tool>`` so identical upstream names never collide, and
    runs previously-unseen tools through the heuristic classifier.  Tools
    are returned in registry order (backend declaration order, then the
    order each backend advertised them).
    """
    namespaces = registry.namespaces
    merged_tools: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    any_success = False
    last_error: Exception | None = None
    raw_fallback_response: httpx.Response | None = None

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            *(client.post(registry.url(ns), json=payload, timeout=5.0) for ns in namespaces),
            return_exceptions=True,
        )

    for namespace, res in zip(namespaces, results):
        if isinstance(res, BaseException):
            last_error = res
            continue
        any_success = True
        raw_fallback_response = res

        try:
            body = res.json()
        except Exception:
            continue

        tools = body.get("result", {}).get("tools", [])
        for tool in tools:
            if not isinstance(tool, dict) or not tool.get("name"):
                continue
            namespaced_tool = registry.register_discovered(namespace, tool)
            if namespaced_tool["name"] not in seen_names:
                seen_names.add(namespaced_tool["name"])
                merged_tools.append(namespaced_tool)
                # Quarantined tools stay listed, but every call to them is blocked
                state = registry.resolve_state(namespaced_tool["name"])
                quarantined = state is ToolState.UNKNOWN
                emit(
                    Checkpoint.AFTER_TOOL_LIST,
                    session_id,
                    namespaced_tool["name"],
                    Decision.BLOCK if quarantined else Decision.MUTATE,
                    payload.get("id"),
                    backend=namespace,
                    upstream_tool=tool["name"],
                    classified_state=state.value,
                    quarantined=quarantined,
                    description=str(tool.get("description", ""))[:200],
                )

    if not any_success:
        return _jsonrpc_error(
            payload.get("id"),
            -32000,
            f"Downstream connection error: {last_error}",
            status=502,
        )

    if not merged_tools and raw_fallback_response is not None:
        return Response(
            content=raw_fallback_response.content,
            status_code=raw_fallback_response.status_code,
            media_type="application/json",
        )

    unified_body = {
        "jsonrpc": "2.0",
        "id": payload.get("id"),
        "result": {"tools": merged_tools},
    }
    return Response(
        content=json.dumps(unified_body),
        status_code=200,
        media_type="application/json",
    )


# ---------------------------------------------------------------------------
# Production entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)
