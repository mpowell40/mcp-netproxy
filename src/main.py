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
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import pathlib
import re
import sys
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response

from src.engine.ingest_scanner import scan_payload_for_untrusted_directives
from src.engine.registry import BackendRegistry, ToolResolutionError
from src.engine.state_machine import SessionGraphManager
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

# Heuristic inspection patterns (Layer 1)
TRAVERSAL_PATTERN = r"(\.\./|\.\.\\|/etc/|~/\.ssh|~/\.env)"
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
) -> FastAPI:
    """Factory function for the FastAPI application.

    Accepts optional pre-built policy/engine instances for testability.
    Backend endpoints come from the policy's ``backends:`` registry;
    ``backend_urls`` overrides them per namespace.  ``downstream_url`` and
    ``fetch_downstream_url`` are kept as shorthands for overriding the
    default backend and the ``web`` backend respectively.
    """
    app = FastAPI(title="MCP Enforcement Proxy (Multi-Backend Behavioral DFA)")

    # Resolve configuration
    policy_path = os.getenv("POLICY_PATH", str(_DEFAULT_POLICY))
    _policy = policy_config or PolicyConfig.from_yaml(policy_path)
    _engine = graph_manager or SessionGraphManager(_policy)

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
        params = payload.get("params", {})

        # -- tools/list: multiplex across backends & auto-classify ---------
        if method == "tools/list":
            return await _handle_tools_list(payload, _registry)

        # -- Non-tool-call requests pass through to the default backend ----
        if method != "tools/call":
            default_ns = _registry.default_namespace
            if default_ns is None:
                return _jsonrpc_error(request_id, -32601, "No backend registered", status=200)
            return await _forward(payload, _registry.url(default_ns))

        # -- Extract session & tool context ------------------------------
        session_id = request.headers.get(
            "X-Session-ID", request.client.host if request.client else "unknown"
        )
        tool_name: str = params.get("name", "")
        arguments: dict = params.get("arguments", {})
        arg_string = " ".join(str(v) for v in arguments.values())

        # -- Resolve namespaced / bare tool name to a backend --------------
        try:
            resolved = _registry.resolve(tool_name)
        except ToolResolutionError as exc:
            logger.warning(
                f"[SECURITY BLOCKED - ROUTING] Session '{session_id}' called ambiguous tool '{tool_name}'"
            )
            return _jsonrpc_error(request_id, -32602, str(exc), data=exc.data, status=200)

        # -- Layer 1: Heuristic & Scope Boundary inspection -------------
        is_traversal = bool(re.search(TRAVERSAL_PATTERN, arg_string))
        is_shell = bool(re.search(SHELL_INJECTION, arg_string))
        is_aws_key = bool(re.search(AWS_KEY_PATTERN, arg_string))

        # Scope boundary check: path arguments must stay inside the backend sandbox
        is_out_of_sandbox = _registry.find_sandbox_violation(resolved, arguments) is not None

        if is_traversal or is_shell or is_aws_key or is_out_of_sandbox:
            reason = (
                "Malicious pattern detected"
                if (is_traversal or is_shell or is_aws_key)
                else "Path outside sandbox boundary"
            )
            logger.warning(
                f"[SECURITY BLOCKED - HEURISTIC] Intercepted '{resolved.canonical}' ({reason}) with args {arguments} from session '{session_id}'"
            )
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
            return _jsonrpc_error(
                request_id, -32601, f"No backend serves tool '{tool_name}'", status=200
            )
        target_backend = _registry.url(resolved.namespace)
        logger.info(
            f"[MULTI-BACKEND DISPATCH] Routing tool='{resolved.canonical}' for session='{session_id}' "
            f"-> {resolved.namespace} ({target_backend})"
        )
        upstream_payload = {**payload, "params": {**params, "name": resolved.upstream}}
        response = await _forward(upstream_payload, target_backend)

        # -- Layer 3: Dynamic Ingest Scanner (response inspection) --------
        # For content-returning tools on backends with scan_responses enabled,
        # scan the response payload for imperative prompt-injection directives.
        if _registry.should_scan(resolved, ToolState(meta["to_state"])):
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
                        _engine.taint_session(session_id, ToolState.UNTRUSTED_INGEST)
                        logger.warning(
                            f"[DYNAMIC INGEST SCANNER] Session '{session_id}' tainted "
                            f"with UNTRUSTED_INGEST from tool '{resolved.canonical}'. Reason: {scan_result.reason}"
                        )
            except Exception:
                pass  # Non-parseable response — leave session state as-is

        return response

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


async def _handle_tools_list(payload: dict, registry: BackendRegistry) -> Response:
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
