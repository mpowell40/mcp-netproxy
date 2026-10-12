"""mcp-netproxy: Zero Trust Policy Enforcement Point for MCP tool calls.

Combines regex-based heuristic inspection with Behavioral State-Machine
Invariant Enforcement and Egress Response Scanning across multiple
downstream MCP backends (e.g., Filesystem MCP on :9000 and Fetch MCP on :9001).

Incoming JSON-RPC 2.0 ``tools/call`` requests are evaluated against the
DFA *before* any downstream forwarding occurs.  Additionally intercepts
``tools/list`` responses to multiplex tool schemas from all configured
backends and dynamically classify previously-unseen tools.
"""

from __future__ import annotations

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

from src.engine.classifier import classify_tool
from src.engine.ingest_scanner import scan_payload_for_untrusted_directives
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

# Static tool-to-backend category sets for multi-backend dispatch
_FETCH_BACKEND_TOOLS = {
    "fetch",
}

_FILESYSTEM_BACKEND_TOOLS = {
    "read_file",
    "read_text_file",
    "read_media_file",
    "read_multiple_files",
    "write_file",
    "edit_file",
    "create_directory",
    "list_directory",
    "list_directory_with_sizes",
    "directory_tree",
    "move_file",
    "search_files",
    "get_file_info",
    "list_allowed_directories",
}

# Read / content-ingestion tools whose responses are inspected by Layer 3
_READ_TOOLS = {
    "read_text_file",
    "read_media_file",
    "read_file",
    "read_multiple_files",
    "get_file_info",
    "fetch",
}


def create_app(
    policy_config: PolicyConfig | None = None,
    graph_manager: SessionGraphManager | None = None,
    downstream_url: str | None = None,
    fetch_downstream_url: str | None = None,
) -> FastAPI:
    """Factory function for the FastAPI application.

    Accepts optional pre-built policy/engine instances for testability.
    Coordinates multiplexing and routing between the Filesystem MCP backend
    (:9000) and the Fetch MCP backend (:9001).
    """
    app = FastAPI(title="MCP Enforcement Proxy (Multi-Backend Behavioral DFA)")

    # Resolve configuration
    policy_path = os.getenv("POLICY_PATH", str(_DEFAULT_POLICY))
    _policy = policy_config or PolicyConfig.from_yaml(policy_path)
    _engine = graph_manager or SessionGraphManager(_policy)

    _fs_downstream = downstream_url or os.getenv(
        "MCP_FILESYSTEM_URL",
        os.getenv(
            "MCP_BACKEND_URL",
            os.getenv("DOWNSTREAM_URL", "http://unprotected:9000/mcp"),
        ),
    )
    _fetch_downstream = fetch_downstream_url or os.getenv(
        "MCP_FETCH_URL",
        "http://fetch-backend:9001/mcp",
    )

    # Dynamic routing table populated with defaults and updated on tools/list
    _tool_routes: dict[str, str] = {}
    for t_name in _FILESYSTEM_BACKEND_TOOLS:
        _tool_routes[t_name] = _fs_downstream
    for t_name in _FETCH_BACKEND_TOOLS:
        _tool_routes[t_name] = _fetch_downstream

    def _resolve_backend_url(tool_name: str) -> str:
        """Select the target backend URL for a given MCP tool call."""
        if tool_name in _FETCH_BACKEND_TOOLS:
            return _fetch_downstream
        if tool_name in _tool_routes:
            return _tool_routes[tool_name]
        return _fs_downstream

    # Store on app.state for access in tests / introspection
    app.state.policy = _policy
    app.state.engine = _engine
    app.state.filesystem_url = _fs_downstream
    app.state.fetch_url = _fetch_downstream
    app.state.tool_routes = _tool_routes

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
            return await _handle_tools_list(
                payload,
                [_fs_downstream, _fetch_downstream],
                _policy,
                _tool_routes,
            )

        # -- Non-tool-call requests pass through to primary backend -------
        if method != "tools/call":
            return await _forward(payload, _fs_downstream)

        # -- Extract session & tool context ------------------------------
        session_id = request.headers.get(
            "X-Session-ID", request.client.host if request.client else "unknown"
        )
        tool_name: str = params.get("name", "")
        arguments: dict = params.get("arguments", {})
        arg_string = " ".join(str(v) for v in arguments.values())

        # -- Layer 1: Heuristic & Scope Boundary inspection -------------
        is_traversal = bool(re.search(TRAVERSAL_PATTERN, arg_string))
        is_shell = bool(re.search(SHELL_INJECTION, arg_string))
        is_aws_key = bool(re.search(AWS_KEY_PATTERN, arg_string))

        # Scope boundary check: ensure filesystem tools remain inside /sandbox
        path_arg = str(arguments.get("path", ""))
        is_out_of_sandbox = False
        if path_arg and tool_name in (
            "read_text_file", "read_media_file", "write_file", "edit_file",
            "read_file", "list_directory", "list_allowed_directories", "get_file_info",
        ):
            normalized = os.path.normpath(path_arg).replace("\\", "/")
            allowed_prefixes = (
                "/mcp-proxy-testbed/sandbox",
                "/sandbox",
            )
            # Must either equal the sandbox root or reside inside it
            if not any(normalized == p or normalized.startswith(f"{p}/") for p in allowed_prefixes):
                is_out_of_sandbox = True

        if is_traversal or is_shell or is_aws_key or is_out_of_sandbox:
            reason = (
                "Malicious pattern detected"
                if (is_traversal or is_shell or is_aws_key)
                else "Path outside sandbox boundary"
            )
            logger.warning(
                f"[SECURITY BLOCKED - HEURISTIC] Intercepted '{tool_name}' ({reason}) with args {arguments} from session '{session_id}'"
            )
            return _jsonrpc_error(
                request_id,
                -32602,
                f"Policy Violation: {reason} blocked by proxy",
                status=200,
            )

        # -- Layer 2: Behavioral DFA enforcement -------------------------
        allowed, reason, meta = _engine.evaluate_transition(session_id, tool_name, arguments)

        if not allowed:
            logger.warning(
                f"[SECURITY BLOCKED - DFA INVARIANT] Session '{session_id}' denied transition: "
                f"tool='{tool_name}', state='{meta['from_state']}' -> '{meta['to_state']}', reason='{reason}'"
            )
            return _jsonrpc_error(
                request_id,
                -32001,
                "Security Invariant Violation",
                data={
                    "current_state": meta["from_state"],
                    "attempted_tool": tool_name,
                    "target_state": meta["to_state"],
                    "reason": reason,
                },
                status=200,
            )

        # -- Dispatch to target downstream MCP server (:9000 or :9001) ----
        target_backend = _resolve_backend_url(tool_name)
        logger.info(
            f"[MULTI-BACKEND DISPATCH] Routing tool='{tool_name}' for session='{session_id}' -> {target_backend}"
        )
        response = await _forward(payload, target_backend)

        # -- Layer 3: Dynamic Ingest Scanner (response inspection) --------
        # For read and fetch tools that returned content, scan the response
        # payload for imperative prompt-injection directives.
        if tool_name in _READ_TOOLS:
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
                            f"with UNTRUSTED_INGEST from tool '{tool_name}'. Reason: {scan_result.reason}"
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


async def _handle_tools_list(
    payload: dict,
    downstream_urls: list[str],
    policy: PolicyConfig,
    tool_routes: dict[str, str] | None = None,
) -> Response:
    """Multiplex ``tools/list`` across all configured backends and auto-classify.

    Queries each backend in ``downstream_urls``, merges their ``result.tools``
    arrays into a unified schema response (deduplicated by tool name),
    records the backend route for each tool, and runs any previously-unseen
    tools through the heuristic classifier.
    """
    merged_tools: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    any_success = False
    last_error: Exception | None = None
    raw_fallback_response: httpx.Response | None = None

    async with httpx.AsyncClient() as client:
        for backend_url in downstream_urls:
            try:
                res = await client.post(backend_url, json=payload, timeout=5.0)
                any_success = True
                raw_fallback_response = res
            except Exception as exc:
                last_error = exc
                continue

            try:
                body = res.json()
            except Exception:
                continue

            tools = body.get("result", {}).get("tools", [])
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                tool_name = tool.get("name", "")
                if not tool_name:
                    continue

                if tool_routes is not None and tool_name not in _FETCH_BACKEND_TOOLS:
                    tool_routes.setdefault(tool_name, backend_url)
                elif tool_routes is not None and tool_name in _FETCH_BACKEND_TOOLS:
                    tool_routes[tool_name] = backend_url

                if tool_name not in seen_names:
                    seen_names.add(tool_name)
                    merged_tools.append(tool)

                if tool_name not in policy.tool_mappings:
                    inferred_state = classify_tool(
                        name=tool_name,
                        description=tool.get("description", ""),
                        input_schema=tool.get("inputSchema", {}),
                        policy=None,
                    )
                    policy.tool_mappings[tool_name] = inferred_state
                    print(
                        f"[DYNAMIC DISCOVERY] Classified new tool "
                        f"'{tool_name}' as {inferred_state.value}"
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