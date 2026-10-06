"""mcp-netproxy: Zero Trust Policy Enforcement Point for MCP tool calls.

Combines regex-based heuristic inspection with Behavioral State-Machine
Invariant Enforcement.  Incoming JSON-RPC 2.0 ``tools/call`` requests are
evaluated against the DFA *before* any downstream forwarding occurs.

Additionally intercepts ``tools/list`` responses to dynamically classify
previously-unseen tools using the heuristic classifier engine.
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
from src.engine.state_machine import SessionGraphManager
from src.models.policy import PolicyConfig

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

# Heuristic inspection patterns (kept from original proxy/main.py)
TRAVERSAL_PATTERN = r"(\.\./|\.\.\\|/etc/|~/\.ssh|~/\.env)"
SHELL_INJECTION = r"(;|\||\&\&|\bcurl\b|\bbash\b)"
AWS_KEY_PATTERN = r"(AKIA[0-9A-Z]{16})"


def create_app(
    policy_config: PolicyConfig | None = None,
    graph_manager: SessionGraphManager | None = None,
    downstream_url: str | None = None,
) -> FastAPI:
    """Factory function for the FastAPI application.

    Accepts optional pre-built policy/engine instances for testability.
    Falls back to loading from environment / default paths when called
    in production mode.
    """
    app = FastAPI(title="MCP Enforcement Proxy (Behavioral DFA)")

    # Resolve configuration
    policy_path = os.getenv("POLICY_PATH", str(_DEFAULT_POLICY))
    _policy = policy_config or PolicyConfig.from_yaml(policy_path)
    _engine = graph_manager or SessionGraphManager(_policy)
    _downstream = downstream_url or os.getenv(
        "MCP_BACKEND_URL",
        os.getenv("DOWNSTREAM_URL", "http://mock-mcp:9000/mcp"),
    )

    # Store on app.state for access in tests / introspection
    app.state.policy = _policy
    app.state.engine = _engine

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

        # -- tools/list: forward then auto-classify discovered tools ------
        if method == "tools/list":
            return await _handle_tools_list(payload, _downstream, _policy)

        # -- Non-tool-call requests pass through directly ----------------
        if method != "tools/call":
            return await _forward(payload, _downstream)

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
        allowed, reason, meta = _engine.evaluate_transition(session_id, tool_name)

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

        # -- Forward to downstream MCP server ----------------------------
        return await _forward(payload, _downstream)

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
    """Forward a JSON-RPC payload to the downstream MCP server."""
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post(downstream_url, json=payload, timeout=5.0)
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
    payload: dict, downstream_url: str, policy: PolicyConfig
) -> Response:
    """Forward ``tools/list``, intercept the response, and auto-classify.

    Any tool in the downstream response whose name is not already in
    ``policy.tool_mappings`` is run through the heuristic classifier and
    registered dynamically so subsequent ``tools/call`` evaluations see it.
    """
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post(downstream_url, json=payload, timeout=5.0)
        except Exception as exc:
            return _jsonrpc_error(
                payload.get("id"),
                -32000,
                f"Downstream connection error: {exc}",
                status=502,
            )

    # Parse downstream response to inspect discovered tools
    try:
        body = res.json()
    except Exception:
        # Can't parse — pass the raw response through unchanged
        return Response(
            content=res.content,
            status_code=res.status_code,
            media_type="application/json",
        )

    tools = body.get("result", {}).get("tools", [])
    for tool in tools:
        tool_name = tool.get("name", "")
        if not tool_name:
            continue
        if tool_name in policy.tool_mappings:
            continue  # Already configured — skip

        # Dynamically classify
        inferred_state = classify_tool(
            name=tool_name,
            description=tool.get("description", ""),
            input_schema=tool.get("inputSchema", {}),
            policy=None,  # Skip policy lookup — we already know it's missing
        )
        policy.tool_mappings[tool_name] = inferred_state
        print(
            f"[DYNAMIC DISCOVERY] Classified new tool "
            f"'{tool_name}' as {inferred_state.value}"
        )

    # Return the original downstream response unmodified
    return Response(
        content=res.content,
        status_code=res.status_code,
        media_type="application/json",
    )


# ---------------------------------------------------------------------------
# Production entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)