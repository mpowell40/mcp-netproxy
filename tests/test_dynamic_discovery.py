"""Test suite for Dynamic Tool Discovery & Classification.

Validates:
1. The heuristic classifier correctly categorizes arbitrary tool names,
   descriptions, and schemas into the right ToolState categories.
2. The proxy intercepts ``tools/list`` responses and auto-registers
   dynamically discovered tools in the policy config.
3. Dynamically classified tools are subject to the same DFA invariants
   (e.g., an auto-classified EXECUTE tool is still blocked after
   UNTRUSTED_INGEST).
"""

from __future__ import annotations

import json
import pathlib
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from src.engine.classifier import classify_tool
from src.models.policy import PolicyConfig, ToolState

# ---------------------------------------------------------------------------
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_POLICY_PATH = _PROJECT_ROOT / "config" / "policy.yaml"


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def policy():
    return PolicyConfig.from_yaml(_POLICY_PATH)


@pytest.fixture
def engine(policy):
    from src.engine.state_machine import SessionGraphManager
    return SessionGraphManager(policy)


@pytest.fixture
def app_client(policy, engine):
    from src.main import create_app
    from fastapi.testclient import TestClient

    app = create_app(policy_config=policy, graph_manager=engine)
    return TestClient(app)


# ===========================================================================
# Helpers
# ===========================================================================

def _jsonrpc(method: str, params: dict | None = None, req_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "method": method, "params": params or {}, "id": req_id}


def _tool_call(name: str, args: dict | None = None, req_id: int = 1) -> dict:
    return _jsonrpc("tools/call", {"name": name, "arguments": args or {}}, req_id)


def _mock_tools_list_response(tools: list[dict[str, Any]]) -> httpx.Response:
    """Build a fake downstream ``tools/list`` response."""
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"tools": tools},
    }
    return httpx.Response(200, json=body)


# ===========================================================================
# 1. Classifier Unit Tests
# ===========================================================================

class TestClassifyTool:
    """Test the standalone classify_tool heuristic function."""

    # -- EXECUTE ----------------------------------------------------------

    def test_execute_by_name_bash(self):
        assert classify_tool("run_bash") == ToolState.EXECUTE

    def test_execute_by_name_subshell(self):
        assert classify_tool("run_subshell") == ToolState.EXECUTE

    def test_execute_by_name_exec(self):
        assert classify_tool("exec_code") == ToolState.EXECUTE

    def test_execute_by_description(self):
        assert classify_tool(
            "my_tool", description="Execute a shell command on the host"
        ) == ToolState.EXECUTE

    def test_execute_by_schema_param(self):
        assert classify_tool(
            "do_thing",
            input_schema={"properties": {"command": {"type": "string"}}},
        ) == ToolState.EXECUTE

    # -- UNTRUSTED_INGEST -------------------------------------------------

    def test_ingest_by_name_fetch(self):
        assert classify_tool("fetch_page") == ToolState.UNTRUSTED_INGEST

    def test_ingest_by_name_spider(self):
        assert classify_tool("spider_web_page") == ToolState.UNTRUSTED_INGEST

    def test_ingest_by_name_scrape(self):
        assert classify_tool("scrape_html") == ToolState.UNTRUSTED_INGEST

    def test_ingest_by_name_duckduckgo(self):
        """query_duckduckgo doesn't match ingest by name alone."""
        # This tool has no URL param, so it should classify based on
        # description or schema.
        result = classify_tool(
            "query_duckduckgo",
            description="Search the web via DuckDuckGo",
        )
        assert result == ToolState.UNTRUSTED_INGEST

    def test_ingest_by_schema_url_param(self):
        assert classify_tool(
            "get_data",
            input_schema={"properties": {"url": {"type": "string"}}},
        ) == ToolState.UNTRUSTED_INGEST

    def test_ingest_by_name_download(self):
        assert classify_tool("download_artifact") == ToolState.UNTRUSTED_INGEST

    # -- LOCAL_WRITE ------------------------------------------------------

    def test_write_by_name(self):
        assert classify_tool("write_blob") == ToolState.LOCAL_WRITE

    def test_write_by_name_save(self):
        assert classify_tool("save_blob_to_disk") == ToolState.LOCAL_WRITE

    def test_write_by_name_delete(self):
        assert classify_tool("delete_entry") == ToolState.LOCAL_WRITE

    def test_write_by_schema_content_path(self):
        assert classify_tool(
            "store_data",
            input_schema={
                "properties": {
                    "content": {"type": "string"},
                    "path": {"type": "string"},
                }
            },
        ) == ToolState.LOCAL_WRITE

    # -- LOCAL_READ -------------------------------------------------------

    def test_read_by_name(self):
        assert classify_tool("read_config") == ToolState.LOCAL_READ

    def test_read_by_name_cat(self):
        assert classify_tool("cat_file") == ToolState.LOCAL_READ

    def test_read_by_name_view(self):
        assert classify_tool("view_log") == ToolState.LOCAL_READ

    # -- DISCOVERY --------------------------------------------------------

    def test_discovery_by_name_list(self):
        assert classify_tool("list_users") == ToolState.DISCOVERY

    def test_discovery_by_name_search(self):
        assert classify_tool("search_index") == ToolState.DISCOVERY

    def test_discovery_by_name_inspect(self):
        assert classify_tool("inspect_schema") == ToolState.DISCOVERY

    # -- NETWORK_EGRESS ---------------------------------------------------

    def test_egress_by_name_webhook(self):
        assert classify_tool("fire_webhook") == ToolState.NETWORK_EGRESS

    def test_egress_by_name_upload(self):
        assert classify_tool("upload_report") == ToolState.NETWORK_EGRESS

    def test_egress_by_description(self):
        assert classify_tool(
            "relay", description="Send email notification to admin"
        ) == ToolState.NETWORK_EGRESS

    # -- UNKNOWN (fallback) -----------------------------------------------

    def test_unknown_fallback(self):
        assert classify_tool("do_magic") == ToolState.UNKNOWN

    def test_unknown_no_signals(self):
        assert classify_tool("xyz_tool_999") == ToolState.UNKNOWN

    # -- Policy-configured tool wins --------------------------------------

    def test_explicit_policy_wins(self, policy):
        """Tools already in policy.tool_mappings bypass heuristics."""
        result = classify_tool("fetch", policy=policy)
        assert result == ToolState.UNTRUSTED_INGEST  # From policy

    def test_policy_overrides_heuristic(self, policy):
        # read_file is mapped in policy — should return from policy
        result = classify_tool("read_file", policy=policy)
        assert result == ToolState.LOCAL_READ

    # -- Adversarial / edge cases -----------------------------------------

    def test_disk_destroyer_classified_as_write(self):
        """A destructive-sounding tool should be classified as LOCAL_WRITE."""
        result = classify_tool(
            "disk_destroyer",
            description="Delete all files from the target directory",
        )
        assert result == ToolState.LOCAL_WRITE

    def test_mixed_signals_execute_wins(self):
        """EXECUTE takes priority over INGEST when both match."""
        result = classify_tool(
            "exec_fetch",  # name matches both EXECUTE and INGEST
            description="",
        )
        assert result == ToolState.EXECUTE  # EXECUTE is higher priority


# ===========================================================================
# 2. Dynamic Discovery via tools/list Interception
# ===========================================================================

class TestDynamicToolsListDiscovery:
    """Test that the proxy auto-classifies tools from tools/list responses."""

    def test_tools_list_registers_unknown_tools(self, app_client, policy):
        """tools/list response containing new tools should register them."""
        fake_tools = [
            {
                "name": "spider_web_page",
                "description": "Crawl and scrape a web page",
                "inputSchema": {"properties": {"url": {"type": "string"}}},
            },
            {
                "name": "disk_destroyer",
                "description": "Delete all files from the target directory",
                "inputSchema": {
                    "properties": {"path": {"type": "string"}}
                },
            },
            {
                "name": "run_sneaky_shell",
                "description": "Execute a command in a subprocess",
                "inputSchema": {
                    "properties": {"command": {"type": "string"}}
                },
            },
        ]
        mock_response = _mock_tools_list_response(fake_tools)

        with patch("src.main.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_response
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            resp = app_client.post(
                "/mcp",
                json=_jsonrpc("tools/list"),
                headers={"X-Session-ID": "discovery-001"},
            )

        assert resp.status_code == 200

        # Verify tools were dynamically registered
        assert "spider_web_page" in policy.tool_mappings
        assert policy.tool_mappings["spider_web_page"] == ToolState.UNTRUSTED_INGEST

        assert "disk_destroyer" in policy.tool_mappings
        assert policy.tool_mappings["disk_destroyer"] == ToolState.LOCAL_WRITE

        assert "run_sneaky_shell" in policy.tool_mappings
        assert policy.tool_mappings["run_sneaky_shell"] == ToolState.EXECUTE

    def test_existing_tools_not_overwritten(self, app_client, policy):
        """Tools already in policy.tool_mappings must not be overwritten."""
        original_state = policy.tool_mappings["fetch"]  # UNTRUSTED_INGEST

        fake_tools = [
            {
                "name": "fetch",
                "description": "Something completely different",
                "inputSchema": {},
            },
        ]
        mock_response = _mock_tools_list_response(fake_tools)

        with patch("src.main.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_response
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            app_client.post(
                "/mcp",
                json=_jsonrpc("tools/list"),
            )

        assert policy.tool_mappings["fetch"] == original_state

    def test_tools_list_response_passed_through(self, app_client):
        """The tools/list response body should be returned to the client."""
        tools = [{"name": "my_tool", "description": "A test tool", "inputSchema": {}}]
        mock_response = _mock_tools_list_response(tools)

        with patch("src.main.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_response
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            resp = app_client.post("/mcp", json=_jsonrpc("tools/list"))

        body = resp.json()
        assert body["result"]["tools"] == tools


# ===========================================================================
# 3. Dynamic Classification + DFA Invariant Enforcement
# ===========================================================================

class TestDynamicToolDFAInvariants:
    """Verify dynamically classified tools are subject to DFA invariants."""

    def test_dynamic_execute_blocked_after_ingest(self, app_client, policy, engine):
        """A dynamically-classified EXECUTE tool must still be blocked
        after UNTRUSTED_INGEST."""
        # Step 1: Discover tools via tools/list
        fake_tools = [
            {
                "name": "run_sneaky_shell",
                "description": "Execute a command",
                "inputSchema": {"properties": {"command": {"type": "string"}}},
            },
        ]
        mock_response = _mock_tools_list_response(fake_tools)

        with patch("src.main.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_response
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            app_client.post(
                "/mcp",
                json=_jsonrpc("tools/list"),
                headers={"X-Session-ID": "dfa-dynamic-001"},
            )

        # Step 2: Do a fetch (transitions START -> UNTRUSTED_INGEST)
        ok, _, _ = engine.evaluate_transition("dfa-dynamic-001", "fetch")
        assert ok is True

        # Step 3: Attempt the dynamically-classified EXECUTE tool
        ok, reason, meta = engine.evaluate_transition(
            "dfa-dynamic-001", "run_sneaky_shell"
        )
        assert ok is False
        assert "BLOCKED" in meta["status"]
        assert meta["to_state"] == "EXECUTE"

    def test_dynamic_write_blocked_after_ingest(self, app_client, policy, engine):
        """A dynamically-classified LOCAL_WRITE tool must still be blocked
        after UNTRUSTED_INGEST."""
        # Discover tool
        fake_tools = [
            {
                "name": "save_blob_to_disk",
                "description": "Save data to a file on disk",
                "inputSchema": {
                    "properties": {
                        "content": {"type": "string"},
                        "path": {"type": "string"},
                    }
                },
            },
        ]
        mock_response = _mock_tools_list_response(fake_tools)

        with patch("src.main.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_response
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            app_client.post(
                "/mcp",
                json=_jsonrpc("tools/list"),
                headers={"X-Session-ID": "dfa-dynamic-002"},
            )

        # Fetch first -> UNTRUSTED_INGEST
        ok, _, _ = engine.evaluate_transition("dfa-dynamic-002", "fetch")
        assert ok is True

        # Attempt write with dynamically classified tool
        ok, reason, meta = engine.evaluate_transition(
            "dfa-dynamic-002", "save_blob_to_disk"
        )
        assert ok is False
        assert meta["to_state"] == "LOCAL_WRITE"

    def test_dynamic_ingest_allowed_after_discovery(self, app_client, policy, engine):
        """A dynamically-classified UNTRUSTED_INGEST tool should be allowed
        after DISCOVERY (legal transition)."""
        fake_tools = [
            {
                "name": "spider_web_page",
                "description": "Crawl a web page",
                "inputSchema": {"properties": {"url": {"type": "string"}}},
            },
        ]
        mock_response = _mock_tools_list_response(fake_tools)

        with patch("src.main.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_response
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            app_client.post(
                "/mcp",
                json=_jsonrpc("tools/list"),
                headers={"X-Session-ID": "dfa-dynamic-003"},
            )

        # DISCOVERY first
        ok, _, _ = engine.evaluate_transition("dfa-dynamic-003", "list_directory")
        assert ok is True

        # Then dynamic INGEST — should be allowed
        ok, reason, _ = engine.evaluate_transition(
            "dfa-dynamic-003", "spider_web_page"
        )
        assert ok is True, f"Expected ALLOWED, got: {reason}"

    def test_full_e2e_jsonrpc_error_on_dynamic_block(self, app_client, policy, engine):
        """End-to-end: tools/list -> fetch -> dynamic-EXECUTE blocked at HTTP layer."""
        # Discover
        fake_tools = [
            {
                "name": "evil_exec",
                "description": "Run arbitrary commands",
                "inputSchema": {"properties": {"command": {"type": "string"}}},
            },
        ]
        mock_response = _mock_tools_list_response(fake_tools)

        with patch("src.main.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_response
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            app_client.post(
                "/mcp",
                json=_jsonrpc("tools/list"),
                headers={"X-Session-ID": "e2e-dynamic-001"},
            )

        # Fetch (advance DFA to UNTRUSTED_INGEST) — use engine directly
        engine.evaluate_transition("e2e-dynamic-001", "fetch")

        # Now call the dynamic tool via HTTP — should get -32001
        resp = app_client.post(
            "/mcp",
            json=_tool_call("evil_exec", {"command": "rm -rf /"}),
            headers={"X-Session-ID": "e2e-dynamic-001"},
        )
        body = resp.json()
        assert body["error"]["code"] == -32001
        assert body["error"]["data"]["target_state"] == "EXECUTE"
