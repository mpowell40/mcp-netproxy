"""Comprehensive test suite for Behavioral State-Machine Invariant Enforcement.

Validates:
1. Benign agent workflows proceed unblocked through legal DFA transitions.
2. Indirect prompt injection vectors (UNTRUSTED_INGEST -> LOCAL_WRITE/EXECUTE)
   are detected and blocked with correct JSON-RPC error responses.
3. The evaluate_transition hot path executes within the 15ms latency budget.
4. Unknown tools are blocked by default.
5. The Mermaid export produces valid diagrams with blocked-state highlighting.
"""

from __future__ import annotations

import json
import os
import pathlib
import time

import pytest

# ---------------------------------------------------------------------------
# Locate the policy YAML relative to this file
# ---------------------------------------------------------------------------
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_POLICY_PATH = _PROJECT_ROOT / "config" / "policy.yaml"


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def policy():
    """Load the default policy config."""
    from src.models.policy import PolicyConfig
    return PolicyConfig.from_yaml(_POLICY_PATH)


@pytest.fixture
def engine(policy):
    """Create a fresh SessionGraphManager."""
    from src.engine.state_machine import SessionGraphManager
    return SessionGraphManager(policy)


@pytest.fixture
def app_client(policy, engine):
    """Create a FastAPI TestClient with the state engine wired in."""
    # We need to import and configure the app with our engine
    from src.main import create_app
    from fastapi.testclient import TestClient

    app = create_app(policy_config=policy, graph_manager=engine)
    return TestClient(app)


# ===========================================================================
# Helper
# ===========================================================================

def _jsonrpc_tool_call(tool_name: str, args: dict | None = None, req_id: int = 1) -> dict:
    """Build a minimal JSON-RPC 2.0 tools/call request."""
    return {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": args or {},
        },
        "id": req_id,
    }


# ===========================================================================
# 1. Benign Agent Flow
# ===========================================================================

class TestBenignAgentFlow:
    """Verify that a well-behaved agent can traverse legal DFA edges."""

    def test_discovery_then_read(self, engine):
        """START -> DISCOVERY -> LOCAL_READ is a legal path."""
        sid = "benign-001"

        ok1, reason1, meta1 = engine.evaluate_transition(sid, "list_directory")
        assert ok1 is True, f"Expected ALLOWED, got: {reason1}"
        assert meta1["from_state"] == "START"
        assert meta1["to_state"] == "DISCOVERY"

        ok2, reason2, meta2 = engine.evaluate_transition(sid, "read_file")
        assert ok2 is True, f"Expected ALLOWED, got: {reason2}"
        assert meta2["from_state"] == "DISCOVERY"
        assert meta2["to_state"] == "LOCAL_READ"

    def test_discovery_then_write(self, engine):
        """START -> DISCOVERY -> LOCAL_WRITE is legal (trusted local context)."""
        sid = "benign-002"

        ok1, _, _ = engine.evaluate_transition(sid, "list_allowed_directories")
        assert ok1 is True

        ok2, reason2, _ = engine.evaluate_transition(sid, "write_file")
        assert ok2 is True, f"Expected ALLOWED, got: {reason2}"

    def test_discovery_then_execute(self, engine):
        """START -> DISCOVERY -> EXECUTE is legal (local trusted context)."""
        sid = "benign-003"

        ok1, _, _ = engine.evaluate_transition(sid, "list_tools")
        assert ok1 is True

        ok2, reason2, _ = engine.evaluate_transition(sid, "execute_command")
        assert ok2 is True, f"Expected ALLOWED, got: {reason2}"

    def test_read_then_write(self, engine):
        """START -> LOCAL_READ -> LOCAL_WRITE is legal."""
        sid = "benign-004"

        ok1, _, _ = engine.evaluate_transition(sid, "read_file")
        assert ok1 is True

        ok2, reason2, _ = engine.evaluate_transition(sid, "write_file")
        assert ok2 is True, f"Expected ALLOWED, got: {reason2}"

    def test_session_history_records_clean_flow(self, engine):
        """Verify session history audit trail for a clean flow."""
        sid = "benign-005"

        engine.evaluate_transition(sid, "list_directory")
        engine.evaluate_transition(sid, "read_file")

        history = engine.get_session_history(sid)
        assert len(history) == 2
        assert all(rec.status == "ALLOWED" for rec in history)
        assert history[0].from_state.value == "START"
        assert history[0].to_state.value == "DISCOVERY"
        assert history[1].from_state.value == "DISCOVERY"
        assert history[1].to_state.value == "LOCAL_READ"


# ===========================================================================
# 2. Indirect Prompt Injection Prevention
# ===========================================================================

class TestIndirectPromptInjectionPrevented:
    """Verify that dangerous post-ingestion transitions are blocked."""

    def test_fetch_then_write_blocked(self, engine):
        """UNTRUSTED_INGEST -> LOCAL_WRITE must be blocked (invariant)."""
        sid = "attack-001"

        ok1, _, _ = engine.evaluate_transition(sid, "fetch")
        assert ok1 is True  # Ingestion itself is allowed from START

        ok2, reason2, meta2 = engine.evaluate_transition(sid, "write_file")
        assert ok2 is False
        assert "BLOCKED" in meta2["status"]
        assert "LOCAL_WRITE" in meta2["to_state"]
        assert "prompt injection" in reason2.lower() or "forbidden" in reason2.lower()

    def test_fetch_then_execute_blocked(self, engine):
        """UNTRUSTED_INGEST -> EXECUTE must be blocked (invariant)."""
        sid = "attack-002"

        ok1, _, _ = engine.evaluate_transition(sid, "web_search")
        assert ok1 is True

        ok2, reason2, meta2 = engine.evaluate_transition(sid, "bash")
        assert ok2 is False
        assert "BLOCKED" in meta2["status"]
        assert "EXECUTE" in meta2["to_state"]

    def test_fetch_then_network_egress_blocked(self, engine):
        """UNTRUSTED_INGEST -> NETWORK_EGRESS must be blocked (exfiltration)."""
        sid = "attack-003"

        ok1, _, _ = engine.evaluate_transition(sid, "fetch")
        assert ok1 is True

        ok2, reason2, meta2 = engine.evaluate_transition(sid, "send_webhook")
        assert ok2 is False
        assert "BLOCKED" in meta2["status"]

    def test_state_does_not_advance_on_block(self, engine):
        """Blocked transitions must NOT advance the session state."""
        sid = "attack-004"

        engine.evaluate_transition(sid, "fetch")  # -> UNTRUSTED_INGEST

        engine.evaluate_transition(sid, "write_file")  # BLOCKED

        # Session should still be in UNTRUSTED_INGEST
        ok3, _, meta3 = engine.evaluate_transition(sid, "read_file")
        assert ok3 is True  # UNTRUSTED_INGEST -> LOCAL_READ is allowed
        assert meta3["from_state"] == "UNTRUSTED_INGEST"

    def test_blocked_call_returns_jsonrpc_error(self, app_client, engine):
        """The proxy endpoint must return JSON-RPC -32001 for blocked calls."""
        # First: do a legit fetch (allowed from START).
        # Note: the forward to downstream will 502 (no real backend in test)
        # but the DFA engine has already advanced the session to UNTRUSTED_INGEST.
        resp1 = app_client.post(
            "/mcp",
            json=_jsonrpc_tool_call("fetch", {"url": "https://example.com"}),
            headers={"X-Session-ID": "http-attack-001"},
        )
        # Accept either 200 (real backend) or 502 (no backend in test).
        # The key check is that the DFA state advanced to UNTRUSTED_INGEST.
        assert resp1.status_code in (200, 502)

        # Second: attempt write_file (must be blocked)
        resp2 = app_client.post(
            "/mcp",
            json=_jsonrpc_tool_call("write_file", {"path": "/tmp/evil.txt", "content": "pwned"}, req_id=2),
            headers={"X-Session-ID": "http-attack-001"},
        )
        assert resp2.status_code == 200
        body = resp2.json()
        assert body["jsonrpc"] == "2.0"
        assert body["id"] == 2
        assert body["error"]["code"] == -32001
        assert "Security Invariant Violation" in body["error"]["message"]
        assert body["error"]["data"]["current_state"] == "UNTRUSTED_INGEST"
        assert body["error"]["data"]["target_state"] == "LOCAL_WRITE"

    def test_backend_never_called_on_block(self, app_client, engine):
        """Verify the downstream MCP server receives zero packets on block.

        We rely on the fact that MCP_BACKEND_URL points to a non-existent
        service. If the proxy incorrectly forwards, we'd get a connection
        error instead of a clean -32001 JSON-RPC response.
        """
        # Set up attack sequence
        resp1 = app_client.post(
            "/mcp",
            json=_jsonrpc_tool_call("fetch", {"url": "https://evil.com"}),
            headers={"X-Session-ID": "http-attack-002"},
        )
        # The fetch itself will fail at forwarding (no backend), but that's fine
        # for this test — we only care about the second call

        resp2 = app_client.post(
            "/mcp",
            json=_jsonrpc_tool_call("execute_command", {"command": "rm -rf /"}, req_id=2),
            headers={"X-Session-ID": "http-attack-002"},
        )
        body = resp2.json()
        # Must be a clean policy error, NOT a connection error
        assert body["error"]["code"] == -32001


# ===========================================================================
# 3. Unknown Tool Handling
# ===========================================================================

class TestUnknownToolBlocking:
    """Unknown tools not in the policy must be blocked by default."""

    def test_unknown_tool_blocked(self, engine):
        sid = "unknown-001"
        ok, reason, meta = engine.evaluate_transition(sid, "totally_unknown_tool")
        assert ok is False
        assert "UNKNOWN" in meta["to_state"]
        assert "not mapped" in reason.lower()

    def test_unknown_tool_jsonrpc_error(self, app_client):
        resp = app_client.post(
            "/mcp",
            json=_jsonrpc_tool_call("evil_custom_tool", {"x": "y"}),
            headers={"X-Session-ID": "unknown-http-001"},
        )
        body = resp.json()
        assert body["error"]["code"] == -32001


# ===========================================================================
# 4. Latency Budget
# ===========================================================================

class TestLatencyBudget:
    """Verify the evaluate_transition hot path stays under 15ms."""

    def test_transition_under_15ms(self, engine):
        """Single transition must complete in <15ms (target <2ms)."""
        sid = "perf-001"

        # Warm up
        engine.evaluate_transition(sid, "list_directory")
        engine.reset_session(sid)

        timings = []
        for i in range(100):
            sid_i = f"perf-{i:04d}"
            t0 = time.perf_counter()
            engine.evaluate_transition(sid_i, "list_directory")
            elapsed_ms = (time.perf_counter() - t0) * 1000
            timings.append(elapsed_ms)

        avg_ms = sum(timings) / len(timings)
        max_ms = max(timings)
        p99_ms = sorted(timings)[98]

        print(f"\n[PERF] avg={avg_ms:.3f}ms  p99={p99_ms:.3f}ms  max={max_ms:.3f}ms")

        assert avg_ms < 15.0, f"Average latency {avg_ms:.3f}ms exceeds 15ms budget"
        assert p99_ms < 15.0, f"p99 latency {p99_ms:.3f}ms exceeds 15ms budget"

    def test_blocked_transition_under_15ms(self, engine):
        """Blocked transitions (invariant check) must also stay under 15ms."""
        timings = []
        for i in range(100):
            sid = f"perf-block-{i:04d}"
            engine.evaluate_transition(sid, "fetch")
            t0 = time.perf_counter()
            engine.evaluate_transition(sid, "write_file")
            elapsed_ms = (time.perf_counter() - t0) * 1000
            timings.append(elapsed_ms)

        avg_ms = sum(timings) / len(timings)
        max_ms = max(timings)

        print(f"\n[PERF-BLOCKED] avg={avg_ms:.3f}ms  max={max_ms:.3f}ms")

        assert avg_ms < 15.0, f"Average blocked latency {avg_ms:.3f}ms exceeds 15ms budget"


# ===========================================================================
# 5. Mermaid Export
# ===========================================================================

class TestMermaidExport:
    """Verify the Mermaid diagram export."""

    def test_clean_session_diagram(self, engine):
        """Clean session produces a valid Mermaid stateDiagram."""
        sid = "mermaid-001"
        engine.evaluate_transition(sid, "list_directory")
        engine.evaluate_transition(sid, "read_file")

        diagram = engine.export_mermaid_graph(sid)
        assert "stateDiagram-v2" in diagram
        assert "START" in diagram
        assert "DISCOVERY" in diagram
        assert "LOCAL_READ" in diagram
        assert "✅" in diagram  # Allowed marker
        assert "❌" not in diagram  # No blocked transitions

    def test_blocked_session_diagram(self, engine):
        """Blocked session highlights the blocked node in red."""
        sid = "mermaid-002"
        engine.evaluate_transition(sid, "fetch")
        engine.evaluate_transition(sid, "write_file")  # BLOCKED

        diagram = engine.export_mermaid_graph(sid)
        assert "stateDiagram-v2" in diagram
        assert "❌" in diagram or "BLOCKED" in diagram
        assert "blocked" in diagram.lower()  # Red styling class
        assert "LOCAL_WRITE" in diagram

    def test_empty_session_diagram(self, engine):
        """Empty session produces a minimal diagram."""
        sid = "mermaid-003"
        diagram = engine.export_mermaid_graph(sid)
        assert "stateDiagram-v2" in diagram
        assert "START" in diagram


# ===========================================================================
# 6. Non-tool-call passthrough
# ===========================================================================

class TestNonToolCallPassthrough:
    """JSON-RPC methods other than tools/call should pass through."""

    def test_initialize_passes_through(self, app_client):
        """An 'initialize' request should not trigger state enforcement."""
        resp = app_client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {},
                "id": 1,
            },
            headers={"X-Session-ID": "passthrough-001"},
        )
        # Should get a downstream error (no real backend), not a policy error
        body = resp.json()
        assert body.get("error", {}).get("code") != -32001
