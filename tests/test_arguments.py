"""Test suite for Layer 1 argument validation.

Validates:
1. Non-object arguments, wrong path/URL types and oversized values are
   rejected, with schema types enforced once the tool's inputSchema is known.
2. Legitimate arguments, including large-but-bounded content, pass.
3. The proxy rejects invalid arguments before forwarding (no backend call),
   including a non-object ``arguments`` that previously raised a 500.
"""

from __future__ import annotations

import pathlib
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.engine.arguments import find_argument_violation
from src.main import create_app
from src.models.policy import ArgumentLimits, PolicyConfig

_POLICY_PATH = pathlib.Path(__file__).resolve().parent.parent / "config" / "policy.yaml"
_LIMITS = ArgumentLimits(max_path_length=64, max_url_length=64, max_total_bytes=1024)
_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string"}, "head": {"type": "number"}, "edits": {"type": "array"}},
    "required": ["path"],
}


def _violation(arguments, schema=_SCHEMA):
    return find_argument_violation(arguments, schema, ["path", "paths"], ["url"], _LIMITS)


class TestArgumentValidation:

    @pytest.mark.parametrize(
        "arguments",
        [
            ["/sandbox/a.txt"],  # not an object
            {"path": {"$ref": "/etc/passwd"}},  # path must be a string
            {"paths": ["/sandbox/a.txt", 3]},  # list path with a non-string
            {"path": "/sandbox/" + "a/" * 40},  # path too long
            {"path": "/sandbox/a.txt", "url": "http://x/" + "q" * 80},  # URL too long
            {"path": "/sandbox/a.txt", "content": "x" * 2000},  # total size
            {"path": "/sandbox/a.txt", "head": "2"},  # schema type
            {"path": "/sandbox/a.txt", "head": True},  # bool is not a JSON number
            {"head": 2},  # missing required
        ],
    )
    def test_rejected(self, arguments):
        assert _violation(arguments) is not None

    @pytest.mark.parametrize(
        "arguments",
        [
            {"path": "/sandbox/a.txt"},
            {"path": "/sandbox/a.txt", "head": 2, "edits": [{"oldText": "a", "newText": "b"}]},
            {"paths": ["/sandbox/a.txt", "/sandbox/b.txt"], "path": "/sandbox"},
        ],
    )
    def test_accepted(self, arguments):
        assert _violation(arguments) is None

    def test_unknown_schema_still_checks_paths_and_size(self):
        assert _violation({"path": "/sandbox/a.txt", "anything": 1}, schema=None) is None
        assert _violation({"path": 7}, schema=None) is not None


class TestProxyRejectsBeforeForwarding:

    @pytest.mark.parametrize(
        "arguments",
        [
            ["not", "an", "object"],
            {"path": "/mcp-proxy-testbed/sandbox/" + "a/" * 4096},
        ],
    )
    def test_invalid_arguments_never_reach_backend(self, arguments):
        client = TestClient(create_app(policy_config=PolicyConfig.from_yaml(_POLICY_PATH)))
        with patch("src.main.httpx.AsyncClient") as mock_client:
            instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = instance
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "read_text_file", "arguments": arguments}},
                headers={"X-Session-ID": "args-01"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["error"]["code"] == -32602
        assert "Invalid arguments" in body["error"]["message"]
        instance.post.assert_not_called()
