"""Test suite for backend connection reuse.

Validates:
1. While the app is running (lifespan active), every forwarded call and
   the tools/list fan-out share one pooled HTTP client.
2. The client is closed on shutdown.
"""

from __future__ import annotations

import pathlib
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from src.main import create_app
from src.models.policy import PolicyConfig

_POLICY_PATH = pathlib.Path(__file__).resolve().parent.parent / "config" / "policy.yaml"


def _result(request: dict) -> httpx.Response:
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": request["id"], "result": {"content": []}})


class TestSharedClient:

    def test_one_client_for_the_app_lifetime(self):
        app = create_app(policy_config=PolicyConfig.from_yaml(_POLICY_PATH))
        with patch("src.main.httpx.AsyncClient") as mock_client:
            instance = AsyncMock()
            instance.post.side_effect = lambda url, json, timeout: _result(json)
            mock_client.return_value = instance
            with TestClient(app) as client:
                client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
                for i in range(3):
                    client.post(
                        "/mcp",
                        json={"jsonrpc": "2.0", "id": i + 2, "method": "tools/call",
                              "params": {"name": "list_directory",
                                         "arguments": {"path": "/mcp-proxy-testbed/sandbox"}}},
                        headers={"X-Session-ID": "pool-01"},
                    )
            assert mock_client.call_count == 1
            assert instance.post.await_count == 2 + 3  # fan-out to both backends, then 3 calls
            instance.aclose.assert_awaited_once()
