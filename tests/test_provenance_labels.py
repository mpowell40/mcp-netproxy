"""Test suite for provenance-based information flow control.

Validates:
1. The ``labels:`` policy section loads and is validated.
2. Path globs match canonical realpaths with ``**`` / ``*`` semantics.
3. Source labels are assigned by tool and by path glob, never by content.
4. The proxy applies source labels to the session after every backend
   response (errors included), records their origins, and never clears them.
"""

from __future__ import annotations

import os
import pathlib

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from src.engine.labels import LabelResolver, glob_match
from src.engine.state_machine import SessionGraphManager
from src.main import create_app
from src.models.policy import LabelPolicy, PolicyConfig, ToolState

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_POLICY_PATH = _PROJECT_ROOT / "config" / "policy.yaml"

_SECRET = "/mcp-proxy-testbed/sandbox/eval/secrets/env.txt"
_INBOX = "/mcp-proxy-testbed/sandbox/eval/inbox/ticket_poisoned.txt"
_PLAIN = "/mcp-proxy-testbed/sandbox/eval/data/sample_data.csv"

_FS_URL = "http://unprotected:9000/mcp"
_WEB_URL = "http://fetch-backend:9001/mcp"


@pytest.fixture
def policy():
    return PolicyConfig.from_yaml(_POLICY_PATH)


@pytest.fixture
def resolver(policy):
    return LabelResolver(policy)


@pytest.fixture
def engine(policy):
    return SessionGraphManager(policy)


@pytest.fixture
def client(policy, engine):
    return TestClient(create_app(
        policy_config=policy, graph_manager=engine, backend_urls={"fs": _FS_URL, "web": _WEB_URL},
    ))


def _tool_call(name: str, args: dict | None = None, req_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": name, "arguments": args or {}}, "id": req_id}


def _text(req_id, text: str = "ok", *, is_error: bool = False) -> httpx.Response:
    result = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": result})


def _ok(url, req):
    return _text(req["id"])


class _Backends:
    """Patch the proxy's outbound client; *respond(url, payload)* answers each call."""

    def __init__(self, respond=_ok) -> None:
        self.respond = respond
        self.calls: list[tuple[str, dict]] = []

    def __enter__(self):
        async def post(url, json, timeout=10.0):
            self.calls.append((url, json))
            return self.respond(url, json)

        self._patcher = patch("src.main.httpx.AsyncClient")
        mock = self._patcher.start()
        instance = AsyncMock()
        instance.post.side_effect = post
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        mock.return_value = instance
        return self

    def __exit__(self, *exc):
        self._patcher.stop()


def _call(client, sid: str, tool: str, args: dict, req_id: int = 1) -> dict:
    return client.post("/mcp", json=_tool_call(tool, args, req_id), headers={"X-Session-ID": sid}).json()


def _labels(origins) -> set[str]:
    return {o.label for o in origins}


# ===========================================================================
# 1. Policy schema
# ===========================================================================

class TestLabelPolicySchema:

    def test_shipped_policy_declares_both_labels(self, policy):
        sources = policy.labels.sources
        assert sources["untrusted"].axis == "integrity"
        assert sources["secret"].axis == "confidentiality"
        assert "web__fetch" in sources["untrusted"].tools
        assert "**/secrets/**" in sources["secret"].paths

    def test_sinks_are_declarative(self, policy):
        sinks = {r.label: set(r.block) for r in policy.labels.sinks}
        assert sinks["untrusted"] == {ToolState.LOCAL_WRITE, ToolState.EXECUTE, ToolState.NETWORK_EGRESS}
        assert sinks["secret"] == {ToolState.NETWORK_EGRESS, ToolState.EXECUTE}

    def test_policy_without_labels_still_loads(self, policy):
        raw = policy.model_dump(mode="json", exclude={"labels"})
        assert PolicyConfig.model_validate(raw).labels.sources == {}

    def test_sink_on_undeclared_label_rejected(self):
        with pytest.raises(ValueError, match="undeclared label"):
            LabelPolicy.model_validate({
                "sources": {"secret": {"axis": "confidentiality"}},
                "sinks": [{"label": "radioactive", "block": ["EXECUTE"], "reason": "x"}],
            })


# ===========================================================================
# 2. Glob semantics
# ===========================================================================

class TestGlobMatching:

    @pytest.mark.parametrize("pattern,path,expected", [
        ("**/secrets/**", "/a/secrets/env.txt", True),
        ("**/secrets/**", "/a/secrets", True),
        ("**/secrets/**", "/a/b/secrets/deep/x", True),
        ("**/secrets/**", "/a/secretsx/env.txt", False),
        ("**/*.env", "/srv/app/.env", True),
        ("**/*.env", "/srv/app/prod.env", True),
        ("**/*.env", "/srv/app/env.example", False),
        ("**/credentials*", "/home/u/.aws/credentials", True),
        ("**/credentials*", "/x/credentials.json", True),
        ("sandbox/**/inbox/**", _INBOX, True),
        ("sandbox/**/inbox/**", "/mcp-proxy-testbed/sandbox/inbox/a", True),
        ("sandbox/**/inbox/**", "/elsewhere/inbox/a", False),
        ("/sandbox/*.txt", "/sandbox/a.txt", True),
        ("/sandbox/*.txt", "/sandbox/sub/a.txt", False),
        ("/sandbox/*.txt", "/x/sandbox/a.txt", False),
    ])
    def test_glob(self, pattern, path, expected):
        assert glob_match(pattern, path) is expected

    def test_secret_santa_is_not_secret(self, resolver):
        # Near-miss fixture (H02): the word "secret" in a filename is not a source rule
        assert resolver.path_labels("/mcp-proxy-testbed/sandbox/eval/docs/secret_santa_list.txt") == []

    def test_dot_segments_cannot_dodge_glob(self, resolver):
        sneaky = "/mcp-proxy-testbed/sandbox/eval/data/../secrets/./env.txt"
        assert ("secret", "**/secrets/**") in resolver.path_labels(sneaky)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
    def test_symlink_resolved_to_canonical_target(self, tmp_path, policy):
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / "env.txt").write_text("API_TOKEN=x")
        link = tmp_path / "harmless.txt"
        link.symlink_to(secrets / "env.txt")
        assert _labels(
            LabelResolver(policy).source_labels("fs__read_text_file", ToolState.LOCAL_READ, {"path": str(link)})
        ) == {"secret"}


# ===========================================================================
# 3. Source labels: by tool, by path, never by content
# ===========================================================================

class TestSourceLabels:

    def test_fetch_is_untrusted_by_tool(self, resolver):
        origins = resolver.source_labels(
            "web__fetch", ToolState.NETWORK_EGRESS, {"url": "https://docs.python.org/3/"}
        )
        (origin,) = origins
        assert origin.label == "untrusted"
        assert origin.rule == "tool:web__fetch"
        assert origin.source == "web__fetch:https://docs.python.org/3/"

    def test_global_ingest_tool_is_untrusted(self, resolver):
        assert _labels(resolver.source_labels("web_search", ToolState.UNTRUSTED_INGEST, {"query": "x"})) == {"untrusted"}

    def test_secret_by_path_glob(self, resolver):
        (origin,) = resolver.source_labels("fs__read_text_file", ToolState.LOCAL_READ, {"path": _SECRET})
        assert origin.label == "secret"
        assert origin.rule == "path:**/secrets/**"
        assert origin.source == f"fs__read_text_file:{_SECRET}"

    def test_inbox_is_untrusted_by_path_glob(self, resolver):
        assert _labels(resolver.source_labels("fs__read_text_file", ToolState.LOCAL_READ, {"path": _INBOX})) == {"untrusted"}

    def test_bare_alias_uses_backend_path_arguments(self, resolver):
        assert _labels(resolver.source_labels("read_text_file", ToolState.LOCAL_READ, {"path": _SECRET})) == {"secret"}

    def test_list_argument_labels_if_any_element_matches(self, resolver):
        origins = resolver.source_labels(
            "fs__read_multiple_files", ToolState.LOCAL_READ, {"paths": [_PLAIN, _SECRET, _INBOX]}
        )
        assert _labels(origins) == {"secret", "untrusted"}

    def test_plain_file_is_unlabeled(self, resolver):
        assert resolver.source_labels("fs__read_text_file", ToolState.LOCAL_READ, {"path": _PLAIN}) == []

    def test_writes_do_not_pick_up_path_labels(self, resolver):
        # Writing into secrets/ returns no secret data to the session
        assert resolver.source_labels("fs__write_file", ToolState.LOCAL_WRITE, {"path": _SECRET}) == []


# ===========================================================================
# 4. Session labeling through the proxy
# ===========================================================================

class TestSessionLabeling:

    def test_fetch_labels_session_untrusted_with_origin(self, client, engine):
        with _Backends():
            _call(client, "lab-01", "fetch", {"url": "https://docs.python.org/3/"})
        session, _ = engine._get_session("lab-01")
        assert session.label_set == {"untrusted"}
        (origin,) = session.labels["untrusted"]
        assert origin.source == "web__fetch:https://docs.python.org/3/"
        assert origin.rule == "tool:web__fetch"

    def test_secret_path_labels_session_secret(self, client, engine):
        with _Backends():
            _call(client, "lab-02", "read_text_file", {"path": _SECRET})
        session, _ = engine._get_session("lab-02")
        assert session.label_set == {"secret"}
        assert session.labels["secret"][0].rule == "path:**/secrets/**"

    def test_labels_are_content_independent(self, client, engine):
        # A page with no directive wording at all is still untrusted
        with _Backends(lambda url, req: _text(req["id"], "Changelog: minor fixes.")):
            _call(client, "lab-03", "fetch", {"url": "https://example.org/changelog"})
        session, _ = engine._get_session("lab-03")
        assert session.label_set == {"untrusted"}

    def test_labels_stick_across_clean_reads(self, engine):
        # Engine level: label stickiness must not depend on what the proxy
        # lets through afterwards.
        engine.record_source("lab-04", "fs__read_text_file", {"path": _SECRET})
        engine.record_source("lab-04", "web__fetch", {"url": "https://example.org/"})
        for _ in range(5):
            assert engine.evaluate_transition("lab-04", "fs__read_text_file", {"path": _PLAIN})[0]
            engine.record_source("lab-04", "fs__read_text_file", {"path": _PLAIN})
            assert engine.evaluate_transition("lab-04", "fs__list_directory", {"path": "/mcp-proxy-testbed/sandbox"})[0]
            engine.record_source("lab-04", "fs__list_directory", {"path": "/mcp-proxy-testbed/sandbox"})
        session, _ = engine._get_session("lab-04")
        assert session.label_set == {"secret", "untrusted"}
        assert session.current_state is ToolState.DISCOVERY

    def test_jsonrpc_error_response_still_labels(self, client, engine):
        def error(url, req):
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32603, "message": "page text"}}
            )

        with _Backends(error):
            _call(client, "lab-05", "fetch", {"url": "https://example.org/"})
        session, _ = engine._get_session("lab-05")
        assert session.label_set == {"untrusted"}

    def test_is_error_result_still_labels(self, client, engine):
        with _Backends(lambda url, req: _text(req["id"], "ENOENT", is_error=True)):
            _call(client, "lab-06", "read_text_file", {"path": _SECRET})
        session, _ = engine._get_session("lab-06")
        assert session.label_set == {"secret"}

    def test_connection_failure_does_not_label(self, client, engine):
        def down(url, req):
            raise httpx.ConnectError("backend down")

        with _Backends(down):
            body = _call(client, "lab-07", "fetch", {"url": "https://example.org/"})
        assert body["error"]["code"] == -32000
        session, _ = engine._get_session("lab-07")
        assert session.label_set == frozenset()

    def test_repeated_source_recorded_once(self, client, engine):
        with _Backends():
            for i in range(3):
                _call(client, "lab-08", "read_text_file", {"path": _SECRET}, i)
        session, _ = engine._get_session("lab-08")
        assert len(session.labels["secret"]) == 1

    def test_origin_bound_never_clears_label(self, engine):
        for i in range(100):
            engine.label("lab-09", "untrusted", source=f"src-{i}")
        session, _ = engine._get_session("lab-09")
        assert session.label_set == {"untrusted"}
        assert len(session.labels["untrusted"]) == 32
        assert session.label_origins_dropped == 68

    def test_context_endpoint_explains_labels(self, client):
        with _Backends():
            _call(client, "lab-10", "read_text_file", {"path": _SECRET}, 1)
            _call(client, "lab-10", "read_text_file", {"path": _INBOX}, 2)
        context = client.get("/session/lab-10").json()
        assert set(context["labels"]) == {"secret", "untrusted"}
        assert context["labels"]["untrusted"][0]["source"] == f"fs__read_text_file:{_INBOX}"
        assert context["labels"]["untrusted"][0]["rule"] == "path:sandbox/**/inbox/**"
        assert context["labels"]["secret"][0]["rule"] == "path:**/secrets/**"

    def test_after_event_reports_applied_labels(self, policy, engine):
        from src.engine.events import Checkpoint, EventCollector

        events = EventCollector(log_events=False)
        client = TestClient(create_app(
            policy_config=policy, graph_manager=engine,
            backend_urls={"fs": _FS_URL, "web": _WEB_URL}, event_collector=events,
        ))
        with _Backends():
            _call(client, "lab-11", "read_text_file", {"path": _SECRET})
        after = [e for e in events.events("lab-11") if e.event_type is Checkpoint.AFTER_TOOL_CALL][0]
        assert [o["label"] for o in after.details["labels_applied"]] == ["secret"]

    def test_session_reset_clears_labels(self, engine):
        engine.label("lab-12", "secret")
        engine.reset_session("lab-12")
        session, _ = engine._get_session("lab-12")
        assert session.label_set == frozenset()
