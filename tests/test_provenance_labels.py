"""Test suite for provenance-based information flow control.

Validates:
1. The ``labels:`` policy section loads and is validated.
2. Path globs match canonical realpaths with ``**`` / ``*`` semantics.
3. Source labels are assigned by tool and by path glob, never by content.
"""

from __future__ import annotations

import os
import pathlib

import pytest

from src.engine.labels import LabelResolver, glob_match
from src.models.policy import LabelPolicy, PolicyConfig, ToolState

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_POLICY_PATH = _PROJECT_ROOT / "config" / "policy.yaml"

_SECRET = "/mcp-proxy-testbed/sandbox/eval/secrets/env.txt"
_INBOX = "/mcp-proxy-testbed/sandbox/eval/inbox/ticket_poisoned.txt"
_PLAIN = "/mcp-proxy-testbed/sandbox/eval/data/sample_data.csv"


@pytest.fixture
def policy():
    return PolicyConfig.from_yaml(_POLICY_PATH)


@pytest.fixture
def resolver(policy):
    return LabelResolver(policy)


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
