"""Shared test configuration.

Most tests address sessions with the legacy ``X-Session-ID`` header (tests
marked ``@pytest.mark.session_tokens`` use proxy-issued tokens), and most
exercise the DFA, scanner and routing with arbitrary example URLs,
so the deployment's egress allowlist is bypassed for them.  Tests marked
``@pytest.mark.egress`` run the real URL policy (see tests/test_egress.py).

Every test gets its own empty file label store, so the policy's
deployment path (/app/state) is never touched and tests never share labels.
"""

from __future__ import annotations

import pytest

from src.engine.egress import EgressPolicy, EgressVerdict


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "egress: run the real egress URL policy instead of bypassing it")
    config.addinivalue_line(
        "markers", "session_tokens: run with proxy-issued session tokens instead of legacy X-Session-ID"
    )


@pytest.fixture(autouse=True)
def _legacy_sessions_unless_marked(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Most tests address sessions by X-Session-ID; token-mode tests opt in."""
    if request.node.get_closest_marker("session_tokens"):
        monkeypatch.setenv("MCP_SESSION_MODE", "token")
    else:
        monkeypatch.setenv("MCP_SESSION_MODE", "legacy")


@pytest.fixture(autouse=True)
def _bypass_egress_unless_marked(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("egress"):
        return

    async def allow(self: EgressPolicy, url: str) -> EgressVerdict:
        return EgressVerdict(True, "egress check bypassed in tests")

    monkeypatch.setattr(EgressPolicy, "check", allow)


@pytest.fixture(autouse=True)
def _isolated_file_label_store(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from src.engine.state_machine import FILE_LABEL_STORE_ENV

    monkeypatch.setenv(FILE_LABEL_STORE_ENV, str(tmp_path / "file_labels.json"))
