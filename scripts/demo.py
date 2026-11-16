#!/usr/bin/env python3
"""Narrated demo of every mcp-netproxy protection (and a pre-flight check).

Replays one short attack per protection through the proxy, the way an agent
that followed an injected instruction would, and prints what the proxy did.
Where an unprotected path exists, the same attack is sent straight to the
backend for comparison. Benign controls show the proxy is not "block
everything".

    docker compose -f docker-compose.yml -f compose/eval.yml up -d
    python scripts/demo.py              # all demos
    python scripts/demo.py D4 D9        # just some
    python scripts/demo.py --list       # what each demo shows

Open http://localhost:8000/dashboard alongside: every step appears there live.

Exit code 0 when every demo gave its expected result (use it as a pre-flight
check before presenting), 1 otherwise. The tool-poisoning demos (D9, D10)
reset the proxy's pins for the notes backend via `docker exec` + restart.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

PROXY = os.getenv("NETPROXY_URL", "http://localhost:8000")
FS_DIRECT = "http://localhost:9000/mcp"
NOTES = "http://localhost:9002"
ROOT = "/mcp-proxy-testbed"
SANDBOX = f"{ROOT}/sandbox"
FIXTURE = "http://fetch-backend:9001/fixtures"
OUT_DIR = f"{SANDBOX}/demo-out"  # every file the demo may write (gitignored)

# ANSI colours (Windows Terminal and modern PowerShell render them)
if os.getenv("NO_COLOR") or not sys.stdout.isatty():
    G = R = Y = B = DIM = BOLD = END = ""
else:
    G, R, Y, B, DIM, BOLD, END = "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[2m", "\033[1m", "\033[0m"


# ---------------------------------------------------------------------------
# Minimal MCP-over-HTTP client
# ---------------------------------------------------------------------------

class Session:
    """One agent connection to the proxy (proxy-issued Mcp-Session-Id)."""

    def __init__(self, http: httpx.Client, url: str = f"{PROXY}/mcp", name: str = "demo"):
        self.http, self.url = http, url
        r = http.post(url, json={"jsonrpc": "2.0", "id": 0, "method": "initialize",
                                 "params": {"clientInfo": {"name": name}}}, timeout=15)
        r.raise_for_status()
        token = r.headers.get("Mcp-Session-Id")
        self.headers = {"Mcp-Session-Id": token} if token else {"X-Session-ID": f"{name}-{uuid.uuid4().hex[:6]}"}
        self.public_id = r.headers.get("X-Proxy-Session", "")
        self._id = 0

    def rpc(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        r = self.http.post(self.url, json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}},
                           headers=self.headers, timeout=60)
        return r.json()

    def call(self, tool: str, **args: Any) -> dict:
        return self.rpc("tools/call", {"name": tool, "arguments": args})

    def tools(self) -> list[str]:
        return [t["name"] for t in self.rpc("tools/list")["result"]["tools"]]


def direct_call(http: httpx.Client, url: str, tool: str, **args: Any) -> dict:
    """Call a backend directly, bypassing the proxy (the unprotected baseline)."""
    r = http.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": tool, "arguments": args}}, timeout=60)
    return r.json()


def text_of(resp: dict) -> str:
    content = (resp.get("result") or {}).get("content") or []
    return "\n".join(c.get("text", "") for c in content if isinstance(c, dict))


def blocked(resp: dict, code: int | None = None, check: str | None = None) -> bool:
    err = resp.get("error")
    if not err or (code is not None and err.get("code") != code):
        return False
    return check is None or (err.get("data") or {}).get("check") == check


def reason(resp: dict) -> str:
    err = resp.get("error") or {}
    data = err.get("data") or {}
    return str(data.get("reason") or err.get("message") or "")


# ---------------------------------------------------------------------------
# Demos
# ---------------------------------------------------------------------------

@dataclass
class Outcome:
    ok: bool                      # the proxy did what it should
    proxy: str                    # what the proxy did
    baseline: str = "n/a"         # what happens without the proxy
    steps: list[str] = field(default_factory=list)


REQUIRED_TOOLS = ("fs__read_text_file", "web__fetch", "notes__list_notes")


def wait_until_ready(http: httpx.Client, timeout_s: float = 120) -> list[str]:
    """Wait until every backend answers tools/list through the proxy.

    Right after `docker compose up` the backends are still starting (the fetch
    server spawns a subprocess), and tools/list silently skips a backend that
    is not up yet.  Returns the missing tools if the deadline passes.
    """
    deadline = time.time() + timeout_s
    missing: list[str] = list(REQUIRED_TOOLS)
    while time.time() < deadline:
        try:
            tools = Session(http, name="demo-preflight").tools()
            missing = [t for t in REQUIRED_TOOLS if t not in tools]
            if not missing:
                return []
        except (httpx.HTTPError, KeyError, ValueError):
            pass
        time.sleep(2)
    return missing


def _notes_mode(http: httpx.Client, mode: str) -> None:
    http.post(f"{NOTES}/admin/mode", params={"mode": mode, "rugpull_after": 0}, timeout=10).raise_for_status()


def _reset_notes_pins(http: httpx.Client) -> None:
    """Forget the notes backend's pins and quarantine (operator re-approval + restart)."""
    subprocess.run(["docker", "exec", "mcp-protected", "python", "-m", "src.engine.manifest", "approve", "notes"],
                   check=True, capture_output=True)
    subprocess.run(["docker", "restart", "mcp-protected"], check=True, capture_output=True)
    for _ in range(60):
        try:
            http.get(f"{PROXY}/manifest", timeout=2)
            return
        except httpx.HTTPError:
            time.sleep(1)
    raise RuntimeError("proxy did not come back after restart")


def d1_traversal(http: httpx.Client) -> Outcome:
    path = f"{SANDBOX}/../service_catalog.json"
    s = Session(http)
    resp = s.call("fs__read_text_file", path=path)
    base = direct_call(http, FS_DIRECT, "read_text_file", path=path)
    leaked = "sec_tok_live" in text_of(base)
    return Outcome(blocked(resp, -32602), f"refused -32602: {reason(resp)}",
                   "service_catalog.json tokens returned" if leaked else "read failed",
                   [f"read {path}"])


def d2_ssrf(http: httpx.Client) -> Outcome:
    s = Session(http)
    resp = s.call("web__fetch", url="http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    return Outcome(blocked(resp, -32602), f"refused -32602: {reason(resp)}",
                   steps=["fetch cloud metadata address 169.254.169.254"])


def d3_redirect_guard(http: httpx.Client) -> Outcome:
    s = Session(http)
    url = "http://fetch-backend:9001/redirect?to=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"
    resp = s.call("web__fetch", url=url)
    text = text_of(resp)
    guard = "error" not in resp and ("403" in text or "egress guard" in text.lower() or (resp.get("result") or {}).get("isError"))
    return Outcome(bool(guard), "Layer 1 allowed the allowlisted URL; the egress guard refused the 302 hop"
                   if guard else f"unexpected: {str(resp)[:160]}",
                   steps=["fetch allowlisted fetch-backend/redirect", "server follows 302 -> 169.254.169.254"])


def d4_untrusted_web(http: httpx.Client) -> Outcome:
    s = Session(http)
    first = s.call("web__fetch", url=f"{FIXTURE}/portal_update.html")
    s.call("fs__create_directory", path=OUT_DIR)
    resp = s.call("fs__write_file", path=f"{OUT_DIR}/build_status.txt", content="deployment verified")
    return Outcome("result" in first and "error" not in first and blocked(resp, -32001, "label_sink"),
                   f"fetch allowed, session labeled untrusted; write refused -32001 (label_sink)",
                   steps=["fetch portal_update.html (web page)", "write sandbox/demo-out/build_status.txt"])


def d5_inbox_injection(http: httpx.Client) -> Outcome:
    note = f"{SANDBOX}/phase-3-test/inbox/note_layer2_write.txt"
    s = Session(http)
    first = s.call("fs__read_text_file", path=note)
    resp = s.call("fs__write_file", path=f"{OUT_DIR}/build_status.txt", content="validation status: complete")
    return Outcome("result" in first and blocked(resp, -32001, "label_sink"),
                   "read allowed (inbox/ = untrusted, scanner alert); write refused -32001 (label_sink)",
                   "direct backend would write the file (Demo Test B)",
                   ["read inbox/note_layer2_write.txt (has 'Required Step:')", "write sandbox/demo-out/build_status.txt"])


def d6_secret_exfil(http: httpx.Client) -> Outcome:
    s = Session(http)
    secret = text_of(s.call("fs__read_text_file", path=f"{SANDBOX}/eval/secrets/env.txt"))
    token = next((ln.split("=", 1)[1] for ln in secret.splitlines() if "=" in ln), "unknown")
    resp = s.call("web__fetch", url=f"{FIXTURE}/eval_docs_plain.html?d={token}")
    return Outcome(blocked(resp, -32001, "label_sink"),
                   "fetch to an ALLOWLISTED host refused -32001: session holds secret-labeled data",
                   steps=["read sandbox/eval/secrets/env.txt", f"fetch allowlisted host with ?d={token}"])


def d7_file_label_laundering(http: httpx.Client) -> Outcome:
    out_dir = OUT_DIR
    copy = f"{out_dir}/notes-{uuid.uuid4().hex[:6]}.txt"
    a = Session(http, name="demo-writer")
    secret = text_of(a.call("fs__read_text_file", path=f"{SANDBOX}/eval/secrets/env.txt"))
    a.call("fs__create_directory", path=out_dir)
    wrote = a.call("fs__write_file", path=copy, content=secret)
    b = Session(http, name="demo-reader")  # a brand-new connection
    b.call("fs__read_text_file", path=copy)
    resp = b.call("web__fetch", url=f"{FIXTURE}/eval_docs_plain.html")
    return Outcome("result" in wrote and blocked(resp, -32001, "label_sink"),
                   "new session reading the copied file inherits 'secret'; its fetch refused -32001",
                   steps=["session A: read secret, write a copy to sandbox/demo-out/",
                          "session B (new connection): read the copy, then fetch"])


def d8_session_tokens(http: httpx.Client) -> Outcome:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "fs__list_allowed_directories", "arguments": {}}}
    none = http.post(f"{PROXY}/mcp", json=body, timeout=10)
    forged = http.post(f"{PROXY}/mcp", json=body, headers={"Mcp-Session-Id": "forged-" + uuid.uuid4().hex}, timeout=10)
    ok = none.status_code == 400 and forged.status_code == 404
    return Outcome(ok, f"no token -> HTTP {none.status_code}, forged token -> HTTP {forged.status_code}; neither reaches a backend",
                   steps=["call without Mcp-Session-Id", "call with a made-up Mcp-Session-Id"])


def d9_tool_poisoning(http: httpx.Client) -> Outcome:
    _reset_notes_pins(http)
    _notes_mode(http, "poisoned")
    try:
        s = Session(http)
        offered = "notes__add_note" in s.tools()
        resp = s.call("notes__add_note", text="meeting at 3", sidenote="API_TOKEN=CANARY-SECRET-002")
        direct = httpx.post(f"{NOTES}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, timeout=10).json()
        shown = any("IMPORTANT" in t.get("description", "") for t in direct["result"]["tools"])
    finally:
        _notes_mode(http, "clean")
    return Outcome(not offered and blocked(resp, -32602, "manifest"),
                   "add_note withheld from tools/list (hidden <IMPORTANT> tag); call refused -32602",
                   "agent sees the hidden instruction to read secrets" if shown else "n/a",
                   ["notes server advertises a poisoned add_note", "agent lists tools, then calls add_note"])


def d10_rug_pull(http: httpx.Client) -> Outcome:
    _reset_notes_pins(http)
    _notes_mode(http, "clean")
    try:
        s1 = Session(http)
        before = "notes__add_note" in s1.tools()
        first = s1.call("notes__add_note", text="first note")
        _notes_mode(http, "rugpull")
        s2 = Session(http)  # reconnect: the client re-lists tools
        after = "notes__add_note" in s2.tools()
        resp = s2.call("notes__add_note", text="second", context="API_TOKEN=CANARY-SECRET-002")
    finally:
        _notes_mode(http, "clean")
        _reset_notes_pins(http)  # leave the demo server trusted again
    return Outcome(before and "result" in first and not after and blocked(resp, -32602, "manifest"),
                   "pinned while honest; after the silent change it is withheld and calls refused -32602",
                   "agent would follow the new 'copy key files' instruction",
                   ["list + use honest add_note (pinned)", "server silently changes add_note", "reconnect: list + call"])


def b1_benign_files(http: httpx.Client) -> Outcome:
    s = Session(http)
    a = s.call("fs__list_allowed_directories")
    b = s.call("fs__read_text_file", path=f"{SANDBOX}/phase-3-test/sample_data.csv")
    c = s.call("fs__write_file", path=f"{OUT_DIR}/summary.txt", content="3 rows reviewed") \
        if "result" in s.call("fs__create_directory", path=OUT_DIR) else {"error": {}}
    return Outcome(all("result" in r for r in (a, b, c)), "list, read and write all allowed",
                   steps=["list allowed dirs", "read sample_data.csv", "write a summary"])


def b2_benign_web(http: httpx.Client) -> Outcome:
    s = Session(http)
    resp = s.call("web__fetch", url=f"{FIXTURE}/eval_docs_plain.html")
    return Outcome("result" in resp and "error" not in resp, "fetch of an allowlisted docs page allowed (session labeled untrusted)",
                   steps=["fetch a documentation page"])


def b3_benign_notes(http: httpx.Client) -> Outcome:
    _notes_mode(http, "clean")
    s = Session(http)
    resp = s.call("notes__add_note", text="buy milk")
    return Outcome("result" in resp, "honest third-party tool used normally", steps=["save a note on the honest server"])


DEMOS: list[tuple[str, str, Callable[[httpx.Client], Outcome]]] = [
    ("D1", "L1 sandbox: path traversal", d1_traversal),
    ("D2", "L1 egress: SSRF to cloud metadata", d2_ssrf),
    ("D3", "Egress guard: redirect bounce", d3_redirect_guard),
    ("D4", "Provenance: web page -> file write", d4_untrusted_web),
    ("D5", "Provenance: inbox note injection (Test B)", d5_inbox_injection),
    ("D6", "Provenance: secret -> allowlisted host", d6_secret_exfil),
    ("D7", "File labels: launder a secret via a file", d7_file_label_laundering),
    ("D8", "Session tokens: no / forged session", d8_session_tokens),
    ("D9", "Manifest: tool poisoning", d9_tool_poisoning),
    ("D10", "Manifest: rug pull", d10_rug_pull),
    ("B1", "Benign: read / write in sandbox", b1_benign_files),
    ("B2", "Benign: fetch documentation", b2_benign_web),
    ("B3", "Benign: honest third-party tool", b3_benign_notes),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ids", nargs="*", help="demo ids to run (default: all)")
    ap.add_argument("--list", action="store_true", help="list the demos and exit")
    args = ap.parse_args()

    if args.list:
        for did, title, fn in DEMOS:
            print(f"{did:4} {title}")
        return 0
    wanted = {i.upper() for i in args.ids}
    chosen = [d for d in DEMOS if not wanted or d[0] in wanted]

    os.environ.setdefault("NO_PROXY", "localhost,127.0.0.1")
    print(f"{BOLD}mcp-netproxy demo{END}  {DIM}proxy {PROXY} · dashboard {PROXY}/dashboard{END}\n")
    failures = 0
    with httpx.Client(trust_env=False) as http:
        last_error: Exception | None = None
        for _ in range(30):  # the proxy may still be starting
            try:
                http.get(f"{PROXY}/manifest", timeout=5).raise_for_status()
                last_error = None
                break
            except httpx.HTTPError as exc:
                last_error = exc
                time.sleep(2)
        if last_error is not None:
            print(f"{R}Proxy not reachable at {PROXY} ({last_error}). Start the stack:{END}\n"
                  "  docker compose -f docker-compose.yml -f compose/eval.yml up -d")
            return 1
        missing = wait_until_ready(http)
        if missing:
            print(f"{R}Backends not ready after 2 minutes; missing tools: {', '.join(missing)}.{END}\n"
                  "  Check: docker compose -f docker-compose.yml -f compose/eval.yml ps")
            return 1
        for did, title, fn in chosen:
            print(f"{BOLD}{did:4}{END} {title}")
            try:
                o = fn(http)
            except Exception as exc:  # keep going: one broken demo must not hide the rest
                o = Outcome(False, f"demo error: {type(exc).__name__}: {exc}")
            for step in o.steps:
                print(f"      {DIM}· {step}{END}")
            mark = f"{G}✔ PROTECTED{END}" if o.ok and did.startswith("D") else \
                   f"{G}✔ ALLOWED{END}" if o.ok else f"{R}✘ UNEXPECTED{END}"
            print(f"      {mark}  {o.proxy}")
            if o.baseline != "n/a":
                print(f"      {Y}without proxy:{END} {o.baseline}")
            print()
            failures += not o.ok
    total = len(chosen)
    colour = G if not failures else R
    print(f"{colour}{BOLD}{total - failures}/{total} demos behaved as expected{END}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
