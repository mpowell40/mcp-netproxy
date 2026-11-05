"""Robust Stdio-to-HTTP JSON-RPC Bridge for Claude Desktop.

Implements byte-level line buffering, unbuffered UTF-8 I/O, and non-blocking
stream flushing to prevent Windows stdio freezes on large MCP responses.

Session handling: the proxy issues a session token (``Mcp-Session-Id``) in
its reply to ``initialize``.  The bridge keeps that token in memory and sends
it on every later request, so each Claude Desktop connection gets its own
isolated session.  Reconnecting the server in Claude Desktop starts a new,
clean session.  If the token expires (HTTP 404), the bridge replays the
original ``initialize`` once to obtain a new token and retries the request.
Against a backend that issues no token (e.g. the unprotected baseline on
port 9000) no session header is sent.
"""

from __future__ import annotations

import io
import json
import os
import sys
import urllib.error
import urllib.request

# 1. Force binary-level UTF-8 streaming on standard I/O (Windows safe)
sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", line_buffering=True, errors="replace")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True, errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", line_buffering=True, errors="replace")

TARGET_PORT = os.environ.get("MCP_TARGET_PORT", "8000")
URL = f"http://127.0.0.1:{TARGET_PORT}/mcp"


SESSION_HEADER = "Mcp-Session-Id"
PUBLIC_ID_HEADER = "X-Proxy-Session"

session_token: str | None = None
init_line: bytes | None = None


def log(message: str) -> None:
    sys.stderr.write(f"[bridge] {message}\n")
    sys.stderr.flush()


def post(body: bytes) -> tuple[int, bytes, dict]:
    """POST one JSON-RPC frame; return (status, body, headers) even on HTTP errors."""
    headers = {"Content-Type": "application/json"}
    if session_token:
        headers[SESSION_HEADER] = session_token
    req = urllib.request.Request(URL, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers or {})


def adopt_session(headers: dict) -> None:
    """Store the token the proxy issued in reply to initialize."""
    global session_token
    lowered = {k.lower(): v for k, v in headers.items()}
    token = lowered.get(SESSION_HEADER.lower())
    if token:
        session_token = token
        log(f"proxy session {lowered.get(PUBLIC_ID_HEADER.lower(), '(id not reported)')}")


def is_initialize(body: bytes) -> bool:
    try:
        frame = json.loads(body)
    except Exception:
        return False
    return isinstance(frame, dict) and frame.get("method") == "initialize"


def forward(body: bytes) -> tuple[int, bytes]:
    """Send a frame, managing the proxy session token."""
    global init_line, session_token
    if is_initialize(body):
        init_line = body
        session_token = None  # a new handshake always starts a new session
        status, resp, headers = post(body)
        if status < 400:
            adopt_session(headers)
        return status, resp

    status, resp, headers = post(body)
    if status == 404 and session_token and init_line is not None:
        log("proxy session expired; re-initializing")
        session_token = None
        init_status, _, init_headers = post(init_line)
        if init_status < 400:
            adopt_session(init_headers)
            status, resp, headers = post(body)
    return status, resp


def write_error(message: str) -> None:
    payload = {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": message}}
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def main() -> None:
    # 2. Process stdin line-by-line using raw stream iteration
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break  # Claude Desktop closed the pipe

            line = line.strip()
            if not line:
                continue

            # 3. Forward and stream the response directly back to Claude
            status, resp_bytes = forward(line.encode("utf-8"))
            resp_str = resp_bytes.decode("utf-8", errors="replace").strip()
            if status >= 400:
                try:
                    # If the proxy or backend returned a JSON-RPC error envelope, pass it clean
                    json.loads(resp_str)
                except Exception:
                    write_error(f"HTTP {status}")
                    continue
            if resp_str:
                sys.stdout.write(resp_str + "\n")
                sys.stdout.flush()

        except Exception as e:
            # Network drops, connection refused, or unexpected pipe failures
            write_error(f"Bridge error: {str(e)}")


if __name__ == "__main__":
    main()
