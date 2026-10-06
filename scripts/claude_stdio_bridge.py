"""Robust Stdio-to-HTTP JSON-RPC Bridge for Claude Desktop.

Implements byte-level line buffering, unbuffered UTF-8 I/O, and non-blocking
stream flushing to prevent Windows stdio freezes on large MCP responses.
"""

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

            # Ensure valid JSON framing before forwarding
            req_bytes = line.encode("utf-8")

            req = urllib.request.Request(
                URL,
                data=req_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-Session-ID": "claude-desktop-client",
                },
                method="POST",
            )

            # 3. Stream response directly back to Claude with explicit timeout
            with urllib.request.urlopen(req, timeout=30.0) as resp:
                resp_bytes = resp.read()
                resp_str = resp_bytes.decode("utf-8", errors="replace").strip()
                if resp_str:
                    sys.stdout.write(resp_str + "\n")
                    sys.stdout.flush()

        except urllib.error.HTTPError as e:
            # Downstream or Proxy returned an HTTP error (e.g. 400, 403, 500, 502)
            err_body = e.read().decode("utf-8", errors="replace").strip()
            try:
                # If backend returned a valid JSON-RPC error envelope, pass it clean
                json.loads(err_body)
                sys.stdout.write(err_body + "\n")
            except Exception:
                err_payload = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32000, "message": f"HTTP {e.code}: {e.reason}"},
                }
                sys.stdout.write(json.dumps(err_payload) + "\n")
            sys.stdout.flush()

        except Exception as e:
            # Network drops, connection refused, or unexpected pipe failures
            err_payload = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32000, "message": f"Bridge error: {str(e)}"},
            }
            sys.stdout.write(json.dumps(err_payload) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()