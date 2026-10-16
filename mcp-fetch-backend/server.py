import asyncio
from contextlib import asynccontextmanager
import json
import os
import pathlib
import sys
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse

proc: asyncio.subprocess.Process | None = None
read_lock = asyncio.Lock()
init_result_cache: dict | None = None

FIXTURES_DIR = (
    pathlib.Path("/mcp-proxy-testbed/tests/fixtures")
    if os.path.exists("/mcp-proxy-testbed/tests/fixtures")
    else pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures"
)


async def _read_jsonrpc_response(req_id: int | str, timeout_seconds: float = 15.0) -> dict | None:
    """Read lines from subprocess stdout until matching JSON-RPC id is found."""
    if not proc or not proc.stdout:
        return None
    start_time = asyncio.get_event_loop().time()
    while True:
        remaining = timeout_seconds - (asyncio.get_event_loop().time() - start_time)
        if remaining <= 0:
            return None
        try:
            line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
        except asyncio.TimeoutError:
            return None
        if not line_bytes:
            return None
        line = line_bytes.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
            if "jsonrpc" in parsed and parsed.get("id") == req_id:
                return parsed
        except json.JSONDecodeError:
            print(f"[mcp-fetch-backend non-json stdout] {line}", flush=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global proc, init_result_cache
    print("Starting official MCP Fetch server (mcp-server-fetch)...", flush=True)

    # Route every outbound request through the proxy's egress guard when set,
    # so redirects are re-validated against the egress policy.
    proxy_args = ["--proxy-url", os.environ["EGRESS_PROXY_URL"]] if os.environ.get("EGRESS_PROXY_URL") else []

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "mcp_server_fetch",
        "--ignore-robots-txt",
        "--allow-private-ips",
        *proxy_args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def log_stderr():
        while True:
            if not proc or not proc.stderr:
                break
            line = await proc.stderr.readline()
            if not line:
                break
            print(f"[mcp-fetch-backend stderr] {line.decode('utf-8', errors='replace').strip()}", flush=True)

    asyncio.create_task(log_stderr())

    # Complete MCP stdio initialization handshake so stateless HTTP calls work immediately
    async with read_lock:
        init_req = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-netproxy-fetch-wrapper", "version": "1.0.0"},
            },
        }
        if proc.stdin:
            proc.stdin.write((json.dumps(init_req) + "\n").encode("utf-8"))
            await proc.stdin.drain()
            init_resp = await _read_jsonrpc_response(0, timeout_seconds=10.0)
            if init_resp:
                init_result_cache = init_resp.get("result")

            initialized_notif = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }
            proc.stdin.write((json.dumps(initialized_notif) + "\n").encode("utf-8"))
            await proc.stdin.drain()

    print("MCP Fetch server process spawned and initialized on port 9001.", flush=True)

    yield

    # Teardown logic
    if proc:
        try:
            proc.terminate()
            await proc.wait()
        except Exception:
            pass


app = FastAPI(
    title="MCP Fetch Server HTTP Wrapper (@modelcontextprotocol/server-fetch)",
    lifespan=lifespan,
)


@app.get("/robots.txt", response_class=PlainTextResponse)
async def serve_robots():
    """Explicitly permit automated fetch tools to access any fixture."""
    return PlainTextResponse("User-agent: *\nAllow: /\n", status_code=200)


@app.get("/", response_class=PlainTextResponse)
async def health():
    return PlainTextResponse("MCP Fetch Backend is operational.", status_code=200)


@app.get("/fixtures/{filename}", response_class=HTMLResponse)
async def serve_fixture(filename: str):
    """Serve local HTML test fixtures for self-contained live fetch testing."""
    target = (FIXTURES_DIR / filename).resolve()
    if not str(target).startswith(str(FIXTURES_DIR.resolve())) or not target.is_file():
        raise HTTPException(status_code=404, detail="Fixture not found")
    return HTMLResponse(content=target.read_text(encoding="utf-8"), status_code=200)


@app.post("/mcp")
async def handle_mcp(request: Request):
    global proc
    if not proc or proc.returncode is not None or not proc.stdin:
        return Response(
            content=json.dumps({
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "Fetch backend not running"},
            }),
            status_code=500,
            media_type="application/json",
        )

    body = await request.body()
    try:
        req_json = json.loads(body)
    except json.JSONDecodeError:
        return Response(
            content=json.dumps({
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": "Invalid JSON"},
            }),
            status_code=400,
            media_type="application/json",
        )

    req_id = req_json.get("id")
    method = req_json.get("method", "")

    # If client sends initialize or notifications/initialized, respond cleanly
    if method == "initialize" and init_result_cache is not None:
        return Response(
            content=json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": init_result_cache,
            }),
            media_type="application/json",
        )

    if req_id is None:
        return Response(content="", status_code=200)

    async with read_lock:
        try:
            payload = body.decode("utf-8").strip() + "\n"
            proc.stdin.write(payload.encode("utf-8"))
            await proc.stdin.drain()
        except Exception as e:
            return Response(
                content=json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": f"Write failed: {str(e)}"},
                }),
                status_code=500,
                media_type="application/json",
            )

        parsed = await _read_jsonrpc_response(req_id, timeout_seconds=15.0)
        if parsed is None:
            return Response(
                content=json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": "Timeout waiting for fetch backend response"},
                }),
                status_code=504,
                media_type="application/json",
            )

        return Response(content=json.dumps(parsed), media_type="application/json")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9001)