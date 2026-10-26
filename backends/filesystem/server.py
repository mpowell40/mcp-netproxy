import asyncio
import json
import os
import uvicorn
from fastapi import FastAPI, Request, Response

app = FastAPI(title="Filesystem Server HTTP Wrapper")

proc: asyncio.subprocess.Process | None = None
read_lock = asyncio.Lock()

# Target directory inside container (defaults to /mcp-proxy-testbed, falls back to /sandbox)
ROOT_DIR = "/mcp-proxy-testbed" if os.path.exists("/mcp-proxy-testbed") else "/sandbox"

@app.on_event("startup")
async def startup():
    global proc
    print(f"Starting official MCP filesystem server rooted at: {ROOT_DIR}...", flush=True)

    proc = await asyncio.create_subprocess_exec(
        "npx", "-y", "@modelcontextprotocol/server-filesystem", ROOT_DIR,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    # Background task to drain and print stderr to Docker logs
    async def log_stderr():
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            print(f"[mock-mcp stderr] {line.decode('utf-8', errors='replace').strip()}", flush=True)

    asyncio.create_task(log_stderr())
    print("Filesystem server process spawned successfully.", flush=True)

@app.on_event("shutdown")
async def shutdown():
    global proc
    if proc:
        try:
            proc.terminate()
            await proc.wait()
        except Exception:
            pass

@app.post("/mcp")
async def handle_mcp(request: Request):
    global proc
    if not proc or proc.returncode is not None:
        return Response(
            content=json.dumps({"jsonrpc": "2.0", "error": {"code": -32000, "message": "Filesystem backend not running"}}),
            status_code=500,
            media_type="application/json"
        )

    body = await request.body()
    try:
        req_json = json.loads(body)
    except json.JSONDecodeError:
        return Response(
            content=json.dumps({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Invalid JSON"}}),
            status_code=400,
            media_type="application/json"
        )

    req_id = req_json.get("id")

    # Serialize I/O with a lock so concurrent requests don't interleave lines
    async with read_lock:
        try:
            payload = body.decode("utf-8").strip() + "\n"
            proc.stdin.write(payload.encode("utf-8"))
            await proc.stdin.drain()
        except Exception as e:
            return Response(
                content=json.dumps({"jsonrpc": "2.0", "error": {"code": -32000, "message": f"Write failed: {str(e)}"}}),
                status_code=500,
                media_type="application/json"
            )

        # JSON-RPC notifications do not expect a response
        if req_id is None:
            return Response(content="", status_code=200)

        # Read async stdout with timeout to prevent hanging client bridge
        timeout_seconds = 10.0
        start_time = asyncio.get_event_loop().time()

        while True:
            remaining = timeout_seconds - (asyncio.get_event_loop().time() - start_time)
            if remaining <= 0:
                return Response(
                    content=json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32000, "message": "Backend filesystem server timed out"}
                    }),
                    status_code=504,
                    media_type="application/json"
                )

            try:
                line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
            except asyncio.TimeoutError:
                return Response(
                    content=json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32000, "message": "Timeout waiting for backend response"}
                    }),
                    status_code=504,
                    media_type="application/json"
                )

            if not line_bytes:
                return Response(
                    content=json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32000, "message": "Subprocess stdout closed unexpectedly"}
                    }),
                    status_code=500,
                    media_type="application/json"
                )

            line = line_bytes.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            try:
                parsed = json.loads(line)
                if "jsonrpc" in parsed and parsed.get("id") == req_id:
                    return Response(content=line, media_type="application/json")
            except json.JSONDecodeError:
                print(f"[mcp-filesystem-backend non-json stdout] {line}", flush=True)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)