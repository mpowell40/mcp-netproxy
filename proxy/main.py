import os
import json
import httpx
import uvicorn
from fastapi import FastAPI, Request, Response

app = FastAPI(title="MCP Enforcement Proxy Stub")
DOWNSTREAM_URL = os.getenv("DOWNSTREAM_URL", "http://mock-mcp:9000/mcp")

@app.post("/proxy/mcp")
async def forward_mcp(request: Request):
    try:
        payload = await request.json()
    except Exception:
        # Standard JSON-RPC 2.0 parse error response
        error_response = {
            "jsonrpc": "2.0",
            "error": {"code": -32700, "message": "Parse error: Invalid JSON payload"},
            "id": None
        }
        return Response(
            content=json.dumps(error_response),
            status_code=400,
            media_type="application/json"
        )

    method = payload.get("method", "unknown")
    print(f"[AUDIT LOG] Intercepted MCP Request Method: {method}")

    async with httpx.AsyncClient() as client:
        res = await client.post(DOWNSTREAM_URL, json=payload, timeout=5.0)
        return Response(
            content=res.content,
            status_code=res.status_code,
            media_type="application/json"
        )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)