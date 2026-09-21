import os
import json
import re
import httpx
import uvicorn
from fastapi import FastAPI, Request, Response

app = FastAPI(title="MCP Enforcement Proxy")
DOWNSTREAM_URL = os.getenv("DOWNSTREAM_URL", "http://mock-mcp:9000/mcp")

# Heuristic inspection patterns
TRAVERSAL_PATTERN = r"(\.\./|\.\.\\|/etc/|~/\.ssh|~/\.env)"
SHELL_INJECTION = r"(;|\||&&|\bcurl\b|\bbash\b)"
AWS_KEY_PATTERN = r"(AKIA[0-9A-Z]{16})"

@app.post("/proxy/mcp")
async def forward_mcp(request: Request):
    try:
        payload = await request.json()
    except Exception:
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
    params = payload.get("params", {})
    arguments = params.get("arguments", {})
    arg_string = " ".join(str(v) for v in arguments.values())

    print(f"[AUDIT LOG] Intercepted Request | Method: {method} | Tool: {params.get('name')} | Args: {arguments}")

    # Policy Enforcement: Drop malicious parameter patterns before forwarding
    if (
        re.search(TRAVERSAL_PATTERN, arg_string)
        or re.search(SHELL_INJECTION, arg_string)
        or re.search(AWS_KEY_PATTERN, arg_string)
    ):
        print(f"[ALERT] Policy violation detected in tool arguments: {arg_string}")
        error_response = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32602,
                "message": "Policy Violation: Malicious payload pattern blocked by proxy"
            },
            "id": payload.get("id")
        }
        return Response(
            content=json.dumps(error_response),
            status_code=403,
            media_type="application/json"
        )

    # Forward benign traffic to downstream MCP server
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post(DOWNSTREAM_URL, json=payload, timeout=5.0)
            return Response(
                content=res.content,
                status_code=res.status_code,
                media_type="application/json"
            )
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": f"Downstream connection error: {str(e)}"},
                "id": payload.get("id")
            }
            return Response(
                content=json.dumps(error_response),
                status_code=502,
                media_type="application/json"
            )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)