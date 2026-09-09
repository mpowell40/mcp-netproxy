import uvicorn
from fastapi import FastAPI, Request

app = FastAPI(title="Mock MCP Target")

@app.post("/mcp")
async def handle_mcp(request: Request):
    data = await request.json()
    req_id = data.get("id", 1)
    params = data.get("params", {})
    tool_name = params.get("name", "generic_tool")

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "status": "success",
            "message": f"Downstream MCP execution reached for tool: {tool_name}"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)