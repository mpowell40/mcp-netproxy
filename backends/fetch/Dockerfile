FROM python:3.11-slim

WORKDIR /app

# Install FastAPI wrapper dependencies and the official MCP Fetch Server
# (published from https://github.com/modelcontextprotocol/servers/tree/main/src/fetch)
RUN pip install --no-cache-dir fastapi uvicorn mcp-server-fetch

COPY server.py .

CMD ["python", "server.py"]

