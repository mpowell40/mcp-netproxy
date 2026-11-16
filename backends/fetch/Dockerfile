FROM python:3.11-slim-bookworm

WORKDIR /app

# FastAPI wrapper and the official MCP Fetch Server, pinned (requirements.txt)
# (published from https://github.com/modelcontextprotocol/servers/tree/main/src/fetch)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

CMD ["python", "server.py"]
