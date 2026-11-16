# Demo-only MCP server for tool-poisoning and rug-pull attacks (see server.py)
FROM python:3.11-slim-bookworm

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

CMD ["python", "server.py"]
