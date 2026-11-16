# Filesystem backend: the official MCP filesystem server behind an HTTP wrapper.
# Versions are pinned so a fresh clone runs the same server the reported eval
# results were measured against. An unpinned `npx -y` fetches whatever is
# latest at container start, and newer majors (2.x) require Node >= 24.

# Stage 1: install the pinned server with npm
FROM node:20-bookworm-slim AS fs-server
ARG FS_SERVER_VERSION=2026.8.31
RUN npm install -g --no-fund --no-audit "@modelcontextprotocol/server-filesystem@${FS_SERVER_VERSION}"

# Stage 2: Python wrapper image with the node runtime and the installed server
# (both stages are Debian bookworm, so the node binary's libraries match)
FROM python:3.11-slim-bookworm
COPY --from=fs-server /usr/local/bin/node /usr/local/bin/node
COPY --from=fs-server /usr/local/lib/node_modules/@modelcontextprotocol /usr/local/lib/node_modules/@modelcontextprotocol
RUN ln -s /usr/local/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js \
          /usr/local/bin/mcp-server-filesystem

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

CMD ["python", "server.py"]
