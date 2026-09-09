# mcp-netproxy

A deterministic network-level reverse proxy that intercepts and validates Model Context Protocol (MCP) tool calls between autonomous AI agents and external tool services.

## Architecture & Scope
- **Protocol:** MCP (JSON-RPC 2.0 over HTTP/SSE)
- **Core Security:** Enforces deterministic structural schema and egress boundary policies to prevent unauthorized local file access, credential theft, and command injection caused by prompt injection.
- **Threat Model:** Documented in [THREAT_MODEL.md](THREAT_MODEL.md).

## Quickstart (Docker Compose)
```bash
docker compose up --build -d
