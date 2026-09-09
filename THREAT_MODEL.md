# Phase 1: Threat Model & Attack Matrix

## 1. System Scope
This project places an inline security proxy directly between an autonomous AI agent and the tools it connects to. Because Model Context Protocol (MCP) tool calls use JSON-RPC 2.0 sent over HTTP/SSE, the proxy intercepts every network packet before the tool server executes it. 

Instead of relying on prompt instructions ("please don't delete files"), the proxy enforces hard, deterministic rules at the network layer. If an agent is tricked by indirect prompt injection, the proxy intercepts and blocks the dangerous tool call.

---

## 2. Attack Matrix & Detection Signals

| Attack Category | What the Attacker Tries to Do | MCP Request Signature (What the Proxy Catches) | Protected System Layer |
| :--- | :--- | :--- | :--- |
| **Path Traversal** | Access restricted system files outside the working directory (e.g., `/etc/passwd` or system logs). | Tool parameter values contain relative dot-segments (`../`, `..\`) or unauthorized root directory paths. | Host File System |
| **Credential Harvesting** | Exfiltrate private tokens, SSH keys, or environment files to an outside server. | Tool arguments reference sensitive file types (`.env`, `id_rsa`, `.pem`) or match known token/secret patterns. | Secret Storage & Egress |
| **Network Egress Violation** | Force the agent to send requests or download payloads from unapproved external IP addresses or domains. | Target hostnames, endpoints, or IP addresses in network tools fall outside permitted CIDR/IP allowlists. | Network Egress Boundary |
| **Command Injection** | Chain unauthorized system commands into an otherwise valid shell or script execution tool. | Arguments contain shell command operators (`;`, `|`, `&&`, `` ` ``, `$()`) designed to execute arbitrary code. | Operating System Subprocess |
| **Protocol Schema Tampering** | Bypass validation rules or crash downstream MCP servers using corrupted payloads. | Payloads omit required JSON-RPC 2.0 structural headers (`jsonrpc: "2.0"`, valid `id`, or standard `method` names). | Protocol Parser & Transport |