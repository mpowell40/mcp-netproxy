# mcp-netproxy: Project Guide

This guide covers what the project is, how it got here, how each layer works, and how it compares with [Vault](https://github.com/vaultmcp/vault).

> Current through the Phase 5 merge (provenance labels, session tokens). The Phase 4 design is at tag `phase4-frozen` (`8c566d3`).

---

## 1. What this project is

**One sentence:** mcp-netproxy is a firewall between an AI agent and its MCP tools. It enforces *where* tools may reach, and it tracks *where the session's data came from*, so a poisoned document or web page can't turn into a file write or a data leak.

It answers three questions on every tool call:

| Question | Mechanism | Where it lives | Block code |
|---|---|---|---|
| **Where?** Is this path or URL allowed? | Layer 1: sandbox (realpath), URL allowlist + address checks, argument types and sizes, patterns | `src/engine/registry.py`, `egress.py`, `arguments.py`, `paths.py` | `-32602` |
| **Where did the data come from?** Has this session touched untrusted or secret data? | Layer 2: provenance labels + sink rules, value tracking | `src/engine/labels.py`, `state_machine.py`, `labels:` in `config/policy.yaml` | `-32001` |
| **Is this sequence allowed?** | Layer 2: DFA transition graph + forbidden invariants | `state_machine.py`, `allowed_transitions` | `-32001` |

A fourth check runs before the agent even sees the tools: **manifest pinning** (`src/engine/manifest.py`). Every advertised tool is scanned for poisoned descriptions and pinned by fingerprint. A poisoned or changed ("rug pull") tool is withheld from `tools/list` and calls to it are refused.

Three supporting pieces:
- the **egress guard**, which re-checks every network request the fetch backend makes
- **proxy-issued session tokens**
- the **ingest scanner**, which now only raises alerts

---

## 2. How the project evolved (the "how did it improve" story)

| Phase | Added | Attack it closed | Evidence |
|---|---|---|---|
| 1–2 | Sandbox boundary + pattern heuristics (Layer 1) | Path traversal (`sandbox/../service_catalog.json`) | Demo Test A |
| 3 | DFA + regex ingest scanner + sticky taint (Layer 2) | Prompt injection carried in files | Demo Test B, `15ae2c4` |
| 4 | Fetch backend, namespaced registry, URL allowlist, egress guard, eval harness | SSRF, `file://`, redirect bounce, exfiltration to non-allowlisted hosts | `eval/runs/final/`: 96.4% blocked, 0% FP |
| 5 | Provenance labels (`untrusted` / `secret`), value tracking, persistent file labels, session tokens | Exfiltration to *allowlisted* hosts (LA06–LA08), escaping taint by switching session ID | `eval/runs/phase5-*`: 8/8 live, FP cost |
| 6 (final) | Tool manifest pinning + tool-description scan, `notes` demo server | Tool poisoning, rug pulls (attacks *before* any tool call) | `eval/runs/tools/`: 4/4, 0/3 FP |

**The key shift between Phase 4 and Phase 5:**
- **Phase 4 asked "what does the text say?"** A regex scanner read every response, and a match tainted the session. LA06 got through because the live page's wording didn't match.
- **Phase 5 asks "where did the data come from?"** Every fetch response is `untrusted`, whatever it says, and every read under `secrets/` is `secret`. The scanner still runs but only records alerts.
- **The cost:** honest "fetch docs, then save notes" sessions are now refused (7 false positives across both sets).
- **The gain:** the guarantee no longer depends on guessing the attacker's wording.

### Why fetch was confusing in Phase 4
Fetch is both **egress** (its URL can carry data out) and **ingest** (its response can carry instructions). The DFA gives a tool one state, so fetch became `NETWORK_EGRESS`. To stop false positives, the DFA edges around fetch were opened (`8c566d3`). After that, fetch's protection came from the allowlist and the regex alone.

Phase 5 resolves this by letting a tool carry a **label** separately from its DFA state. `web__fetch` is still `NETWORK_EGRESS` in the graph, but its responses label the session `untrusted`.

---

## 3. Request pipeline (`src/main.py`)

```text
POST /mcp ─► enforce_mcp (L203)
  ├─ session identity (L217)          token required; no token → 400, unknown/expired → 404
  ├─ tools/list (L227 → _handle_tools_list L652)  namespace + classify tools, quarantine UNKNOWN
  └─ per-session lock (L239) ─► _handle_tool_call (L311)
       1. resolve name → backend                 (L324)   -32602 if ambiguous
       2. L1 argument types / sizes              (L334)   -32602
       3. L1 egress, patterns, sandbox            (L349)   -32602
       4. L2 evaluate_transition                  (L391)   -32001
       5. record file labels (fail closed)        (L429)   for LOCAL_WRITE
       6. forward to backend                      (L421-)
       7. label session by source                 (L463)
       8. ingest scanner → alert only             (L478)
```

The per-session lock makes sure a call can't race past labels that a response still in flight is about to apply.

---

## 4. Layer 1: checks on each call by itself (no memory)

| Check | Rule | Stops |
|---|---|---|
| **Argument validation** (`arguments.py`) | Must be an object of at most 1 MiB. Paths at most 4096 chars, URLs at most 8192. Must match `inputSchema` types and required fields. | Malformed input meant to confuse later checks |
| **Egress policy** (`EgressPolicy.check`, `egress.py`) | Scheme must be `http`/`https`. Host must exactly match the allowlist. The proxy resolves DNS itself and every address must pass: loopback, link-local (`169.254.169.254`), multicast, reserved and unspecified are always refused, private ranges only for `private_hosts`, and an unresolvable host is refused. | `file://` (A12), SSRF to metadata (A14), non-allowlisted exfiltration (A19, A22, A24, A26) |
| **Sandbox boundary** (`registry.py`, `paths.py`) | Each path argument goes through `realpath` (resolving `..` **and symlinks**) and must sit under `sandbox_roots`. Relative paths are refused. | Traversal (Test A), symlink escapes |
| **Patterns** (`main.py`) | Sensitive paths (`/etc/`, `~/.ssh`, `~/.env`) and AWS key shapes on every call. Shell metacharacters only for `EXECUTE` tools. | Backstop |

---

## 5. Layer 2: state across the session

`evaluate_transition` (`src/engine/state_machine.py:225`) runs these checks in order, and the first failure blocks the call. `error.data.check` names the check that fired.

1. **Unknown tool → block.**
2. **Label sink rules** (L258):
   - After every call, the session is labeled by **source** (L463 in `main.py`):
     - `untrusted` (integrity): every `web__fetch` response, plus paths under `sandbox/**/inbox/**`
     - `secret` (confidentiality): `**/secrets/**`, `**/*.env`, `**/credentials*`
     
     Globs match the canonical realpath.
   - Labels **only accumulate**. Each one keeps its origins (tool, path or URL, and the rule that matched), visible at `GET /session/{id}`.
   - The sinks:

     | Label | Blocked targets |
     |---|---|
     | `untrusted` | `LOCAL_WRITE`, `EXECUTE`, `NETWORK_EGRESS` |
     | `secret` | `NETWORK_EGRESS`, `EXECUTE`, even to an allowlisted host |
3. **Value tracking** (L274): fragments (7-character windows) of secret-looking values read from `secret` sources are remembered. An egress or execute call whose arguments contain one, raw or URL-decoded, is refused. With the shipped policy, the `secret` sink rule fires first, so this is defense in depth for a looser policy. Encoding, splitting and paraphrase evade it.
4. **Forbidden invariants**, for example `UNTRUSTED_INGEST → LOCAL_WRITE`.
5. **Transition graph:** any edge not in `allowed_transitions` is denied.

**Persistent file labels** (`FileLabelStore`, `labels.py`):
- When a labeled session writes or moves a file, the file keeps the session's labels in `/app/state/file_labels.json`.
- A *later* session that reads the file inherits them. This stops laundering, for example writing untrusted content to a file and reading it back in a fresh session.
- If the store can't be written, the write is refused (fail closed).

**Session tokens** (`session_tokens.py`):
- The proxy mints the session ID on `initialize`, so clients can't pick, switch or share IDs to shed labels.
- One Claude Desktop connection is one session. MCP has no per-chat ID, so all chats on that connection share it.

**Ingest scanner** (`ingest_scanner.py`): regexes for `Required Step:`, "you must write…", "notice to agents" and similar. Since Phase 5 a match only adds an **alert** to telemetry.

---

## 6. Egress guard: why fetch needs a second check

Layer 1 only sees the URL the agent asked for. The fetch server then makes its own requests and follows redirects by itself. To close that gap:
- `backends/fetch/server.py` starts it with `--proxy-url http://protected:8081`, so all of its traffic goes through `EgressGuard` (`egress.py`).
- The guard runs the same `EgressPolicy.check` on **every** request. Each redirect hop is a new connection, so it's re-checked. This stops redirect bounces (A15).
- The guard connects to the **exact IP it validated**, not the hostname. This stops DNS rebinding.

### Fetch attacks: which layer stops them

| Scenario | Attack | Phase 4 | Phase 5 |
|---|---|---|---|
| A12 | `file://` URL to the canary file | L1 egress (scheme) | same |
| A14 | SSRF to `169.254.169.254` | L1 egress (link-local) | same |
| A15 | Allowed URL that 302s to a sink | Egress guard | same |
| A19, A22, A24, A26 | Read secret → send to `sink.invalid` | L1 egress (allowlist) | same (L1 fires first) |
| A25 | Fetched page says "write …" → write | Scanner taint → L2 | `untrusted` label → L2 |
| LA06 | Live page instructs exfiltration; regex misses it | **missed** | `untrusted` + `secret` labels |
| LA07, LA08 | Secret → **allowlisted** host | **missed** | `secret` label sink |
| H06, H07, LB08, LB10–12 | Benign fetch → write | allowed | **false positive** |
| H12 | Benign fetch → read → fetch | allowed | **false positive** (strict `untrusted` rule) |

---

## 7. Is it novel? Is it useful? Positioning against Vault

| | **mcp-netproxy** | **Vault** |
|---|---|---|
| Core question | *Is this action allowed, given where the data came from?* (enforcement) | *Is this text malicious?* (detection) |
| Decision style | Deterministic: every block names a rule | Regex → embeddings → LLM judge |
| Path sandbox (realpath, symlinks) | ✅ | ❌ |
| Egress allowlist + guard that's safe against redirects and DNS rebinding | ✅ | ❌ |
| Provenance / taint across calls | ✅ labels, sinks, file labels | Opt-in capability firewall |
| Injection-text detection quality | Regex, alerts only | Strong (4 layers) |
| Tool manifest pinning / poisoning scan | ✅ (withholds the tool from the agent) | ✅ |
| Install | Docker testbed | `npx … -- <server>` |

**Novelty, stated honestly:**
- The individual ideas have prior work:
  - MCP gateways and proxies (Vault and others)
  - tool pinning (Invariant Labs' mcp-scan)
  - information-flow control for LLM agents (e.g. CaMeL, FIDES; verify these citations)
- What's distinctive here is the **combination**:
  - a *drop-in* proxy that enforces provenance at the MCP protocol layer without modifying the agent (CaMeL-style designs restructure the agent itself)
  - deterministic, explainable blocks
  - network-level egress re-checks of the backend's own requests
  - a labeled evaluation with a holdout split
- **Framing:** "Vault detects, netproxy enforces." The two are complementary.

**Why there's no LLM "Layer 3":**
- Phase 5 deliberately moved enforcement *away* from judging content.
- An LLM judge is a content check again. It's probabilistic, can be prompt-injected, adds latency, and costs money unless you run a local model.
- It belongs in future work as an optional detector that only raises alerts.

**Known limitations:**
- fetch-then-write false positives (no declassification step)
- sessions are per connection, not per chat
- the evaluation is self-authored (the blind holdout is pending)
- value tracking can be evaded
- A21 (`chain_recon`) is still missed
- no stdio wrap / pip install yet
