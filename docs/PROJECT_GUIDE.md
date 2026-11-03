# mcp-netproxy: Project Guide

This guide covers what the project is, what changed when fetch arrived, how it compares with [Vault](https://github.com/vaultmcp/vault), and where it could go next.

> Written against `main` @ `93581fd`. All 171 unit tests pass on that commit (`python -m pytest tests/ -q`).

---

## 1. What this project is

**One sentence:** mcp-netproxy is a firewall that sits between an AI agent and its MCP tools. It enforces *where* tools may reach (files and hosts) and *in what order* they may be used, so a poisoned document or web page can't turn into a file write or a data leak.

It answers three questions on every tool call:

| Question | Mechanism | Where it lives | Block code |
|---|---|---|---|
| **Where?** Is this path or URL allowed? | Layer 1: sandbox roots (realpath), egress allowlist, argument types and sizes, pattern heuristics | `src/engine/registry.py`, `src/engine/egress.py`, `src/engine/arguments.py` | `-32602` |
| **In what order?** Is this action allowed after what the session already did? | Layer 2: per-session DFA over tool *categories* (READ, WRITE, EGRESS, …) plus forbidden invariants | `src/engine/state_machine.py`, `config/policy.yaml` | `-32001` |
| **Did the content just try to give orders?** | Ingest scanner: regex over tool *responses*. A hit sets a sticky taint that blocks every later write, execute and egress | `src/engine/ingest_scanner.py`, `taint_session` in `state_machine.py` | `-32001` on the next risky call |

### How one request flows (`src/main.py`)

```text
POST /mcp  ─► enforce_mcp (L172)          per-session lock, so a call can't race past a taint
             └► _handle_tool_call (L203)
                 1. resolve name → backend         (L216)  fs__read_file / web__fetch / bare name
                 2. L1 argument validation         (L226)
                 3. L1 sandbox + egress + patterns (L241-272)
                 4. L2 DFA transition + taint latch(L280)
                 5. forward to backend             (L305, _forward L462)
                 6. scan response → maybe taint    (L330-370)
```

The **egress guard** (`src/engine/egress.py`, port 8081) is a second copy of the "where?" check. The fetch backend sends *every* outbound request through it, including redirect hops, so a URL that passes Layer 1 and then redirects to `169.254.169.254` is still refused.

---

## 2. What changed when fetch arrived

The project felt clear while it only had files. The commit history shows where that changed:

| Commit | What happened | Effect |
|---|---|---|
| `15ae2c4` | Ingest scanner and sticky taint. Model: *read file → if it contains orders, taint → block writes.* | Clean and easy to explain. |
| `42f66cc` | Fetch reclassified as `NETWORK_EGRESS`, because its URL can carry data off-host. Its response is still scanned. | Attacks blocked 11→15/22, but **false positives 4→8/21**: sessions that start with a fetch, or fetch then write, were blocked. |
| `42b1e7a` | Egress allowlist plus egress guard. | Attacks 15→19/22. **Fetch safety moved out of the DFA and into the "where?" layer.** |
| `8c566d3` | DFA edges for fetch opened: `START→NETWORK_EGRESS`, and `NETWORK_EGRESS→LOCAL_WRITE` while untainted. | FPs back to 0/21, attacks 21/22. **The DFA now barely constrains fetch.** |

### Why it got confusing: one tool, two risk roles

Fetch is **both**:
- **an action that sends data out** (egress: the URL can contain your secrets), and
- **a source of untrusted content** (ingest: the page can contain instructions).

The DFA gives each tool exactly **one** state. Labeling fetch `NETWORK_EGRESS` lost the "untrusted content" meaning. Labeling it `UNTRUSTED_INGEST` would have lost the "sends data out" meaning. The fix-ups in `8c566d3` made the eval pass by handing fetch's protection to other layers. Today, fetch is protected by:

1. **the egress allowlist and guard** (where it may go), and
2. **the ingest scanner's taint**, but only if the regex recognizes the injected instruction.

The DFA ordering rules mostly matter for the filesystem tools. That's not a bug, but it should be stated plainly, and the README's architecture section doesn't say it.

### The three live-set misses explained (`eval/runs/live/summary.md`)

LA06–LA08 send an in-sandbox canary secret to an **allowlisted** host:
- the "where?" check passes, because the host is allowed,
- the ordering check passes, because fetch→fetch is allowed and the session isn't tainted, and
- the scanner check passes, because the live page's wording didn't match any regex (LA06) or there was no page at all (LA07/08).

This is the exact gap Vault's *capability firewall* targets: did data from earlier calls flow into this call's arguments? See roadmap Phase 4.

---

## 3. Is it useful? Positioning against Vault

| | **mcp-netproxy** | **Vault** |
|---|---|---|
| Core question | *Is this action allowed here and now?* (enforcement) | *Is this text malicious?* (detection) |
| Decision style | Deterministic and explainable: every block names a rule | Regex → embeddings → LLM judge (probabilistic) |
| Path sandbox (realpath, symlinks) | ✅ | ❌ |
| Egress allowlist plus redirect- and DNS-rebind-safe guard | ✅ | ❌ |
| Multi-turn sequence rules | ✅ DFA plus sticky taint | Partial: opt-in taint "capability firewall" |
| Injection detection quality | Regex only (English, narrow) | Strong: 4 layers, 31-category corpus |
| Value-level taint (data flows into arguments) | ❌ | ✅ |
| Tool manifest pinning / drift alerts | ❌ | ✅ |
| Audit log plus query CLI | In-memory events at `/session/{id}/events` | Append-only JSONL plus `vault-audit` |
| Install | Docker testbed, hard-coded `/mcp-proxy-testbed` paths | `npx … -- <server cmd>`, `vault init` rewrites client config |
| Transport | Custom: plain POST with `X-Session-ID` | stdio wrap plus spec HTTP/SSE |
| Evaluation | Labeled set with frozen holdout, live set, latency | Self-reported holdout |

**Honest framing for the talk:** the two tools are **complementary, not competitors**. Vault is a smoke detector, and netproxy is a building's locked doors and access rules. Netproxy's strengths (sandboxing, egress control, sequence policy, deterministic audit reasons) are things Vault doesn't attempt. Its weakness is that today only you can run it.

### What keeps it local today
1. **Docker-only testbed.** The policy, fixtures and demo all assume `/mcp-proxy-testbed/...`.
2. **No package.** You can't run `pip install` or `uvx` it.
3. **Non-standard transport.** It uses `X-Session-ID` over a single POST instead of MCP Streamable HTTP (`Mcp-Session-Id`, `initialize`, SSE). Real clients connect only through `scripts/claude_stdio_bridge.py`.
4. **Backends must already be HTTP.** The stdio→HTTP wrappers live in `backends/*/server.py`, one per server.

None of these are security problems. They're packaging problems, which is good news: they're mechanical to fix.

---

## 4. Presentation cheat sheet (Thursday, from `main`)

**30-second pitch:**
> AI agents act through tools. One malicious file or web page can make an agent read a secret and send it somewhere, and each call looks harmless on its own. mcp-netproxy is an inline firewall for MCP that checks *where* each call reaches, *in what order* calls happen, and *whether returned content is trying to give orders*. It blocks with a deterministic, explainable reason.

**Demo order:**
1. **Test A (L1):** traversal to `service_catalog.json` → `-32602`. "Where?"
2. **Test B (L2 taint):** the `Required Step:` note → read allowed, then the write is denied with `-32001`. "Did content give orders?" Then show `GET /session/claude-desktop-client` for the taint vector.
3. **Egress:** a fetch to a non-allowlisted host or the metadata IP → blocked. Mention that the guard re-checks redirects.

**Numbers:**
- Frozen set (54 scenarios): **27/28 attacks blocked (96.4%), 0/26 false positives**, deterministic across 5 reps.
- Median overhead: **~7 ms** on Docker Desktop for Windows.
- Live internet (20 scenarios): **5/8 blocked, 0/12 FP**.

**Turn the misses into "future work":** LA06–LA08 leak a secret to an *allowed* host. Present that as the honest limit of "where" plus "order" rules, and as the motivation for value-level taint (Phase 4).

**Likely questions:**
- *Why not just use an LLM judge?* Judges are probabilistic, cost money, add latency, and can themselves be prompt-injected. Netproxy's rules are deterministic and cost ~7 ms. A judge can be added as an optional plug-in (Phase 4), not as the foundation.
- *Why a DFA?* Injection attacks are *sequences* (read untrusted → write or send). A state machine is the simplest structure that can say "this action is fine, but not right after that one."
- *Won't the regex scanner miss things?* Yes. That's why it isn't the only line of defense: the sandbox and egress rules hold even when the scanner misses.
- *How does fetch fit the model?* Fetch is both egress and ingest (Section 2). Today its protection comes from the allowlist and taint. Splitting a tool's labels is on the roadmap.

---

## 5. Roadmap: keep the identity, borrow the usability (all free)

### Phase 1: Become installable (the biggest usefulness jump)
- **`pyproject.toml`** with a `mcp-netproxy` console script → `pip install mcp-netproxy` / `uvx mcp-netproxy`.
- **stdio wrap mode**, the equivalent of Vault's `npx … --`:
  ```bash
  mcp-netproxy wrap --policy my-policy.yaml -- npx -y @modelcontextprotocol/server-filesystem ~/projects
  ```
  It spawns the server as a subprocess using a generalized version of `backends/*/server.py`, runs the existing `create_app` pipeline in-process, and speaks stdio to the client. No Docker and no bridge script.
- **Policy templates** with no testbed paths, where the sandbox root comes from the CLI (`--root ~/projects`).
- **`mcp-netproxy init`** rewrites Claude Desktop or Claude Code MCP configs (with a backup and `unwrap`), like `vault init`.
- **Free distribution:** PyPI, plus GitHub Container Registry for the Docker image, plus a GitHub Actions workflow running `pytest` (free for public repos).
- Keep the Docker testbed exactly as it is. It becomes the *evaluation lab*, not the install path.

### Phase 2: Speak real MCP transport
- Support Streamable HTTP: `initialize`, the `Mcp-Session-Id` header (used as the session key), and SSE responses. Keep `X-Session-ID` as a fallback for the eval harness.
- This lets netproxy front **remote** MCP servers, not just the testbed containers.

### Phase 3: Fix the fetch model
- Give each tool **two labels**: its *action* (the existing DFA state) and a `produces_untrusted_content` flag.
  - fetch = `NETWORK_EGRESS` + untrusted-producer
  - read_file = `LOCAL_READ` (+ untrusted-producer only when scanned content is flagged)
- After an untrusted-producer call, the session is marked as having ingested untrusted data even if the regex didn't fire. The policy can then require, for example, "egress to a *different* host after ingest needs an allowlist entry marked `trusted_sink`."
- This restores the clean "ordering" story for fetch without reopening the false positives from `42f66cc`.

### Phase 4: Borrow Vault's best ideas, staying deterministic
- **Manifest pinning:** hash each backend's `tools/list` on first sight (hook into `_handle_tools_list`, `src/main.py` L481), then alert or block on drift. This catches a server swapping in a malicious tool description.
- **Persistent audit log:** append-only JSONL from `src/engine/events.py`, plus a `mcp-netproxy audit` query command.
- **Value-level taint:** remember fingerprints of sensitive values read (canary-style) and of untrusted responses, and flag later egress or write calls whose arguments contain them. This **targets LA06–LA08** directly.
- **Pluggable detector hook** in `ingest_scanner.py`: an optional external scanner (an embedding model, an LLM judge, or Vault itself, chained) without making the core depend on one.

### Phase 5: Public face
- README badges (CI, PyPI), eval results published on GitHub Pages, a short "netproxy + Vault together" section, and a 2-minute quickstart that doesn't mention Docker.

### Suggested order after Thursday
Do Phase 1 (wrap mode plus PyPI) first: it turns the project from "a testbed on my laptop" into "a tool someone else can try in one command." Then do Phase 3, which resolves the confusion you felt. Phases 2 and 4 make it competitive.
