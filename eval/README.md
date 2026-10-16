# mcp-netproxy evaluation set

Labeled tool-call scenarios for measuring the proxy's block rate (TPR) and
false-positive rate. The harness (`run_eval.py`, Stage 2) replays each
scenario through the running proxy over HTTP.

## Layout

- `scenarios/*.yaml`: one scenario per file (28 attack, 26 benign; 13 benign are hard near-misses)
- `gen_scenarios.py`: source of truth for the scenario set (`python eval/gen_scenarios.py eval/scenarios`)
- `canary/outside_secret.txt`: canary placed outside `sandbox/` (`CANARY-SECRET-001`)
- `../sandbox/eval/`: in-sandbox fixtures (fake secret `CANARY-SECRET-002`, poisoned ticket, project files)
- `../tests/fixtures/eval_*.html`: web fixtures served by the fetch backend at `/fixtures/<name>`

## Scenario schema

| Field | Meaning |
|---|---|
| `id`, `category`, `kind` | `kind` is `attack` or `benign` |
| `difficulty` | benign only: `easy` or `hard` (near-miss) |
| `holdout` | `true` = excluded from policy tuning; reported separately |
| `setup` | optional pre-steps (`file` or `symlink`) the harness creates and later removes |
| `calls` | ordered MCP `tools/call` requests (`tool`, `args`); `{"$generate": ...}` expands to a large string |
| `expected_verdict` | `block` or `allow` for the scenario as a whole |
| `block_at` | 0-based index of the call that must not reach the backend (null for benign) |
| `also_acceptable_block_at` | earlier indices where blocking also counts as a true positive |
| `label_flag` | open question about the label, for the author to review |

## Methodology notes

- **Information available when writing scenarios.** The scenarios were written
  from a threat model and the MCP tool surface: the README, the two backend
  wrappers (`mcp-filesystem-backend/`, `mcp-fetch-backend/`), and the sandbox
  fixtures. The author of the scenarios had **already seen
  `config/policy.yaml`** (DFA states, forbidden transitions, tool mappings)
  earlier in the same session, so the set is not fully blind to the
  policy. `src/` and `tests/` were **not** read while writing scenarios.
  The holdout split (11/54, ~20%) partly offsets this bias.
- **Inert payloads only.** Secrets are canary strings (`CANARY-*`), outbound
  destinations use the reserved `.invalid` TLD, and injected instructions are
  plain `INJECTED-INSTRUCTION:` marker lines. The eval measures whether the
  proxy blocks the *pattern*, not whether a realistic payload works.
- **Scope: shell execution is out of scope for this testbed.** No shell or
  command-execution MCP server sits behind the proxy, so command-injection
  scenarios are omitted. Three `unregistered_tool` scenarios (A16 to A18)
  instead check that calls to tools no backend serves fail closed.
- **Sandbox boundary.** The filesystem backend is rooted at the whole repo
  (`/mcp-proxy-testbed`), so the proxy is the only thing enforcing
  `sandbox/`. Path canonicalization cases (A01 to A09) target that boundary.

## Running the harness

```powershell
docker compose -f docker-compose.yml -f tests/eval/docker-compose.eval.yml up -d
python eval/run_eval.py --set dev --out eval/runs/<name>   # tuning runs
python eval/run_eval.py --set all --out eval/runs/<name>   # final run only
```

The overlay adds `eval-redirect` (`tests/eval/redirect_server.py`), an
eval-only 302 service used by A15. Outputs:

Each run writes to its `--out` directory (`eval/runs/baseline/` is the pre-fix baseline):

- `summary.md`: confusion matrices, rates, per-category and per-layer breakdowns, latency
- `results.csv` / `results_calls.csv`: dev-set rows per scenario and per call
- `.holdout/`: per-scenario holdout rows (git-ignored). **Do not open while tuning
  the policy**; holdout results are reported only in aggregate in `summary.md`.
  `--set dev` (the default) never sends holdout scenarios.

The harness resets `sandbox/`, `eval/canary/` and `sandbox_evil/` to their
pre-run contents before and after every replay. Every call in a scenario is
sent even after a block, so the outcome checks see what actually got through.

## Testbed caveats

- **Private-address exception (testbed only).** The egress policy refuses
  hosts that resolve to private addresses, but `fetch-backend` (the fixture
  server) lives on Docker's internal network, so `config/policy.yaml` lists it
  under `private_hosts`. This exception exists only so fixtures can be
  fetched in this testbed; a deployment fetching real sites should leave
  `private_hosts` empty. Loopback, link-local and metadata addresses are
  refused even for `private_hosts`.
- **Relative paths are refused.** The sandbox check resolves every path
  argument with `realpath` before comparing it to the sandbox roots. A
  relative path depends on the backend's working directory, which the proxy
  cannot know, so it fails closed. Clients must send absolute paths.
- **Latency was measured on Docker Desktop / Windows.** The harness runs on
  the Windows host; every POST into Docker pays a ~47 ms floor (measured
  and subtracted from the blocked-call figure; it cancels out of overhead).
  The proxy resolves symlinks on a bind mount of a Windows directory, so
  each `realpath` crosses Docker Desktop's file-sharing layer (~21 ms per
  path measured inside the container). On a native Linux mount this costs
  microseconds, so overhead figures here overstate production cost.
  Run-to-run variation is tens of milliseconds; compare medians.
