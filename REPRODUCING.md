# Reproducing the reported results

Every number in the README and the presentation maps to a committed run in `eval/runs/` and a command that regenerates it. A fresh run is checked **scenario by scenario** against the committed one, comparing outcome, first blocked call, layer and leaks. It isn't checked only on the headline percentages.

## One command

```bash
pip install -r requirements-dev.txt
scripts/reproduce.sh --phase4        # Linux / macOS
```

```powershell
pip install -r requirements-dev.txt
.\scripts\reproduce.ps1 -Phase4      # Windows (Docker Desktop)
```

Expected output:

```text
PASS   pytest: unit + integration tests
PASS   Phase 5 dev: 21/22 attacks blocked, 3/21 false positives (eval/runs/phase5-dev)
PASS   Phase 4 frozen: 27/28 attacks blocked (96.4%), 0/26 false positives (eval/runs/final)
```

You can also run it on a clean GitHub runner: **Actions → reproduce → Run workflow**.

**Before the first run:**
- Docker must be running. On Windows, start Docker Desktop and wait for "Engine running".
- The Phase 4 check needs the `phase4-frozen` tag (`git fetch --tags`).
- The first run builds the images, which takes a few minutes and needs internet.

## Claims

| Claim | Code / policy | Command | Committed run | Checked how |
|---|---|---|---|---|
| Phase 4: 27/28 attacks blocked (96.4%), 0/26 FP; dev 21/22, holdout 6/6 | tag `phase4-frozen` (`8c566d3`) | `reproduce.sh --phase4` | `eval/runs/final/` | Dev rows per scenario; holdout via `summary.md` headline (holdout rows are not committed) |
| Phase 5: dev 21/22 blocked, 3/21 FP (H06, H07, H12) | current `config/policy.yaml` (tag `phase5-eval` = `1189528`) | `reproduce.sh` | `eval/runs/phase5-dev/` | Per scenario |
| Phase 5 live: 8/8 blocked, 4/12 FP | `config/policy.phase5.live.yaml` | see below | `eval/runs/phase5-live/` | **Indicative**: depends on live websites |
| Phase 4 live: 5/8 blocked, 0/12 FP | `config/policy.live.yaml` | see below | `eval/runs/live/` | **Indicative** |
| Median added latency ~7 ms (p95 ~18 ms) | — | any eval run (`summary.md`) | `eval/runs/final/` | **Indicative**: measured on Docker Desktop for Windows, where `realpath` crosses the file-sharing layer. A Linux host measured ~3 ms. |
| 282 unit and integration tests pass (280 + 2 skipped on Windows: symlink tests need POSIX) | current code | `python -m pytest tests/ -q` | — | `ci.yml` on every push |

### Live-internet sets (not part of the one-command check)

```bash
docker compose -f docker-compose.yml -f compose/phase5-live.yml up -d
python eval/run_eval.py --scenarios eval/scenarios_live --set all --reps 3 --out my-live
python eval/compare_runs.py eval/runs/phase5-live my-live
docker compose up -d
```

These scenarios fetch real public pages, whose content and availability change. A mismatch here means a website changed, not that the proxy did. The attack verdicts depend on provenance labels, not page wording, so they should be stable.

## What is pinned, and why

| Component | Pin | Where |
|---|---|---|
| Proxy Python deps | exact versions | `requirements.txt` |
| Test / harness deps | exact versions | `requirements-dev.txt` |
| Filesystem MCP server | `@modelcontextprotocol/server-filesystem@2026.8.31`, installed at image build | `backends/filesystem/Dockerfile` |
| Fetch MCP server | `mcp-server-fetch==2026.10.19` | `backends/fetch/requirements.txt` |
| Base images | `python:3.11-slim-bookworm`, `node:20-bookworm-slim` | Dockerfiles |

Before pinning, the filesystem backend ran `npx -y @modelcontextprotocol/server-filesystem` **at container start**. That fetched whatever was the latest version, and newer majors (2.x) declare Node ≥ 24 while the image ships Node 20.

As of Nov 16 2026, both the pinned versions and the latest ones (filesystem 2.3.0) reproduce every committed verdict. The pins are there so this stays true when upstream changes. To try a different filesystem server version:

```bash
docker compose build --build-arg FS_SERVER_VERSION=<version> unprotected
```

## Rules the reported numbers follow

- The Phase 4 holdout split was run **once**, on the frozen policy. Re-running it to reproduce is fine. Changing the policy in response to it is not.
- Phase 5 was designed after seeing the Phase 4 results, so both of its sets are dev sets. A blind number needs `eval/scenarios_phase5_holdout/` (see its README).
- The persistent file label store (`/app/state/file_labels.json`) must start empty. `reproduce.sh` clears it before the Phase 5 run.
