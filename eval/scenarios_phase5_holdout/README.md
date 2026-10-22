# Phase 5 blind holdout set (to be written)

This directory is reserved for a new holdout set that evaluates the Phase 5
provenance-label policy (`config/policy.yaml` after tag `phase4-frozen`).
It is intentionally empty. The Phase 4 holdout scenarios in `../scenarios/`
were seen by the Phase 4 run and must not be reused to report Phase 5.

## Rules for the author

- Write the scenarios without reading `src/`, `tests/` or the Phase 5 run
  outputs (`../runs/phase5-dev/`, `../runs/phase5-live/`). Record what you did
  read under "Information available" in the methodology note below.
- One scenario per `*.yaml` file, same schema as `../scenarios/`
  (see `../README.md`, "Scenario schema"). Set `holdout: true` on every file.
  Use opaque file names and IDs (e.g. `p5-3f9a1c.yaml`) so a listing does not
  reveal the category or verdict.
- Inert payloads only: `CANARY-*` strings, `.invalid` sinks, plain
  `INJECTED-INSTRUCTION:` markers.
- Cover both directions the labels are meant to handle, and the costs:
  attacks via untrusted sources (fetch, `inbox/` paths), exfiltration of
  secret-labeled data (`secrets/`, `*.env`, `credentials*`, and copies or
  moves of them), and benign workflows that read, fetch and write.
- Freeze the policy before the run: tag the commit (e.g. `phase5-frozen`)
  and do not change `config/` or `src/` in response to holdout results.

## Running it (once)

```powershell
docker compose -f docker-compose.yml -f compose/eval.yml up -d --build
docker exec mcp-protected sh -c 'rm -f /app/state/file_labels.json' ; docker restart mcp-protected
python eval/run_eval.py --scenarios eval/scenarios_phase5_holdout --set holdout --out eval/runs/phase5-holdout
```

Per-scenario rows land in `eval/runs/phase5-holdout/.holdout/` (git-ignored);
`summary.md` reports them in aggregate only. Live-internet holdout scenarios,
if any, go in a sibling directory and run under `compose/phase5-live.yml`.

## Methodology note (fill in)

- Information available when writing the scenarios:
- Scenario count (attack / benign / hard benign):
- Freeze commit and tag:
