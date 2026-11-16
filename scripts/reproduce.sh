#!/usr/bin/env bash
# Reproduce the reported mcp-netproxy results from a clean clone.
#
#   scripts/reproduce.sh            unit tests + Phase 5 dev set (current code)
#   scripts/reproduce.sh --phase4   also rebuild the Phase 4 policy from tag
#                                   phase4-frozen and re-run its dev + holdout set
#
# Options:
#   --no-build     use images that are already built (skip docker compose build)
#   --skip-tests   skip the pytest suite
#   REPS=<n>       repetitions per scenario (default 1; verdicts are deterministic,
#                  the committed runs used 5)
#
# Needs: Docker with Compose v2, Python 3.11+, and `pip install -r requirements-dev.txt`.
# Every check compares per-scenario verdicts (outcome, first blocked call,
# layer, leaks) with the committed run in eval/runs/ via eval/compare_runs.py.
# Latency and the live-internet set are not checked: see REPRODUCING.md.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUILD=1; TESTS=1; PHASE4=0
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    --skip-tests) TESTS=0 ;;
    --phase4) PHASE4=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done
REPS="${REPS:-1}"
PY="${PYTHON:-python3}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/netproxy-repro.XXXXXX")"
export NO_PROXY="localhost,127.0.0.1${NO_PROXY:+,$NO_PROXY}" no_proxy="localhost,127.0.0.1${no_proxy:+,$no_proxy}"

declare -a RESULTS=()
record() { RESULTS+=("$(printf '%-6s %s' "$1" "$2")"); }

wait_for_proxy() {
  for _ in $(seq 1 60); do
    curl -fsS -o /dev/null "http://localhost:8000/sessions" 2>/dev/null && return 0
    curl -fsS -o /dev/null "http://localhost:8000/session/probe" 2>/dev/null && return 0
    # Phase 4 has no /sessions; any HTTP answer from :8000 means it is up
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://localhost:8000/mcp" -d '{}' 2>/dev/null)
    [ "$code" != "000" ] && return 0
    sleep 2
  done
  echo "proxy did not come up on :8000" >&2; return 1
}

# Each phase gets its own Compose project, so its images (<project>-protected,
# ...) never stand in for the other phase's.  Container names are fixed in the
# compose files, so only one phase runs at a time.
compose_up() {  # $1 = project name, $2 = project dir, $3 = eval overlay (relative to it)
  local proj=$1 dir=$2 overlay=$3 flags=(-d)
  [ "$BUILD" = 1 ] && flags+=(--build) || flags+=(--no-build)
  (cd "$dir" && docker compose -p "$proj" -f docker-compose.yml -f "$overlay" up "${flags[@]}") >/dev/null
}
compose_down() {  # $1 = project name, $2 = project dir, $3 = eval overlay
  (cd "$2" && docker compose -p "$1" -f docker-compose.yml -f "$3" down) >/dev/null 2>&1
}

# 1. Unit and integration tests ------------------------------------------
if [ "$TESTS" = 1 ]; then
  echo "== pytest"
  if "$PY" -m pytest tests/ -q -p no:cacheprovider; then record PASS "pytest: unit + integration tests"
  else record FAIL "pytest: unit + integration tests"; fi
fi

# 2. Phase 5 (current code): dev set vs eval/runs/phase5-dev ---------------
echo "== Phase 5 dev set (config/policy.yaml)"
compose_up mcp-netproxy "$ROOT" compose/eval.yml && wait_for_proxy
# Start from an empty persistent file label store, as the reported run did
docker exec mcp-protected rm -f /app/state/file_labels.json >/dev/null 2>&1 && docker restart mcp-protected >/dev/null && wait_for_proxy
"$PY" eval/run_eval.py --set dev --reps "$REPS" --out "$OUT/phase5-dev" >"$OUT/phase5-dev.log" 2>&1
if "$PY" eval/compare_runs.py eval/runs/phase5-dev "$OUT/phase5-dev"; then
  record PASS "Phase 5 dev: 21/22 attacks blocked, 3/21 false positives (eval/runs/phase5-dev)"
else
  record FAIL "Phase 5 dev: see $OUT/phase5-dev"
fi

# 3. Phase 4 (tag phase4-frozen): dev + holdout vs eval/runs/final ---------
if [ "$PHASE4" = 1 ]; then
  echo "== Phase 4 frozen policy (tag phase4-frozen), dev + holdout"
  if ! git rev-parse -q --verify "refs/tags/phase4-frozen" >/dev/null; then
    git fetch -q origin "refs/tags/phase4-frozen:refs/tags/phase4-frozen" 2>/dev/null
  fi
  if git rev-parse -q --verify "refs/tags/phase4-frozen" >/dev/null; then
    compose_down mcp-netproxy "$ROOT" compose/eval.yml
    WT="$OUT/phase4-src"
    git worktree add -q --detach "$WT" phase4-frozen
    # The tag's backend images ran `npx -y` / unpinned pip at build and start
    # time. Swap in today's pinned backend builds (same wrappers, pinned server
    # versions) so the rebuilt testbed is the one the results were measured on.
    cp backends/filesystem/{Dockerfile,requirements.txt,server.py} "$WT/mcp-filesystem-backend/"
    cp backends/fetch/{Dockerfile,requirements.txt} "$WT/mcp-fetch-backend/"
    cp Dockerfile requirements.txt "$WT/"
    compose_up mcp-netproxy-phase4 "$WT" tests/eval/docker-compose.eval.yml && wait_for_proxy
    (cd "$WT" && "$PY" eval/run_eval.py --set all --reps "$REPS" --out "$OUT/phase4-all") >"$OUT/phase4-all.log" 2>&1
    rows_ok=0; head_ok=0
    "$PY" eval/compare_runs.py eval/runs/final "$OUT/phase4-all" && rows_ok=1
    # Holdout rows are not committed (eval/**/.holdout/ is ignored); compare
    # the reported headline lines of summary.md instead.
    if diff <(grep -E "Block rate|False-positive" eval/runs/final/summary.md) \
            <(grep -E "Block rate|False-positive" "$OUT/phase4-all/summary.md"); then head_ok=1; fi
    if [ "$rows_ok" = 1 ] && [ "$head_ok" = 1 ]; then
      record PASS "Phase 4 frozen: 27/28 attacks blocked (96.4%), 0/26 false positives (eval/runs/final)"
    else
      record FAIL "Phase 4 frozen: see $OUT/phase4-all"
    fi
    compose_down mcp-netproxy-phase4 "$WT" tests/eval/docker-compose.eval.yml
    git worktree remove --force "$WT"
    compose_up mcp-netproxy "$ROOT" compose/eval.yml
  else
    record FAIL "Phase 4 frozen: tag phase4-frozen not found (git fetch --tags)"
  fi
fi

echo
echo "== Reproduction summary (fresh runs in $OUT)"
printf '%s\n' "${RESULTS[@]}"
printf '%s\n' "${RESULTS[@]}" | grep -q '^FAIL' && exit 1 || exit 0
