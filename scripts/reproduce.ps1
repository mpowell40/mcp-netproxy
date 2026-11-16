# Reproduce the reported mcp-netproxy results from a clean clone (Windows / PowerShell).
# Same checks as scripts/reproduce.sh; see REPRODUCING.md.
#
#   .\scripts\reproduce.ps1            unit tests + Phase 5 dev set + tool-poisoning set (current code)
#   .\scripts\reproduce.ps1 -Phase4    also rebuild tag phase4-frozen and re-run its dev + holdout set
#
#   -NoBuild     use images that are already built
#   -SkipTests   skip the pytest suite
#   -Reps <n>    repetitions per scenario (default 1; the committed runs used 5)
#
# Needs: Docker Desktop (Compose v2), Python 3.11+, and
#   pip install -r requirements-dev.txt
param(
    [switch]$Phase4,
    [switch]$NoBuild,
    [switch]$SkipTests,
    [int]$Reps = 1,
    [string]$Python = "python"
)
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Out = Join-Path ([IO.Path]::GetTempPath()) ("netproxy-repro-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $Out | Out-Null
$env:NO_PROXY = "localhost,127.0.0.1"
$Results = New-Object System.Collections.Generic.List[string]
function Record($status, $text) { $Results.Add(("{0,-6} {1}" -f $status, $text)) }

function Wait-Proxy {
    for ($i = 0; $i -lt 60; $i++) {
        try {
            Invoke-WebRequest -Method Post -Uri "http://localhost:8000/mcp" -Body "{}" -ContentType "application/json" -UseBasicParsing -TimeoutSec 3 | Out-Null
            return $true
        } catch {
            # Any HTTP status (400, 404, ...) means the proxy is answering
            if ($_.Exception.Response) { return $true }
        }
        Start-Sleep -Seconds 2
    }
    Write-Error "proxy did not come up on :8000"; return $false
}

# Each phase gets its own Compose project so their images never mix.
# The compose files give containers fixed names (mcp-protected, ...). A stack started
# by hand with `docker compose up` belongs to a project named after the checkout
# folder, so remove those testbed containers before starting ours.
function Clear-Testbed {
    foreach ($c in "mcp-protected", "mcp-unprotected", "mcp-fetch-backend", "mcp-eval-redirect", "mcp-notes-backend") {
        docker rm -f $c 2>&1 | Out-Null
    }
}

function Compose-Up($project, $dir, $overlay) {
    Clear-Testbed
    $flag = if ($NoBuild) { "--no-build" } else { "--build" }
    Push-Location $dir
    docker compose -p $project -f docker-compose.yml -f $overlay up -d $flag
    $ok = ($LASTEXITCODE -eq 0)
    Pop-Location
    if (-not $ok) { Write-Host "docker compose up failed for $project (see output above)" -ForegroundColor Red }
    return $ok
}

function Assert-Docker {
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Docker is not reachable. Start Docker Desktop, wait until it says 'Engine running', then re-run." -ForegroundColor Red
        Write-Host ""
        Write-Host "== Reproduction summary"
        $Results | ForEach-Object { Write-Host $_ }
        Write-Host "FAIL   Docker not running: evaluation checks were not run"
        exit 1
    }
}
function Compose-Down($project, $dir, $overlay) {
    Push-Location $dir
    docker compose -p $project -f docker-compose.yml -f $overlay down 2>&1 | Out-Null
    Pop-Location
}

# 1. Unit and integration tests
if (-not $SkipTests) {
    Write-Host "== pytest"
    & $Python -m pytest tests/ -q -p no:cacheprovider
    if ($LASTEXITCODE -eq 0) { Record "PASS" "pytest: unit + integration tests" } else { Record "FAIL" "pytest: unit + integration tests" }
}

# 2. Phase 5 (current code): dev set vs eval/runs/phase5-dev
Write-Host "== Phase 5 dev set (config/policy.yaml)"
Assert-Docker
if (-not (Compose-Up "mcp-netproxy" $Root "compose/eval.yml")) { Record "FAIL" "Phase 5 dev: testbed did not start"; $Results | ForEach-Object { Write-Host $_ }; exit 1 }
Wait-Proxy | Out-Null
# Empty file label and manifest pin stores, as the reported run did
docker exec mcp-protected rm -f /app/state/file_labels.json /app/state/manifest_pins.json | Out-Null
docker restart mcp-protected | Out-Null
Wait-Proxy | Out-Null
& $Python eval/run_eval.py --set dev --reps $Reps --out "$Out/phase5-dev" *> "$Out/phase5-dev.log"
& $Python eval/compare_runs.py eval/runs/phase5-dev "$Out/phase5-dev"
if ($LASTEXITCODE -eq 0) { Record "PASS" "Phase 5 dev: 21/22 attacks blocked, 3/21 false positives (eval/runs/phase5-dev)" }
else { Record "FAIL" "Phase 5 dev: see $Out/phase5-dev" }

# 2b. Tool poisoning / rug pull (manifest pinning) vs eval/runs/tools
Write-Host "== Tool poisoning / rug pull set (notes backend)"
& $Python eval/run_tool_eval.py --out "$Out/tools" *> "$Out/tools.log"
& $Python eval/compare_runs.py eval/runs/tools "$Out/tools"
if ($LASTEXITCODE -eq 0) { Record "PASS" "Tool poisoning: 4/4 attacks blocked, 0/3 false positives (eval/runs/tools)" }
else { Record "FAIL" "Tool poisoning: see $Out/tools" }

# 3. Phase 4 (tag phase4-frozen): dev + holdout vs eval/runs/final
if ($Phase4) {
    Write-Host "== Phase 4 frozen policy (tag phase4-frozen), dev + holdout"
    git rev-parse -q --verify refs/tags/phase4-frozen | Out-Null
    if ($LASTEXITCODE -ne 0) { git fetch -q origin "refs/tags/phase4-frozen:refs/tags/phase4-frozen" 2>&1 | Out-Null }
    git rev-parse -q --verify refs/tags/phase4-frozen | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Compose-Down "mcp-netproxy" $Root "compose/eval.yml"
        $Wt = Join-Path $Out "phase4-src"
        git worktree add -q --detach $Wt phase4-frozen
        # Swap in today's pinned backend builds (the tag ran `npx -y` / unpinned pip)
        Copy-Item backends/filesystem/Dockerfile, backends/filesystem/requirements.txt, backends/filesystem/server.py "$Wt/mcp-filesystem-backend/" -Force
        Copy-Item backends/fetch/Dockerfile, backends/fetch/requirements.txt "$Wt/mcp-fetch-backend/" -Force
        Copy-Item Dockerfile, requirements.txt "$Wt/" -Force
        Compose-Up "mcp-netproxy-phase4" $Wt "tests/eval/docker-compose.eval.yml" | Out-Null
        Wait-Proxy | Out-Null
        Push-Location $Wt
        & $Python eval/run_eval.py --set all --reps $Reps --out "$Out/phase4-all" *> "$Out/phase4-all.log"
        Pop-Location
        & $Python eval/compare_runs.py eval/runs/final "$Out/phase4-all"
        $rowsOk = ($LASTEXITCODE -eq 0)
        # Holdout rows are not committed; compare the reported headline lines instead
        $ref = Select-String -Path eval/runs/final/summary.md -Pattern "Block rate|False-positive" | ForEach-Object { $_.Line }
        $new = Select-String -Path "$Out/phase4-all/summary.md" -Pattern "Block rate|False-positive" | ForEach-Object { $_.Line }
        $headOk = -not (Compare-Object $ref $new)
        if ($rowsOk -and $headOk) { Record "PASS" "Phase 4 frozen: 27/28 attacks blocked (96.4%), 0/26 false positives (eval/runs/final)" }
        else { Record "FAIL" "Phase 4 frozen: see $Out/phase4-all" }
        Compose-Down "mcp-netproxy-phase4" $Wt "tests/eval/docker-compose.eval.yml"
        git worktree remove --force $Wt
        Compose-Up "mcp-netproxy" $Root "compose/eval.yml" | Out-Null
    } else {
        Record "FAIL" "Phase 4 frozen: tag phase4-frozen not found (git fetch --tags)"
    }
}

Write-Host ""
Write-Host "== Reproduction summary (fresh runs in $Out)"
$Results | ForEach-Object { Write-Host $_ }
if ($Results | Where-Object { $_ -like "FAIL*" }) { exit 1 } else { exit 0 }
