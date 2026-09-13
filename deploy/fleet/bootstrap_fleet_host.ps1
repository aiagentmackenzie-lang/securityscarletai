# SecurityScarletAI -- fleet host bootstrap for WINDOWS (V0.6a cross-platform fleet).
#
# Installs and starts the fleet shipper on ONE Windows agent host after the
# SIEM admin enrolled the host:
#
#   1. on the SIEM node:   POST /api/v1/fleet/enroll -Platform windows
#   2. on this agent host: powershell -ExecutionPolicy Bypass -File bootstrap_fleet_host.ps1 -SiemUrl ... -Token ...
#
# Fail-closed by design (mirrors bootstrap_fleet_host.sh):
#   - SIEM unreachable / unhealthy        -> nothing is installed (exit 4)
#   - Token rejected (401/403)            -> nothing is installed (exit 3)
#   - osqueryd / python missing           -> exact install commands printed, exit 2
# The AUTH PROBE is zero-write: a malformed line is refused server-side
# (rejected_parse), so proving the token never persists telemetry.
#
# What this does NOT do (honest scope):
#   - it does NOT install the osqueryd MSI (prints the command instead)
#   - it does NOT enable PowerShell script block logging (Group Policy
#     prerequisite of the powershell_events schedule -- documented in
#     config/osquery.windows.conf and the kit README; the schedule stays
#     DORMANT without it, no telemetry, no fake rows)
#   - it does NOT restart the osqueryd service if it is stopped (prints the
#     command; restarting a host security agent without the operator watching
#     is a decision for the operator)
#   - shipper crash-restart uses the built-in Task Scheduler restart settings
#     (systemd Restart=on-failure equivalent); the production-grade service
#     wrapper alternative is NSSM (documented in the kit README, not required)
#
# Exit codes: 1 fatal · 2 usage/missing dependency · 3 token rejected (401/403)
#             · 4 SIEM unreachable/unhealthy · 5 install/registration failure
#
# Requires: Windows PowerShell 5.1+ (also runs under pwsh 7), admin session.

param(
    [Parameter(Mandatory = $true)][string]$SiemUrl,
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$ResultsLog = "C:\ProgramData\osquery\log\osqueryd.results.log",
    [string]$InstallDir = "C:\Program Files\ScarletAI",
    [string]$DataDir    = "C:\ProgramData\ScarletAI",
    [string]$ConfPath   = "C:\ProgramData\osquery\osquery.conf",
    [string]$KitDir     = $PSScriptRoot,
    [switch]$AllowHttp,
    [switch]$SkipOsqueryCheck
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Log([string]$msg)  { Write-Host "[bootstrap] $msg" }
function Fail([string]$msg) { Write-Error "[bootstrap] FATAL: $msg"; exit 1 }

# ---------------------------------------------------------------- validate --
if (-not $SiemUrl.StartsWith("https://")) {
    if ($SiemUrl.StartsWith("http://") -and $AllowHttp) {
        Log "WARNING: -AllowHttp: shipping telemetry + bearer token in PLAINTEXT on a trusted LAN. Lab use only."
    } else {
        Fail "-SiemUrl must start with https:// (or http:// with -AllowHttp)"
    }
}
$SiemUrl = $SiemUrl.TrimEnd("/")
if (-not $Token -or $Token.Length -lt 20) { Fail "-Token looks empty/too short" }

# ------------------------------------------------------- dependency checks --
$osquerydCandidates = @(
    "C:\Program Files\osquery\osqueryd\osqueryd.exe",
    "C:\Program Files\osquery\osqueryd.exe"
)
$osquerydPath = $null
foreach ($c in $osquerydCandidates) { if (Test-Path $c) { $osquerydPath = $c; break } }
if (-not $osquerydPath) {
    if ($SkipOsqueryCheck) {
        Log "WARNING: -SkipOsqueryCheck: osqueryd not found, continuing (lab only)"
    } else {
        Write-Host "[bootstrap] FATAL: osqueryd.exe not found (MSI default paths checked). Install it first:" >&2
        Write-Host "  winget install --id osquery.osquery  # or the MSI from https://osquery.io/downloads" >&2
        exit 2
    }
}
$python = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $python) { Write-Host "[bootstrap] FATAL: python.exe not found on PATH. Install Python 3.8+ from python.org." >&2; exit 2 }

# ------------------------------------------------------------- preflight ----
try {
    $health = Invoke-WebRequest -UseBasicParsing -Uri "$SiemUrl/api/v1/health" -TimeoutSec 15
    if ($health.StatusCode -ne 200) { Fail "SIEM /health returned $($health.StatusCode)" }
    Log "preflight: SIEM healthy"
} catch {
    Write-Host "[bootstrap] FATAL: SIEM unreachable ($($_.Exception.Message))" >&2
    exit 4
}

# Auth probe: ZERO-WRITE (a malformed line is refused server-side as
# rejected_parse, so token verification never persists telemetry).
#   202 + rejected_parse >= 1 -> token ACCEPTED
#   401/403                   -> token wrong/revoked -> exit 3 (fail-closed)
$probeBody = '{"lines": ["scarletai-bootstrap auth probe (not an osquery line)"]}'
try {
    $probe = Invoke-WebRequest -UseBasicParsing -Method Post `
        -Uri "$SiemUrl/api/v1/ingest/osquery" `
        -Headers @{ Authorization = "Bearer $Token" } `
        -ContentType "application/json" -Body $probeBody -TimeoutSec 15
    if ($probe.StatusCode -eq 202) {
        Log "probe: token ACCEPTED (202, malformed line rejected server-side; zero rows persisted)"
    } else {
        Write-Host "[bootstrap] FATAL: unexpected probe response $($probe.StatusCode)" >&2
        exit 4
    }
} catch {
    $code = $null
    try { $code = [int]$_.Exception.Response.StatusCode } catch { }
    if ($code -in 401, 403) {
        Write-Host "[bootstrap] FATAL: token REJECTED (HTTP $code) -- nothing installed" >&2
        exit 3
    }
    Write-Host "[bootstrap] FATAL: probe failed (HTTP $code): $($_.Exception.Message)" >&2
    exit 4
}
Log "preflight ok: SIEM healthy, token verified (zero-write probe)"

# ------------------------------------------------------------- install ------
# Everything AFTER this point only runs on a verified token.
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$confSource = Join-Path $KitDir "osqueryd.conf.windows.example"
if (-not (Test-Path $confSource)) { Fail "kit file missing: $confSource" }
$confDir = Split-Path -Parent $ConfPath
New-Item -ItemType Directory -Force -Path $confDir | Out-Null
Copy-Item $confSource $ConfPath -Force
Log "osquery config installed -> $ConfPath"

# Validate the config parses as JSON BEFORE osqueryd ever loads it
# (fail-closed: a corrupt config would kill the osqueryd service silently).
try {
    Get-Content $ConfPath -Raw | ConvertFrom-Json | Out-Null
    Log "config JSON validated"
} catch {
    Fail "installed config failed JSON validation: $($_.Exception.Message)"
}

Copy-Item (Join-Path $KitDir "..\..\scripts\fleet_shipper.py") `
          (Join-Path $InstallDir "fleet_shipper.py") -Force
Log "shipper installed -> $InstallDir\fleet_shipper.py"

# Token file: ACL-locked, SYSTEM + Administrators only (the 0600 equivalent;
# locale-independent SIDs: *S-1-5-18 = SYSTEM, *S-1-5-32-544 = Administrators).
$tokenPath = Join-Path $DataDir "fleet-token"
[IO.File]::WriteAllText($tokenPath, $Token)
icacls.exe $tokenPath /inheritance:r /grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F" | Out-Null
Log "token file ACL-locked -> $tokenPath (SYSTEM + Administrators only)"

# ------------------------------------------------------- scheduled task -----
# Continuous loop shipper (the script polls internally), SYSTEM account,
# at-startup trigger, restart-on-failure (systemd Restart=on-failure
# equivalent), NO execution time limit (Task Scheduler's default 3-day
# limit would kill the loop silently).
$action = New-ScheduledTaskAction -Execute $python.Source -Argument `
    ("""$InstallDir\fleet_shipper.py"" --url ""$SiemUrl/api/v1/ingest/osquery"" " +
     "--token-file ""$tokenPath"" --log-path ""$ResultsLog"" " +
     "--checkpoint ""$DataDir\fleet_shipper_checkpoint.json"" --batch-max-lines 500")
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable
try {
    Register-ScheduledTask -TaskName "ScarletAIFleetShipper" -Action $action `
        -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    Log "scheduled task registered: ScarletAIFleetShipper (SYSTEM, at startup, restart-on-failure)"
} catch {
    Write-Host "[bootstrap] FATAL: task registration failed: $($_.Exception.Message)" >&2
    exit 5
}

# ------------------------------------------------------- osqueryd config ----
if ($osquerydPath) {
    Log "osqueryd: $osquerydPath"
    $svc = Get-Service -Name osqueryd -ErrorAction SilentlyContinue
    if ($svc) {
        Log "osqueryd service found ($($svc.Status)); config takes effect on next restart:"
        Log "  Restart-Service osqueryd   # run as admin when ready"
    } else {
        Log "osqueryd service not registered (MSI registers it; if running osqueryd manually:"
        Log "  $osquerydPath --config=$ConfPath --logger_path=$(Split-Path -Parent $ResultsLog))"
    }
}

Log "DONE. Next steps:"
Log "  1. restart osqueryd (command above) so the V0.6a Windows schedule loads"
Log "  2. Start-ScheduledTask -TaskName ScarletAIFleetShipper   # or wait for reboot"
Log "  3. verify on the SIEM: GET /api/v1/fleet/hosts shows last_seen_at moving"
exit 0