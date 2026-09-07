#Requires -Version 5.1
<#
  PhishGuard — one-time Windows auto-start installer.

  Registers a Task Scheduler task "PhishGuard Backend" that starts the backend
  automatically at logon (hidden, no console window, via pythonw.exe) so you
  never have to open a terminal, VS Code, or OpenCode to run it.

  Safe to re-run any time (e.g. after moving the project). Pass -Uninstall to
  remove the auto-start task instead.
#>
[CmdletBinding()]
param(
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$TaskName = "PhishGuard Backend"
$Marker = Join-Path $ProjectRoot "backend\autostart-installed.txt"

Write-Host "=== PhishGuard auto-start setup ==="
Write-Host "Project root : $ProjectRoot"

# ---------------------------------------------------------------------------
# 1. Locate the active Python interpreter (the one that already has the deps)
# ---------------------------------------------------------------------------
$pythonExe = $null
function Test-PythonWithDeps($candidate) {
    if (-not $candidate) { return $null }
    $out = & $candidate -c "import sys, uvicorn, fastapi; print(sys.executable)" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
    $exe = $out.Trim().Split("`n")[-1]
    if (-not (Test-Path -LiteralPath $exe)) { return $null }
    return $exe
}

foreach ($cand in @("python", "python3")) {
    $pythonExe = Test-PythonWithDeps $cand
    if ($pythonExe) { break }
}
if (-not $pythonExe) {
    foreach ($ver in @("3.14", "3.13", "3.12", "3.11", "3.10", "3")) {
        $pythonExe = Test-PythonWithDeps "py -$ver"
        if ($pythonExe) { break }
    }
}
if (-not $pythonExe) {
    throw "Could not find a Python interpreter with uvicorn/fastapi installed.`nPlease run the extension's backend setup first, or install the deps then re-run this script."
}

$pythonwExe = Join-Path (Split-Path -Parent $pythonExe) "pythonw.exe"
if (-not (Test-Path -LiteralPath $pythonwExe)) {
    throw "pythonw.exe not found next to $pythonExe"
}
$runScript = Join-Path $ProjectRoot "run_server.py"
if (-not (Test-Path -LiteralPath $runScript)) {
    throw "run_server.py not found at $runScript"
}

Write-Host "Python       : $pythonExe"
Write-Host "Launcher     : $pythonwExe"
Write-Host "Run script   : $runScript"

# ---------------------------------------------------------------------------
# Uninstall mode
# ---------------------------------------------------------------------------
if ($Uninstall) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'."
    } else {
        Write-Host "Scheduled task '$TaskName' was not installed."
    }
    if (Test-Path -LiteralPath $Marker) { Remove-Item -LiteralPath $Marker -Force }
    Write-Host "=== Done (uninstalled) ==="
    exit 0
}

# ---------------------------------------------------------------------------
# 2. Register / refresh the logon scheduled task (no admin required)
# ---------------------------------------------------------------------------
$action = New-ScheduledTaskAction -Execute $pythonwExe -Argument ("`"{0}`"" -f $runScript) -WorkingDirectory $ProjectRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User ([Environment]::UserName)
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "Scheduled task '$TaskName' registered (runs at logon, hidden)."

# ---------------------------------------------------------------------------
# 3. Write the marker so re-runs / status checks are easy
# ---------------------------------------------------------------------------
@"
task=$TaskName
project=$ProjectRoot
pythonw=$pythonwExe
run_script=$runScript
installed=$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

From now on, the backend starts automatically whenever you log into Windows.
The Chrome extension will wait for it and reconnect automatically.
"@ | Set-Content -LiteralPath $Marker -Encoding UTF8

# ---------------------------------------------------------------------------
# 4. Start it now (if not already up) and verify
# ---------------------------------------------------------------------------
$alreadyListening = $false
try {
    $tcp = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
    $alreadyListening = $null -ne $tcp
} catch { }

if (-not $alreadyListening) {
    Write-Host "Starting backend now..."
    Start-ScheduledTask -TaskName $TaskName
} else {
    Write-Host "Backend already listening on port 8000 — leaving it running."
}

$healthy = $false
for ($i = 0; $i -lt 10; $i++) {
    Start-Sleep -Seconds 3
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" -UseBasicParsing -TimeoutSec 3
        if ($resp.StatusCode -eq 200) { $healthy = $true; break }
    } catch { }
}

Write-Host ""
Write-Host "=== Done ==="
if ($healthy) {
    Write-Host "Backend is UP and healthy (http://127.0.0.1:8000/health)."
    Write-Host "Restart your laptop: everything starts automatically. No manual commands needed."
} else {
    Write-Warning "Backend is not responding yet — check backend\phishguard-server.log. It should come up within about 30s of logon."
}