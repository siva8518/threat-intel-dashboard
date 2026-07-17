# Restarts the Threat Intel Dashboard backend + Ollama on a schedule.
#
# Guards against a recurring memory-exhaustion pattern found live on this
# machine (2026-07-17): Ollama's llama-server subprocesses leak on
# crash/restart cycles -- each one leaves ~150-400MB behind instead of
# freeing it -- which compounds over a few hours into genuine OS-level
# memory exhaustion. That eventually crashed Ollama's own inference calls
# outright ("failed to allocate buffer... unable to allocate CPU buffer"),
# then Node itself ("FATAL ERROR: process out of memory"), which took the
# whole dashboard down since every widget depends on the backend. A
# periodic full restart clears both accumulated leaks before they reach
# that point, mirroring the exact manual recovery steps used to fix this
# live: stop the backend, clear leaked llama-server processes, force a
# clean Ollama restart, start a fresh backend.
#
# Registered as the "ThreatIntelDashboard-BackendRestart" Scheduled Task
# (see scripts/register-restart-task.ps1), running every 6 hours.

$ProjectDir = "C:\Users\sivak\OneDrive\Desktop\threat-intel-dashboard"
$NodeExe = "C:\Program Files\nodejs\node.exe"
$LogDir = Join-Path $ProjectDir "logs"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}

# Keep at most 7 days of restart logs -- this runs every 6 hours forever,
# so unbounded log files would otherwise accumulate indefinitely.
Get-ChildItem $LogDir -Filter "backend-*.log" -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } |
    Remove-Item -Force -ErrorAction SilentlyContinue

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutLog = Join-Path $LogDir "backend-$Timestamp.log"
$ErrLog = Join-Path $LogDir "backend-$Timestamp.err.log"

# 1. Stop the current backend, whatever's listening on 8080.
$conn = Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    foreach ($c in $conn) {
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2
}

# 2. Clear any leaked llama-server subprocesses (see header comment).
Get-Process -Name "llama-server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# 3. Force a clean Ollama restart every cycle -- its own tray launcher
# ("ollama app.exe", left untouched here) relaunches ollama.exe within a
# few seconds on its own, confirmed reliable throughout today's session.
Stop-Process -Name "ollama" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# 4. Start a fresh backend, detached, logging to its own timestamped files.
Start-Process -FilePath $NodeExe -ArgumentList "server/index.js" -WorkingDirectory $ProjectDir `
    -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog -WindowStyle Hidden
