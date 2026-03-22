#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Arobi Network node as a Windows startup task.
    Runs at system BOOT as SYSTEM — no login required, auto-restarts on crash.

.USAGE
    Right-click PowerShell → "Run as administrator", then:
    powershell -ExecutionPolicy Bypass -File scripts\install-startup.ps1
#>

$ErrorActionPreference = 'Stop'

# ── Paths ────────────────────────────────────────────────────────────────────
$BinarySource = Join-Path $PSScriptRoot "..\target\release\arobi-network.exe"
$DataDir      = "$env:USERPROFILE\.arobi"
$BinaryDest   = "$DataDir\arobi-network.exe"
$WalletPath   = "$DataDir\wallet.json"
$LogFile      = "$DataDir\node.log"
$SeedFile     = "$DataDir\seeds.txt"
$AdvertiseFile= "$DataDir\advertise.txt"
$TaskName     = "ArobiNetworkNode"

Write-Host ""
Write-Host "  AROBI Network Node — Startup Installer" -ForegroundColor Cyan
Write-Host "  ─────────────────────────────────────────"
Write-Host ""

# ── Validate ─────────────────────────────────────────────────────────────────
if (-not (Test-Path $BinarySource)) {
    Write-Error "Binary not found at $BinarySource`nRun 'cargo build --release' first."
    exit 1
}
if (-not (Test-Path $WalletPath)) {
    Write-Error "Wallet not found at $WalletPath`nRun 'arobi-network wallet new' first."
    exit 1
}

$walletJson  = Get-Content $WalletPath | ConvertFrom-Json
$nodeAddress = $walletJson.address
Write-Host "  Wallet address : $nodeAddress" -ForegroundColor Green
Write-Host "  Data dir       : $DataDir"
Write-Host "  Log file       : $LogFile"
Write-Host "  Seed file      : $SeedFile"
Write-Host "  Advertise file : $AdvertiseFile"
Write-Host ""

# ── Step 1: Copy binary to stable path ───────────────────────────────────────
Write-Host "[1/3] Copying binary to stable location..."
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
Copy-Item -Path $BinarySource -Destination $BinaryDest -Force
Write-Host "      $BinaryDest"

# Create seed + advertise files if missing (persisted startup config)
if (-not (Test-Path $SeedFile)) {
    @(
        "# One peer endpoint per line (host:port or ip:port)",
        "# Example:",
        "# p2p.aura-genesis.org:30333"
    ) | Set-Content -Path $SeedFile -Encoding UTF8
}

if (-not (Test-Path $AdvertiseFile)) {
    @(
        "# Endpoint this node advertises to peers",
        "p2p.aura-genesis.org:30333"
    ) | Set-Content -Path $AdvertiseFile -Encoding UTF8
}

# ── Step 2: Register scheduled task ──────────────────────────────────────────
Write-Host "[2/3] Registering scheduled task '$TaskName'..."

# Wrap in powershell to capture logs and enable auto-restart on crash
$Command = "& '$BinaryDest' start" +
           " --data-dir '$DataDir'" +
           " --api-port 8099" +
           " --p2p-port 30333" +
           " --seed-file '$SeedFile'" +
           " --advertise-file '$AdvertiseFile'" +
           " --redial-secs 15" +
           " *>> '$LogFile'"

$Action = New-ScheduledTaskAction `
    -Execute   "powershell.exe" `
    -Argument  "-NonInteractive -WindowStyle Hidden -Command `"$Command`"" `
    -WorkingDirectory $DataDir

$Trigger = New-ScheduledTaskTrigger -AtStartup

$Settings = New-ScheduledTaskSettingsSet `
    -RestartCount       9999 `
    -RestartInterval    (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Days 3650) `
    -MultipleInstances  IgnoreNew

$Principal = New-ScheduledTaskPrincipal `
    -UserId    "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel  Highest

# Remove existing task if present
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "      Removing existing task first..."
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask `
    -TaskName    $TaskName `
    -Action      $Action `
    -Trigger     $Trigger `
    -Settings    $Settings `
    -Principal   $Principal `
    -Description "Arobi Network validator node — $nodeAddress" `
    | Out-Null

# ── Step 3: Start now ────────────────────────────────────────────────────────
Write-Host "[3/3] Starting node now..."
Start-ScheduledTask -TaskName $TaskName

Start-Sleep -Seconds 3
$state = (Get-ScheduledTask -TaskName $TaskName).State
Write-Host "      Task state: $state" -ForegroundColor $(if ($state -eq 'Running') { 'Green' } else { 'Yellow' })

Write-Host ""
Write-Host "  ✅  Node installed and running!" -ForegroundColor Green
Write-Host ""
Write-Host "  API   : http://localhost:8099/api/v1/info"
Write-Host "  P2P   : :30333"
Write-Host "  Logs  : $LogFile"
Write-Host "  Seeds : $SeedFile"
Write-Host "  Adv   : $AdvertiseFile"
Write-Host ""
Write-Host "  Management commands:" -ForegroundColor Cyan
Write-Host "    Check status : Get-ScheduledTask -TaskName '$TaskName' | Select-Object TaskName,State"
Write-Host "    View logs    : Get-Content '$LogFile' -Tail 50"
Write-Host "    Stop node    : Stop-ScheduledTask -TaskName '$TaskName'"
Write-Host "    Start node   : Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "    Uninstall    : powershell -File scripts\uninstall-startup.ps1"
Write-Host ""

# Quick health check
Start-Sleep -Seconds 5
try {
    $info = Invoke-RestMethod "http://localhost:8099/api/v1/info" -TimeoutSec 5
    Write-Host "  Node health  : Block #$($info.height)  ·  $($info.peer_count) peers" -ForegroundColor Green
} catch {
    Write-Host "  Node health  : Starting up... check logs in a few seconds" -ForegroundColor Yellow
}
Write-Host ""
