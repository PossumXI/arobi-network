#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stops and removes the Arobi Network startup task.
.USAGE
    powershell -ExecutionPolicy Bypass -File scripts\uninstall-startup.ps1
#>

$TaskName = "ArobiNetworkNode"

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) {
    Write-Host "Task '$TaskName' is not installed." -ForegroundColor Yellow
    exit 0
}

Write-Host "Stopping task..."
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "Removing task..."
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false

Write-Host ""
Write-Host "✅  '$TaskName' removed. Node will no longer start at boot." -ForegroundColor Green
Write-Host "    The binary at $env:USERPROFILE\.arobi\arobi-network.exe and wallet.json are untouched."
