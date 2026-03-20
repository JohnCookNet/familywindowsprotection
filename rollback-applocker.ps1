# Rollback-AppLocker-Revised.ps1
# Run as Administrator

$BackupDir = "C:\AppLockerBackup"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window (Run as Administrator)."
}

Write-Host ""
Write-Host "Rolling back local AppLocker policy..." -ForegroundColor Yellow

# Remove local AppLocker policy
Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2' -Recurse -Force -ErrorAction SilentlyContinue

# Stop forcing Application Identity service to auto-start
try {
    Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
} catch {}

try {
    Set-Service -Name AppIDSvc -StartupType Manual -ErrorAction SilentlyContinue
} catch {}

gpupdate /force | Out-Null

Write-Host ""
Write-Host "Local AppLocker policy removed." -ForegroundColor Green
Write-Host "Have the restricted user sign out and sign back in."
Write-Host ""

if (Test-Path $BackupDir) {
    Write-Host "Backup folder still exists at:" -ForegroundColor Cyan
    Write-Host " $BackupDir"
    Write-Host ""
    Write-Host "If needed, you may find these files there:" -ForegroundColor Cyan
    Write-Host " - AppLocker-Backup-Existing.xml"
    Write-Host " - AppLocker-BasePolicy.xml"
    Write-Host " - AppLocker-PackagedApps.xml"
}
