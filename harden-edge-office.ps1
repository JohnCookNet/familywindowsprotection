# Harden-Edge-Office.ps1
# Run as Administrator
#
# Intended for a simple "Word + Edge" machine.
# Review the settings at the top before running.

$BlockAllDownloads = $false
# false = block potentially dangerous downloads (recommended balance)
# true  = block all downloads in Edge

$BlockAllExtensions = $true
# true  = blocks all Edge extensions unless explicitly allowlisted below

$AllowedEdgeExtensions = @(
    # Example:
    # "extension_id_here"
)

$OfficeVersion = "16.0"   # Microsoft 365 / Office 2016+ policy path

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window (Run as Administrator)."
}

function Ensure-Key {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Set-DwordValue {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    Ensure-Key -Path $Path
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Set-StringValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )
    Ensure-Key -Path $Path
    New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
}

# -------------------------------------------------
# Edge policy hardening (machine-wide)
# Policy path documented by Microsoft:
# HKLM\SOFTWARE\Policies\Microsoft\Edge
# -------------------------------------------------
$edgePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
Ensure-Key $edgePolicy

# SmartScreen on
Set-DwordValue -Path $edgePolicy -Name "SmartScreenEnabled" -Value 1

# SmartScreen PUA blocking on
Set-DwordValue -Path $edgePolicy -Name "SmartScreenPuaEnabled" -Value 1

# DownloadRestrictions values:
# 0 = no special restrictions
# 1 = BlockMaliciousDownloads
# 2 = BlockPotentiallyDangerousDownloads
# 3 = BlockAllDownloads
$downloadMode = if ($BlockAllDownloads) { 3 } else { 2 }
Set-DwordValue -Path $edgePolicy -Name "DownloadRestrictions" -Value $downloadMode

# Optional extra SmartScreen hardening:
# Prevent bypassing SmartScreen warnings for files and sites
Set-DwordValue -Path $edgePolicy -Name "PreventSmartScreenPromptOverride" -Value 1
Set-DwordValue -Path $edgePolicy -Name "PreventSmartScreenPromptOverrideForFiles" -Value 1

# Block all extensions unless allowlisted
if ($BlockAllExtensions) {
    $extBlockPath = Join-Path $edgePolicy "ExtensionInstallBlocklist"
    Ensure-Key $extBlockPath
    New-ItemProperty -Path $extBlockPath -Name "1" -PropertyType String -Value "*" -Force | Out-Null

    if ($AllowedEdgeExtensions.Count -gt 0) {
        $extAllowPath = Join-Path $edgePolicy "ExtensionInstallAllowlist"
        Ensure-Key $extAllowPath

        $i = 1
        foreach ($ext in $AllowedEdgeExtensions) {
            New-ItemProperty -Path $extAllowPath -Name ([string]$i) -PropertyType String -Value $ext -Force | Out-Null
            $i++
        }
    }
}

# -------------------------------------------------
# Office hardening (per-user policy)
# Applied to HKCU so it governs the signed-in user.
# Run once while signed in as the protected user account if you want it applied directly there.
# -------------------------------------------------
$officeBase = "HKCU:\Software\Policies\Microsoft\Office\$OfficeVersion"
Ensure-Key $officeBase

# Common security policy
$officeCommonSecurity = "$officeBase\Common\Security"
Ensure-Key $officeCommonSecurity

# Block macros/content from internet-origin files
Set-DwordValue -Path $officeCommonSecurity -Name "BlockContentExecutionFromInternet" -Value 1

# Office apps to harden
$apps = @("Word","Excel","PowerPoint")

foreach ($app in $apps) {
    $secPath = "$officeBase\$app\Security"
    Ensure-Key $secPath

    # VBAWarnings:
    # 1 = Enable all macros
    # 2 = Disable all macros with notification
    # 3 = Disable all macros except digitally signed macros
    # 4 = Disable all macros without notification
    #
    # For a family machine, 4 is the strongest / simplest.
    Set-DwordValue -Path $secPath -Name "VBAWarnings" -Value 4

    # Require add-ins to be signed by Trusted Publisher
    Set-DwordValue -Path $secPath -Name "RequireAddinSig" -Value 1

    # Do not allow trusted locations on network shares
    $trustedLocPath = "$secPath\Trusted Locations"
    Ensure-Key $trustedLocPath
    Set-DwordValue -Path $trustedLocPath -Name "AllowNetworkLocations" -Value 0
}

# -------------------------------------------------
# Defender PUA protection (machine-wide) if available
# -------------------------------------------------
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    try {
        Set-MpPreference -PUAProtection 1
        try { Set-MpPreference -ScanDownloads $true } catch {}
        Write-Host "Microsoft Defender PUA protection enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Could not configure Defender preferences: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

gpupdate /force | Out-Null

Write-Host ""
Write-Host "Edge + Office hardening applied." -ForegroundColor Green
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host " - Edge SmartScreen enabled"
Write-Host " - Edge PUA blocking enabled"
Write-Host " - Edge download restriction mode: $downloadMode"
if ($BlockAllExtensions) {
    Write-Host " - Edge extensions blocked except allowlist"
}
Write-Host " - Office internet-origin macro blocking enabled"
Write-Host " - Word/Excel/PowerPoint macros disabled"
Write-Host " - Office add-ins must be signed by Trusted Publisher"
Write-Host " - Network trusted locations disabled"
Write-Host ""
Write-Host "Important: For the Office HKCU policy, run this while signed into the protected user's account if you want the settings applied directly to that user."
