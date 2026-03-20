# Rollback-Edge-Office.ps1
# Run as Administrator

$OfficeVersion = "16.0"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window (Run as Administrator)."
}

# Edge policies
$edgePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$edgeNames = @(
    "SmartScreenEnabled",
    "SmartScreenPuaEnabled",
    "DownloadRestrictions",
    "PreventSmartScreenPromptOverride",
    "PreventSmartScreenPromptOverrideForFiles"
)

foreach ($name in $edgeNames) {
    Remove-ItemProperty -Path $edgePolicy -Name $name -ErrorAction SilentlyContinue
}

Remove-Item -Path "$edgePolicy\ExtensionInstallBlocklist" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$edgePolicy\ExtensionInstallAllowlist" -Recurse -Force -ErrorAction SilentlyContinue

# Office policies for current user
$officeBase = "HKCU:\Software\Policies\Microsoft\Office\$OfficeVersion"

Remove-ItemProperty -Path "$officeBase\Common\Security" -Name "BlockContentExecutionFromInternet" -ErrorAction SilentlyContinue

foreach ($app in @("Word","Excel","PowerPoint")) {
    $secPath = "$officeBase\$app\Security"
    Remove-ItemProperty -Path $secPath -Name "VBAWarnings" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $secPath -Name "RequireAddinSig" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "$secPath\Trusted Locations" -Name "AllowNetworkLocations" -ErrorAction SilentlyContinue
}

# Defender rollback
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    try {
        Set-MpPreference -PUAProtection 0
    } catch {}
}

gpupdate /force | Out-Null

Write-Host "Edge + Office hardening settings removed for this user/machine." -ForegroundColor Green
