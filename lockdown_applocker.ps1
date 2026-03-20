# Lockdown-AppLocker-Revised.ps1
# Purpose:
#   - Keep a standard user from running/installing most downloaded apps, installers, and scripts
#   - Cover classic apps (EXE/MSI/Script) plus installed packaged apps
#   - Optionally enable Microsoft Defender PUA protection
#
# Run from an elevated PowerShell window.
# Recommended timing: after Office / Edge / printer software / approved apps are already installed.

$StrictPerUserAppBlock = $true    # Blocks %LocalAppData%\Programs\* too. Set to $false if you need to allow per-user apps.
$EnableDefenderPUA     = $true    # Turns on Microsoft Defender PUA protection if Defender cmdlets are present.
$BackupDir             = "C:\AppLockerBackup"

# ----------------------------
# Preconditions
# ----------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window (Run as Administrator)."
}

if (-not (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue)) {
    throw "AppLocker cmdlets not found. AppLocker may be unavailable on this Windows edition/configuration."
}

New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

# Backup current local AppLocker policy if one exists
try {
    $existingPolicyXml = Get-AppLockerPolicy -Local -Xml
    if ($existingPolicyXml) {
        $existingPolicyXml | Out-File -FilePath (Join-Path $BackupDir "AppLocker-Backup-Existing.xml") -Encoding utf8
    }
} catch {
    Write-Host "No existing local AppLocker policy found to back up." -ForegroundColor Yellow
}

$usersSid    = "S-1-5-32-545"  # BUILTIN\Users
$everyoneSid = "S-1-1-0"       # Everyone
$adminsSid   = "S-1-5-32-544"  # BUILTIN\Administrators

# ----------------------------
# High-risk user-writeable paths
# ----------------------------
$blockedPaths = @(
    '%OSDRIVE%\Users\*\Downloads\*',
    '%OSDRIVE%\Users\*\Desktop\*',
    '%OSDRIVE%\Users\*\Documents\*',
    '%OSDRIVE%\Users\*\AppData\Local\Temp\*',
    '%OSDRIVE%\Users\*\AppData\Local\Microsoft\Windows\INetCache\*',
    '%OSDRIVE%\Users\*\AppData\Local\Packages\*\TempState\*'
)

if ($StrictPerUserAppBlock) {
    $blockedPaths += '%OSDRIVE%\Users\*\AppData\Local\Programs\*'
}

# ----------------------------
# XML helpers for classic app collections
# ----------------------------
function New-PathRuleXml {
    param(
        [string]$Name,
        [string]$Sid,
        [string]$Action,
        [string]$Path
    )

@"
    <FilePathRule Id="$([guid]::NewGuid().Guid)" Name="$Name" Description="" UserOrGroupSid="$Sid" Action="$Action">
      <Conditions>
        <FilePathCondition Path="$Path" />
      </Conditions>
    </FilePathRule>
"@
}

function New-ExeCollection {
    param([string[]]$DenyPaths)

    $rules = @()
    $rules += New-PathRuleXml -Name "Allow Administrators - all EXE files" -Sid $adminsSid -Action "Allow" -Path "*"
    $rules += New-PathRuleXml -Name "Allow Everyone - Windows folder" -Sid $everyoneSid -Action "Allow" -Path "%WINDIR%\*"
    $rules += New-PathRuleXml -Name "Allow Everyone - Program Files" -Sid $everyoneSid -Action "Allow" -Path "%PROGRAMFILES%\*"
    $rules += New-PathRuleXml -Name "Allow Everyone - Program Files x86" -Sid $everyoneSid -Action "Allow" -Path "%OSDRIVE%\Program Files (x86)\*"

    foreach ($p in $DenyPaths) {
        $rules += New-PathRuleXml -Name "Deny Users - $p" -Sid $usersSid -Action "Deny" -Path $p
    }

@"
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
$($rules -join "`n")
  </RuleCollection>
"@
}

function New-MsiCollection {
    param([string[]]$DenyPaths)

    $rules = @()
    $rules += New-PathRuleXml -Name "Allow Administrators - all MSI/MSP/MST files" -Sid $adminsSid -Action "Allow" -Path "*"
    $rules += New-PathRuleXml -Name "Allow Everyone - Windows Installer cache" -Sid $everyoneSid -Action "Allow" -Path "%WINDIR%\Installer\*"

    foreach ($p in $DenyPaths) {
        $rules += New-PathRuleXml -Name "Deny Users - $p" -Sid $usersSid -Action "Deny" -Path $p
    }

@"
  <RuleCollection Type="Msi" EnforcementMode="Enabled">
$($rules -join "`n")
  </RuleCollection>
"@
}

function New-ScriptCollection {
    param([string[]]$DenyPaths)

    $rules = @()
    $rules += New-PathRuleXml -Name "Allow Administrators - all scripts" -Sid $adminsSid -Action "Allow" -Path "*"
    $rules += New-PathRuleXml -Name "Allow Everyone - Windows folder scripts" -Sid $everyoneSid -Action "Allow" -Path "%WINDIR%\*"
    $rules += New-PathRuleXml -Name "Allow Everyone - Program Files scripts" -Sid $everyoneSid -Action "Allow" -Path "%PROGRAMFILES%\*"
    $rules += New-PathRuleXml -Name "Allow Everyone - Program Files x86 scripts" -Sid $everyoneSid -Action "Allow" -Path "%OSDRIVE%\Program Files (x86)\*"

    foreach ($p in $DenyPaths) {
        $rules += New-PathRuleXml -Name "Deny Users - $p" -Sid $usersSid -Action "Deny" -Path $p
    }

@"
  <RuleCollection Type="Script" EnforcementMode="Enabled">
$($rules -join "`n")
  </RuleCollection>
"@
}

# ----------------------------
# Build base classic-app policy
# ----------------------------
$basePolicyXml = @"
<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">
$(New-ExeCollection -DenyPaths $blockedPaths)
$(New-MsiCollection -DenyPaths $blockedPaths)
$(New-ScriptCollection -DenyPaths $blockedPaths)
</AppLockerPolicy>
"@

$basePolicyPath = Join-Path $BackupDir "AppLocker-BasePolicy.xml"
$basePolicyXml | Out-File -FilePath $basePolicyPath -Encoding utf8

# ----------------------------
# Start AppLocker service
# ----------------------------
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc

# ----------------------------
# Apply base policy
# ----------------------------
[xml]$baseXmlDoc = Get-Content -Path $basePolicyPath
Set-AppLockerPolicy -XmlPolicy $baseXmlDoc

# ----------------------------
# Add packaged app allow rules for what is already installed
# This helps keep built-in/installed AppX packages working while still controlling packaged apps.
# ----------------------------
try {
    $appxPackages = Get-AppxPackage -AllUsers -ErrorAction Stop

    if ($appxPackages -and $appxPackages.Count -gt 0) {
        $pkgFileInfo = $appxPackages | Get-AppLockerFileInformation -ErrorAction Stop

        if ($pkgFileInfo) {
            $packagedPolicyXml = $pkgFileInfo |
                New-AppLockerPolicy -RuleType Publisher -User Everyone -Optimize -Xml

            $packagedPolicyPath = Join-Path $BackupDir "AppLocker-PackagedApps.xml"
            $packagedPolicyXml | Out-File -FilePath $packagedPolicyPath -Encoding utf8

            [xml]$packagedXmlDoc = Get-Content -Path $packagedPolicyPath
            Set-AppLockerPolicy -XmlPolicy $packagedXmlDoc -Merge

            Write-Host "Packaged app allow rules generated from currently installed packages." -ForegroundColor Green
        }
        else {
            Write-Host "No packaged app file information was generated." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "No AppX packages returned by Get-AppxPackage -AllUsers." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Could not generate packaged app rules automatically: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "Classic EXE/MSI/Script rules were still applied." -ForegroundColor Yellow
}

# ----------------------------
# Optional Defender hardening
# ----------------------------
if ($EnableDefenderPUA -and (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
    try {
        # 1 = Enable PUA protection
        Set-MpPreference -PUAProtection 1

        # Optional: keep downloaded files and email attachments checked more aggressively if available
        try { Set-MpPreference -ScanDownloads $true } catch {}
        try { Set-MpPreference -DisableEmailScanning $false } catch {}

        Write-Host "Microsoft Defender PUA protection enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Unable to configure Defender PUA settings: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

gpupdate /force | Out-Null

Write-Host ""
Write-Host "Lockdown policy applied." -ForegroundColor Green
Write-Host "Have the restricted user sign out and sign back in."
Write-Host ""
Write-Host "Blocked classic-app launch locations for standard users:" -ForegroundColor Yellow
$blockedPaths | ForEach-Object { Write-Host " - $_" }
Write-Host ""
Write-Host "Backups / generated policy files:" -ForegroundColor Yellow
Write-Host " - $BackupDir"
Write-Host ""
Write-Host "Notes:" -ForegroundColor Cyan
Write-Host " - This is strongest when the user is a Standard User, not an Administrator."
Write-Host " - Install Office / approved software before applying."
Write-Host " - If something legitimate breaks, first try setting `$StrictPerUserAppBlock = `$false and reapply."