> ⚠️ Run all scripts as Administrator.  
> Test on a non-production system before use.
### Overview

This project provides a simple, practical set of PowerShell scripts to harden a Windows 11 system against accidental malware installation.

It is designed for real-world use cases such as protecting a family member or non-technical user who may unknowingly download and run unsafe software.

The solution uses a layered approach:

- AppLocker → prevents untrusted programs from running
    
- Microsoft Edge hardening → reduces risky downloads and browser threats
    
- Microsoft Office hardening → blocks macro-based attacks
    
- Microsoft Defender protections → blocks potentially unwanted apps (PUA)
    

---

## Scripts

### 1. Lockdown-AppLocker-Revised.ps1

Purpose:  
Prevents users from running downloaded or untrusted applications using Windows AppLocker.

What it does:

- Allows applications only from:
    
    - C:\Windows
        
    - C:\Program Files
        
- Blocks execution from common high-risk locations:
    
    - Downloads
        
    - Desktop
        
    - Documents
        
    - Temp folders
        
    - Browser cache
        
- Optionally blocks per-user installs:
    
    - AppData\Local\Programs
        
- Automatically allows installed Microsoft Store (AppX) apps
    
- Enables the Application Identity service
    
- Optionally enables Microsoft Defender PUA protection
    
- Creates backups in:  
    C:\AppLockerBackup
    

What it protects against:

- Downloaded .exe malware
    
- Installer files (.msi)
    
- Script-based attacks (.ps1, .bat, .cmd, etc.)
    
- Portable applications launched from user folders
    

---

### 2. Harden-Edge-Office.ps1

Purpose:  
Reduces risk from web browsing and Office documents.

Microsoft Edge hardening:

- Enables SmartScreen protection
    
- Enables PUA (potentially unwanted app) blocking
    
- Restricts downloads:
    
    - Blocks potentially dangerous downloads (default)
        
    - Optional: block all downloads
        
- Prevents bypassing SmartScreen warnings
    
- Blocks all extensions unless explicitly allowlisted
    

Microsoft Office hardening (Word, Excel, PowerPoint):

- Disables all macros
    
- Blocks content from internet-origin files
    
- Requires add-ins to be digitally signed
    
- Disables trusted locations on network shares
    

Important note:

- Office settings apply per-user (HKCU)
    
- Run this script while logged in as the target user for full effect
    

---

## Recommended Usage

1. Reset or prepare the Windows 11 system
    
2. Log in as Administrator
    
3. Install required software:
    
    - Microsoft 365 / Office
        
    - Printer drivers
        
    - Any necessary applications
        
4. Run:  
    Lockdown-AppLocker-Revised.ps1
    
5. Sign out and log in as the standard user
    
6. Run:  
    Harden-Edge-Office.ps1
    

---

## Security Model

This solution uses layered protection:

Layer: AppLocker  
Protection: Blocks execution of untrusted programs

Layer: Defender (PUA)  
Protection: Blocks unwanted or suspicious apps

Layer: Edge SmartScreen  
Protection: Blocks malicious downloads and phishing

Layer: Office Hardening  
Protection: Prevents macro-based attacks

---

## Limitations

This solution significantly reduces risk, but does not eliminate all threats.

Not fully covered:

- Phishing attacks
    
- Social engineering
    
- Malicious browser extensions (if allowlisted)
    
- Abuse of built-in Windows tools
    

---

## Requirements

- Windows 11 (Pro/Enterprise recommended for AppLocker)
    
- Administrator privileges
    
- PowerShell (run as Administrator)
    

---

## Safety Notes

- Install all required applications before applying AppLocker
    
- Test with a standard user account after setup
    
- If something breaks:
    
    - Re-run AppLocker script with:  
        $StrictPerUserAppBlock = $false
        
    - Or use rollback scripts
        

---

## Use Case

Ideal for:

- Family PCs
    
- Elderly or non-technical users
    
- Shared home computers
    
- Low-maintenance secure environments
    

---

## Disclaimer

These scripts are provided as-is. Use at your own risk.  
Always test before deploying in a production environment.