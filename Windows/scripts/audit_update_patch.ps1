<#
    File:        audit_update_patch.ps1
    Repository:  Harden‑Self / playbooks / windows / scripts
    Author:      yasinabedini
    Purpose:     Validate Windows Update & Patch Management settings
    Tested On:   Windows Server 2019 / 2022 / Windows 11
#>

Write-Host "`n⚙️  Harden‑Self — Windows Update Audit" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------`n"

function Test-Result($C){if($C){"[✔] Passed"}else{"[✘] Failed"}}
$Results=@()

### 1. Automatic Updates Enabled
$au=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue).AUOptions
$Results+=[pscustomobject]@{Check="Automatic Updates Enabled";Status=Test-Result($au -eq 4)}

### 2. WSUS Source
$source=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue).WUServer
$Results+=[pscustomobject]@{Check="Update Source Controlled (WSUS)";Status=Test-Result($source)}

### 3. Driver Signature Enforcement
$drv=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DriverSigning" -ErrorAction SilentlyContinue).DriverSigning
$Results+=[pscustomobject]@{Check="Driver Signing Required";Status=Test-Result($drv -eq 1)}

### 4. Reboot Protection
$noreboot=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue).NoAutoRebootWithLoggedOnUsers
$Results+=[pscustomobject]@{Check="No Auto Reboot With Logged Users";Status=Test-Result($noreboot -eq 1)}

### 5. Event ID Verification
$evUpd=Get-WinEvent -FilterHashtable @{LogName='System';Id=19} -MaxEvents 1 -ErrorAction SilentlyContinue
$Results+=[pscustomobject]@{Check="Update Events Present";Status=Test-Result($evUpd)}

$Results|Format-Table -AutoSize
Write-Host "`n🧩  Update/Patch Audit complete.`n"-ForegroundColor Yellow
