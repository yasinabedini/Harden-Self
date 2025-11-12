<#
    File:        audit_credential_protection.ps1
    Repository:  Harden‑Self / playbooks / windows / scripts
    Author:      yasinabedini
    Purpose:     Validate Credential Guard + LSA Protection policies
    Tested On:   Windows Server 2019 / 2022 / Windows 11
#>

Write-Host "`n⚙️  Harden‑Self — Credential Protection Audit" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------`n"

function Test-Result($C){if($C){"[✔] Passed"}else{"[✘] Failed"}}
$Results=@()

### 1. LSA Protection
$lsaReg=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL
$Results+=[pscustomobject]@{Check="LSA Protection (RunAsPPL)";Status=Test-Result($lsaReg -eq 1)}

### 2. Credential Guard
$cguard=(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard").SecurityServicesRunning
$Results+=[pscustomobject]@{Check="Credential Guard Running";Status=Test-Result(($cguard -contains 1))}

### 3. NTLMv1 Disabled
$lmCompat=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue)."LmCompatibilityLevel"
$Results+=[pscustomobject]@{Check="NTLMv1 Disabled";Status=Test-Result($lmCompat -ge 5)}

### 4. AMSI Active
$amsi=(Get-ItemProperty "HKLM:\Software\Microsoft\AMSI" -ErrorAction SilentlyContinue)
$Results+=[pscustomobject]@{Check="AMSI Active";Status=Test-Result($amsi -ne $null)}

### 5. Defender RealTime
$def=(Get-MpComputerStatus).AntivirusEnabled
$Results+=[pscustomobject]@{Check="Defender Active";Status=Test-Result($def)}

$Results|Format-Table -AutoSize
Write-Host "`n🧩  Credential Protection audit complete.`n"-ForegroundColor Yellow
