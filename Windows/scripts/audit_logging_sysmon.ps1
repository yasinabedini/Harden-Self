<#
    File:        audit_logging_sysmon.ps1
    Repository:  Harden‑Self / playbooks / windows / scripts
    Author:      yasinabedini
    Purpose:     Validate Audit Policy & Sysmon Logging baseline
    Tested On:   Windows Server 2019 / 2022 / Windows 11
#>

Write-Host "`n⚙️  Harden‑Self — Logging & Sysmon Audit" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------`n"

function Test-Result($C){if($C){"[✔] Passed"}else{"[✘] Failed"}}
$Results=@()

### 1. Audit Policy Active
$Audit=(AuditPol /get /category:* | Select-String "Success and Failure").Count
$Results+=[pscustomobject]@{Check="Audit Policy Success+Failure";Status=Test-Result($Audit -gt 5)}

### 2. Event Retention
$ret=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows\EventLog\Security").Retention
$Results+=[pscustomobject]@{Check="Log Retention Configured";Status=Test-Result($ret -ne $null)}

### 3. Sysmon Service
$sys=(Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue).Status
$Results+=[pscustomobject]@{Check="Sysmon Service Running";Status=Test-Result($sys -eq "Running")}

### 4. Sysmon Config Validated
$cfg=(Get-Item "C:\Windows\Sysmon.xml" -ErrorAction SilentlyContinue)
$Results+=[pscustomobject]@{Check="Sysmon Configuration Found";Status=Test-Result($cfg)}

### 5. Critical Event ID presence
$ev=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=1,3,10} -MaxEvents 3 -ErrorAction SilentlyContinue
$Results+=[pscustomobject]@{Check="Sysmon Event Stream Active";Status=Test-Result($ev.Count -ge 1)}

$Results|Format-Table -AutoSize
Write-Host "`n🧩  Logging/Sysmon audit complete.`n"-ForegroundColor Yellow
