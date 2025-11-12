<#
    File:        audit_service_policy.ps1
    Repository:  Harden‑Self / playbooks / windows / scripts
    Author:      yasinabedini
    Purpose:     Validate Scheduled Task & Service Policy Hardening
    Tested On:   Windows Server 2019 / 2022 / Windows 11
#>

Write-Host "`n⚙️  Harden‑Self — Service & Scheduled Task Audit" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------`n"

function Test-Result($C){if($C){"[✔] Passed"}else{"[✘] Failed"}}
$Results=@()

### 1. Unexpected SYSTEM Tasks
$sysTask=(Get-ScheduledTask|Where-Object{$_.Principal.RunLevel -eq "Highest" -and $_.Principal.UserId -eq "SYSTEM"}).Count
$Results+=[pscustomobject]@{Check="Excessive SYSTEM Privileged Tasks";Status=Test-Result($sysTask -lt 5)}

### 2. Unauthorized Services
$badSvc=(Get-WmiObject Win32_Service|Where-Object{$_.StartMode -eq "Auto" -and $_.PathName -like "*Users*"}).Count
$Results+=[pscustomobject]@{Check="Unauthorized Auto Services";Status=Test-Result($badSvc -eq 0)}

### 3. Service Account Minimization
$svcAccs=(Get-WmiObject Win32_Service|Where-Object{$_.StartName -eq "LocalSystem"}).Count
$Results+=[pscustomobject]@{Check="Service Accounts Minimized";Status=Test-Result($svcAccs -lt 100)}

### 4. Event Monitoring 7045
$evSvc=Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 1 -ErrorAction SilentlyContinue
$Results+=[pscustomobject]@{Check="Event 7045 Log Enabled";Status=Test-Result($evSvc)}

$Results|Format-Table -AutoSize
Write-Host "`n🧩  Service Policy compliance checked.`n"-ForegroundColor Yellow
