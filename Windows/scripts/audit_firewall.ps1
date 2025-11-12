<#
    File:        audit_firewall.ps1
    Repository:  Harden‑Self / playbooks / windows / scripts
    Author:      yasinabedini
    Purpose:     Validate Windows Firewall Isolation & Logging
    Tested On:   Windows Server 2019 / 2022 / Windows 11
#>

Write-Host "`n⚙️  Harden‑Self — Firewall Isolation Audit" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------`n"

function Test-Result($C){if($C){"[✔] Passed"}else{"[✘] Failed"}}
$Results=@()

### 1. Firewall Enabled (All Profiles)
$fwOK=(Get-NetFirewallProfile|Where-Object{$_.Enabled -eq $true}).Count -eq 3
$Results+=[pscustomobject]@{Check="Firewall Enabled (Domain/Private/Public)";Status=Test-Result($fwOK)}

### 2. Logging Active
$logEnabled=(Get-NetFirewallProfile).LogFileName|Where-Object{Test-Path $_}
$Results+=[pscustomobject]@{Check="Firewall Logging Active";Status=Test-Result($logEnabled)}

### 3. Block Outbound Unauthorized
$outRules=(Get-NetFirewallRule|Where-Object{($_.Direction -eq 'Outbound') -and ($_.Action -eq 'Allow')}).Count
$Results+=[pscustomobject]@{Check="Outbound Restriction";Status=Test-Result($outRules -lt 200)}

### 4. SMB Signing Required
$smbSign=(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters").RequireSecuritySignature
$Results+=[pscustomobject]@{Check="SMB Signing Required";Status=Test-Result($smbSign -eq 1)}

### 5. Default Zone Segmentation
$policy=(Get-NetConnectionProfile).NetworkCategory -contains 'DomainAuthenticated'
$Results+=[pscustomobject]@{Check="Zone Segmentation Config";Status=Test-Result($policy)}

$Results|Format-Table -AutoSize
Write-Host "`n🧩  Audit completed — Firewall isolation check ended.`n"-ForegroundColor Yellow
