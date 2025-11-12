<#
    File:        audit_rdp.ps1
    Repository:  Harden‑Self / playbooks / windows
    Author:      yasinabedini
    Purpose:     Validate RDP Hardening baselines on Windows Hosts
    Tested On:   Windows Server 2019 / 2022 / Windows 11
#>

Write-Host "`n🛡️  Harden‑Self — RDP Hardening Audit" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------`n"

# Utility function to return ✔ or ✘
function Test-Result($Condition) {
    if ($Condition) { return "[✔] Passed" } else { return "[✘] Failed" }
}

# Collect results
$Results = @()

### 1. Network Level Authentication
$UserAuth = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").UserAuthentication
$Results += [pscustomobject]@{
    Check = "NLA Enabled"
    Status = Test-Result ($UserAuth -eq 1)
}

### 2. Encryption & TLS
$EncLevel = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").MinEncryptionLevel
$SecLayer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").SecurityLayer
$Results += [pscustomobject]@{
    Check = "TLS SecurityLayer=2 & MinEncryptionLevel=3"
    Status = Test-Result (($EncLevel -eq 3) -and ($SecLayer -eq 2))
}

### 3. Redirection Disabled
$redirKeys = @("fDisableClip","fDisableDrive","fDisableCcm","fDisableLPT","fDisablePNPRedir")
$redirOk = $true
foreach ($key in $redirKeys) {
    $v = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue).$key
    if ($v -ne 1) { $redirOk = $false }
}
$Results += [pscustomobject]@{
    Check = "All Redirections Disabled"
    Status = Test-Result $redirOk
}

### 4. Session Idle & Disconnect Timeout
$path = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$idle = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).MaxIdleTime
$disc = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).MaxDisconnectionTime
$Results += [pscustomobject]@{
    Check = "Idle <=15min & Disconnect <=10min"
    Status = Test-Result (($idle -eq 900000) -and ($disc -eq 600000))
}

### 5. Restrict RDP Logon Rights (Administrators only)
$allowed = (secedit /export /cfg "$env:TEMP\secp.cfg" | Out-Null; 
            (Select-String "SeRemoteInteractiveLogonRight" "$env:TEMP\secp.cfg").ToString())
Remove-Item "$env:TEMP\secp.cfg" -Force -ErrorAction SilentlyContinue
$Results += [pscustomobject]@{
    Check = "Only Administrators allowed RDP logon"
    Status = Test-Result ($allowed -match "BUILTIN\\Administrators")
}

### 6. Credential Guard
$LsaCfg = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).LsaCfgFlags
$VBS = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
$Results += [pscustomobject]@{
    Check = "Credential Guard + VBS Enabled"
    Status = Test-Result (($LsaCfg -eq 1) -and ($VBS -eq 1))
}

### 7. Smart Card / MFA Requirement
$SmartCard = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue).fEnableSmartCard
$Results += [pscustomobject]@{
    Check = "SmartCard / MFA Enforced"
    Status = Test-Result ($SmartCard -eq 1)
}

### 8. Account Lockout Policy
$LockoutThreshold = (net accounts | Select-String "Lockout threshold").ToString().Split(":")[1].Trim()
$Results += [pscustomobject]@{
    Check = "Lockout Threshold <= 5"
    Status = Test-Result ([int]$LockoutThreshold -le 5)
}

### 9. Firewall & Port
$rdpPort = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").PortNumber
$firewallStatus = ((Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'True'}).Count -ge 1)
$Results += [pscustomobject]@{
    Check = "Firewall Enabled & RDP Port ≠ 3389"
    Status = Test-Result ($firewallStatus -and ($rdpPort -ne 3389))
}

### 10. RDP Auditing Enabled
$audit1 = (auditpol /get /subcategory:"Logon" | Select-String "Success").ToString()
$audit2 = (auditpol /get /subcategory:"Network Connection" | Select-String "Success").ToString()
$auditOK = ($audit1 -match "Success and Failure") -and ($audit2 -match "Success and Failure")
$Results += [pscustomobject]@{
    Check = "RDP Auditing (Logon + Network Connection)"
    Status = Test-Result $auditOK
}

### 11. Dynamic Firewall Rule for Brute‑Force Protection
$rule = Get-NetFirewallRule -DisplayName "TEMP_Block_RDP_BruteForce" -ErrorAction SilentlyContinue
$Results += [pscustomobject]@{
    Check = "Dynamic Brute‑Force Rule Exists"
    Status = Test-Result ($null -ne $rule)
}

# Output summary
$Results | Format-Table -AutoSize -Wrap
Write-Host "`n🧩  Completed. Review any ❌ Failed items for remediation.`n" -ForegroundColor Yellow
