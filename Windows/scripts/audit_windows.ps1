# Author: yasinabedini
# Purpose: Audit basic Windows Hardening configuration
# Tested on: Windows Server 2019, 2022, Windows 10/11

Write-Host "=== Windows Hardening Audit ==="
$score = 0
$total = 10

function pass { param($msg) Write-Host "[+] $msg OK"; $GLOBALS:score++ }
function warn { param($msg) Write-Host "[!] $msg WARN" }

# 1 - Password Policy
$pwd = (Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue)
if ($pwd.MinPasswordLength -ge 12 -and $pwd.ComplexityEnabled) { pass "Password Policy" } else { warn "Weak Password Policy" }

# 2 - Audit Policy
$audit = (auditpol /get /category:"Logon/Logoff")
if ($audit -match "Success" -and $audit -match "Failure") { pass "Audit Policy" } else { warn "Incomplete Audit Policy" }

# 3 - UAC
$uac = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
if ($uac.EnableLUA -eq 1 -and $uac.ConsentPromptBehaviorAdmin -eq 2) { pass "UAC Level" } else { warn "UAC Configuration" }

# 4 - SMB Signing
$smb = Get-SmbServerConfiguration
if ($smb.EnableSecuritySignature -and -not $smb.EnableSMB1Protocol) { pass "SMB Signing" } else { warn "SMB config weak" }

# 5 - LLMNR
$llmnr = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
if ($llmnr.EnableMulticast eq 0) { pass "LLMNR Disabled" } else { warn "LLMNR Active" }

# 6 - Remote Registry
Get-Service remoteRegistry | Where-Object {$_.StartType -eq "Disabled"} | Out-Null
if ($?) { pass "Remote Registry Disabled" } else { warn "Remote Registry Active" }

# 7 - Defender
$def = Get-MpPreference
if ($def.DisableRealtimeMonitoring -eq $false) { pass "Defender Active" } else { warn "Defender Disabled" }

# 8 - NLA
$rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
if ($rdp.UserAuthentication -eq 1) { pass "RDP NLA Active" } else { warn "RDP NLA Disabled" }

# 9 - Registry Harden
$lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if ($lsa.RestrictAnonymous -eq 1) { pass "Anonymous Restriction" } else { warn "LSA permissive" }

# 10 - Patch check
$lastUpdate = (Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 1).InstalledOn
if ((Get-Date) - $lastUpdate -lt (New-TimeSpan -Days 30)) { pass "Recent Patches Installed" } else { warn "System out of date" }

$percent = [math]::Round(($score / $total) * 100, 0)
Write-Host "`nSecurity Score: $percent%"
