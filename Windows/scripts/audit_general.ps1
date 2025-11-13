<#
.SYNOPSIS
    General System Hardening Audit (Enhanced)
.AUTHOR
    yasinabedini
.VERSION
    2.0
#>

[CmdletBinding()]
param(
    [switch]$ExportJSON,
    [string]$LogPath = "C:\HardenAudit\Logs"
)

$ErrorActionPreference = "SilentlyContinue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
if (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }

Write-Host "`n═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "🛡️  General System Hardening Audit" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════`n" -ForegroundColor Cyan

function Test-Compliance {
    param([bool]$Condition, [string]$Hint = "")
    if ($Condition) { 
        @{Pass=$true; Icon="✔"; Color="Green"; Remediation=""} 
    } else { 
        @{Pass=$false; Icon="✘"; Color="Red"; Remediation=$Hint} 
    }
}

$Results = @()
$score = 0
$total = 15

# Test 1: UAC Enabled
$uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA").EnableLUA
$uacOK = ($uac -eq 1)
$test1 = Test-Compliance $uacOK "Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"
$Results += [PSCustomObject]@{
    Check = "UAC (User Account Control) Enabled"
    Status = $test1.Icon
    Value = $(if($uac -eq 1){"Enabled"}else{"Disabled"})
    Remediation = $test1.Remediation
}
if ($test1.Pass) { $score++ }
Write-Host "[$($test1.Icon)] UAC: " -NoNewline -ForegroundColor $test1.Color
Write-Host $(if($uac -eq 1){"Active"}else{"Disabled"})

# Test 2: Administrator Account Renamed
$admin = Get-LocalUser | Where-Object {$_.SID -like "*-500"}
$adminOK = ($admin.Name -ne "Administrator")
$test2 = Test-Compliance $adminOK "Rename-LocalUser -Name Administrator -NewName CustomAdminName"
$Results += [PSCustomObject]@{
    Check = "Built-in Admin Renamed"
    Status = $test2.Icon
    Value = $admin.Name
    Remediation = $test2.Remediation
}
if ($test2.Pass) { $score++ }
Write-Host "[$($test2.Icon)] Admin Account: " -NoNewline -ForegroundColor $test2.Color
Write-Host $admin.Name

# Test 3: Guest Account Disabled
$guest = Get-LocalUser -Name "Guest"
$guestOK = ($guest.Enabled -eq $false)
$test3 = Test-Compliance $guestOK "Disable-LocalUser -Name Guest"
$Results += [PSCustomObject]@{
    Check = "Guest Account Disabled"
    Status = $test3.Icon
    Value = $(if($guest.Enabled){"Enabled"}else{"Disabled"})
    Remediation = $test3.Remediation
}
if ($test3.Pass) { $score++ }
Write-Host "[$($test3.Icon)] Guest Account: " -NoNewline -ForegroundColor $test3.Color
Write-Host $(if($guest.Enabled){"Active"}else{"Disabled"})

# Test 4: Password Complexity Enabled
$complexity = net accounts | Select-String "Password complexity"
$complexOK = ($complexity -match "Yes")
$test4 = Test-Compliance $complexOK "secedit /export /cfg C:\secpol.cfg; modify and import back"
$Results += [PSCustomObject]@{
    Check = "Password Complexity Required"
    Status = $test4.Icon
    Value = $(if($complexOK){"Yes"}else{"No"})
    Remediation = $test4.Remediation
}
if ($test4.Pass) { $score++ }
Write-Host "[$($test4.Icon)] Password Complexity: " -NoNewline -ForegroundColor $test4.Color
Write-Host $(if($complexOK){"Enforced"}else{"Disabled"})

# Test 5: Minimum Password Length (≥14)
$minPw = net accounts | Select-String "Minimum password length"
$minLength = [int]($minPw -replace '\D','')
$pwLenOK = ($minLength -ge 14)
$test5 = Test-Compliance $pwLenOK "net accounts /minpwlen:14"
$Results += [PSCustomObject]@{
    Check = "Minimum Password Length (≥14)"
    Status = $test5.Icon
    Value = $minLength
    Remediation = $test5.Remediation
}
if ($test5.Pass) { $score++ }
Write-Host "[$($test5.Icon)] Min Password Length: " -NoNewline -ForegroundColor $test5.Color
Write-Host $minLength

# Test 6: Password Age (Max ≤90 days)
$maxAge = net accounts | Select-String "Maximum password age"
$maxDays = [int]($maxAge -replace '\D','')
$ageOK = ($maxDays -le 90 -and $maxDays -gt 0)
$test6 = Test-Compliance $ageOK "net accounts /maxpwage:90"
$Results += [PSCustomObject]@{
    Check = "Password Max Age (≤90 days)"
    Status = $test6.Icon
    Value = "$maxDays days"
    Remediation = $test6.Remediation
}
if ($test6.Pass) { $score++ }
Write-Host "[$($test6.Icon)] Max Password Age: " -NoNewline -ForegroundColor $test6.Color
Write-Host "$maxDays days"

# Test 7: Account Lockout Threshold
$lockout = net accounts | Select-String "Lockout threshold"
$threshold = [int]($lockout -replace '\D','')
$lockOK = ($threshold -gt 0 -and $threshold -le 5)
$test7 = Test-Compliance $lockOK "net accounts /lockoutthreshold:5"
$Results += [PSCustomObject]@{
    Check = "Account Lockout (1-5 attempts)"
    Status = $test7.Icon
    Value = $threshold
    Remediation = $test7.Remediation
}
if ($test7.Pass) { $score++ }
Write-Host "[$($test7.Icon)] Lockout Threshold: " -NoNewline -ForegroundColor $test7.Color
Write-Host $threshold

# Test 8: AutoPlay Disabled
$autoplay = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -ErrorAction SilentlyContinue).DisableAutoplay
$autoOK = ($autoplay -eq 1)
$test8 = Test-Compliance $autoOK "Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name DisableAutoplay -Value 1"
$Results += [PSCustomObject]@{
    Check = "AutoPlay Disabled"
    Status = $test8.Icon
    Value = $(if($autoOK){"Disabled"}else{"Enabled"})
    Remediation = $test8.Remediation
}
if ($test8.Pass) { $score++ }
Write-Host "[$($test8.Icon)] AutoPlay: " -NoNewline -ForegroundColor $test8.Color
Write-Host $(if($autoOK){"Blocked"}else{"Active"})

# Test 9: SMBv1 Protocol Disabled
$smbv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
$smbOK = ($null -eq $smbv1 -or $smbv1.State -eq "Disabled")
$test9 = Test-Compliance $smbOK "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
$Results += [PSCustomObject]@{
    Check = "SMBv1 Protocol Disabled"
    Status = $test9.Icon
    Value = $(if($smbv1){$smbv1.State}else{"Not Installed"})
    Remediation = $test9.Remediation
}
if ($test9.Pass) { $score++ }
Write-Host "[$($test9.Icon)] SMBv1: " -NoNewline -ForegroundColor $test9.Color
Write-Host $(if($smbv1){$smbv1.State}else{"Not Found"})

# Test 10: Anonymous SID Translation Disabled
$sidTranslate = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TurnOffAnonymousBlock" -ErrorAction SilentlyContinue).TurnOffAnonymousBlock
$sidOK = ($null -eq $sidTranslate -or $sidTranslate -eq 1)
$test10 = Test-Compliance $sidOK "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name TurnOffAnonymousBlock -Value 1"
$Results += [PSCustomObject]@{
    Check = "Anonymous SID Translation Blocked"
    Status = $test10.Icon
    Value = $(if($sidOK){"Blocked"}else{"Allowed"})
    Remediation = $test10.Remediation
}
if ($test10.Pass) { $score++ }
Write-Host "[$($test10.Icon)] Anonymous SID: " -NoNewline -ForegroundColor $test10.Color
Write-Host $(if($sidOK){"Disabled"}else{"Enabled"})

# Test 11: LLMNR Disabled
$llmnr = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
$llmnrOK = ($llmnr -eq 0)
$test11 = Test-Compliance $llmnrOK "Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0"
$Results += [PSCustomObject]@{
    Check = "LLMNR Protocol Disabled"
    Status = $test11.Icon
    Value = $(if($llmnrOK){"Disabled"}else{"Enabled"})
    Remediation = $test11.Remediation
}
if ($test11.Pass) { $score++ }
Write-Host "[$($test11.Icon)] LLMNR: " -NoNewline -ForegroundColor $test11.Color
Write-Host $(if($llmnrOK){"Blocked"}else{"Active"})

# Test 12: NetBIOS over TCP/IP Disabled
$netbios = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.TcpipNetbiosOptions -ne 2}
$netbiosOK = ($netbios.Count -eq 0)
$test12 = Test-Compliance $netbiosOK "Set via network adapter settings: Disable NetBIOS over TCP/IP"
$Results += [PSCustomObject]@{
    Check = "NetBIOS over TCP/IP Disabled"
    Status = $test12.Icon
    Value = $(if($netbiosOK){"Disabled"}else{"$($netbios.Count) adapters active"})
    Remediation = $test12.Remediation
}
if ($test12.Pass) { $score++ }
Write-Host "[$($test12.Icon)] NetBIOS: " -NoNewline -ForegroundColor $test12.Color
Write-Host $(if($netbiosOK){"Blocked"}else{"Active on $($netbios.Count) adapters"})

# Test 13: WDigest Credential Caching Disabled
$wdigest = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
$wdOK = ($wdigest -eq 0)
$test13 = Test-Compliance $wdOK "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0"
$Results += [PSCustomObject]@{
    Check = "WDigest Credential Cache Disabled"
    Status = $test13.Icon
    Value = $(if($wdOK){"Disabled"}else{"Enabled"})
    Remediation = $test13.Remediation
}
if ($test13.Pass) { $score++ }
Write-Host "[$($test13.Icon)] WDigest: " -NoNewline -ForegroundColor $test13.Color
Write-Host $(if($wdOK){"Secure"}else{"Vulnerable"})

# Test 14: Windows Telemetry (Minimal)
$telemetry = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
$telemetryOK = ($telemetry -eq 0 -or $telemetry -eq 1)
$test14 = Test-Compliance $telemetryOK "Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -Value 1"
$Results += [PSCustomObject]@{
    Check = "Telemetry = Security/Basic (0-1)"
    Status = $test14.Icon
    Value = $telemetry
    Remediation = $test14.Remediation
}
if ($test14.Pass) { $score++ }
Write-Host "[$($test14.Icon)] Telemetry Level: " -NoNewline -ForegroundColor $test14.Color
Write-Host $telemetry

# Test 15: Core Isolation (Memory Integrity)
$hvci = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
$hvciOK = ($null -ne $hvci -and $hvci.Enabled -eq 1)
$test15 = Test-Compliance $hvciOK "Enable via Settings > Privacy & Security > Windows Security > Device Security > Core Isolation"
$Results += [PSCustomObject]@{
    Check = "Memory Integrity (HVCI) Enabled"
    Status = $test15.Icon
    Value = $(if($hvciOK){"Enabled"}else{"Disabled"})
    Remediation = $test15.Remediation
}
if ($test15.Pass) { $score++ }
Write-Host "[$($test15.Icon)] Memory Integrity: " -NoNewline -ForegroundColor $test15.Color
Write-Host $(if($hvciOK){"Active"}else{"Disabled"})

# Summary
$percentage = [math]::Round(($score / $total) * 100, 1)
Write-Host "`n───────────────────────────────────────────────────" -ForegroundColor Yellow
Write-Host "🎯 Compliance Score: $score/$total ($percentage%)" -ForegroundColor $(if($percentage -ge 80){"Green"}else{"Red"})
Write-Host "───────────────────────────────────────────────────`n" -ForegroundColor Yellow

# Export
$output = @{
    Timestamp = $timestamp
    Module = "General_Hardening"
    Score = "$score/$total"
    Percentage = $percentage
    Results = $Results
}

if ($ExportJSON) {
    $jsonPath = Join-Path $LogPath "general_audit_$timestamp.json"
    $output | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8
    Write-Host "📄 JSON exported to: $jsonPath" -ForegroundColor Cyan
}

# Remediation
$failed = $Results | Where-Object {$_.Status -eq "✘"}
if ($failed) {
    Write-Host "🔧 Remediation Steps:" -ForegroundColor Yellow
    $failed | ForEach-Object {
        Write-Host "   • $($_.Check): " -NoNewline -ForegroundColor Red
        Write-Host $_.Remediation -ForegroundColor White
    }
}

Write-Host ""
