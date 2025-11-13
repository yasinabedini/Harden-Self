<#
.SYNOPSIS
    Remote Desktop Protocol (RDP) Security Audit (Enhanced)
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
Write-Host "🖥️  Remote Desktop Protocol (RDP) Security Audit" -ForegroundColor Cyan
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
$total = 10

# Test 1: RDP Disabled (if not needed)
$rdpEnabled = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections
$rdpOK = ($rdpEnabled -eq 1)
$test1 = Test-Compliance $rdpOK "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1"
$Results += [PSCustomObject]@{
    Check = "RDP Disabled (if not required)"
    Status = $test1.Icon
    Value = $(if($rdpEnabled -eq 1){"Disabled"}else{"Enabled"})
    Remediation = $test1.Remediation
}
if ($test1.Pass) { $score++ }
Write-Host "[$($test1.Icon)] RDP Status: " -NoNewline -ForegroundColor $test1.Color
Write-Host $(if($rdpEnabled -eq 1){"Disabled"}else{"Enabled"})

# Test 2: NLA (Network Level Authentication) Required
$nla = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication").UserAuthentication
$nlaOK = ($nla -eq 1)
$test2 = Test-Compliance $nlaOK "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
$Results += [PSCustomObject]@{
    Check = "Network Level Authentication (NLA)"
    Status = $test2.Icon
    Value = $(if($nla -eq 1){"Required"}else{"Not Required"})
    Remediation = $test2.Remediation
}
if ($test2.Pass) { $score++ }
Write-Host "[$($test2.Icon)] NLA: " -NoNewline -ForegroundColor $test2.Color
Write-Host $(if($nla -eq 1){"Enforced"}else{"Disabled"})

# Test 3: Strong Encryption Level (High/FIPS)
$encLevel = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel").MinEncryptionLevel
$encOK = ($encLevel -ge 3)
$test3 = Test-Compliance $encOK "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3"
$Results += [PSCustomObject]@{
    Check = "Encryption Level (≥High)"
    Status = $test3.Icon
    Value = $(switch($encLevel){1{"Low"}2{"Client Compatible"}3{"High"}4{"FIPS"}default{"Unknown"}})
    Remediation = $test3.Remediation
}
if ($test3.Pass) { $score++ }
Write-Host "[$($test3.Icon)] Encryption Level: " -NoNewline -ForegroundColor $test3.Color
Write-Host $(switch($encLevel){1{"Low"}2{"Client Compatible"}3{"High"}4{"FIPS"}default{"Unknown"}})

# Test 4: RDP Port Changed (Not 3389)
$rdpPort = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber").PortNumber
$portOK = ($rdpPort -ne 3389)
$test4 = Test-Compliance $portOK "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -Value 33891"
$Results += [PSCustomObject]@{
    Check = "RDP Port Changed (Not 3389)"
    Status = $test4.Icon
    Value = $rdpPort
    Remediation = $test4.Remediation
}
if ($test4.Pass) { $score++ }
Write-Host "[$($test4.Icon)] RDP Port: " -NoNewline -ForegroundColor $test4.Color
Write-Host $rdpPort

# Test 5: Account Lockout Policy
$lockout = net accounts | Select-String "Lockout threshold"
$lockoutValue = if($lockout){[int]($lockout -replace '\D','')}else{0}
$lockoutOK = ($lockoutValue -gt 0 -and $lockoutValue -le 5)
$test5 = Test-Compliance $lockoutOK "net accounts /lockoutthreshold:5"
$Results += [PSCustomObject]@{
    Check = "Account Lockout Threshold (1-5)"
    Status = $test5.Icon
    Value = $(if($lockoutValue -eq 0){"Never"}else{$lockoutValue})
    Remediation = $test5.Remediation
}
if ($test5.Pass) { $score++ }
Write-Host "[$($test5.Icon)] Lockout Threshold: " -NoNewline -ForegroundColor $test5.Color
Write-Host $(if($lockoutValue -eq 0){"Never"}else{$lockoutValue})

# Test 6: Session Timeout Configured
$timeout = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MaxIdleTime" -ErrorAction SilentlyContinue).MaxIdleTime
$timeoutOK = ($null -ne $timeout -and $timeout -le 900000)
$test6 = Test-Compliance $timeoutOK "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MaxIdleTime -Value 600000"
$Results += [PSCustomObject]@{
    Check = "Session Timeout (≤15min)"
    Status = $test6.Icon
    Value = $(if($timeout){"$([math]::Round($timeout/60000,0)) min"}else{"Not Set"})
    Remediation = $test6.Remediation
}
if ($test6.Pass) { $score++ }
Write-Host "[$($test6.Icon)] Session Timeout: " -NoNewline -ForegroundColor $test6.Color
Write-Host $(if($timeout){"$([math]::Round($timeout/60000,0)) min"}else{"Not Set"})

# Test 7: Restricted RDP Access (Specific IPs Only)
$rdpRule = Get-NetFirewallRule -DisplayName "*Remote Desktop*" -Enabled True -ErrorAction SilentlyContinue | 
           Get-NetFirewallAddressFilter | Where-Object {$_.RemoteAddress -ne "Any"}
$restrictOK = ($null -ne $rdpRule)
$test7 = Test-Compliance $restrictOK "Set-NetFirewallRule -DisplayName 'Remote Desktop' -RemoteAddress '192.168.1.0/24'"
$Results += [PSCustomObject]@{
    Check = "RDP Access Restricted (IP Whitelist)"
    Status = $test7.Icon
    Value = $(if($restrictOK){"Configured"}else{"Open to Any"})
    Remediation = $test7.Remediation
}
if ($test7.Pass) { $score++ }
Write-Host "[$($test7.Icon)] IP Restriction: " -NoNewline -ForegroundColor $test7.Color
Write-Host $(if($restrictOK){"Active"}else{"None"})

# Test 8: Administrator Account Renamed
$adminName = (Get-LocalUser | Where-Object {$_.SID -like "*-500"}).Name
$adminOK = ($adminName -ne "Administrator")
$test8 = Test-Compliance $adminOK "Rename-LocalUser -Name 'Administrator' -NewName 'SysAdmin'"
$Results += [PSCustomObject]@{
    Check = "Administrator Account Renamed"
    Status = $test8.Icon
    Value = $adminName
    Remediation = $test8.Remediation
}
if ($test8.Pass) { $score++ }
Write-Host "[$($test8.Icon)] Admin Account: " -NoNewline -ForegroundColor $test8.Color
Write-Host $adminName

# Test 9: RDP Logging Enabled
$rdpLog = Get-WinEvent -ListLog "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" -ErrorAction SilentlyContinue
$rdpLogOK = ($null -ne $rdpLog -and $rdpLog.IsEnabled)
$test9 = Test-Compliance $rdpLogOK "wevtutil sl Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational /e:true"
$Results += [PSCustomObject]@{
    Check = "RDP Operational Logging Enabled"
    Status = $test9.Icon
    Value = $(if($rdpLogOK){"Enabled"}else{"Disabled"})
    Remediation = $test9.Remediation
}
if ($test9.Pass) { $score++ }
Write-Host "[$($test9.Icon)] RDP Logging: " -NoNewline -ForegroundColor $test9.Color
Write-Host $(if($rdpLogOK){"Active"}else{"Disabled"})

# Test 10: RestrictedAdmin Mode Enabled
$restrictedAdmin = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -ErrorAction SilentlyContinue).DisableRestrictedAdmin
$raOK = ($null -eq $restrictedAdmin -or $restrictedAdmin -eq 0)
$test10 = Test-Compliance $raOK "Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name DisableRestrictedAdmin -Value 0"
$Results += [PSCustomObject]@{
    Check = "RestrictedAdmin Mode Enabled"
    Status = $test10.Icon
    Value = $(if($raOK){"Enabled"}else{"Disabled"})
    Remediation = $test10.Remediation
}
if ($test10.Pass) { $score++ }
Write-Host "[$($test10.Icon)] RestrictedAdmin: " -NoNewline -ForegroundColor $test10.Color
Write-Host $(if($raOK){"Active"}else{"Disabled"})

# Summary
$percentage = [math]::Round(($score / $total) * 100, 1)
Write-Host "`n───────────────────────────────────────────────────" -ForegroundColor Yellow
Write-Host "🎯 Compliance Score: $score/$total ($percentage%)" -ForegroundColor $(if($percentage -ge 80){"Green"}else{"Red"})
Write-Host "───────────────────────────────────────────────────`n" -ForegroundColor Yellow

# Export
$output = @{
    Timestamp = $timestamp
    Module = "RDP"
    Score = "$score/$total"
    Percentage = $percentage
    Results = $Results
}

if ($ExportJSON) {
    $jsonPath = Join-Path $LogPath "rdp_audit_$timestamp.json"
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
