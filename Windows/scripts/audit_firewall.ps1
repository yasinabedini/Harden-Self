<#
.SYNOPSIS
    Windows Firewall & Network Protection Audit (Enhanced)
.AUTHOR
    yasinabedini
.VERSION
    2.1 (Clean)
#>

[CmdletBinding()]
param(
    [switch]$ExportJSON,
    [string]$LogPath = "C:\HardenAudit\Logs"
)

$ErrorActionPreference = "SilentlyContinue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
if (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host " Windows Firewall & Network Protection Audit" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

function Test-Compliance {
    param([bool]$Condition, [string]$Hint = "")
    if ($Condition) { 
        return @{Pass=$true; Icon="OK"; Color="Green"; Remediation=""} 
    } else { 
        return @{Pass=$false; Icon="FAIL"; Color="Red"; Remediation=$Hint} 
    }
}

$Results = @()
$score = 0
$total = 9

# Test 1-3: Firewall Profiles Enabled
$profiles = Get-NetFirewallProfile
foreach ($profile in $profiles) {
    $enabled = ($profile.Enabled -eq $true)
    $test = Test-Compliance $enabled "Set-NetFirewallProfile -Profile $($profile.Name) -Enabled True"
    $Results += [PSCustomObject]@{
        Check = "Firewall $($profile.Name) Profile"
        Status = $test.Icon
        Value = $profile.Enabled
        Remediation = $test.Remediation
    }
    if ($test.Pass) { $score++ }
    Write-Host "[$($test.Icon)] $($profile.Name) Profile: " -NoNewline -ForegroundColor $test.Color
    Write-Host $profile.Enabled
}

# Test 4: Default Inbound Action = Block
$publicProfile = $profiles | Where-Object {$_.Name -eq "Public"}
$inboundBlock = ($publicProfile.DefaultInboundAction -eq "Block")
$test4 = Test-Compliance $inboundBlock "Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block"
$Results += [PSCustomObject]@{
    Check = "Public: Default Inbound = Block"
    Status = $test4.Icon
    Value = $publicProfile.DefaultInboundAction
    Remediation = $test4.Remediation
}
if ($test4.Pass) { $score++ }
Write-Host "[$($test4.Icon)] Public Inbound Action: " -NoNewline -ForegroundColor $test4.Color
Write-Host $publicProfile.DefaultInboundAction

# Test 5: Logging Enabled
$logSettings = Get-NetFirewallProfile -Profile Domain | Select-Object LogFileName, LogMaxSizeKilobytes
$loggingOK = ($null -ne $logSettings.LogFileName -and $logSettings.LogMaxSizeKilobytes -ge 4096)
$test5 = Test-Compliance $loggingOK "Set-NetFirewallProfile -All -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384"
$Results += [PSCustomObject]@{
    Check = "Firewall Logging Enabled (≥4MB)"
    Status = $test5.Icon
    Value = "$($logSettings.LogMaxSizeKilobytes) KB"
    Remediation = $test5.Remediation
}
if ($test5.Pass) { $score++ }
Write-Host "[$($test5.Icon)] Logging: " -NoNewline -ForegroundColor $test5.Color
Write-Host "$($logSettings.LogMaxSizeKilobytes) KB"

# Test 6: Stealth Mode (Block Unsolicited)
$stealthMode = ($publicProfile.NotifyOnListen -eq $false)
$test6 = Test-Compliance $stealthMode "Set-NetFirewallProfile -Profile Public -NotifyOnListen False"
$Results += [PSCustomObject]@{
    Check = "Stealth Mode (Public)"
    Status = $test6.Icon
    Value = -not $publicProfile.NotifyOnListen
    Remediation = $test6.Remediation
}
if ($test6.Pass) { $score++ }
Write-Host "[$($test6.Icon)] Stealth Mode: " -NoNewline -ForegroundColor $test6.Color
Write-Host $(if($stealthMode){"Active"}else{"Disabled"})

# Test 7: No Unnecessary Inbound Rules
$inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True | Where-Object {$_.Action -eq "Allow"}
$suspiciousRules = $inboundRules | Where-Object {$_.DisplayName -match "Remote|Admin|File|Print" -and $_.Profile -eq "Public"}
$rulesOK = ($suspiciousRules.Count -eq 0)
$test7 = Test-Compliance $rulesOK "Review and disable: $($suspiciousRules.DisplayName -join ', ')"
$Results += [PSCustomObject]@{
    Check = "No Risky Inbound Rules (Public)"
    Status = $test7.Icon
    Value = "$($suspiciousRules.Count) found"
    Remediation = $test7.Remediation
}
if ($test7.Pass) { $score++ }
Write-Host "[$($test7.Icon)] Suspicious Rules: " -NoNewline -ForegroundColor $test7.Color
Write-Host "$($suspiciousRules.Count)"

# Test 8: SMBv1 Blocked
$smbRule = Get-NetFirewallRule -DisplayName "*SMB*" | Where-Object {$_.Enabled -and $_.Action -eq "Block"}
$smbOK = ($null -ne $smbRule)
$test8 = Test-Compliance $smbOK "New-NetFirewallRule -DisplayName 'Block SMBv1' -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block"
$Results += [PSCustomObject]@{
    Check = "SMBv1 Explicitly Blocked"
    Status = $test8.Icon
    Value = $smbOK
    Remediation = $test8.Remediation
}
if ($test8.Pass) { $score++ }
Write-Host "[$($test8.Icon)] SMBv1 Block Rule: " -NoNewline -ForegroundColor $test8.Color
Write-Host $(if($smbOK){"Exists"}else{"Missing"})

# Test 9: IPsec Enforcement
$ipsec = Get-NetIPsecRule | Where-Object {$_.Enabled}
$ipsecOK = ($ipsec.Count -gt 0)
$test9 = Test-Compliance $ipsecOK "Configure IPsec policies via Group Policy or New-NetIPsecRule"
$Results += [PSCustomObject]@{
    Check = "IPsec Rules Configured"
    Status = $test9.Icon
    Value = "$($ipsec.Count) rules"
    Remediation = $test9.Remediation
}
if ($test9.Pass) { $score++ }
Write-Host "[$($test9.Icon)] IPsec Rules: " -NoNewline -ForegroundColor $test9.Color
Write-Host "$($ipsec.Count)"

# Summary
$percentage = [math]::Round(($score / $total) * 100, 1)
Write-Host ""
Write-Host "---------------------------------------------------" -ForegroundColor Yellow
Write-Host " Compliance Score: $score / $total  ($percentage%)" -ForegroundColor $(if($percentage -ge 80){"Green"}else{"Red"})
Write-Host "---------------------------------------------------" -ForegroundColor Yellow
Write-Host ""

# Export
$output = @{
    Timestamp = $timestamp
    Module = "Firewall"
    Score = "$score/$total"
    Percentage = $percentage
    Results = $Results
}

if ($ExportJSON) {
    $jsonPath = Join-Path $LogPath "firewall_audit_$timestamp.json"
    $output | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8
    Write-Host "JSON exported to: $jsonPath" -ForegroundColor Cyan
}

# Remediation
$failed = $Results | Where-Object {$_.Status -eq "FAIL"}
if ($failed) {
    Write-Host "Remediation Steps:" -ForegroundColor Yellow
    $failed | ForEach-Object {
        Write-Host "   - $($_.Check): " -NoNewline -ForegroundColor Red
        Write-Host $_.Remediation -ForegroundColor White
    }
}

Write-Host ""
