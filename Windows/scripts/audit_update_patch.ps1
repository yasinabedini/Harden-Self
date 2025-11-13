<#
.SYNOPSIS
    Windows Update & Patching Status Audit (Enhanced)
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
Write-Host "🔄  Windows Update & Patching Status Audit" -ForegroundColor Cyan
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
$total = 8

# Test 1: Windows Update Service Running
$wuService = Get-Service -Name "wuauserv"
$wuOK = ($wuService.Status -eq "Running" -and $wuService.StartType -ne "Disabled")
$test1 = Test-Compliance $wuOK "Set-Service wuauserv -StartupType Automatic; Start-Service wuauserv"
$Results += [PSCustomObject]@{
    Check = "Windows Update Service Active"
    Status = $test1.Icon
    Value = "$($wuService.Status) / $($wuService.StartType)"
    Remediation = $test1.Remediation
}
if ($test1.Pass) { $score++ }
Write-Host "[$($test1.Icon)] Update Service: " -NoNewline -ForegroundColor $test1.Color
Write-Host "$($wuService.Status) / $($wuService.StartType)"

# Test 2: Automatic Updates Enabled
$auOption = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate
$auOK = ($null -eq $auOption -or $auOption -eq 0)
$test2 = Test-Compliance $auOK "Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0"
$Results += [PSCustomObject]@{
    Check = "Automatic Updates Enabled"
    Status = $test2.Icon
    Value = $(if($auOK){"Enabled"}else{"Disabled"})
    Remediation = $test2.Remediation
}
if ($test2.Pass) { $score++ }
Write-Host "[$($test2.Icon)] Auto Updates: " -NoNewline -ForegroundColor $test2.Color
Write-Host $(if($auOK){"Active"}else{"Disabled"})

# Test 3: Last Update Check (within 7 days)
$updateSession = New-Object -ComObject Microsoft.Update.Session
$updateSearcher = $updateSession.CreateUpdateSearcher()
$historyCount = $updateSearcher.GetTotalHistoryCount()
if ($historyCount -gt 0) {
    $history = $updateSearcher.QueryHistory(0, 1)
    $lastUpdate = $history | Select-Object -First 1
    $daysSince = (New-TimeSpan -Start $lastUpdate.Date -End (Get-Date)).Days
    $updateOK = ($daysSince -le 7)
    $test3 = Test-Compliance $updateOK "Run Windows Update: UsoClient StartInteractiveScan"
    $Results += [PSCustomObject]@{
        Check = "Last Update Check (≤7 days)"
        Status = $test3.Icon
        Value = "$daysSince days ago"
        Remediation = $test3.Remediation
    }
    if ($test3.Pass) { $score++ }
    Write-Host "[$($test3.Icon)] Last Check: " -NoNewline -ForegroundColor $test3.Color
    Write-Host "$daysSince days ago"
} else {
    Write-Host "[⚠] Last Check: No history found" -ForegroundColor Yellow
}

# Test 4: Pending Updates Count
$pendingUpdates = $updateSearcher.Search("IsInstalled=0 and Type='Software'").Updates
$pendingOK = ($pendingUpdates.Count -eq 0)
$test4 = Test-Compliance $pendingOK "Install-Module PSWindowsUpdate; Get-WindowsUpdate -Install -AcceptAll"
$Results += [PSCustomObject]@{
    Check = "No Pending Critical Updates"
    Status = $test4.Icon
    Value = "$($pendingUpdates.Count) pending"
    Remediation = $test4.Remediation
}
if ($test4.Pass) { $score++ }
Write-Host "[$($test4.Icon)] Pending Updates: " -NoNewline -ForegroundColor $test4.Color
Write-Host $pendingUpdates.Count

# Test 5: Windows Version (up-to-date)
$osVersion = [System.Environment]::OSVersion.Version
$build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
$ubr = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
$fullBuild = "$build.$ubr"
# Latest known stable: 19045 (Win 10 22H2), 22621 (Win 11 22H2)
$versionOK = ($build -ge 19045)
$test5 = Test-Compliance $versionOK "Update to latest feature update via Windows Update"
$Results += [PSCustomObject]@{
    Check = "Windows Build Up-to-Date"
    Status = $test5.Icon
    Value = $fullBuild
    Remediation = $test5.Remediation
}
if ($test5.Pass) { $score++ }
Write-Host "[$($test5.Icon)] OS Build: " -NoNewline -ForegroundColor $test5.Color
Write-Host $fullBuild

# Test 6: WSUS Configuration (if enterprise)
$wsus = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue
if ($wsus) {
    $wsusOK = ($null -ne $wsus.WUServer)
    $test6 = Test-Compliance $wsusOK "Verify WSUS server connectivity"
    $Results += [PSCustomObject]@{
        Check = "WSUS Server Configured"
        Status = $test6.Icon
        Value = $wsus.WUServer
        Remediation = $test6.Remediation
    }
    if ($test6.Pass) { $score++ }
    Write-Host "[$($test6.Icon)] WSUS Server: " -NoNewline -ForegroundColor $test6.Color
    Write-Host $wsus.WUServer
} else {
    Write-Host "[ℹ] WSUS: Not configured (using Microsoft Update)" -ForegroundColor Cyan
}

# Test 7: Delivery Optimization (P2P) Configured
$doMode = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue).DODownloadMode
$doOK = ($null -ne $doMode -and $doMode -in @(1,2))
$test7 = Test-Compliance $doOK "Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name DODownloadMode -Value 1"
$Results += [PSCustomObject]@{
    Check = "Delivery Optimization Enabled"
    Status = $test7.Icon
    Value = $(if($doMode){$doMode}else{"Not Set"})
    Remediation = $test7.Remediation
}
if ($test7.Pass) { $score++ }
Write-Host "[$($test7.Icon)] Delivery Optimization: " -NoNewline -ForegroundColor $test7.Color
Write-Host $(if($doMode){"Mode $doMode"}else{"Disabled"})

# Test 8: Automatic Reboot After Updates (Controlled)
$rebootDelay = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue).NoAutoRebootWithLoggedOnUsers
$rebootOK = ($rebootDelay -eq 1)
$test8 = Test-Compliance $rebootOK "Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoRebootWithLoggedOnUsers -Value 1"
$Results += [PSCustomObject]@{
    Check = "No Auto-Reboot with Users Logged On"
    Status = $test8.Icon
    Value = $(if($rebootOK){"Protected"}else{"Uncontrolled"})
    Remediation = $test8.Remediation
}
if ($test8.Pass) { $score++ }
Write-Host "[$($test8.Icon)] Auto-Reboot Control: " -NoNewline -ForegroundColor $test8.Color
Write-Host $(if($rebootOK){"Enabled"}else{"Disabled"})

# Summary
$percentage = [math]::Round(($score / $total) * 100, 1)
Write-Host "`n───────────────────────────────────────────────────" -ForegroundColor Yellow
Write-Host "🎯 Compliance Score: $score/$total ($percentage%)" -ForegroundColor $(if($percentage -ge 80){"Green"}else{"Red"})
Write-Host "───────────────────────────────────────────────────`n" -ForegroundColor Yellow

# Export
$output = @{
    Timestamp = $timestamp
    Module = "Update_Patching"
    Score = "$score/$total"
    Percentage = $percentage
    Results = $Results
}

if ($ExportJSON) {
    $jsonPath = Join-Path $LogPath "update_audit_$timestamp.json"
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
