<#
.SYNOPSIS
    Service & Scheduled Task Security Audit (Enhanced)
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
Write-Host "⚙️  Service & Scheduled Task Security Audit" -ForegroundColor Cyan
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
$total = 12

# Risky Services to Check
$riskyServices = @(
    "RemoteRegistry",
    "RemoteAccess",
    "Fax",
    "SSDPSRV",
    "upnphost",
    "WerSvc",
    "TapiSrv",
    "SharedAccess",
    "WMPNetworkSvc",
    "HomeGroupListener",
    "HomeGroupProvider",
    "XblAuthManager",
    "XblGameSave",
    "XboxNetApiSvc"
)

$disabledCount = 0
foreach ($svc in $riskyServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service -and $service.StartType -eq "Disabled") {
        $disabledCount++
    }
}

$svcOK = ($disabledCount -ge ($riskyServices.Count * 0.8))
$test1 = Test-Compliance $svcOK "Disable risky services: Set-Service -Name ServiceName -StartupType Disabled"
$Results += [PSCustomObject]@{
    Check = "Unnecessary Services Disabled"
    Status = $test1.Icon
    Value = "$disabledCount/$($riskyServices.Count)"
    Remediation = $test1.Remediation
}
if ($test1.Pass) { $score++ }
Write-Host "[$($test1.Icon)] Risky Services Disabled: " -NoNewline -ForegroundColor $test1.Color
Write-Host "$disabledCount/$($riskyServices.Count)"

# Test 2: Windows Update Service Running
$wuauserv = Get-Service -Name "wuauserv"
$wuOK = ($wuauserv.Status -eq "Running")
$test2 = Test-Compliance $wuOK "Start-Service wuauserv; Set-Service wuauserv -StartupType Automatic"
$Results += [PSCustomObject]@{
    Check = "Windows Update Service Active"
    Status = $test2.Icon
    Value = $wuauserv.Status
    Remediation = $test2.Remediation
}
if ($test2.Pass) { $score++ }
Write-Host "[$($test2.Icon)] Windows Update: " -NoNewline -ForegroundColor $test2.Color
Write-Host $wuauserv.Status

# Test 3: Windows Defender Service Running
$windefend = Get-Service -Name "WinDefend"
$defOK = ($windefend.Status -eq "Running")
$test3 = Test-Compliance $defOK "Start-Service WinDefend"
$Results += [PSCustomObject]@{
    Check = "Windows Defender Service Active"
    Status = $test3.Icon
    Value = $windefend.Status
    Remediation = $test3.Remediation
}
if ($test3.Pass) { $score++ }
Write-Host "[$($test3.Icon)] Defender Service: " -NoNewline -ForegroundColor $test3.Color
Write-Host $windefend.Status

# Test 4: Task Scheduler Service Running
$schedule = Get-Service -Name "Schedule"
$schedOK = ($schedule.Status -eq "Running")
$test4 = Test-Compliance $schedOK "Start-Service Schedule"
$Results += [PSCustomObject]@{
    Check = "Task Scheduler Active"
    Status = $test4.Icon
    Value = $schedule.Status
    Remediation = $test4.Remediation
}
if ($test4.Pass) { $score++ }
Write-Host "[$($test4.Icon)] Task Scheduler: " -NoNewline -ForegroundColor $test4.Color
Write-Host $schedule.Status

# Test 5: No Suspicious Scheduled Tasks
$tasks = Get-ScheduledTask | Where-Object {$_.State -eq "Ready" -and $_.Principal.UserId -notmatch "SYSTEM|Administrators"}
$suspiciousTasks = $tasks | Where-Object {$_.Actions.Execute -match "powershell|cmd|wscript|cscript" -and $_.TaskPath -notmatch "Microsoft"}
$taskOK = ($suspiciousTasks.Count -eq 0)
$test5 = Test-Compliance $taskOK "Review and remove: $($suspiciousTasks.TaskName -join ', ')"
$Results += [PSCustomObject]@{
    Check = "No Suspicious Scheduled Tasks"
    Status = $test5.Icon
    Value = "$($suspiciousTasks.Count) found"
    Remediation = $test5.Remediation
}
if ($test5.Pass) { $score++ }
Write-Host "[$($test5.Icon)] Suspicious Tasks: " -NoNewline -ForegroundColor $test5.Color
Write-Host $suspiciousTasks.Count

# Test 6: Services Running as SYSTEM (Minimize)
$systemSvcs = Get-WmiObject Win32_Service | Where-Object {$_.StartMode -ne "Disabled" -and $_.StartName -eq "LocalSystem"}
$systemOK = ($systemSvcs.Count -le 50)
$test6 = Test-Compliance $systemOK "Review services and use least privilege accounts"
$Results += [PSCustomObject]@{
    Check = "Services as SYSTEM (≤50)"
    Status = $test6.Icon
    Value = $systemSvcs.Count
    Remediation = $test6.Remediation
}
if ($test6.Pass) { $score++ }
Write-Host "[$($test6.Icon)] SYSTEM Services: " -NoNewline -ForegroundColor $test6.Color
Write-Host $systemSvcs.Count

# Test 7: Print Spooler Disabled (if not needed)
$spooler = Get-Service -Name "Spooler"
$spoolerOK = ($spooler.StartType -eq "Disabled" -or $spooler.Status -eq "Stopped")
$test7 = Test-Compliance $spoolerOK "Set-Service Spooler -StartupType Disabled; Stop-Service Spooler"
$Results += [PSCustomObject]@{
    Check = "Print Spooler Disabled"
    Status = $test7.Icon
    Value = "$($spooler.Status) / $($spooler.StartType)"
    Remediation = $test7.Remediation
}
if ($test7.Pass) { $score++ }
Write-Host "[$($test7.Icon)] Print Spooler: " -NoNewline -ForegroundColor $test7.Color
Write-Host "$($spooler.Status) / $($spooler.StartType)"

# Test 8: Remote Registry Disabled
$remoteReg = Get-Service -Name "RemoteRegistry"
$regOK = ($remoteReg.StartType -eq "Disabled")
$test8 = Test-Compliance $regOK "Set-Service RemoteRegistry -StartupType Disabled"
$Results += [PSCustomObject]@{
    Check = "Remote Registry Disabled"
    Status = $test8.Icon
    Value = $remoteReg.StartType
    Remediation = $test8.Remediation
}
if ($test8.Pass) { $score++ }
Write-Host "[$($test8.Icon)] Remote Registry: " -NoNewline -ForegroundColor $test8.Color
Write-Host $remoteReg.StartType

# Test 9: Windows Error Reporting Disabled
$wer = Get-Service -Name "WerSvc"
$werOK = ($wer.StartType -eq "Disabled")
$test9 = Test-Compliance $werOK "Set-Service WerSvc -StartupType Disabled"
$Results += [PSCustomObject]@{
    Check = "Error Reporting Disabled"
    Status = $test9.Icon
    Value = $wer.StartType
    Remediation = $test9.Remediation
}
if ($test9.Pass) { $score++ }
Write-Host "[$($test9.Icon)] Error Reporting: " -NoNewline -ForegroundColor $test9.Color
Write-Host $wer.StartType

# Test 10: Xbox Services Disabled (if not gaming)
$xbox = Get-Service -Name "XblAuthManager","XblGameSave","XboxNetApiSvc" -ErrorAction SilentlyContinue
$xboxDisabled = ($xbox | Where-Object {$_.StartType -eq "Disabled"}).Count
$xboxOK = ($xboxDisabled -eq 3)
$test10 = Test-Compliance $xboxOK "Get-Service Xbl* | Set-Service -StartupType Disabled"
$Results += [PSCustomObject]@{
    Check = "Xbox Services Disabled"
    Status = $test10.Icon
    Value = "$xboxDisabled/3"
    Remediation = $test10.Remediation
}
if ($test10.Pass) { $score++ }
Write-Host "[$($test10.Icon)] Xbox Services: " -NoNewline -ForegroundColor $test10.Color
Write-Host "$xboxDisabled/3 disabled"

# Test 11: Service Recovery Options Set
$criticalSvcs = @("WinDefend","wuauserv","EventLog")
$recoveryOK = $true
foreach ($svc in $criticalSvcs) {
    $recovery = sc.exe qfailure $svc | Select-String "RESTART"
    if (-not $recovery) { $recoveryOK = $false; break }
}
$test11 = Test-Compliance $recoveryOK "sc.exe failure ServiceName reset=86400 actions=restart/60000/restart/60000/restart/60000"
$Results += [PSCustomObject]@{
    Check = "Service Recovery Configured"
    Status = $test11.Icon
    Value = $(if($recoveryOK){"Set"}else{"Missing"})
    Remediation = $test11.Remediation
}
if ($test11.Pass) { $score++ }
Write-Host "[$($test11.Icon)] Recovery Options: " -NoNewline -ForegroundColor $test11.Color
Write-Host $(if($recoveryOK){"Configured"}else{"Not Set"})

# Test 12: No Services with Weak Permissions
$weakPerms = Get-WmiObject Win32_Service | Where-Object {
    $acl = Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" -ErrorAction SilentlyContinue
    $acl.Access | Where-Object {$_.IdentityReference -match "Users|Everyone" -and $_.AccessControlType -eq "Allow"}
}
$permOK = ($weakPerms.Count -eq 0)
$test12 = Test-Compliance $permOK "Review and restrict permissions on service registry keys"
$Results += [PSCustomObject]@{
    Check = "No Weak Service Permissions"
    Status = $test12.Icon
    Value = "$($weakPerms.Count) found"
    Remediation = $test12.Remediation
}
if ($test12.Pass) { $score++ }
Write-Host "[$($test12.Icon)] Weak Permissions: " -NoNewline -ForegroundColor $test12.Color
Write-Host $weakPerms.Count

# Summary
$percentage = [math]::Round(($score / $total) * 100, 1)
Write-Host "`n───────────────────────────────────────────────────" -ForegroundColor Yellow
Write-Host "🎯 Compliance Score: $score/$total ($percentage%)" -ForegroundColor $(if($percentage -ge 80){"Green"}else{"Red"})
Write-Host "───────────────────────────────────────────────────`n" -ForegroundColor Yellow

# Export
$output = @{
    Timestamp = $timestamp
    Module = "Service_Policy"
    Score = "$score/$total"
    Percentage = $percentage
    Results = $Results
}

if ($ExportJSON) {
    $jsonPath = Join-Path $LogPath "service_audit_$timestamp.json"
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
