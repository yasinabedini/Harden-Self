<#
.SYNOPSIS
    Logging & Sysmon Configuration Audit (Enhanced)
.AUTHOR
    yasinabedini
.VERSION
    2.1 (Clean & Compatible)
#>

[CmdletBinding()]
param(
    [switch]$ExportJSON,
    [string]$LogPath = "C:\HardenAudit\Logs"
)

$ErrorActionPreference = "SilentlyContinue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
if (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }

Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host "   Logging & Sysmon Configuration Audit" -ForegroundColor Cyan
Write-Host "===================================================`n" -ForegroundColor Cyan

function Test-Compliance {
    param([bool]$Condition, [string]$Hint = "")
    if ($Condition) { 
        @{Pass=$true; Icon="PASS"; Color="Green"; Remediation=""} 
    } else { 
        @{Pass=$false; Icon="FAIL"; Color="Red"; Remediation=$Hint} 
    }
}

$Results = @()
$score = 0
$total = 10

# Test 1: Sysmon Installed
$sysmon = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
$sysmonOK = ($null -ne $sysmon -and $sysmon.Status -eq "Running")
$test1 = Test-Compliance $sysmonOK "Download Sysmon from Sysinternals and run: sysmon64.exe -accepteula -i sysmonconfig.xml"
$Results += [PSCustomObject]@{
    Check = "Sysmon64 Service Running"
    Status = $test1.Icon
    Value = $(if($sysmon){$sysmon.Status}else{"Not Installed"})
    Remediation = $test1.Remediation
}
if ($test1.Pass) { $score++ }
Write-Host "[$($test1.Icon)] Sysmon Status: " -NoNewline -ForegroundColor $test1.Color
Write-Host $(if($sysmon){$sysmon.Status}else{"Missing"})

# Test 2: Sysmon Version
if ($sysmon) {
    $sysmonExe = Get-Item "C:\Windows\Sysmon64.exe" -ErrorAction SilentlyContinue
    $version = $sysmonExe.VersionInfo.FileVersion
    $versionOK = ([version]$version -ge [version]"15.0")
    $test2 = Test-Compliance $versionOK "Update Sysmon: sysmon64.exe -u and install the latest version"
    $Results += [PSCustomObject]@{
        Check = "Sysmon Version (>=15.0)"
        Status = $test2.Icon
        Value = $version
        Remediation = $test2.Remediation
    }
    if ($test2.Pass) { $score++ }
    Write-Host "[$($test2.Icon)] Sysmon Version: " -NoNewline -ForegroundColor $test2.Color
    Write-Host $version
}

# Test 3: Event Log Size - Security
$secLog = Get-WinEvent -ListLog Security
$secLogOK = ($secLog.MaximumSizeInBytes -ge 512MB)
$test3 = Test-Compliance $secLogOK "wevtutil sl Security /ms:1073741824"
$Results += [PSCustomObject]@{
    Check = "Security Log Size (>=512MB)"
    Status = $test3.Icon
    Value = "$([math]::Round($secLog.MaximumSizeInBytes/1MB,0)) MB"
    Remediation = $test3.Remediation
}
if ($test3.Pass) { $score++ }
Write-Host "[$($test3.Icon)] Security Log: " -NoNewline -ForegroundColor $test3.Color
Write-Host "$([math]::Round($secLog.MaximumSizeInBytes/1MB,0)) MB"

# Test 4: Event Log Size - Sysmon
$sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
if ($sysmonLog) {
    $sysmonLogOK = ($sysmonLog.MaximumSizeInBytes -ge 512MB)
    $test4 = Test-Compliance $sysmonLogOK "wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824"
    $Results += [PSCustomObject]@{
        Check = "Sysmon Log Size (>=512MB)"
        Status = $test4.Icon
        Value = "$([math]::Round($sysmonLog.MaximumSizeInBytes/1MB,0)) MB"
        Remediation = $test4.Remediation
    }
    if ($test4.Pass) { $score++ }
    Write-Host "[$($test4.Icon)] Sysmon Log: " -NoNewline -ForegroundColor $test4.Color
    Write-Host "$([math]::Round($sysmonLog.MaximumSizeInBytes/1MB,0)) MB"
}

# Test 5: PowerShell Logging
$psTranscript = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
$psLogOK = ($null -ne $psTranscript -and $psTranscript.EnableTranscripting -eq 1)
$test5 = Test-Compliance $psLogOK "Enable via GPO: Computer Config > Admin Templates > Windows Components > PowerShell > Turn on Transcription"
$Results += [PSCustomObject]@{
    Check = "PowerShell Transcription Enabled"
    Status = $test5.Icon
    Value = $(if($psLogOK){"Enabled"}else{"Disabled"})
    Remediation = $test5.Remediation
}
if ($test5.Pass) { $score++ }
Write-Host "[$($test5.Icon)] PowerShell Transcription: " -NoNewline -ForegroundColor $test5.Color
Write-Host $(if($psLogOK){"Active"}else{"Disabled"})

# Test 6: Script Block Logging
$psScriptBlock = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
$sbLogOK = ($null -ne $psScriptBlock -and $psScriptBlock.EnableScriptBlockLogging -eq 1)
$test6 = Test-Compliance $sbLogOK "Enable via GPO: PowerShell > Turn on Script Block Logging"
$Results += [PSCustomObject]@{
    Check = "PowerShell Script Block Logging"
    Status = $test6.Icon
    Value = $(if($sbLogOK){"Enabled"}else{"Disabled"})
    Remediation = $test6.Remediation
}
if ($test6.Pass) { $score++ }
Write-Host "[$($test6.Icon)] Script Block Logging: " -NoNewline -ForegroundColor $test6.Color
Write-Host $(if($sbLogOK){"Active"}else{"Disabled"})

# Test 7: Advanced Audit Policy - Process Creation
$auditProc = auditpol /get /subcategory:"Process Creation" | Select-String "Success"
$procLogOK = ($null -ne $auditProc)
$test7 = Test-Compliance $procLogOK "auditpol /set /subcategory:'Process Creation' /success:enable"
$Results += [PSCustomObject]@{
    Check = "Audit Policy: Process Creation"
    Status = $test7.Icon
    Value = $(if($procLogOK){"Success"}else{"Not Configured"})
    Remediation = $test7.Remediation
}
if ($test7.Pass) { $score++ }
Write-Host "[$($test7.Icon)] Process Creation Audit: " -NoNewline -ForegroundColor $test7.Color
Write-Host $(if($procLogOK){"Enabled"}else{"Disabled"})

# Test 8: Command Line Logging
$cmdLine = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ErrorAction SilentlyContinue
$cmdLogOK = ($null -ne $cmdLine -and $cmdLine.ProcessCreationIncludeCmdLine_Enabled -eq 1)
$test8 = Test-Compliance $cmdLogOK "Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1"
$Results += [PSCustomObject]@{
    Check = "Command Line in Process Events"
    Status = $test8.Icon
    Value = $(if($cmdLogOK){"Enabled"}else{"Disabled"})
    Remediation = $test8.Remediation
}
if ($test8.Pass) { $score++ }
Write-Host "[$($test8.Icon)] Command Line Logging: " -NoNewline -ForegroundColor $test8.Color
Write-Host $(if($cmdLogOK){"Active"}else{"Disabled"})

# Test 9: Audit Policy - Logon Events
$auditLogon = auditpol /get /subcategory:"Logon" | Select-String "Success and Failure"
$logonOK = ($null -ne $auditLogon)
$test9 = Test-Compliance $logonOK "auditpol /set /subcategory:'Logon' /success:enable /failure:enable"
$Results += [PSCustomObject]@{
    Check = "Audit Policy: Logon Events"
    Status = $test9.Icon
    Value = $(if($logonOK){"Success+Failure"}else{"Incomplete"})
    Remediation = $test9.Remediation
}
if ($test9.Pass) { $score++ }
Write-Host "[$($test9.Icon)] Logon Audit: " -NoNewline -ForegroundColor $test9.Color
Write-Host $(if($logonOK){"Configured"}else{"Missing"})

# Test 10: Windows Defender Logs
$defenderLog = Get-WinEvent -ListLog "Microsoft-Windows-Windows Defender/Operational" -ErrorAction SilentlyContinue
$defLogOK = ($null -ne $defenderLog -and $defenderLog.IsEnabled)
$test10 = Test-Compliance $defLogOK "Enable Defender Operational log via Event Viewer"
$Results += [PSCustomObject]@{
    Check = "Defender Operational Log Enabled"
    Status = $test10.Icon
    Value = $(if($defLogOK){"Enabled"}else{"Disabled"})
    Remediation = $test10.Remediation
}
if ($test10.Pass) { $score++ }
Write-Host "[$($test10.Icon)] Defender Log: " -NoNewline -ForegroundColor $test10.Color
Write-Host $(if($defLogOK){"Active"}else{"Disabled"})

# Summary
$percentage = [math]::Round(($score / $total) * 100, 1)
Write-Host "`n---------------------------------------------------" -ForegroundColor Yellow
Write-Host "Compliance Score: $score/$total ($percentage%)" -ForegroundColor $(if($percentage -ge 80){"Green"}else{"Red"})
Write-Host "---------------------------------------------------`n" -ForegroundColor Yellow

# Export
$output = @{
    Timestamp = $timestamp
    Module = "Logging_Sysmon"
    Score = "$score/$total"
    Percentage = $percentage
    Results = $Results
}

if ($ExportJSON) {
    $jsonPath = Join-Path $LogPath "logging_audit_$timestamp.json"
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
