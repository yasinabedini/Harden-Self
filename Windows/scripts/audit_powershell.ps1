<#
.SYNOPSIS
    PowerShell Security Configuration Audit (Enhanced)
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
Write-Host "⚡  PowerShell Security Configuration Audit" -ForegroundColor Cyan
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

# Test 1: Execution Policy
$execPolicy = Get-ExecutionPolicy
$policyOK = ($execPolicy -eq "RemoteSigned" -or $execPolicy -eq "AllSigned")
$test1 = Test-Compliance $policyOK "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine"
$Results += [PSCustomObject]@{
    Check = "Execution Policy (RemoteSigned/AllSigned)"
    Status = $test1.Icon
    Value = $execPolicy
    Remediation = $test1.Remediation
}
if ($test1.Pass) { $score++ }
Write-Host "[$($test1.Icon)] Execution Policy: " -NoNewline -ForegroundColor $test1.Color
Write-Host $execPolicy

# Test 2: PowerShell v2 Disabled
$psv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
$psv2OK = ($null -eq $psv2 -or $psv2.State -eq "Disabled")
$test2 = Test-Compliance $psv2OK "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root"
$Results += [PSCustomObject]@{
    Check = "PowerShell v2 Disabled"
    Status = $test2.Icon
    Value = $(if($psv2){$psv2.State}else{"Not Installed"})
    Remediation = $test2.Remediation
}
if ($test2.Pass) { $score++ }
Write-Host "[$($test2.Icon)] PS v2 Status: " -NoNewline -ForegroundColor $test2.Color
Write-Host $(if($psv2){$psv2.State}else{"Not Installed"})

# Test 3: Constrained Language Mode
$langMode = $ExecutionContext.SessionState.LanguageMode
$langOK = ($langMode -eq "ConstrainedLanguage")
$test3 = Test-Compliance $langOK "Set via AppLocker or WDAC policy"
$Results += [PSCustomObject]@{
    Check = "Language Mode = ConstrainedLanguage"
    Status = $test3.Icon
    Value = $langMode
    Remediation = $test3.Remediation
}
if ($test3.Pass) { $score++ }
Write-Host "[$($test3.Icon)] Language Mode: " -NoNewline -ForegroundColor $test3.Color
Write-Host $langMode

# Test 4: Script Block Logging
$sbLog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
$sbOK = ($null -ne $sbLog -and $sbLog.EnableScriptBlockLogging -eq 1)
$test4 = Test-Compliance $sbOK "Enable via GPO: Windows Components > PowerShell > Turn on Script Block Logging"
$Results += [PSCustomObject]@{
    Check = "Script Block Logging Enabled"
    Status = $test4.Icon
    Value = $(if($sbOK){"Enabled"}else{"Disabled"})
    Remediation = $test4.Remediation
}
if ($test4.Pass) { $score++ }
Write-Host "[$($test4.Icon)] Script Block Logging: " -NoNewline -ForegroundColor $test4.Color
Write-Host $(if($sbOK){"Active"}else{"Disabled"})

# Test 5: Transcription Logging
$transcript = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
$transOK = ($null -ne $transcript -and $transcript.EnableTranscripting -eq 1)
$test5 = Test-Compliance $transOK "Enable via GPO: PowerShell > Turn on PowerShell Transcription"
$Results += [PSCustomObject]@{
    Check = "PowerShell Transcription Enabled"
    Status = $test5.Icon
    Value = $(if($transOK){"Enabled"}else{"Disabled"})
    Remediation = $test5.Remediation
}
if ($test5.Pass) { $score++ }
Write-Host "[$($test5.Icon)] Transcription: " -NoNewline -ForegroundColor $test5.Color
Write-Host $(if($transOK){"Active"}else{"Disabled"})

# Test 6: Module Logging
$modLog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
$modOK = ($null -ne $modLog -and $modLog.EnableModuleLogging -eq 1)
$test6 = Test-Compliance $modOK "Enable via GPO: PowerShell > Turn on Module Logging"
$Results += [PSCustomObject]@{
    Check = "Module Logging Enabled"
    Status = $test6.Icon
    Value = $(if($modOK){"Enabled"}else{"Disabled"})
    Remediation = $test6.Remediation
}
if ($test6.Pass) { $score++ }
Write-Host "[$($test6.Icon)] Module Logging: " -NoNewline -ForegroundColor $test6.Color
Write-Host $(if($modOK){"Active"}else{"Disabled"})

# Test 7: AMSI Enabled
$amsi = Get-ItemProperty "HKLM:\Software\Microsoft\AMSI" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
$amsiOK = ($null -eq $amsi -or $amsi.DisableAntiSpyware -ne 1)
$test7 = Test-Compliance $amsiOK "Remove-ItemProperty 'HKLM:\Software\Microsoft\AMSI' -Name DisableAntiSpyware"
$Results += [PSCustomObject]@{
    Check = "AMSI Protection Active"
    Status = $test7.Icon
    Value = $(if($amsiOK){"Active"}else{"Bypassed"})
    Remediation = $test7.Remediation
}
if ($test7.Pass) { $score++ }
Write-Host "[$($test7.Icon)] AMSI Status: " -NoNewline -ForegroundColor $test7.Color
Write-Host $(if($amsiOK){"Protected"}else{"Disabled"})

# Test 8: JEA (Just Enough Administration) Configured
$jea = Get-PSSessionConfiguration -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*JEA*"}
$jeaOK = ($null -ne $jea)
$test8 = Test-Compliance $jeaOK "Configure JEA endpoints: New-PSSessionConfigurationFile -SessionType RestrictedRemoteServer"
$Results += [PSCustomObject]@{
    Check = "JEA Endpoints Configured"
    Status = $test8.Icon
    Value = $(if($jea){"$($jea.Count) endpoints"}else{"None"})
    Remediation = $test8.Remediation
}
if ($test8.Pass) { $score++ }
Write-Host "[$($test8.Icon)] JEA Endpoints: " -NoNewline -ForegroundColor $test8.Color
Write-Host $(if($jea){"$($jea.Count) configured"}else{"Not configured"})

# Summary
$percentage = [math]::Round(($score / $total) * 100, 1)
Write-Host "`n───────────────────────────────────────────────────" -ForegroundColor Yellow
Write-Host "🎯 Compliance Score: $score/$total ($percentage%)" -ForegroundColor $(if($percentage -ge 80){"Green"}else{"Red"})
Write-Host "───────────────────────────────────────────────────`n" -ForegroundColor Yellow

# Export
$output = @{
    Timestamp = $timestamp
    Module = "PowerShell"
    Score = "$score/$total"
    Percentage = $percentage
    Results = $Results
}

if ($ExportJSON) {
    $jsonPath = Join-Path $LogPath "powershell_audit_$timestamp.json"
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
