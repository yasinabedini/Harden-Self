
<#
.SYNOPSIS
    Windows Defender & ASR Rules Audit (Enhanced)
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
Write-Host "🛡️  Windows Defender & ASR Audit" -ForegroundColor Cyan
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

$pref = Get-MpPreference
$status = Get-MpComputerStatus

# Test 1: Real-Time Protection
$rtOK = $status.RealTimeProtectionEnabled
$test1 = Test-Compliance $rtOK "Set-MpPreference -DisableRealtimeMonitoring 0"
$Results += [PSCustomObject]@{
    Check = "Real-Time Protection"
    Status = $test1.Icon
    Value = $rtOK
    Remediation = $test1.Remediation
}
if ($test1.Pass) { $score++ }
Write-Host "[$($test1.Icon)] Real-Time Protection: " -NoNewline -ForegroundColor $test1.Color
Write-Host $rtOK

# Test 2: Cloud-Delivered Protection
$cloudOK = ($pref.MAPSReporting -eq 2)
$test2 = Test-Compliance $cloudOK "Set-MpPreference -MAPSReporting Advanced"
$Results += [PSCustomObject]@{
    Check = "Cloud-Delivered Protection (Advanced)"
    Status = $test2.Icon
    Value = $pref.MAPSReporting
    Remediation = $test2.Remediation
}
if ($test2.Pass) { $score++ }
Write-Host "[$($test2.Icon)] Cloud Protection: " -NoNewline -ForegroundColor $test2.Color
Write-Host "Level $($pref.MAPSReporting)"

# Test 3: Tamper Protection
$tamperOK = $status.IsTamperProtected
$test3 = Test-Compliance $tamperOK "Enable via Windows Security > Virus & threat protection > Manage settings"
$Results += [PSCustomObject]@{
    Check = "Tamper Protection"
    Status = $test3.Icon
    Value = $tamperOK
    Remediation = $test3.Remediation
}
if ($test3.Pass) { $score++ }
Write-Host "[$($test3.Icon)] Tamper Protection: " -NoNewline -ForegroundColor $test3.Color
Write-Host $tamperOK

# Test 4: PUA Protection
$puaOK = ($pref.PUAProtection -eq 1 -or $pref.PUAProtection -eq 2)
$test4 = Test-Compliance $puaOK "Set-MpPreference -PUAProtection Enabled"
$Results += [PSCustomObject]@{
    Check = "PUA Protection"
    Status = $test4.Icon
    Value = $pref.PUAProtection
    Remediation = $test4.Remediation
}
if ($test4.Pass) { $score++ }
Write-Host "[$($test4.Icon)] PUA Protection: " -NoNewline -ForegroundColor $test4.Color
Write-Host $(if($puaOK){"Enabled"}else{"Disabled"})

# Test 5: ASR Rules Configured
$asrIds = $pref.AttackSurfaceReductionRules_Ids
$asrActions = $pref.AttackSurfaceReductionRules_Actions
$asrOK = ($asrIds.Count -ge 5 -and ($asrActions -contains 1))
$test5 = Test-Compliance $asrOK "Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Enabled"
$Results += [PSCustomObject]@{
    Check = "ASR Rules (≥5 rules in Block mode)"
    Status = $test5.Icon
    Value = "$($asrIds.Count) rules"
    Remediation = $test5.Remediation
}
if ($test5.Pass) { $score++ }
Write-Host "[$($test5.Icon)] ASR Rules: " -NoNewline -ForegroundColor $test5.Color
Write-Host "$($asrIds.Count) configured"

# Test 6: LSASS Protection Rule
$lsassGuid = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
$lsassEnabled = ($asrIds -contains $lsassGuid -and $asrActions[($asrIds.IndexOf($lsassGuid))] -eq 1)
$test6 = Test-Compliance $lsassEnabled "Add ASR rule for LSASS credential theft"
$Results += [PSCustomObject]@{
    Check = "ASR: Block LSASS credential theft"
    Status = $test6.Icon
    Value = $lsassEnabled
    Remediation = $test6.Remediation
}
if ($test6.Pass) { $score++ }
Write-Host "[$($test6.Icon)] LSASS Protection: " -NoNewline -ForegroundColor $test6.Color
Write-Host $(if($lsassEnabled){"Active"}else{"Missing"})

# Test 7: Signature Updates
$sigAge = (Get-Date) - $status.AntivirusSignatureLastUpdated
$sigOK = ($sigAge.TotalHours -lt 24)
$test7 = Test-Compliance $sigOK "Update-MpSignature"
$Results += [PSCustomObject]@{
    Check = "Signature Updates (<24h)"
    Status = $test7.Icon
    Value = "$([math]::Round($sigAge.TotalHours,1))h ago"
    Remediation = $test7.Remediation
}
if ($test7.Pass) { $score++ }
Write-Host "[$($test7.Icon)] Signature Age: " -NoNewline -ForegroundColor $test7.Color
Write-Host "$([math]::Round($sigAge.TotalHours,1)) hours"

# Test 8: Engine Version
$engineOK = ([version]$status.AMEngineVersion -ge [version]"1.1.19000.0")
$test8 = Test-Compliance $engineOK "Update-MpSignature"
$Results += [PSCustomObject]@{
    Check = "Defender Engine (≥1.1.19000)"
    Status = $test8.Icon
    Value = $status.AMEngineVersion
    Remediation = $test8.Remediation
}
if ($test8.Pass) { $score++ }
Write-Host "[$($test8.Icon)] Engine Version: " -NoNewline -ForegroundColor $test8.Color
Write-Host $status.AMEngineVersion

# Summary
$percentage = [math]::Round(($score / $total) * 100, 1)
Write-Host "`n───────────────────────────────────────────────────" -ForegroundColor Yellow
Write-Host "🎯 Compliance Score: $score/$total ($percentage%)" -ForegroundColor $(if($percentage -ge 80){"Green"}else{"Red"})
Write-Host "───────────────────────────────────────────────────`n" -ForegroundColor Yellow

# Export
$output = @{
    Timestamp = $timestamp
    Module = "Defender_ASR"
    Score = "$score/$total"
    Percentage = $percentage
    Results = $Results
}

if ($ExportJSON) {
    $jsonPath = Join-Path $LogPath "defender_audit_$timestamp.json"
    $output | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8
    Write-Host "📄 JSON exported to: $jsonPath" -ForegroundColor Cyan
}

# Remediation
$failed = $Results | Where-Object-eq "✘"}
if ($failed) {
    Write-Host "🔧 Remediation
