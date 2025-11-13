<#
.SYNOPSIS
    BitLocker & TPM Encryption Audit (Enhanced)
.DESCRIPTION
    Validates BitLocker encryption with XTS-AES-256, TPM+PIN, and Secure Boot
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

# Initialize
$ErrorActionPreference = "SilentlyContinue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
if (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }

Write-Host "`n═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "🔐  BitLocker & TPM Encryption Audit" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════`n" -ForegroundColor Cyan

# Helper Functions
function Test-Compliance {
    param([bool]$Condition, [string]$Hint = "")
    $status = if ($Condition) { 
        @{Pass=$true; Icon="✔"; Color="Green"; Remediation=""} 
    } else { 
        @{Pass=$false; Icon="✘"; Color="Red"; Remediation=$Hint} 
    }
    return $status
}

# Results Array
$Results = @()
$score = 0
$total = 6

# Test 1: OS Drive Encryption
$bitlocker = Get-BitLockerVolume -MountPoint "C:"
$encrypted = ($bitlocker.VolumeStatus -eq "FullyEncrypted")
$test1 = Test-Compliance $encrypted "Run: Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256"
$Results += [PSCustomObject]@{
    Check = "OS Drive Encrypted (C:)"
    Status = $test1.Icon
    Value = $bitlocker.VolumeStatus
    Remediation = $test1.Remediation
}
if ($test1.Pass) { $score++ }
Write-Host "[$($test1.Icon)] OS Drive Encryption: " -NoNewline -ForegroundColor $test1.Color
Write-Host $bitlocker.VolumeStatus

# Test 2: XTS-AES-256
$method = $bitlocker.EncryptionMethod
$isXTS = ($method -eq "XtsAes256")
$test2 = Test-Compliance $isXTS "Change method: manage-bde -upgrade C: -EncryptionMethod XtsAes256"
$Results += [PSCustomObject]@{
    Check = "Encryption Method = XTS-AES-256"
    Status = $test2.Icon
    Value = $method
    Remediation = $test2.Remediation
}
if ($test2.Pass) { $score++ }
Write-Host "[$($test2.Icon)] Encryption Method: " -NoNewline -ForegroundColor $test2.Color
Write-Host $method

# Test 3: TPM + PIN
$protectors = $bitlocker.KeyProtector
$tpmPin = ($protectors | Where-Object {$_.KeyProtectorType -eq "TpmPin"})
$test3 = Test-Compliance ($null -ne $tpmPin) "Add TPM+PIN: Add-BitLockerKeyProtector -MountPoint C: -TpmAndPinProtector"
$Results += [PSCustomObject]@{
    Check = "TPM + PIN Protector Active"
    Status = $test3.Icon
    Value = if($tpmPin){"Enabled"}else{"Disabled"}
    Remediation = $test3.Remediation
}
if ($test3.Pass) { $score++ }
Write-Host "[$($test3.Icon)] TPM + PIN: " -NoNewline -ForegroundColor $test3.Color
Write-Host $(if($tpmPin){"Active"}else{"Missing"})

# Test 4: Recovery Key in AD/Azure
$recoveryKey = ($protectors | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"})
$test4 = Test-Compliance ($null -ne $recoveryKey) "Backup key: Backup-BitLockerKeyProtector -MountPoint C: -KeyProtectorId {ID}"
$Results += [PSCustomObject]@{
    Check = "Recovery Key Configured"
    Status = $test4.Icon
    Value = if($recoveryKey){"Present"}else{"Missing"}
    Remediation = $test4.Remediation
}
if ($test4.Pass) { $score++ }
Write-Host "[$($test4.Icon)] Recovery Key: " -NoNewline -ForegroundColor $test4.Color
Write-Host $(if($recoveryKey){"Configured"}else{"Not Found"})

# Test 5: Secure Boot
$secureBoot = Confirm-SecureBootUEFI
$test5 = Test-Compliance $secureBoot "Enable in UEFI/BIOS settings"
$Results += [PSCustomObject]@{
    Check = "Secure Boot Enabled"
    Status = $test5.Icon
    Value = $secureBoot
    Remediation = $test5.Remediation
}
if ($test5.Pass) { $score++ }
Write-Host "[$($test5.Icon)] Secure Boot: " -NoNewline -ForegroundColor $test5.Color
Write-Host $secureBoot

# Test 6: TPM Version
$tpm = Get-Tpm
$tpmOK = ($tpm.TpmPresent -and $tpm.TpmReady -and ($tpm.ManufacturerVersion -ge 2.0))
$test6 = Test-Compliance $tpmOK "Upgrade to TPM 2.0"
$Results += [PSCustomObject]@{
    Check = "TPM 2.0 Ready"
    Status = $test6.Icon
    Value = "v$($tpm.ManufacturerVersion)"
    Remediation = $test6.Remediation
}
if ($test6.Pass) { $score++ }
Write-Host "[$($test6.Icon)] TPM Status: " -NoNewline -ForegroundColor $test6.Color
Write-Host "Present=$($tpm.TpmPresent), Ready=$($tpm.TpmReady)"

# Summary
$percentage = [math]::Round(($score / $total) * 100, 1)
Write-Host "`n───────────────────────────────────────────────────" -ForegroundColor Yellow
Write-Host "🎯 Compliance Score: $score/$total ($percentage%)" -ForegroundColor $(if($percentage -ge 80){"Green"}else{"Red"})
Write-Host "───────────────────────────────────────────────────`n" -ForegroundColor Yellow

# Export Results
$output = @{
    Timestamp = $timestamp
    Module = "BitLocker"
    Score = "$score/$total"
    Percentage = $percentage
    Results = $Results
}

if ($ExportJSON) {
    $jsonPath = Join-Path $LogPath "bitlocker_audit_$timestamp.json"
    $output | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8
    Write-Host "📄 JSON exported to: $jsonPath" -ForegroundColor Cyan
}

# Show Remediation
$failed = $Results | Where-Object {$_.Status -eq "✘"}
if ($failed) {
    Write-Host "🔧 Remediation Steps:" -ForegroundColor Yellow
    $failed | ForEach-Object {
        Write-Host "   • $($_.Check): " -NoNewline -ForegroundColor Red
        Write-Host $_.Remediation -ForegroundColor White
    }
}

Write-Host ""
