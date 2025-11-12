<#
    File:        audit_bitlocker.ps1
    Repository:  Harden‑Self / playbooks / windows / scripts
    Author:      yasinabedini
    Purpose:     Validate BitLocker & TPM encryption policies
    Tested On:   Windows Server 2019 / 2022 / Windows 11
#>

Write-Host "`n⚙️  Harden‑Self — BitLocker Audit" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------`n"

function Test-Result($C){if($C){"[✔] Passed"}else{"[✘] Failed"}}
$Results=@()

### 1. OS Drive Encryption
$enc=(Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue).EncryptionMethod
$Results+=[pscustomobject]@{Check="OS Drive Encrypted";Status=Test-Result($enc)}

### 2. Encryption Method
$Results+=[pscustomobject]@{Check="XTS‑AES‑256 Used";Status=Test-Result($enc -eq "XtsAes256")}

### 3. TPM+PIN protector check
$tpmProt=(Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue).KeyProtector | Where-Object {$_.KeyProtectorType -eq "TPMAndPIN"}
$Results+=[pscustomobject]@{Check="TPM + PIN Active";Status=Test-Result($tpmProt)}

### 4. Recovery Key Location
$rkPath=(Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue).RecoveryKeyPath
$Results+=[pscustomobject]@{Check="Recovery Key stored (AD/Azure)";Status=Test-Result($rkPath)}

### 5. Secure Boot Enabled
$secure=(Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)
$Results+=[pscustomobject]@{Check="Secure Boot Enabled";Status=Test-Result($secure)}

$Results|Format-Table -AutoSize
Write-Host "`n🧩  BitLocker audit complete.`n"-ForegroundColor Yellow
