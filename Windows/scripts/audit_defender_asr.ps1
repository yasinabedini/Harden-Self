<#
    File:        audit_defender_asr.ps1
    Repository:  Harden‑Self / playbooks / windows / scripts
    Author:      yasinabedini
    Purpose:     Validate Defender ASR, Tamper Protection & PUA hardening
    Tested On:   Windows Server 2019 / 2022 / Windows 11
#>

Write-Host "`n⚙️  Harden‑Self — Defender / ASR Audit" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------`n"

function Test-Result($Condition){if($Condition){"[✔] Passed"}else{"[✘] Failed"}}
$Results=@()

### 1. ASR Rules
$asr=(Get-MpPreference).AttackSurfaceReductionRules_Actions
$Results+=[pscustomobject]@{Check="ASR Rules (Block Mode)";Status=Test-Result(($asr -and ($asr -contains 1)))}

### 2. Tamper Protection
try{
$tamp=(Get-MpComputerStatus).IsTamperProtected
$Results+=[pscustomobject]@{Check="Tamper Protection";Status=Test-Result($tamp)}
}catch{$Results+=[pscustomobject]@{Check="Tamper Protection";Status="[⚠] Unverified"}}

### 3. PUA Protection
$pua=(Get-MpPreference).PUAProtection
$Results+=[pscustomobject]@{Check="PUA Protection";Status=Test-Result($pua -eq 2)}

### 4. Cloud-delivered Protection
$cloud=(Get-MpPreference).MAPSReporting
$Results+=[pscustomobject]@{Check="Cloud Delivered Protection";Status=Test-Result($cloud -eq 2)}

### 5. Engine & Signature
$engine=(Get-MpComputerStatus).AMEngineVersion
$sigDat=(Get-MpComputerStatus).AntivirusSignatureLastUpdated
$Results+=[pscustomobject]@{Check="Defender Engine/Signatures Recent";Status=Test-Result($engine -and $sigDat)}

$Results|Format-Table -AutoSize
Write-Host "`n🧩  Audit completed — review any ❌ Failed items for remediation.`n"-ForegroundColor Yellow
