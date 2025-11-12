<#
    File:        audit_powershell.ps1
    Repository:  Harden‑Self / playbooks / windows
    Author:      yasinabedini
    Purpose:     Validate PowerShell Execution & Logging Hardening
    Tested On:   Windows Server 2019 / 2022 / Windows 11
#>

Write-Host "`n⚙️  Harden‑Self — PowerShell Hardening Audit" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------`n"

function Test-Result($Condition) { if ($Condition) { "[✔] Passed" } else { "[✘] Failed" } }

$Results = @()

### 1. Execution Policy
$execPolicy = (Get-ExecutionPolicy -Scope LocalMachine)
$Results += [pscustomobject]@{
    Check = "ExecutionPolicy = AllSigned/RemoteSigned"
    Status = Test-Result ($execPolicy -in @("AllSigned","RemoteSigned"))
}

### 2. CLM Enforcement
$langMode = $ExecutionContext.SessionState.LanguageMode
$Results += [pscustomobject]@{
    Check = "ConstrainedLanguage active for non-admins"
    Status = Test-Result ($langMode -eq "ConstrainedLanguage" -or ([Security.Principal.WindowsIdentity]::GetCurrent().Name -like "*Administrator*"))
}

### 3. ScriptBlock & Module Logging
$sbLog = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$modLog = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging
$Results += [pscustomobject]@{
    Check = "Logging (ScriptBlock + Module)"
    Status = Test-Result (($sbLog -eq 1) -and ($modLog -eq 1))
}

### 4. AMSI Status
$AmsiDll = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\AMSI" -ErrorAction SilentlyContinue)
$DefenderRT = (Get-MpPreference).DisableRealtimeMonitoring
$Results += [pscustomobject]@{
    Check = "AMSI + Defender RealTime Enabled"
    Status = Test-Result (($AmsiDll -ne $null) -and ($DefenderRT -eq $false))
}

### 5. Transcription Logging Path
$TransPath = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).OutputDirectory
$Results += [pscustomobject]@{
    Check = "Transcription Logging Active"
    Status = Test-Result ($TransPath)
}

### 6. PowerShell v2 Engine Disabled
$v2State = (Get-WindowsOptionalFeature -Online -FeatureName "PowerShellv2" -ErrorAction SilentlyContinue).State
$Results += [pscustomobject]@{
    Check = "PowerShell v2 Engine Disabled"
    Status = Test-Result ($v2State -eq "Disabled")
}

### 7. Defender Integration
$DefenderState = (Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status
$Results += [pscustomobject]@{
    Check = "Defender Service Running"
    Status = Test-Result ($DefenderState -eq "Running")
}

### 8. Audit Visibility (Events 4103/4104)
$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4103,4104} -MaxEvents 10 -ErrorAction SilentlyContinue
$Results += [pscustomobject]@{
    Check = "Event Logging Operational"
    Status = Test-Result ($events.Count -ge 1)
}

# Show summary
$Results | Format-Table -AutoSize -Wrap
Write-Host "`n🧩  Audit completed — review any ❌ Failed items for remediation.`n" -ForegroundColor Yellow
