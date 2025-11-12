# ⚙️ PowerShell Hardening & Execution Control — Enterprise Baseline

> **Scope:** Windows Server 2016‑2022 / Windows 10‑11  
> **Goal:** Prevent offensive use of PowerShell while keeping admin functionality.

---

## 1️⃣ Execution Policy — Secure by Signature

Set system‑wide policy to **AllSigned** for servers, **RemoteSigned** for workstations.  
This ensures only scripts signed by trusted publishers can execute.  

🧭 **Goal:** Block untrusted .ps1 files from remote or local sources.

---

## 2️⃣ Constrained Language Mode (CLM)

Enable CLM for non‑admins via AppLocker or WDAC user rules.  
CLM restricts access to Reflection, COM, and raw Windows API.  
Admins continue in FullLanguageMode.  

🧭 **Goal:** Limit exploit scripts without affecting legitimate admin tasks.

---

## 3️⃣ ScriptBlock and Module Logging

Under  
HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging  
set EnableScriptBlockLogging=1  

Under  
HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging  
set EnableModuleLogging=1  

🧭 **Goal:** Capture commands and module load paths for auditing.

---

## 4️⃣ AMSI (Windows Antimalware Scan Interface)

Ensure AMSI is enabled:
- `HKLM\Software\Microsoft\AMSI` → Antivirus provider loaded  
- Defender real‑time protection active  

🧭 **Goal:** Send script content to antivirus engines before execution.

---

## 5️⃣ Transcription Logging

Enable transcription logging to record console I/O.  
Directory: `C:\PSLogs\%ComputerName%` (secured NTFS ACL Admins only).  

🧭 **Goal:** Maintain plain‑text audit of interactive sessions.

---

## 6️⃣ Block PowerShell v2 Engine

Disable optional feature:
Control Panel → Windows Features → Uncheck “Windows PowerShell 2.0 Engine”  
or via DISM `/Disable‑Feature:PowerShellv2`.  

🧭 **Goal:** Remove legacy engine without AMSI support.

---

## 7️⃣ Event Monitoring and SIEM Integration

Forward these critical events:  
- 4103 → Module Logging  
- 4104 → ScriptBlock Logging  
- 400 / 403 → Engine Start/Stop  

🧭 **Goal:** SOC visibility for PowerShell activity.

---

## 8️⃣ AppLocker / WDAC Whitelisting

Allow only signed .ps1, .psm1, and .psd1 files from trusted Publishers.  
Block all Path‑based rules except Admin directories.  

🧭 **Goal:** Prevent unsigned execution from temp folders or user profiles.

---

## 9️⃣ Defender Integration Check

Validate Defender scanning within PowerShell process.  
Defender Real‑Time Scan = ON  
PS engine registry → AMSI DLL present  

🧭 **Goal:** Ensure built‑in AV cooperates with AMSI for script scanning.

---

## 🔟 Baseline Audit Verification

Run `audit_powershell.ps1` to validate all previous controls.  
Example output:  

| Control | Status |
|----------|---------|
| Execution Policy | ✅ AllSigned |
| Logging | ✅ Enabled |
| CLM | ✅ Active for Users |
| AMSI | ✅ Active |
| v2 Engine | ✅ Disabled |

🧭 **Goal:** Confirm corporate baseline compliance.

---

| Author | Repository | License | Last Update |
|---------|-------------|----------|--------------|
| [**yasinabedini**](https://github.com/yasinabedini) | Harden‑Self / playbooks / windows | MIT | 2025‑11‑13 |

---

🔹 *Hardening PowerShell today prevents tomorrow’s Post‑Exploit.*
