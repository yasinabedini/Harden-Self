# 🛡 Windows Defender & Attack Surface Reduction (ASR) Hardening

## 🧭 Scope
Enterprise‑level configuration for Windows 10/11 and Windows Server 2019/2022.  
Focus: Strengthen malware protection, script control, and exploit mitigation baseline.

---

## 🔒 1. Real‑Time Protection & Cloud Security

Setting → Real‑Time Protection = Enabled  
Setting → Cloud‑Delivered Protection = Enabled (MAPSReporting = 2)  
Setting → Automatic Sample Submission = Enabled  
Setting → Tamper Protection = ON  

🧭 Goal: Ensure Defender stays active and cannot be bypassed by local admins or malware.

---

## 🧩 2. Attack Surface Reduction (ASR) Rules

Enable ASR Rules in **Block Mode** for recommended Microsoft set:

| Rule Category | Recommended State | Description |
|----------------|------------------|--------------|
| Prevent credential stealing | Enabled | Blocks LSASS memory dump |
| Block Office child processes | Enabled | Stops Excel/Word macro launches |
| Block script obfuscation techniques | Enabled | Thwarts droppers / encoded PowerShell |
| Block process creation from WMI commands | Enabled | Stops lateral movement scripts |
| Use advanced Protection Mode on untrusted DLLs | Enabled | Prevents DLL injection |
| Block untrusted executables from USB media | Enabled | Protects from removable device malware |

🧭 Goal: Prevent exploit chains leveraging Office, WMI, USB or LSA vectors.

---

## 🧰 3. Potentially Unwanted Applications (PUA)

PUA Protection = Enabled  
Action → Block Potentially Unwanted Apps  

🧭 Goal: Remove adware, bundlers, and toolbars that reduce operations security.

---

## 🔐 4. Signature & Update Policy

SignatureUpdateInterval = every 2 hours (minimum)  
CloudProtectionLevel = High (3)  
Fallback signature source = MSCloud only  
Proxy update channel secured with TLS  

🧭 Goal: Maintain latest definition baseline and close timing gap against new malware.

---

## ⚙️ 5. Optional Enhanced Defender Scanning

• Use `MpCmdRun.exe –Scan –ScanType 2` for daily full scans.  
• Configure `Scheduled Scan = Daily 03:00 am`.  
• Alert Level = High / Critical only to email channel DefenderAlerts@domain.local.  

🧭 Goal: Continuous automated scanning without consuming business‑hours performance.

---

## 🧠 6. Validation Checks (Inline Query)

Verify ASR rules status → Get‑MpPreference | Select -Expand AttackSurfaceReductionRules_Ids  
Verify PUA mode → Get‑MpPreference | Select PUAProtection  
Verify Cloud Protection → Get‑MpPreference | Select MAPSReporting, CloudBlockLevel  
Verify Tamper Protection → Get‑ItemProperty HKLM:\SOFTWARE\Microsoft\Windows Defender\Features → TamperProtection  

🧭 Goal: Confirm applied configuration against Defender’s active runtime settings.

---

**Author:** yasinabedini  
**Repository:** Harden‑Self / playbooks / windows  
**License:** MIT  
**Last Update:** 2025‑11‑13

---

🔹 Defender ASR policy creates the first line of defense against fileless attacks and in‑memory execution. Combined with PowerShell AllSigned and Credential Guard, it provides a foundation for enterprise‑class endpoint hardening.
