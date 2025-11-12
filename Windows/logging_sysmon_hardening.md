# 🧾 Windows Logging & Sysmon Baseline Hardening

## 🧭 Scope
Enterprise‑level configuration for host‑based telemetry collection across Windows 10/11 and Windows Server 2019/2022.  
Objective: Improve audit depth, event retention, and Sysmon correlation for threat detection.

---

## 🧩 1. Advanced Audit Policy Configuration

Enable the following audit categories for **Success** and **Failure** unless noted:

| Category | Subcategory | Setting | Purpose |
|-----------|--------------|----------|----------|
| Account Logon | Credential Validation | Success+Failure | Track login attempts |
| Logon/Logoff | Logon | Success+Failure | Detect interactive and network logons |
| Logon/Logoff | Special Logon | Success | Detect Admin/System sessions |
| Object Access | File System + Registry Access | Success+Failure | Monitor critical asset access |
| Policy Change | Authentication Policy Change | Success+Failure | Detect security policy modifications |
| Privilege Use | Sensitive Privilege Use | Success+Failure | Detect use of SeDebugPrivilege etc. |
| System | Security State Change, IPSec Driver | Success+Failure | Detect system start / policy app |

🧭 Goal: Provide rich audit data for SIEM and threat detection.

---

## 🧱 2. Event Log Retention & Size

| Log Name | Minimum Retention | Max Size (MB) | Action on Full |
|-----------|------------------|---------------|----------------|
| Security | 45 Days | 1024 MB | Overwrite as needed |
| System | 30 Days | 512 MB | Overwrite oldest |
| Application | 30 Days | 512 MB | Overwrite oldest |
| PowerShell Operational | 30 Days | 256 MB | Overwrite oldest |

Enforce centralized IMR export to SIEM every 15 min via WinRM or NXLog.  
🧭 Goal: Prevent log loss and maintain forensic window.

---

## ⚙️ 3. Sysmon Baseline Policy

Install Sysmon (version ≥ 14.x) and apply standard Microsoft / SwiftOnSecurity config adapted for Enterprise:
Key recommended monitored events:

| Event ID | Monitored Action | Core Purpose |
|-----------|------------------|---------------|
| 1 | Process Creation | Visibility on cmdline execution |
| 3 | Network Connections | Detect C2 / lateral movement |
| 7 | Image Load | Detect DLL injection |
| 9 | Raw Access Read | Detect Mimikatz / LSA access |
| 11 | File Create | Detect script/implant dropper |
| 13 | Registry Modification | Detect persistence |
| 15 | File Create Stream Hash | Identify alternate data streams |
| 17‑18 | Pipe Events | Detect NamedPipe C2 |
| 22‑23 | DNS Query | Detect DNS‑based exfiltration |

🧠 Filtering:
Exclude benign noise like Windows Update, Defender, and browser processes to reduce false positives.  

🧭 Goal: Balanced visibility without telemetry overload.

---

## 🧰 4. Log Forwarding Strategy

* Use Windows Event Collector (WEC) in HTTPS‑mode for Tier 1→0 forwarding.  
* Enable “Source‑Initiated Subscriptions” secured by certificates.  
* Forward Security, Sysmon, PowerShell Operational.  
* Use tagging (`Computer Group`) according to Tiering model.  
* Validate forwarder health via `wecutil es`.

🧭 Goal: Centralized visibility and response correlation.

---

## 🔐 5. PowerShell Operational Event Integration

Ensure alignment with PowerShell Hardening baseline:

* Event 4103, 4104, 4105 enabled.  
* Log to `Microsoft‑Windows‑PowerShell/Operational`.  
* Integrate Sysmon Event 1 (ProcessCreate) to map child scripts.  
* Create custom XML filter in SIEM to correlate PowerShell activity → Defender alerts.  

🧭 Goal: Unified script activity collection.

---

## 🧩 6. Validation Checklist

Verify:
* `AuditPol /Get /Category:*` shows Success+Failure for core categories.  
* Security log retains ≥ 45 days of events.  
* Sysmon service running and `Get‑EventLog ‑LogName "Microsoft‑Windows‑Sysmon/Operational"` returns events.  
* WEC forwarded events appear in `Forwarded Events` log.  
* PowerShell events correlate to Sysmon Process IDs.  

🧭 Goal: Confirm telemetry pipeline works end‑to‑end.

---

**Author:** yasinabedini  
**Repository:** Harden‑Self / playbooks / windows  
**License:** MIT  
**Last Update:** 2025‑11‑13

---

🔹 A solid logging and Sysmon baseline turns raw Windows telemetry into actionable threat data for SOC and Hunting 
یعنی الان سه‌تا از هفت‌تای advanced تکمیل شدن:  
1️⃣ Defender ASR  
2️⃣ Firewall Isolation  
3️⃣ Logging + Sysmon  

مرحله بعدی طبق برنامه می‌ریم برای **Scheduled Task / Service Policy Hardening** → فایل بعدی `service
