# ⚙️ Windows Scheduled Task & Service Policy Hardening

## 🧭 Scope
Applies to Windows 10/11 and Windows Server 2019/2022 environments.  
Goal: Prevent persistence via scheduled tasks, service misconfiguration, and unauthorized auto‑start executables.

---

## 🔒 1. Scheduled Task Audit & Cleanup

Baseline policy:
* Enumerate all tasks under  
  `C:\Windows\System32\Tasks\` and `C:\Windows\Tasks\`.
* Remove obsolete vendor or “update” tasks not signed by Microsoft.
* Disable third‑party tasks that run with **Highest Privileges**.
* Block any task executing from non‑system paths (e.g., `C:\Users\...`).

🧭 Objective: Reduce persistence vectors created by PowerShell droppers or malicious installers.

---

## 🧱 2. Task Privilege Enforcement

For critical tasks:
* Ensure “Run as user” is **Local Service** or **Network Service** where possible.  
* Avoid “Run as SYSTEM” unless strictly required.
* Clear stored credentials (`Delete Stored Credential on TaskCreation`).  
* Disable the option *Run with highest privileges* except for core system jobs.

🧭 Objective: Prevent attackers from leveraging SYSTEM‑level task execution.

---

## ⚙️ 3. Service Auto‑Start Policy

| Service Type | Recommended Startup Mode | Notes |
|---------------|--------------------------|-------|
| Critical OS | Automatic | Required for system boot |
| Network‑Bound | Automatic (Delayed Start) | Avoid boot‑time congestion |
| Optional Features | Manual | Reduce attack surface |
| Unused / Third‑Party | Disabled | Prevent persistence |

Check via: `services.msc` or `Get‑Service | Where‑Object { StartType -ne 'Automatic' }`.  
Regularly export service states for baseline comparison.

🧭 Objective: Control running surface and boot sequence attack vectors.

---

## 🔐 4. Service Account Privilege Minimization

* Replace “Local System” with deprived identities (`Local Service`, `Network Service`) whenever applicable.  
* Avoid assigning domain accounts to local services.
* Remove write permissions for **Users**, **Authenticated Users**, **Interactive** on service registry keys (`HKLM\SYSTEM\CurrentControlSet\Services\<Service>`).  
* Implement *Restricted SACL* on service binary path directories.

🧭 Objective: Prevent credential exposure and service hijacking.

---

## 🧰 5. Unauthorized Service Monitoring

Enable Event IDs:
* **7045** → New service installed  
* **7030** → Service set to interact with desktop  
* **7038** → Service logon account change  

Forward these events to SIEM and trigger alert rules correlating with Sysmon Event ID 13 (Registry Modification).

🧭 Objective: Detect service‑based persistence in real time.

---

## 🧠 6. DLL & Executable Path Validation

Monthly scan of service binaries:
* Verify digital signature → Microsoft or Approved Vendor.  
* Confirm binary path ✅ within `%SystemRoot%` or `%ProgramFiles%`.  
* Flag anomalies (path under Temp or User profile) as critical.  
* Hash comparison against baseline (SHA‑256).  

🧭 Objective: Detect tampering or replacement of service executables.

---

## 🧩 7. Validation Checklist

Ensure:
* No unauthorized tasks in `System32\Tasks`.  
* All enabled tasks use least‑privilege principals.  
* Non‑Microsoft auto‑start services reviewed and disabled.  
* Service registry keys protected from user write access.  
* Event IDs 7045–7038 captured and forwarded.  
* Sysmon Event 13 correlation working.

🧭 Goal: Full compliance with CIS Windows Server 2.0 Control 2.2.3 and 4.1.6.

---

**Author:** yasinabedini  
**Repository:** Harden‑Self / playbooks / windows  
**License:** MIT  
**Last Update:** 2025‑11‑13

---

🔹 Scheduled Task and Service Policy Hardening shuts down the core persistence layer used by malware and pentest implants, ensuring host integrity post‑compromise.

