# 🔐 Credential Protection & LSA Hardening

## 🧭 Scope
Applies to Windows 10/11 Enterprise and Windows Server 2019/2022 machines.  
Goal: Protect in‑memory credentials, block unauthorized harvesting, and enforce secure authentication channels.

---

## ⚙️ 1. LSA Protection Enforcement

| Registry Path | Key | Recommended Value | Purpose |
|----------------|-----|------------------|----------|
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `RunAsPPL` | 1 | Run LSASS as Protected Process Light |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `RunAsPPLBoot` | 1 | Force early boot protection |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe` | `AuditLevel` | 8 | Log tamper attempts |

🧭 Objective: Harden LSASS against memory injection (Mimikatz, Cobalt Strike dump techniques).

---

## 🔒 2. Credential Guard & VBS Isolation

* Enable **Credential Guard** using Virtualization‑based Security (VBS).  
* Enforce Hyper‑V code integrity via Secure Boot and TPM 2.0.  
* Store cached credentials inside isolated container (`IsolatedCredentials`).  
* Policy: *Computer Configuration → Admin Templates → System → Device Guard → Turn On Credential Guard = Enabled with UEFI lock*.  
* Prevent disabling via Group Policy preferences.

🧭 Objective: Segregate authentication secrets from OS memory.

---

## 🧰 3. NTLM & Legacy Authentication Controls

* Block **NTLMv1** and restrict **NTLMv2** usage to domain controllers only.  
* Configure LAN Manager level to 5 (Send NTLMv2 only).  
* Disable “Store LM Hash” in SAM database.  
* Audit every NTLM usage event (IDs 8001–8004).  
* Migrate internal services to Kerberos + TLS where possible.

🧭 Objective: Reduce hash‑based replay surface and enforce modern protocols.

---

## 🧱 4. LSASS Memory Access Restrictions

* Deploy **Protected Process Light (PPL)** mode for LSASS.  
* Deny process access except from `SYSTEM`, `NT AUTHORITY\SERVICE`, and `LOCAL SECURITY AUTHORITY`.  
* Restrict minidump permissions (`%SystemRoot%\System32\config\systemprofile\AppData\Local\CrashDumps`).  
* Monitor Event ID 3065 (Unauthorized Process Access to LSASS).  
* Block PowerShell access to LSASS handle via AMSI enforcement.

🧭 Objective: Prevent direct credential extraction and privilege escalation from admin accounts.

---

## 🪪 5. AMSI & Antimalware Integration

* Ensure AMSI (Anti‑Malware Scan Interface) is active system‑wide.  
* Integrate Defender/MDE for LSASS blocking behavior: `Behavior ID: LSASSCredentialDump`.  
* Enable advanced memory scanning (`MpEnableEdit: 1`).  
* Link Defender alerts to Security Ops dashboards.

🧭 Objective: Add behavioral defense layer to credential protection.

---

## 🔍 6. Network Authentication Hardening

* Enforce **Kerberos Integrity & Encryption Types** → AES 256 SHA‑1 & AES 128.  
* Disable fallback to DES or RC4.  
* Use SMB Signing and **Require NTLM v2**.  
* Require Network Level Authentication (NLA) on RDP endpoints.  
* Disable cached credentials (`Allow Cached Logon = 0`).

🧭 Objective: End‑to‑end protection for credentials in transit and at rest.

---

## 🧠 7. Validation Checklist

Ensure:
* LSASS running as Protected Process (LSA PPL).  
* Credential Guard with VBS active and locked.  
* NTLMv1 disabled; LM hash storage blocked.  
* No LSASS minidump privileges granted to users.  
* AMSI active and Defender scanning LSASS behaviors.  
* Kerberos/AES used for all interactive logons.

🧭 Goal: Compliance with CIS Benchmark 9.1.7 & 12.2.5 and Microsoft Secure Kernel Guidelines v2025.

---

**Author:** yasinabedini  
**Repository:** Harden‑Self / playbooks / windows  
**License:** MIT  
**Last Update:** 2025‑11‑13

---

🔹 Credential Protection & LSA Hardening seals the endpoint’s identity boundary, turning LSASS and Kerberos handling into a tamper‑proof authentication module resistant to modern credential‑theft vectors.
