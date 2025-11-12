# 🛡️ BitLocker / Disk Protection Hardening

## 🧭 Scope
Applicable to Windows 10/11 Enterprise and Windows Server 2019/2022.  
Goal: Ensure full‑disk encryption, secure key storage, and integrity validation against physical tampering or data exfiltration.

---

## 🔒 1. BitLocker Enforcement Baseline

| Policy | Recommended Value | Purpose |
|---------|-------------------|----------|
| Encryption Method | XTS‑AES 256 | Maximum resistance against brute‑force |
| Drive Types | OS, Fixed, Removable | Enforce full coverage |
| Require BitLocker | Enabled | All system disks |
| Auto‑Unlock | Disabled | Prevent non‑interactive use |
| TPM Requirement | v2.0 with PCR 0–11 binding | Hardware trust link |

🧭 Objective: Ensure all storage media adhere to high‑level encryption standards.

---

## ⚙️ 2. Key Protection & Recovery

* Use **TPM + PIN** for startup authentication (multi‑factor).  
* Store recovery keys **in Active Directory or Azure AD**, not locally.  
* Disable USB key storage except for isolated recovery stations.  
* Periodically rotate recovery keys (annual policy).  
* Restrict access to `msFVE-RecoveryInformation` entries via delegated GPO.  

🧭 Objective: Secure recovery material and prevent unauthorized decryption.

---

## 🧩 3. Data‑at‑Rest and Boot Integrity

* Enable **Secure Boot** and verify boot policy enforcement.  
* Combine BitLocker with **Trusted Boot / Measured Boot** via TPM PCR chain validation.  
* Configure *Allow Secure Boot for Integrity Policy* = Enabled.  
* Ensure boot‑loader files reside in verified EFI partition.  
* Audit Event ID 512 (BitLocker Integrity Check) → forward to SIEM.

🧭 Objective: Detect and block pre‑boot compromise or disk manipulation.

---

## 🧰 4. Removable Media Encryption

| Drive Category | Action |
|----------------|---------|
| USB / External HDD | Encrypt via BitLocker To Go |
| CD/DVD | Not applicable |
| SD / Flash | Allowed only if encrypted |
| Cloud‑Mapped Storage | Enforce client‑side encryption |

Policy via GPO → *Removable Data Drives: Require BitLocker Protection before Access*.  
🧭 Objective: Prevent data leakage through portable devices.

---

## 🔐 5. Administrative Lockdown

* Disable ability to suspend BitLocker (`Prevent suspend option` = Enabled).  
* Remove permission to change encryption type without admin approval.  
* Monitor WMI class `Win32_EncryptableVolume` for state changes.  
* Alert on transitions: `ProtectionStatus = 1 → 0` (Disabled).  
* Record *BitLocker management events* (Event ID 789–795).

🧭 Objective: Enforce non‑tamperable policies against insider or attacker manipulation.

---

## ⚡ 6. Validation Checklist

Ensure:
* **All drives encrypted with XTS‑AES 256**.  
* **TPM + PIN** active on all OS volumes.  
* **Recovery keys stored in AD / Azure AD**.  
* **Secure Boot + Measured Boot chain validated**.  
* **BitLocker To Go** enforced on removable drives.  
* **Suspension events monitored and alerted.**

🧭 Goal: Compliance with CIS Benchmark 12.1–12.3 and Microsoft Security Baseline BitLocker Settings.

---

**Author:** yasinabedini  
**Repository:** Harden‑Self / playbooks / windows  
**License:** MIT  
**Last Update:** 2025‑11‑13

---

🔹 BitLocker Hardening transforms storage security from reactive protection to proactive integrity assurance, closing one of the last physical attack surfaces.
