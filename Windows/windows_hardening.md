# Windows General Hardening Guide

## 🧩 Scope
Baseline hardening checklist for Windows Server 2019/2022 and Windows 10/11.  
Applies to domain members and standalone hosts.

---

## 🔒 1. Account Policies

| Policy | Recommended Value | Purpose |
|--------|-------------------|----------|
| Minimum password length | ≥ 12 | Prevent weak passwords |
| Complexity requirement | Enabled | Blocks trivial passwords |
| Maximum password age | 90 days | Rotate passwords periodically |
| Account lockout threshold | 5 invalid attempts | Brute-force prevention |
| Lockout duration | >=15 minutes | Delay repeated attacks |

---

## 🕵️‍♂️ 2. Audit Policy

| Policy | Recommended Setting | Notes |
|---------|--------------------|-------|
| Audit logon events | Success & Failure | Track all authentication |
| Audit account logon events | Success & Failure | Useful for AD correlation |
| Audit object access | Success & Failure | File & Registry protection |
| Audit policy change | Success & Failure | Detect tampering |
| Audit privilege use | Success & Failure | Detect abuse of rights |
| Audit system events | Success & Failure | Catch shutdowns & service changes |

Use **Group Policy Editor** →  
`Computer Configuration > Windows Settings > Security Settings > Local Policies > Audit Policy`

---

## 🧱 3. User Account Control (UAC)

| Setting | Recommended Value |
|----------|------------------|
| “Admin Approval Mode” | Enabled |
| “Run all administrators in Admin Approval Mode” | On |
| “Prompt on Secure Desktop” | Enabled |

Ensures privilege elevation is explicitly approved.

---

## 🔐 4. SMB & Network Protocols

| Policy | Recommended Value | Purpose |
|---------|------------------|----------|
| SMB Signing | Required | Prevent tampering or MITM |
| SMBv1 | Disabled | Legacy protocol vulnerability |
| LLMNR & NetBIOS | Disabled | Prevent name spoofing attacks |
| Remote Registry | Disabled | Reduce attack surface |
| Unnecessary shares | Removed | Prevent unintentional exposure |

---

## 🧩 5. Service & System Hardening

| Service | Action |
|----------|--------|
| Telnet | Disable |
| FTP | Disable unless isolated |
| Remote Desktop | Require NLA (Network Level Authentication) |
| Windows Remote Management (WinRM) | Enable only secure HTTPS listener |
| Windows Defender Real‑Time Protection | Enabled |
| Attack Surface Reduction (ASR) rules | Enabled |

---

## ⚙️ Validation Commands
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select RequireSecuritySignature
Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSecuritySignature
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" | Select ConsentPromptBehaviorAdmin, EnableLUA
auditpol /get /category:*
