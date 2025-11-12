# 🧩 Windows General Hardening Guide

## 🧭 Scope
Baseline hardening checklist for Windows Server 2019 / 2022 and Windows 10 / 11.  
Applies to both domain members and standalone hosts.

---

## 🔒 1. Account Policies

Policy → Minimum password length = ≥ 12 | Prevents weak passwords  
Policy → Complexity requirement = Enabled | Blocks trivial passwords  
Policy → Maximum password age = 90 days | Enforces rotation  
Policy → Account lockout threshold = 5 invalid attempts | Stops brute‑force  
Policy → Lockout duration = ≥ 15 minutes | Delays repeated attacks  

🧭 Goal: Ensure password and lockout policies resist common cracking attempts.

---

## 🕵️‍♂️ 2. Audit Policy Configuration

Audit logon events = Success & Failure → Tracks all authentications  
Audit account logon events = Success & Failure → Useful for AD correlation  
Audit object access = Success & Failure → Monitors File and Registry changes  
Audit policy change = Success & Failure → Detects tampering  
Audit privilege use = Success & Failure → Identifies privilege abuse  
Audit system events = Success & Failure → Catches service and shutdown actions  

Path to apply via Group Policy:  
Computer Configuration → Windows Settings → Security Settings → Local Policies → Audit Policy

🧭 Goal: Provide full visibility into authentication, policy, and system changes.

---

## 🧱 3. User Account Control (UAC)

Setting → Admin Approval Mode = Enabled  
Setting → Run all administrators in Admin Approval Mode = On  
Setting → Prompt on Secure Desktop = Enabled  

🧭 Goal: Force explicit elevation approval and prevent background privilege escalation.

---

## 🔐 4. SMB & Network Protocols

• SMB Signing = Required — Prevents tampering or MITM attacks  
• SMBv1 = Disabled — Legacy protocol vulnerability (EternalBlue, WannaCry)  
• LLMNR & NetBIOS = Disabled — Stops name spoofing and hash exfiltration  
• Remote Registry = Disabled — Reduces attack surface  
• Unnecessary shares = Removed — Prevents unintentional exposure  

🧭 Goal: Harden legacy protocols and contain lateral movement vectors.

---

## 🧩 5. Service & System Hardening

Service Telnet → Disable  
Service FTP → Disable unless isolated and secured (SFTP preferred)  
Remote Desktop → Require Network Level Authentication (NLA)  
Windows Remote Management (WinRM) → Enable only HTTPS listener (5986)  
Windows Defender Real‑Time Protection → Enabled  
Attack Surface Reduction (ASR) rules → Enabled via Defender policy  

🧭 Goal: Shrink the attack surface and enforce secure remote access paths.

---

## ⚙️ Validation Steps (Inline Commands)

Check SMB Security Signature → Get‑ItemProperty HKLM \SYSTEM \CurrentControlSet \Services \LanManServer \Parameters → RequireSecuritySignature  

Check SMB Protocol and Signing → Get‑SmbServerConfiguration → EnableSMB1Protocol, EnableSecuritySignature  

Check UAC Policies → Get‑ItemProperty HKLM \Software \Microsoft \Windows \CurrentVersion \Policies \System → ConsentPromptBehaviorAdmin, EnableLUA  

View Audit Policy → auditpol /get /category:*  

🧭 Goal: Validate applied policies without modifying system state.

---

**Author:** yasinabedini  
**Repository:** Harden‑Self / playbooks / windows  
**License:** MIT  
**Last Update:** 2025‑11‑13  

---

🔹 Consistent application of these baselines across Windows hosts prevents credential theft, lateral movement, and configuration drift. Continuous audit ensures these controls remain enforced enterprise‑wide.
