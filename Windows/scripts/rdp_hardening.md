# 🛡️ Windows Remote Desktop (RDP) Hardening — Unified Guide

> **Scope:** Windows Server 2016–2022 and Windows 10/11  
> **Goal:** Secure RDP against credential theft, brute‑force, and lateral movement.

---

## 1️⃣ Network Level Authentication (NLA)
Require credential validation before session creation.
Create the value UserAuthentication=1 under  
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp  

🧭 **Goal:** Block unauthenticated pre‑sessions.

---

## 2️⃣ High Encryption and TLS 1.2
Set MinEncryptionLevel=3 and SecurityLayer=2 under the same path above.  
Disable TLS 1.0 and enable TLS 1.2 under  
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols  

🧭 **Goal:** Enforce modern encryption and TLS 1.2/FIPS compliance.

---

## 3️⃣ Disable Redirections
Under HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services  
set all these values to 1: fDisableClip, fDisableDrive, fDisableCcm, fDisableLPT, fDisablePNPRedir  

🧭 **Goal:** Prevent clipboard and drive data exfiltration.

---

## 4️⃣ Session Timeout and Auto‑Disconnect
In the same path above, set MaxIdleTime=900000 (15 minutes)  
and MaxDisconnectionTime=600000 (10 minutes).  

🧭 **Goal:** Terminate idle or disconnected sessions quickly.

---

## 5️⃣ Restrict RDP Logon Rights
From Group Policy:  
Local Policies → User Rights Assignment → Allow log on through Remote Desktop Services  
Only Administrators or HelpDesk accounts should be allowed.  

🧭 **Goal:** Limit RDP access to trusted operators.

---

## 6️⃣ Credential Guard and Virtualization‑Based Security
Under HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard set EnableVirtualizationBasedSecurity=1  
and under HKLM\SYSTEM\CurrentControlSet\Control\Lsa set LsaCfgFlags=1.  

🧭 **Goal:** Protect LSASS memory against credential dumping.

---

## 7️⃣ Enforce Smart Card or MFA
Under HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services set fEnableSmartCard=1.  
Then, in Group Policy enable “Require use of Smart Card for logon”.  

🧭 **Goal:** Require hardware tokens or multi‑factor authentication.

---

## 8️⃣ Account Lockout Policy
Run this command to protect from brute‑force attempts:  
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15  

🧭 **Goal:** Lock user accounts after several failed logons.

---

## 9️⃣ Firewall and Port Obfuscation
Enable firewall with  
Set‑NetFirewallProfile ‑Profile Domain,Private,Public ‑Enabled True  
Change RDP port to 45289 by editing PortNumber=45289  
and create a new inbound firewall rule for port 45289.  

🧭 **Goal:** Hide RDP from default 3389 scans and enforce inbound rules.

---

## 🔍 10️⃣ RDP Audit and Logging
Enable auditing with  
auditpol /set /subcategory:"Logon" /success:enable /failure:enable  
auditpol /set /subcategory:"Network Connection" /success:enable /failure:enable  
Activate event logs:  
Microsoft‑Windows‑TerminalServices‑LocalSessionManager/Operational  
Microsoft‑Windows‑TerminalServices‑RemoteConnectionManager/Operational  

Event IDs:  
4624‑4625 → logon success/failure  
4778‑4779 → reconnect/disconnect  
1149 → RDP attempted connection  

🧭 **Goal:** Full visibility into all RDP logins.

---

## 🧩 11️⃣ Dynamic Brute‑Force Block
Add temporary firewall rule:  
New‑NetFirewallRule ‑DisplayName "TEMP_Block_RDP_BruteForce" ‑Direction Inbound ‑Protocol TCP ‑LocalPort 3389 ‑Action Block  
Automate removal of this rule every 30 minutes via Task Scheduler.  

🧭 **Goal:** Dynamically block repeated failed connections.

---

## ✅ Validation
Run audit script: .\scripts\audit_rdp.ps1  

Sample output:
NLA enabled  
Encryption level high  
Clipboard redirection disabled  
Credential Guard active  
Smart Card required  
Security Score: 95 %

---

| Author | Repository | License | Last Update |
|---------|-------------|----------|--------------|
| [**yasinabedini**](https://github.com/yasinabedini) | Harden‑Self / playbooks / windows | MIT | 2025‑11‑12 |

---

🔹 *Lock the door before the burglar learns your RDP port.*
