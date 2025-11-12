# 🔥 Windows Firewall & Network Isolation Hardening

## 🧭 Scope
Enterprise‑grade configuration for Windows 10/11 and Windows Server 2019/2022.  
Focus: Host‑based isolation and strict inbound/outbound control for Tiered networks.

---

## 🔐 1. Firewall Profile Policy

| Profile | Default Inbound | Default Outbound | Logging | Notes |
|----------|----------------|------------------|----------|--------|
| Domain | Block | Allow | Enabled | Internal trusted zone |
| Private | Block | Allow | Enabled | Limited LAN access |
| Public | Block | Allow | Enabled | Internet/Limited access |

All profiles must enforce inbound = Block by default.  
Outbound allows only explicitly required business ports (443, 80, 53).  

🧭 Goal: Deny all unsolicited inbound traffic and limit egress scope.

---

## 🧩 2. Firewall Logging Baseline

* Log file path → `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`  
* Maximum file size → 16 MB  
* Log dropped packets = Enabled  
* Log successful connections = Enabled  
* Retention policy = 30 days, rotated weekly  

🧭 Goal: Ensure audit trail of all incoming/outgoing blocks.

---

## 🧱 3. Zone Segmentation

Group devices by zone levels (Tier 0→3 or Domain/Private/Public).  

| Zone | Example Hosts | Allowed Ports |
|------|----------------|---------------|
| Tier 0 | Domain Controllers, CA | 389, 636, 3268, 443 |
| Tier 1 | Application Servers | 443, 5985 |
| Tier 2 | Workstations | 443 only |
| Tier 3 | DMZ/Public | Explicit custom rules only |

Implement rules based on source/destination zone pairs.  
🧭 Goal: Prevent lateral movement and unauthorized RPC/WMI.

---

## ⚙️ 4. Secure Windows Remote Management (WinRM)

* Allow WinRM traffic only over HTTPS (Port 5986).  
* Create explicit rules: “Allow WinRM from Tier 1 Subnet to Tier 0 Hosts”.  
* Block HTTP Port 5985 for non‑privileged users.  
* Logging: Event ID = 6 and 91 correlation in EventViewer → Microsoft‑Windows‑WinRM.

🧭 Goal: Harden remote management path to prevent clear‑text sessions.

---

## 🧰 5. Outbound Control Policy

Recommended outbound allowances:
* HTTPS (443) → Corporate Proxy IPs only  
* DNS (53) → Internal Resolvers only  
* NTP (123) → Domain Time Servers  
* Block SMTP 25 for non‑mail systems  
* Enforce proxy compliance for browser and app traffic  

🧭 Goal: Stop leakage and tunneling toward uncontrolled external hosts.

---

## 🧠 6. Dynamic Brute‑Force Block (Optional)

Enable automatic IP blocking after N connection failures:  
Event IDs 5152/5157 → Trigger PowerShell action creating temporary Firewall rule.  
Retention = 120 minutes.  

🧭 Goal: Rate‑limit repeated attack patterns at the firewall layer.

---

## 🧩 7. Validation Checkpoints

Confirm:
* Firewall profiles = “All Enabled”  
* Default Inbound = Block  
* Logging file exists and records activity  
* WinRM HTTP disabled, HTTPS allowed  
* Outbound rules aligned with baseline ports ‎(443, 53, 123)  
* Dynamic block rule creation tested under controlled failed login attempts  

🧭 Goal: Full alignment with CIS Windows Server 2.0 Control 10.9.1 through 10.9.4.

---

**Author:** yasinabedini  
**Repository:** Harden‑Self / playbooks / windows  
**License:** MIT  
**Last Update:** 2025‑11‑13

---

🔹 Proper firewall segmentation is the cornerstone of network isolation. It blocks lateral spread, enforces least privilege connectivity, and ensures forensic visibility via logs.
