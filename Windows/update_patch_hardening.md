# 🔄 Windows Update & Patch Management Hardening

## 🧭 Scope
Applies to Windows 10/11 and Windows Server 2019/2022 environments in corporate or tiered networks.  
Goal: Enforce secure, timely patch deployment, reduce exploitation windows, and maintain compliant baselines.

---

## 🧰 1. Automatic Update Enforcement

| Setting | Recommended Value | Description |
|----------|-------------------|--------------|
| `AUOptions` | 4 | Automatically download and install updates |
| `ScheduledInstallDay` | 0 (Every day) | Daily installation cycle |
| `ScheduledInstallTime` | 03:00 | Non‑business hour |
| `NoAutoRebootWithLoggedOnUsers` | 1 | Prevent auto reboot during sessions |

🧭 Objective: Keep systems patched without user interruption or admin delays.

---

## 🔒 2. Update Source Control

* Define WSUS or Windows Update for Business servers inside the domain.  
  Example: `http://wsus.domain.local:8530`  
* Force update source via GPO → *Specify Intranet Microsoft update service location*.  
* Block external update servers unless through approved corporate proxy.  
* Validate update source connectivity weekly using scheduled test jobs.

🧭 Objective: Prevent rogue, unverified updates and preserve control of content distribution.

---

## ⚙️ 3. Driver & Firmware Signature Enforcement

* Require signed drivers only (`DriverSigning=1`).  
* Enable Device Guard code integrity for kernel drivers.  
* Maintain firmware updates through OEM‑approved signed packages.  
* Deny legacy unsigned `.inf` driver installation attempts.  

🧭 Objective: Stop unapproved driver injection and ensure kernel‑level trust.

---

## 🧩 4. Patch Testing & Deployment Tiering

Use **Tiered release** model for enterprise scalability:

| Tier | Device Type | Patch Delay | Method |
|------|--------------|--------------|--------|
| 0 | Domain Controllers, Core Infra | 0 Days | Immediate deployment |
| 1 | Application Servers | 3 Days | Staged rollout |
| 2 | Workstations | 7 Days | Standard cycle |
| 3 | Lab / Test | ≥ 7 Days | Validation sandbox |

Apply pilot patch testing under Tier 3 before global rollout.  
🧭 Objective: Avoid service disruption while maintaining timely patch coverage.

---

## 🔐 5. Security Baseline Synchronization

Weekly automation tasks:
* Query CVE feeds matched to current Windows build number.  
* Map missing KBs → WSUS dynamic approval workflow.  
* Alert Security Ops if patch gap > 14 days.  
* Export compliance report into CSV → `\\SIEM\Reports\PatchCompliance.csv`.

🧭 Objective: Maintain visibility on patch health and compliance posture.

---

## 🧠 6. Delivery Optimization Policy

Recommended configuration for bandwidth control:
* Mode = Group (1) — share within subnet only.  
* Max cache age = 7 Days.  
* Max cache size = 10 GB.  
* Do not use Internet peers for update delivery.  

🧭 Objective: Efficient but isolated update propagation.

---

## 🧾 7. Validation Checklist

Ensure:
* Automatic updates enabled (`AUOptions = 4`).  
* WSUS/Business update source configured and active.  
* All installed drivers verified as signed.  
* Tiered deployment schedule enforced.  
* Compliance report generation successful.  

🧭 Goal: Continuous alignment with CIS Benchmark 13.2.1–13.3.3 and Microsoft Security Update Guide policies.

---

**Author:** yasinabedini  
**Repository:** Harden‑Self / playbooks / windows  
**License:** MIT  
**Last Update:** 2025‑11‑13

---

🔹 Patch Management closes the lifecycle gap between vulnerability disclosure and system exposure, maintaining resilience against privilege escalation and remote exploit chains.
