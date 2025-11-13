# Harden-Safe

**Comprehensive Security Hardening Scripts and Guides for Windows, Linux, and Active Directory Environments**

---

## Project Structure

This repository is organized into three main operational areas: `ActiveDirectory`, `Linux`, and `Windows`.

<img width="1154" height="373" alt="image" src="https://github.com/user-attachments/assets/80019d56-8e00-48eb-837a-f9e63f936ac8" />
<img width="345" height="414" alt="image" src="https://github.com/user-attachments/assets/39c60047-e1de-4720-a85f-56851d9101b6" />



---

## Overview

`Harden-Safe` is a curated collection of documentation and automated scripts designed for the professional hardening of critical systems and services. The project's primary goal is to provide reliable, auditable, and actionable resources to significantly reduce the attack surface and enhance the security posture across diverse IT infrastructures.

---

## Content Breakdown


### Linux

This section provides in-depth security guides (`.md` files) for various Linux services and system components, alongside corresponding Bash audit scripts (`.sh` files) for quick security checks.

| Service/Component | Documentation | Audit Script |
| :--- | :--- | :--- |
| **Web Server** | `apache_hardening.md`, `nginx_hardening.md` | `audit_apache.sh`, `audit_nginx.sh` |
| **Database** | `mysql_hardening.md` | `audit_mysql.sh` |
| **System** | `pam_hardening.md`, `ssh_hardening.md` | `audit_pam.sh`, `audit_ssh.sh` |
| **Containers** | `docker_hardening.md` | `audit_docker.sh` |
| **DNS** | `bind_hardening.md` | `audit_bind.sh` |

### Windows

This section includes specific hardening guides (`.md` files) and automated PowerShell scripts (`.ps1` files) focused on strengthening the Windows operating system and its built-in security features.

| Focus Area | Documentation | Audit Script |
| :--- | :--- | :--- |
| **Endpoint Protection** | `defender_asr_hardening.md` | `audit_defender_asr.ps1` |
| **Encryption** | `bitlocker_hardening.md` | `audit_bitlocker.ps1` |
| **Credential Security** | `credential_protection_hardening.md` | `audit_credential_protection.ps1` |
| **Logging/Detection** | `logging_sysmon_hardening.md` | `audit_logging_sysmon.ps1` |
| **Networking** | `firewall_hardening.md`, `rdp_hardening.md` | `audit_firewall.ps1`, `audit_rdp.ps1` |
| **Management** | `powershell_hardening.md` | `audit_powershell.ps1` |
| **Maintenance** | `update_patch_hardening.md` | `audit_update_patch.ps1` |

---

## How to Use

1. **Clone the Repository:**
```bash
   git clone https://github.com/yasinabedini/harden-safe.git
   cd harden-safe


Author : yasinabedini GitHub : https://github.com/yasinabedini

