# PAM (Pluggable Authentication Modules) Hardening Guide

### 📋 Overview
PAM provides a flexible way to manage system authentication on Linux.  
Incorrect or weak configurations can result in brute‑force vulnerabilities, missing account lockouts, or poor password policies.

This guide targets **Debian/Ubuntu** systems.

---

## 🧩 Common Weak Points
- No account lockout after failed logins  
- Weak password complexity  
- No session timeout or TTY limits  
- No password history enforcement  
- Insecure `sudo` PAM integration  
- Incorrect file permissions on `/etc/security/*`

---

## 🔒 Hardening Steps

| # | Action | File | Recommended Setting | Purpose |
|---|---------|------|--------------------|----------|
| 1 | Enable account lockout | `/etc/pam.d/common-auth` and `/etc/security/faillock.conf` | use `pam_tally2.so` | Prevent brute‑force |
| 2 | Configure lockout duration & threshold | `/etc/security/faillock.conf` | `deny = 5`, `unlock_time = 600` | Balance blocking and usability |
| 3 | Enforce strong password complexity | `/etc/security/pwquality.conf` | `minlen = 12`, `ucredit = -1`, `lcredit = -1`, `dcredit = -1`, `ocredit = -1` | Stop weak passwords |
| 4 | Enforce password expiration and history | `/etc/login.defs` | `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 7` | Rotate passwords |
| 5 | Restrict `su` command access | `/etc/pam.d/su` | `auth required pam_wheel.so group=admin` | Limit privilege escalation |
| 6 | Disable null passwords | `/etc/pam.d/common-auth` | `nullok` **must NOT exist** | Prevent blank logins |
| 7 | Protect security files | `/etc/security/*` | `chmod 600` | Prevent tampering |
| 8 | Enable password history | `/etc/pam.d/common-password` | `remember=5` in `pam_unix.so` line | Stop reuse |
| 9 | Audit sudo PAM | `/etc/pam.d/sudo` | include `auth required pam_tally2.so` or faillock | Track failed sudo attempts |
| 10 | Apply consistent session limits | `/etc/security/limits.conf` | `* hard maxlogins 10` | Prevent abuse via many sessions |

---

### 🔧 Example PAM snippet (lockout)
```bash
# /etc/pam.d/common-auth
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=600
auth required pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=600
account required pam_tally2.so
```

| Author | Repository | Last Update |
|---------|-------------|----------|--------------|
| [**yasinabedini**](https://github.com/yasinabedini) | Harden‑Self / playbooks / linux | 2025‑11‑13 |
