### 📋 Overview
SSH (Secure Shell) provides remote access and system management capabilities. A misconfigured SSH service can expose your system to brute-force attacks, privilege escalation, and remote exploitation.

---

## 🧩 Common Weak Points
- Root login allowed
- Password-based authentication enabled
- Weak cipher or MAC algorithms
- No idle session timeout
- Protocol 1 enabled
- Open to all users without restrictions
- X11 forwarding or TCP forwarding enabled unnecessarily
- SSH banners revealing OS or version info

---

## 🔒 Hardening Steps

| # | Action | Config File | Recommended Setting | Purpose |
|---|---------|--------------|--------------------|----------|
| 1 | Disable root login | `/etc/ssh/sshd_config` | `PermitRootLogin no` | Prevent direct root compromise |
| 2 | Disable password auth (use keys) | `/etc/ssh/sshd_config` | `PasswordAuthentication no` | Mitigate brute-force attacks |
| 3 | Enforce protocol 2 | `/etc/ssh/sshd_config` | `Protocol 2` | Use modern SSH protocol |
| 4 | Limit users/groups | `/etc/ssh/sshd_config` | `AllowUsers user1 user2` | Restrict access scope |
| 5 | Set session timeout | `/etc/ssh/sshd_config` | `ClientAliveInterval 300` + `ClientAliveCountMax 0` | Auto-disconnect idle sessions |
| 6 | Disable X11 forwarding | `/etc/ssh/sshd_config` | `X11Forwarding no` | Prevent GUI injection attacks |
| 7 | Disable TCP forwarding | `/etc/ssh/sshd_config` | `AllowTcpForwarding no` | Prevent local port tunneling |
| 8 | Set login banner | `/etc/ssh/sshd_config` | `Banner /etc/issue.net` | Legal & privacy notice |
| 9 | Restrict ciphers | `/etc/ssh/sshd_config` | `Ciphers aes256-ctr,aes192-ctr,aes128-ctr` | Enforce strong encryption |
| 10 | Restrict MACs | `/etc/ssh/sshd_config` | `MACs hmac-sha2-512,hmac-sha2-256` | Secure message authentication |
| 11 | PermitEmptyPasswords | ` etc/ssh/sshd_config` | `PermitEmptyPasswords no` | Enforce Password |
| 12 | MaxAuthTries | ` etc/ssh/sshd_config` | `MaxAuthTries 3` | Restriction failed login |
| 13 | MaxSessions  | ` etc/ssh/sshd_config` | `MaxSessions 2` | Restriction open session |
| 14 | Listen Address  | ` etc/ssh/sshd_config` | `ListenAddress 10.0.0.1` | Restriction Source IP |
| 15 | Port  | ` etc/ssh/sshd_config` | `Port 2222` | Change Default Port |
---

## 🧠 Verify & Apply
After editing, restart SSH service:
```bash
sudo systemctl restart sshd
```

| Author | Repository| Last Update |
|---------|-------------|----------|--------------|
| [**yasinabedini**](https://github.com/yasinabedini) | Harden‑Self / playbooks / linux | 2025‑11‑13 |
