# BIND (DNS) Hardening Guide

### 📋 Overview
BIND is the oldest and most popular DNS server. Misconfiguration can allow attacks such as cache poisoning, zone transfer leaks, recursion abuse, and amplification in DDoS attacks.

---

## 🧩 Common Weak Points
- Recursion enabled for everyone  
- Zone transfers open to any host  
- DNS version and server info disclosed  
- Weak file permissions on zone data  
- Missing `rate-limit` configuration  
- Logging disabled or too verbose  

---

## 🔒 Hardening Steps

| # | Action | Config File | Recommended Setting | Purpose |
|---|---------|--------------|--------------------|----------|
| 1 | Disable recursion for external clients | `/etc/named.conf` | `recursion no;` | Prevents abuse as open resolver |
| 2 | Restrict zone transfers | `/etc/named.conf` or zone files | `allow-transfer { none; };` | Stops data leakage |
| 3 | Hide BIND version | `/etc/named.conf` | `version "DNS Server";` | Prevents fingerprinting |
| 4 | Limit query sources | `/etc/named.conf` | `listen-on { 127.0.0.1; 192.168.x.x; };` | Restrict requests by IP |
| 5 | Enable response rate limiting | `/etc/named.conf` | `rate-limit { responses-per-second 5; };` | Throttle abuse attempts |
| 6 | Disable zone recursion caching for external | `/etc/named.conf` | Separate `view "internal"` and `view "external"` | Isolation |
| 7 | Restrict control interface | `/etc/rndc.conf` | `controls { inet 127.0.0.1; };` | Prevents remote abuse |
| 8 | Adjust file permissions | `/var/named/*` | Owned by `named:named`, 640 | Prevent unauthorized reads |
| 9 | Enable detailed logging | `/etc/named.conf` | Use `channel query_log` | Incident response visibility |
| 10 | Regularly patch/update | `system packages` | `yum update bind` or `apt upgrade bind9` | Fix known vulnerabilities |

### Example Snippet:
```bash
options {
directory "/var/named";
recursion no;
allow-transfer { none; };
listen-on { 127.0.0.1; 10.0.0.1; };
version "DNS Server";
rate-limit {
responses-per-second 5;
};
};

| Author | Repository | Last Update |
|---------|-------------|----------|--------------|
| [**yasinabedini**](https://github.com/yasinabedini) | Harden‑Self / playbooks / linux | 2025‑11‑13 |
