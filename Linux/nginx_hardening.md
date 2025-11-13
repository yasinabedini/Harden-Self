# Nginx Hardening Guide

### 📋 Overview
Nginx is a high‑performance web server and reverse proxy.  
Although lightweight and efficient, a weak configuration can expose security flaws such as information disclosure, HTTP header attacks, or SSL downgrade vulnerabilities.

---

## 🧩 Common Weak Points
- Server version and OS info exposed  
- Directory browsing enabled  
- Weak or outdated SSL/TLS configuration  
- Missing essential HTTP security headers  
- Default configurations active (`default_server`)  
- Access logs disabled or world‑readable  
- Client request body or header size not restricted (DoS attack vector)  

---

## 🔒 Hardening Steps

| # | Action | Config File | Recommended Setting | Purpose |
|---|---------|--------------|--------------------|----------|
| 1 | Hide Nginx version | `/etc/nginx/nginx.conf` | `server_tokens off;` | Prevent version disclosure |
| 2 | Disable directory listing | Site config `/etc/nginx/sites-available/*.conf` | `autoindex off;` | Prevent directory browsing |
| 3 | Add security headers | same | `add_header` directives (see below) | XSS / clickjacking protection |
| 4 | Enforce HTTPS (redirect HTTP → HTTPS) | Site config | `return 301 https://$host$request_uri;` | Encrypt connections |
| 5 | Harden SSL/TLS | `/etc/nginx/snippets/ssl-params.conf` | Disable TLS < 1.2 | Strong encryption only |
| 6 | limit_conn_zone | same | `$binary_remote_addr zone=addr:10m;` | Prevent DoS / overflow |
| 7 | Limit request size | same | `client_max_body_size 10M;` | Prevent DoS / overflow |
| 8 | Protect logs | `/var/log/nginx` | `chmod 640 access.log error.log` | Restrict log access |
| 9 | Disable unnecessary modules | build/config | disable mail, stream if unused | Reduce attack surface |
| 10 | Enable rate limiting | site config | `limit_req_zone` & `limit_req` | Prevent brute‑force or flooding attacks |

📦 Example Security Headers:
```nginx
add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "no-referrer-when-downgrade";
add_header Permissions-Policy "geolocation=(), microphone=()";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
```

| Author | Repository | Last Update |
|---------|-------------|----------|--------------|
| [**yasinabedini**](https://github.com/yasinabedini) | Harden‑Self / playbooks / linux | 2025‑11‑13 |
