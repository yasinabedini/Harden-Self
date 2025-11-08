# Apache Hardening Guide

### 📋 Overview
Apache HTTP Server is one of the most widely used web servers. Misconfigurations can expose sensitive data, enable information leakage, or allow attackers to exploit insecure modules and permissions.

---

## 🧩 Common Weak Points
- Directory listing enabled  
- Server signature and version exposed  
- Weak SSL/TLS configuration or outdated protocols (SSLv2/3, TLS 1.0)  
- `.htaccess` misuse allowing overrides  
- Publicly writable directories  
- Modules enabled unnecessarily (autoindex, status, proxy, etc.)  
- Lack of file permission restrictions  

---

## 🔒 Hardening Steps

| # | Action | Config File | Recommended Setting | Purpose |
|---|---------|--------------|--------------------|----------|
| 1 | Disable directory listing | `/etc/httpd/conf/httpd.conf` OR `/etc/apache2/apache2.conf` | `Options -Indexes` | Prevents listing of directory contents |
| 2 | Hide Apache version and OS info | same | `ServerTokens Prod` & `ServerSignature Off` | Prevents exposure of system details |
| 3 | Enforce secure HTTP headers | site config or `.conf` in `/etc/httpd/conf.d/` | add `<IfModule mod_headers.c>` rules | Mitigate XSS and clickjacking |
| 4 | Enforce HTTPS only | `/etc/httpd/conf.d/ssl.conf` | Redirect HTTP → HTTPS | Encrypt communication |
| 5 | Enable strong SSL/TLS | `/etc/httpd/conf.d/ssl.conf` | `SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1` | Disable weak protocols |
| 6 | Use strong cipher suites | same | `SSLCipherSuite HIGH:!aNULL:!MD5` | Prevent weak encryption |
| 7 | Disable unnecessary modules | `/etc/httpd/conf.modules.d/` | comment out unused modules | Reduce attack surface |
| 8 | Set permissions | `/var/www/html` | `chown -R root:root` and limit write | Prevent unauthorized files |
| 9 | Restrict .htaccess overrides | `/etc/httpd/conf/httpd.conf` | `AllowOverride None` | Centralize configuration |
| 10 | Enable logging and monitoring | `/etc/httpd/conf/httpd.conf` | Ensure `CustomLog` and `ErrorLog` paths set | For auditing events |

Example headers you can enforce:
```apache
<IfModule mod_headers.c>
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "no-referrer-when-downgrade"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>
