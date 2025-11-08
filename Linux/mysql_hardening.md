# MySQL Hardening Guide (Debian/Ubuntu)

### 📋 Overview
MySQL’s default configuration is often permissive and exposes the server to privilege escalation, weak authentication, or data exfiltration. This guide focuses on securing MySQL 5.7+ and 8.x on Debian/Ubuntu systems.

---

## 🧩 Common Weak Points
- Root account accessible remotely  
- Anonymous or empty‑password accounts  
- Old authentication plugins (mysql_native_password) enabled  
- Insecure privileges (`GRANT ALL ON *.*`)  
- Weak or missing SSL/TLS enforcement  
- World‑readable config files  
- Lack of audit logging  

---

## 🔒 Hardening Steps

| # | Action | File/Command | Recommended Setting | Purpose |
|---|---------|---------------|--------------------|----------|
| 1 | Disable remote root login | `mysql` CLI | `UPDATE mysql.user SET host='localhost' WHERE user='root';` | Prevent external root access |
| 2 | Remove anonymous users | `mysql` CLI | `DELETE FROM mysql.user WHERE user='';` | Close anonymous access |
| 3 | Enforce strong password policy | `/etc/mysql/mysql.conf.d/mysqld.cnf` | `validate_password.policy=STRONG` | Enforce robust passwords |
| 4 | Require SSL connections | `/etc/mysql/mysql.conf.d/mysqld.cnf` | `require_secure_transport=ON` | Encrypt all connections |
| 5 | Restrict user host source | via SQL | `CREATE USER 'dbuser'@'10.0.%' IDENTIFIED BY ...;` | Limit login IPs |
| 6 | Remove test database | `DROP DATABASE test;` | Test DB can leak data |
| 7 | Enable binary log and audit log | `/etc/mysql/mysql.conf.d/mysqld.cnf` | `log_error`, `general_log`, `slow_query_log` enabled | Track suspicious ops |
| 8 | Limit privileges | SQL | Use least‑privilege GRANTs | Prevent privilege misuse |
| 9 | Secure file permissions | `/etc/mysql/` | `chmod 600 my.cnf` | Hide credentials |
| 10 | Disable old/insecure plugins | `/etc/mysql/` | `auth_plugin=mysql_native_password` only if needed | Restrict downgrade auth |

---

### ⚙️ Example Secure Snippet:
```bash
[mysqld]
require_secure_transport = ON
validate_password.policy = STRONG
validate_password.length = 12
skip-symbolic-links
bind-address = 127.0.0.1
secure-file-priv = /var/lib/mysql-files
