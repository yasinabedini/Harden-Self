# MySQL/MariaDB Security Hardening Guide

📋 Overview
MySQL is an open source relational database management system (RDBMS) that's used to store and manage data. Its reliability, performance, scalability, and ease of use make MySQL a popular choice for developers.

## Security Checklist

- [ ] Root password set and strong
- [ ] Anonymous users removed
- [ ] Remote root login disabled
- [ ] Test database removed
- [ ] `caching_sha2_password` authentication enabled
- [ ] `bind-address` set to 127.0.0.1 or specific IP
- [ ] SSL/TLS enabled and enforced
- [ ] Firewall rules configured
- [ ] File permissions properly set
- [ ] `local-infile` disabled
- [ ] Logging enabled and monitored
- [ ] Backup strategy implemented
- [ ] Regular updates scheduled
- [ ] Security audits performed monthly

---

## 1. Authentication & User Management

### Secure Authentication Plugin (MySQL 8.0+)
sql
-- Set default authentication plugin in /etc/mysql/mysql.conf.d/mysqld.cnf
[mysqld]
default_authentication_plugin=caching_sha2_password

### Remove Insecure Users
sql
-- Connect as root
mysql -u root -p

-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root access
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Apply changes
FLUSH PRIVILEGES;

### Create Secure Application User
sql
-- Create user with strong authentication
CREATE USER 'app_user'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'StrongP@ssw0rd!123';

-- Grant minimal required privileges
GRANT SELECT, INSERT, UPDATE, DELETE ON application_db.* TO 'app_user'@'localhost';

-- Apply changes
FLUSH PRIVILEGES;

### Password Policy
sql
-- Set password policy (MySQL 8.0+)
SET GLOBAL validate_password.policy=STRONG;
SET GLOBAL validate_password.length=14;
SET GLOBAL validate_password.mixed_case_count=1;
SET GLOBAL validate_password.number_count=1;
SET GLOBAL validate_password.special_char_count=1;

---

## 2. Network Security

### Configuration File: `/etc/mysql/mysql.conf.d/mysqld.cnf`

ini
[mysqld]
# Bind to localhost only (disable external access)
bind-address = 127.0.0.1

# Skip networking if only local access needed
# skip-networking

# SSL/TLS Configuration
require_secure_transport = ON
ssl_ca = /etc/mysql/ssl/ca-cert.pem
ssl_cert = /etc/mysql/ssl/server-cert.pem
ssl_key = /etc/mysql/ssl/server-key.pem
tls_version = TLSv1.2,TLSv1.3

# Connection Limits
max_connections = 100
max_connect_errors = 10
max_user_connections = 50

# Timeout Settings
wait_timeout = 300
interactive_timeout = 300
connect_timeout = 10

### Generate SSL Certificates
bash
# Create SSL directory
sudo mkdir -p /etc/mysql/ssl
cd /etc/mysql/ssl

# Generate CA certificate
sudo openssl genrsa 2048 > ca-key.pem
sudo openssl req -new -x509 -nodes -days 3650 -key ca-key.pem -out ca-cert.pem

# Generate server certificate
sudo openssl req -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem -out server-req.pem
sudo openssl rsa -in server-key.pem -out server-key.pem
sudo openssl x509 -req -in server-req.pem -days 3650 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 -out server-cert.pem

# Set permissions
sudo chown mysql:mysql /etc/mysql/ssl/*
sudo chmod 600 /etc/mysql/ssl/*-key.pem
sudo chmod 644 /etc/mysql/ssl/*-cert.pem

### Firewall Configuration
bash
# Allow MySQL only from specific IP (if remote access needed)
sudo ufw allow from 192.168.1.100 to any port 3306

# Or block all external access
sudo ufw deny 3306/tcp

---

## 3. File System Security

### Configuration File: `/etc/mysql/mysql.conf.d/mysqld.cnf`

ini
[mysqld]
# Disable LOCAL INFILE
local-infile = 0

# Disable symbolic links
symbolic-links = 0

# Restrict file operations
secure-file-priv = /var/lib/mysql-files/

# Data directory permissions
datadir = /var/lib/mysql

### Set Proper Permissions
bash
# MySQL data directory
sudo chown -R mysql:mysql /var/lib/mysql
sudo chmod 750 /var/lib/mysql

# Configuration files
sudo chown root:root /etc/mysql/my.cnf
sudo chmod 644 /etc/mysql/my.cnf

# Secure file directory
sudo mkdir -p /var/lib/mysql-files
sudo chown mysql:mysql /var/lib/mysql-files
sudo chmod 750 /var/lib/mysql-files

---

## 4. Logging & Monitoring

### Configuration File: `/etc/mysql/mysql.conf.d/mysqld.cnf`

ini
[mysqld]
# Error Log
log_error = /var/log/mysql/error.log

# General Query Log (careful with disk space)
general_log = 1
general_log_file = /var/log/mysql/general.log

# Slow Query Log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

# Binary Logging (for replication/recovery)
log_bin = /var/log/mysql/mysql-bin.log
expire_logs_days = 7
max_binlog_size = 100M

### Log Rotation
bash
# Create logrotate configuration
sudo nano /etc/logrotate.d/mysql


/var/log/mysql/*.log {
daily
rotate 7
missingok
compress
delaycompress
notifempty
create 640 mysql adm
sharedscripts
postrotate
/usr/bin/mysql -e 'FLUSH LOGS'
endscript
}

---

## 5. Additional Security Measures

### Disable Unused Features
ini
[mysqld]
# Disable LOAD DATA LOCAL
local-infile = 0

# Disable SHOW DATABASES for non-privileged users
skip-show-database

# Disable external file access
secure-file-priv = /var/lib/mysql-files/

### Query Limits
sql
-- Set resource limits for users
ALTER USER 'app_user'@'localhost' WITH 
MAX_QUERIES_PER_HOUR 1000 
MAX_UPDATES_PER_HOUR 100 
MAX_CONNECTIONS_PER_HOUR 50;

### Audit Plugin (Enterprise/Percona)
sql
-- Install audit plugin
INSTALL PLUGIN audit_log SONAME 'audit_log.so';

-- Configure in my.cnf
[mysqld]
plugin-load-add=audit_log.so
audit_log_file=/var/log/mysql/audit.log
audit_log_format=JSON
audit_log_rotate_on_size=10485760

---

## 6. Backup Security

### Secure Backup Script
bash
#!/bin/bash
# /usr/local/bin/mysql_backup.sh

BACKUP_DIR="/backup/mysql"
DATE=$(date +%Y%m%d_%H%M%S)
MYSQL_USER="backup_user"
MYSQL_PASS="SecureBackupPass123!"

# Create backup
mysqldump -u$MYSQL_USER -p$MYSQL_PASS --all-databases --single-transaction \
--quick --lock-tables=false > "$BACKUP_DIR/mysql_backup_$DATE.sql"

# Encrypt backup
gpg --encrypt --recipient backup@example.com "$BACKUP_DIR/mysql_backup_$DATE.sql"

# Remove unencrypted file
rm "$BACKUP_DIR/mysql_backup_$DATE.sql"

# Keep only last 7 days
find $BACKUP_DIR -name "*.gpg" -mtime +7 -delete

---


## References

- [MySQL 8.0 Security Guide](https://dev.mysql.com/doc/refman/8.0/en/security.html)
- [MariaDB Security Documentation](https://mariadb.com/kb/en/securing-mariadb/)
- [CIS MySQL Benchmark](https://www.cisecurity.org/benchmark/mysql)
- [OWASP Database Security](https://owasp.org/www-community/vulnerabilities/SQL_Injection)

| Author | Repository  | Last Update |
|---------|-------------|----------|--------------|
| [**yasinabedini**](https://github.com/yasinabedini) | Harden‑Self / playbooks / linux | 2025‑11‑13 |
