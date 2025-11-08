#!/bin/bash
# Author: yasinabedini
# GitHub: https://github.com/yasinabedini
# Purpose: Audit MySQL hardening state (Debian/Ubuntu)
# Requires: mysql client with root or sudo privileges

USER="root"
MYSQL="mysql -u${USER} -p -e"
SCORE=0
TOTAL=10

echo "=== MySQL Hardening Audit ==="

check_mysql(){
  local desc="$1"
  local query="$2"
  local expected="$3"
  local result
  result=$(sudo mysql -sN -e "$query" 2>/dev/null)
  if echo "$result" | grep -iq "$expected"; then
    echo "[+] $desc ✅"
    ((SCORE++))
  else
    echo "[!] $desc ❌"
  fi
}

# 1 Root remote access check
root_hosts=$(sudo mysql -sN -e "SELECT host FROM mysql.user WHERE user='root';")
if echo "$root_hosts" | grep -qv "localhost"; then
  echo "[!] Root accessible remotely ❌"
else
  echo "[+] Root restricted to localhost ✅"
  ((SCORE++))
fi

# 2 Anonymous users
anon_count=$(sudo mysql -sN -e "SELECT COUNT(*) FROM mysql.user WHERE user='';")
[ "$anon_count" -eq 0 ] && echo "[+] No anonymous users ✅" && ((SCORE++)) || echo "[!] Anonymous users exist ❌"

# 3 Password policy
pw_policy=$(sudo mysql -sN -e "SHOW VARIABLES LIKE 'validate_password.policy';" | awk '{print $2}')
[[ "$pw_policy" =~ (MEDIUM|STRONG|2|3) ]] && echo "[+] Password policy strong ✅" && ((SCORE++)) || echo "[!] Weak password policy ❌"

# 4 SSL enforcement
ssl=$(sudo mysql -sN -e "SHOW VARIABLES LIKE 'require_secure_transport';" | awk '{print $2}')
[[ "$ssl" == "ON" ]] && echo "[+] SSL enforced ✅" && ((SCORE++)) || echo "[!] SSL not required ❌"

# 5 Test database removed
testdb=$(sudo mysql -sN -e "SHOW DATABASES LIKE 'test';")
[ -z "$testdb" ] && echo "[+] Test DB removed ✅" && ((SCORE++)) || echo "[!] Test DB still present ❌"

# 6 Binary log enabled
binlog=$(sudo mysql -sN -e "SHOW VARIABLES LIKE 'log_bin';" | awk '{print $2}')
[[ "$binlog" == "ON" ]] && echo "[+] Binary logging enabled ✅" && ((SCORE++)) || echo "[!] Binary log disabled ❌"

# 7 Error log set
elog=$(sudo mysql -sN -e "SHOW VARIABLES LIKE 'log_error';" | awk '{print $2}')
[ -n "$elog" ] && echo "[+] Error log path set ✅" && ((SCORE++)) || echo "[!] No error log defined ❌"

# 8 my.cnf permissions
perm=$(stat -c "%a" /etc/mysql/my.cnf 2>/dev/null)
[ "$perm" -le 600 ] && echo "[+] /etc/mysql/my.cnf permissions OK ✅" && ((SCORE++)) || echo "[!] Weak permissions on my.cnf ❌"

# 9 skip-symbolic-links check
grep -Eq 'skip-symbolic-links' /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null && echo "[+] skip-symbolic-links set ✅" && ((SCORE++)) || echo "[!] skip-symbolic-links missing ❌"

# 10 Binding interface
grep -Eq '^bind-address\s*=\s*127\.0\.0\.1' /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null && echo "[+] Bound to localhost ✅" && ((SCORE++)) || echo "[!] MySQL bound to external interface ❌"

PERCENT=$((SCORE * 100 / TOTAL))
echo -e "\nSecurity Score: ${PERCENT}%"
