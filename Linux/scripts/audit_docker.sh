#!/bin/bash
# Author: yasinabedini
# GitHub: https://github.com/yasinabedini
# Purpose: Audit Docker Hardening configuration (Debian/Ubuntu)

DAEMON_JSON="/etc/docker/daemon.json"
SERVICE_FILE="/lib/systemd/system/docker.service"
SCORE=0
TOTAL=10

echo "=== Docker Hardening Audit ==="

check_json(){
  local key="$1"
  local val="$2"
  jq -e ".$key == $val" "$DAEMON_JSON" >/dev/null 2>&1
}

# 1 socket exposure
grep -Eq '\-H\s+tcp:\/\/0\.0\.0\.0:2375' "$SERVICE_FILE" 2>/dev/null && \
  echo "[!] Docker socket exposed ❌" || { echo "[+] Socket exposure: Secure ✅"; ((SCORE++)); }

# 2 userns remap
grep -Eq '"userns-remap"\s*:\s*"default"' "$DAEMON_JSON" 2>/dev/null && { echo "[+] User namespace remap enabled ✅"; ((SCORE++)); } || echo "[!] userns-remap disabled ❌"

# 3 inter-container communication
grep -Eq '"icc"\s*:\s*false' "$DAEMON_JSON" 2>/dev/null && { echo "[+] Inter-container communication disabled ✅"; ((SCORE++)); } || echo "[!] ICC enabled ❌"

# 4 seccomp profile
grep -Eq '"seccomp-profile"' "$DAEMON_JSON" 2>/dev/null && { echo "[+] Seccomp profile defined ✅"; ((SCORE++)); } || echo "[!] Seccomp profile missing ❌"

# 5 capabilities default drop
ps -ef | grep dockerd | grep -vi grep | grep -q "no-new-privileges" && { echo "[+] no-new-privileges active ✅"; ((SCORE++)); } || echo "[!] Privileged containers allowed ❌"

# 6 log driver
grep -Eq '"log-driver"\s*:\s*"json-file"' "$DAEMON_JSON" 2>/dev/null && { echo "[+] Log driver correct ✅"; ((SCORE++)); } || echo "[!] Log driver misconfigured ❌"

# 7 log rotation
grep -Eq '"max-size"' "$DAEMON_JSON" 2>/dev/null && { echo "[+] Log rotation configured ✅"; ((SCORE++)); } || echo "[!] No log rotation ❌"

# 8 live restore
grep -Eq '"live-restore"\s*:\s*true' "$DAEMON_JSON" 2>/dev/null && { echo "[+] Live restore enabled ✅"; ((SCORE++)); } || echo "[!] Live restore disabled ❌"

# 9 perms on /var/run/docker.sock
sock_perm=$(stat -c "%a" /var/run/docker.sock 2>/dev/null)
[ "$sock_perm" -le 660 ] && { echo "[+] Docker socket permissions OK ✅"; ((SCORE++)); } || echo "[!] Docker socket overly permissive ❌"

# 10 daemon user check
stat -c "%U" /var/run/docker.sock | grep -q "root" && { echo "[+] Docker runs as root (expected) ✅"; ((SCORE++)); } || echo "[!] Unexpected Docker daemon owner ❌"

PERCENT=$((SCORE * 100 / TOTAL))
echo -e "\nSecurity Score: ${PERCENT}%"
