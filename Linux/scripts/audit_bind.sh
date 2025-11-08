#!/bin/bash
# Author: yasinabedini
# GitHub: https://github.com/yasinabedini
# Purpose: Audit BIND (named) configuration for secure setup

CONFIG="/etc/named.conf"
if [ ! -f "$CONFIG" ]; then
    CONFIG="/etc/bind/named.conf.options"
fi

SCORE=0
TOTAL=10

echo "=== BIND (DNS) Hardening Audit ==="

check_conf() {
    local desc="$1"
    local pattern="$2"
    local expected="$3"
    if grep -Eiq "$pattern" "$CONFIG" 2>/dev/null; then
        echo "[+] $desc ✅"
        ((SCORE++))
    else
        echo "[!] $desc ❌  (recommended: $expected)"
    fi
}

check_conf "Recursion disabled" "recursion\s+no" "recursion no;"
check_conf "Zone transfer restricted" "allow-transfer\s+\{[[:space:]]*none" "allow-transfer { none; };"
check_conf "Version string hidden" "version\s+\"(DNS|Bind|Server)" 'version "DNS Server";'
check_conf "Listen-on restricted" "listen-on\s+\{[0-9\.\;\ ]+\}" "listen-on { 127.0.0.1; 192.168.x.x; };"
check_conf "Rate-limit enabled" "rate-limit\s+\{" "rate-limit { responses-per-second 5; };"
grep -Eiq "view\s+\"internal\"" "$CONFIG" && echo "[+] Split internal/external views ✅" && ((SCORE++)) || echo "[!] No internal/external view separation ❌"
grep -Eiq "controls\s+\{.+127\.0\.0\.1" "$CONFIG" && echo "[+] RNDC control restricted ✅" && ((SCORE++)) || echo "[!] RNDC accessible remotely ❌"
[ "$(stat -c '%a' /var/named 2>/dev/null)" -le 750 ] && echo "[+] Zone file permissions OK ✅" && ((SCORE++)) || echo "[!] Zone permissions too loose ❌"
grep -Eiq "channel\s+query_log" "$CONFIG" && echo "[+] Query logging enabled ✅" && ((SCORE++)) || echo "[!] Query logging missing ❌"
/usr/sbin/named -v 2>/dev/null | grep -qiE "9\.[0-9]+" && echo "[+] BIND version check passed ✅" && ((SCORE++)) || echo "[!] Could not verify BIND version ❌"

PERCENT=$((SCORE * 100 / TOTAL))
echo -e "\nSecurity Score: ${PERCENT}%"
