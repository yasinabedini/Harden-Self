
#!/bin/bash
# Author: yasinabedini
# GitHub: https://github.com/yasinabedini
# Purpose: Audit SSH configuration for basic hardening compliance

CONFIG="/etc/ssh/sshd_config"
SCORE=0
TOTAL=10

check() {
    local desc="$1"
    local key="$2"
    local expected="$3"
    local result
    result=$(grep -E "^\s*$key" "$CONFIG" | tail -1 | awk '{print $2}')
    if [ "$result" == "$expected" ]; then
        echo -e "[+] $desc ($key): $result ✅"
        ((SCORE++))
    else
        echo -e "[!] $desc ($key): ${result:-not set} ❌  (recommended: $expected)"
    fi
}

echo "=== SSH Hardening Audit ==="
check "Root login" "PermitRootLogin" "no"
check "Password Authentication" "PasswordAuthentication" "no"
check "Protocol Version" "Protocol" "2"
check "X11 Forwarding" "X11Forwarding" "no"
check "TCP Forwarding" "AllowTcpForwarding" "no"
check "Client Alive Interval" "ClientAliveInterval" "300"
check "Client Alive Count" "ClientAliveCountMax" "0"
check "Ciphers" "Ciphers" "aes256-ctr,aes192-ctr,aes128-ctr"
check "MACs" "MACs" "hmac-sha2-512,hmac-sha2-256"

if grep -q "^AllowUsers" "$CONFIG"; then
    echo "[+] AllowUsers directive set ✅"
    ((SCORE++))
else
    echo "[!] AllowUsers directive not set ❌"
fi

PERCENT=$((SCORE * 100 / TOTAL))
echo -e "\nSecurity Score: ${PERCENT}%"
