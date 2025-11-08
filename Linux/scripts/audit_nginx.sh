#!/bin/bash
# Author: yasinabedini
# GitHub: https://github.com/yasinabedini
# Purpose: Audit Nginx configuration security posture

CONFIG_MAIN="/etc/nginx/nginx.conf"
SITES="/etc/nginx/sites-enabled"
SSL_SNIPPET="/etc/nginx/snippets/ssl-params.conf"

SCORE=0
TOTAL=10

echo "=== Nginx Hardening Audit ==="

check_pattern() {
    local desc="$1"
    local pattern="$2"
    local expected="$3"
    if grep -Eiq "$pattern" "$CONFIG_MAIN" "$SITES" "$SSL_SNIPPET" 2>/dev/null; then
        echo "[+] $desc ✅"
        ((SCORE++))
    else
        echo "[!] $desc ❌  (recommended: $expected)"
    fi
}

check_pattern "Hide version (server_tokens off)" "server_tokens\s+off" "server_tokens off;"
check_pattern "Directory listing disabled" "autoindex\s+off" "autoindex off;"
check_pattern "X-Frame-Options header set" "X-Frame-Options" "add_header X-Frame-Options SAMEORIGIN;"
check_pattern "Strict-Transport-Security header set" "Strict-Transport-Security" "add_header Strict-Transport-Security;"
check_pattern "HTTPS redirect configured" "return\s+301\s+https://" "return 301 https://\$host\$request_uri;"
grep -Eiq "TLSv1(\.1)?|SSLv3" "$SSL_SNIPPET" 2>/dev/null && echo "[!] Weak SSL/TLS version ❌" || { echo "[+] Strong SSL/TLS ✅"; ((SCORE++)); }
grep -Eiq "ssl_ciphers.*(AES_256|CHACHA20)" "$SSL_SNIPPET" 2>/dev/null && echo "[+] Strong SSL ciphers ✅" && ((SCORE++)) || echo "[!] Weak SSL ciphers ❌"
check_pattern "client_max_body_size limited" "client_max_body_size" "client_max_body_size 10M;"
[ "$(stat -c '%a' /var/log/nginx 2>/dev/null)" -le 750 ] && echo "[+] Log directory permission OK ✅" && ((SCORE++)) || echo "[!] Log directory permission weak ❌"
check_pattern "Rate limiting set" "limit_req" "limit_req_zone / limit_req configured"

PERCENT=$((SCORE * 100 / TOTAL))
echo -e "\nSecurity Score: ${PERCENT}%"
