#!/bin/bash
# Author: yasinabedini
# GitHub: https://github.com/yasinabedini
# Purpose: Audit Apache configurations for hardening compliance

CONFIG_MAIN="/etc/httpd/conf/httpd.conf"
CONFIG_SSL="/etc/httpd/conf.d/ssl.conf"

# For Ubuntu/Debian path fallback
if [ ! -f "$CONFIG_MAIN" ]; then
    CONFIG_MAIN="/etc/apache2/apache2.conf"
    CONFIG_SSL="/etc/apache2/mods-enabled/ssl.conf"
fi

SCORE=0
TOTAL=10

check() {
    local desc="$1"
    local pattern="$2"
    local expected="$3"
    if grep -Eiq "$pattern" "$CONFIG_MAIN" "$CONFIG_SSL" 2>/dev/null; then
        echo "[+] $desc ✅"
        ((SCORE++))
    else
        echo "[!] $desc ❌  (recommended: $expected)"
    fi
}

echo "=== Apache Hardening Audit ==="

check "Directory listing disabled" "Options\s+-Indexes" "Options -Indexes"
check "ServerSignature Off" "ServerSignature\s+Off" "ServerSignature Off"
check "ServerTokens Prod" "ServerTokens\s+Prod" "ServerTokens Prod"
check "X-Frame-Options Header Set" "X-Frame-Options" "Header always set X-Frame-Options SAMEORIGIN"
check "HTTPS enforced" "RewriteRule\s+\^https" "Redirect HTTP to HTTPS"
grep -Eiq "SSLProtocol.*-SSLv2.*-SSLv3" "$CONFIG_SSL" 2>/dev/null && echo "[+] SSLProtocol hardened ✅" && ((SCORE++)) || echo "[!] SSLProtocol weak ❌ (recommend: disable SSLv2/v3/TLSv1/1.1)"
grep -Eiq "SSLCipherSuite.*HIGH" "$CONFIG_SSL" 2>/dev/null && echo "[+] SSLCipherSuite strong ✅" && ((SCORE++)) || echo "[!] Weak SSLCipherSuite ❌"
check ".htaccess Restricted" "AllowOverride\s+None" "AllowOverride None"
check "Unnecessary modules disabled" "#LoadModule" "Comment out unused modules"
grep -Eiq "CustomLog\s+" "$CONFIG_MAIN" && grep -Eiq "ErrorLog\s+" "$CONFIG_MAIN" && echo "[+] Logging enabled ✅" && ((SCORE++)) || echo "[!] Logging incomplete ❌"

PERCENT=$((SCORE * 100 / TOTAL))
echo -e "\nSecurity Score: ${PERCENT}%"
