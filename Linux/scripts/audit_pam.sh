#!/bin/bash
# Author: yasinabedini
# GitHub: https://github.com/yasinabedini
# Purpose: Audit PAM configuration (Debian/Ubuntu)

AUTH_FILE="/etc/pam.d/common-auth"
PASS_FILE="/etc/pam.d/common-password"
FAILLOCK="/etc/security/faillock.conf"
LOGIN_DEFS="/etc/login.defs"
LIMITS="/etc/security/limits.conf"

SCORE=0
TOTAL=10

echo "=== PAM Hardening Audit (Debian) ==="

check_conf() {
    local desc="$1"
    local pattern="$2"
    local file="$3"
    local expected="$4"
    if grep -Eiq "$pattern" "$file" 2>/dev/null; then
        echo "[+] $desc ✅"
        ((SCORE++))
    else
        echo "[!] $desc ❌  (recommended: $expected)"
    fi
}

# 1-2 Account lockout policy
check_conf "Faillock configured" "pam_faillock\.so" "$AUTH_FILE" "use pam_faillock.so"
check_conf "Lockout threshold set" "deny\s*=\s*[1-9]" "$FAILLOCK" "deny = 5, unlock_time = 600"

# 3 Password complexity
check_conf "Password complexity enforced" "minlen\s*=\s*1[2-9]" "/etc/security/pwquality.conf" "minlen >= 12"

# 4 Password expiration
check_conf "Password expiration configured" "PASS_MAX_DAYS\s+[1-9]" "$LOGIN_DEFS" "PASS_MAX_DAYS 90"

# 5 su restriction
check_conf "su restricted to admin group" "pam_wheel\.so" "/etc/pam.d/su" "auth required pam_wheel.so group=admin"

# 6 Null passwords disabled
grep -Eiq "nullok" "$AUTH_FILE" && echo "[!] Null passwords allowed ❌" || { echo "[+] Null passwords disabled ✅"; ((SCORE++)); }

# 7 Permissions on /etc/security/
find /etc/security -type f -perm /022 -exec echo "[!] Weak perms on {} ❌" \; | grep -q . \
    || { echo "[+] /etc/security permissions secure ✅"; ((SCORE++)); }

# 8 Password history
grep -Eiq "pam_unix\.so.*remember=" "$PASS_FILE" && echo "[+] Password history enforced ✅" && ((SCORE++)) \
    || echo "[!] Password history not enforced ❌"

# 9 sudo PAM logging
grep -Eiq "pam_(tally2|faillock)\.so" "/etc/pam.d/sudo" && echo "[+] sudo PAM auditing enabled ✅" && ((SCORE++)) \
    || echo "[!] sudo PAM auditing missing ❌"

# 10 Session limits
grep -Eiq "maxlogins" "$LIMITS" && echo "[+] Session limit defined ✅" && ((SCORE++)) \
    || echo "[!] No session limits configured ❌"

PERCENT=$((SCORE * 100 / TOTAL))
echo -e "\nSecurity Score: ${PERCENT}%"
