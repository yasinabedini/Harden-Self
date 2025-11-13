#!/bin/bash
################################################################################
# Script Name:  audit_apache.sh
# Author:       yasinabedini
# GitHub:       https://github.com/yasinabedini
# Purpose:      Simple Apache security audit
# Version:      3.0 (Simplified)
# Date:         2025-11-13
################################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Config
APACHE_CONF="/etc/apache2/apache2.conf"
SECURITY_CONF="/etc/apache2/conf-available/security.conf"
SITES_ENABLED="/etc/apache2/sites-enabled"

PASS=0
FAIL=0

echo "=========================================="
echo "    Apache Security Audit"
echo "=========================================="
echo ""

# Check 1: Apache installed
if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Apache installed"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Apache not installed"
    ((FAIL++))
fi

# Check 2: ServerTokens Prod
if grep -qE "^\s*ServerTokens\s+Prod" "$SECURITY_CONF" "$APACHE_CONF" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} ServerTokens set to Prod"
    ((PASS++))
else
    echo -e "${RED}✗${NC} ServerTokens not set to Prod"
    ((FAIL++))
fi

# Check 3: ServerSignature Off
if grep -qE "^\s*ServerSignature\s+Off" "$SECURITY_CONF" "$APACHE_CONF" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} ServerSignature Off"
    ((PASS++))
else
    echo -e "${RED}✗${NC} ServerSignature not Off"
    ((FAIL++))
fi

# Check 4: TraceEnable Off
if grep -qE "^\s*TraceEnable\s+Off" "$SECURITY_CONF" "$APACHE_CONF" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} TraceEnable Off"
    ((PASS++))
else
    echo -e "${RED}✗${NC} TraceEnable not Off"
    ((FAIL++))
fi

# Check 5: Options -Indexes
if grep -qE "Options.*-Indexes" "$APACHE_CONF" "$SITES_ENABLED"/* 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Directory listing disabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Directory listing not disabled"
    ((FAIL++))
fi

# Check 6: mod_security enabled
if apache2ctl -M 2>/dev/null | grep -q "security2_module"; then
    echo -e "${GREEN}✓${NC} ModSecurity enabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} ModSecurity not enabled"
    ((FAIL++))
fi

# Check 7: mod_evasive enabled
if apache2ctl -M 2>/dev/null | grep -q "evasive"; then
    echo -e "${GREEN}✓${NC} mod_evasive enabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} mod_evasive not enabled"
    ((FAIL++))
fi

# Check 8: mod_headers enabled
if apache2ctl -M 2>/dev/null | grep -q "headers_module"; then
    echo -e "${GREEN}✓${NC} mod_headers enabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} mod_headers not enabled"
    ((FAIL++))
fi

# Check 9: X-Frame-Options header
if grep -qE "Header.*X-Frame-Options" "$SECURITY_CONF" "$APACHE_CONF" "$SITES_ENABLED"/* 2>/dev/null; then
    echo -e "${GREEN}✓${NC} X-Frame-Options configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} X-Frame-Options missing"
    ((FAIL++))
fi

# Check 10: X-Content-Type-Options header
if grep -qE "Header.*X-Content-Type-Options" "$SECURITY_CONF" "$APACHE_CONF" "$SITES_ENABLED"/* 2>/dev/null; then
    echo -e "${GREEN}✓${NC} X-Content-Type-Options configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} X-Content-Type-Options missing"
    ((FAIL++))
fi

# Check 11: HSTS header
if grep -qE "Header.*Strict-Transport-Security" "$SECURITY_CONF" "$APACHE_CONF" "$SITES_ENABLED"/* 2>/dev/null; then
    echo -e "${GREEN}✓${NC} HSTS configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} HSTS missing"
    ((FAIL++))
fi

# Check 12: SSL/TLS enabled
if apache2ctl -M 2>/dev/null | grep -q "ssl_module"; then
    echo -e "${GREEN}✓${NC} SSL module enabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} SSL module not enabled"
    ((FAIL++))
fi

# Check 13: Modern SSL protocols (TLS 1.2/1.3)
if grep -qE "SSLProtocol.*-all.*\+TLSv1\.[23]" "$APACHE_CONF" "$SITES_ENABLED"/* 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Modern TLS protocols (1.2/1.3)"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Weak or missing TLS protocols"
    ((FAIL++))
fi

# Check 14: Strong SSL ciphers
if grep -qE "SSLCipherSuite" "$APACHE_CONF" "$SITES_ENABLED"/* 2>/dev/null; then
    echo -e "${GREEN}✓${NC} SSL ciphers configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} SSL ciphers not configured"
    ((FAIL++))
fi

# Check 15: Apache running as non-root user
if ps aux | grep -E "(apache2|httpd)" | grep -v root | grep -v grep >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Apache running as non-root"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Apache running as root"
    ((FAIL++))
fi

TOTAL=$((PASS + FAIL))
PERCENT=$((PASS * 100 / TOTAL))

echo ""
echo "=========================================="
echo "  Score: $PASS/$TOTAL ($PERCENT%)"
echo "=========================================="
