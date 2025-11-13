#!/bin/bash
################################################################################
# Script Name:  audit_nginx.sh
# Author:       yasinabedini
# GitHub:       https://github.com/yasinabedini
# Purpose:      Simple Nginx security audit
# Version:      3.0 (Simplified)
# Date:         2025-11-13
################################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Config
NGINX_CONF="/etc/nginx/nginx.conf"
SITES_ENABLED="/etc/nginx/sites-enabled"

PASS=0
FAIL=0

echo "=========================================="
echo "    Nginx Security Audit"
echo "=========================================="
echo ""

# Check 1: Nginx installed
if command -v nginx >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Nginx installed"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Nginx not installed"
    ((FAIL++))
fi

# Check 2: server_tokens off
if grep -qE "^\s*server_tokens\s+off" "$NGINX_CONF" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} server_tokens off"
    ((PASS++))
else
    echo -e "${RED}✗${NC} server_tokens not off"
    ((FAIL++))
fi

# Check 3: Non-root user
if grep -qE "^\s*user\s+(?!root)" "$NGINX_CONF" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Running as non-root user"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Running as root or not configured"
    ((FAIL++))
fi

# Check 4: autoindex off
if grep -qE "^\s*autoindex\s+on" "$NGINX_CONF" "$SITES_ENABLED"/* 2>/dev/null; then
    echo -e "${RED}✗${NC} Directory listing enabled"
    ((FAIL++))
else
    echo -e "${GREEN}✓${NC} Directory listing disabled"
    ((PASS++))
fi

# Check 5: X-Frame-Options
if grep -qE "add_header\s+X-Frame-Options" "$NGINX_CONF" "$SITES_ENABLED"/* 2>/dev/null; then
    echo -e "${GREEN}✓${NC} X-Frame-Options configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} X-Frame-Options missing"
    ((FAIL++))
fi

# Check 6: X-Content-Type-Options
if grep -qE "add_header\s+X-Content-Type-Options" "$NGINX_CONF" "$SITES_ENABLED"/* 2>/dev/null; then
    echo -e "${GREEN}✓${NC} X-Content-Type-Options configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} X-Content-Type-Options missing"
    ((FAIL++))
fi

# Check 7: HSTS
if grep -qE "add_header\s+Strict-Transport-Security" "$NGINX_CONF" "$SITES_ENABLED"/* 2>/dev/null; then
    echo -e "${GREEN}✓${NC} HSTS configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} HSTS missing"
    ((FAIL++))
fi

# Check 8: SSL Protocols (TLS 1.2/1.3)
if grep -qE "ssl_protocols.*TLSv1\.(2|3)" "$NGINX_CONF" "$SITES_ENABLED"/* 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Modern TLS protocols (1.2/1.3)"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Weak or missing TLS protocols"
    ((FAIL++))
fi

# Check 9: Rate limiting
if grep -qE "limit_req_zone|limit_conn_zone" "$NGINX_CONF" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Rate limiting configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Rate limiting not configured"
    ((FAIL++))
fi

# Check 10: client_max_body_size
if grep -qE "^\s*client_max_body_size" "$NGINX_CONF" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} client_max_body_size configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} client_max_body_size not configured"
    ((FAIL++))
fi

TOTAL=$((PASS + FAIL))
PERCENT=$((PASS * 100 / TOTAL))

echo ""
echo "=========================================="
echo "  Score: $PASS/$TOTAL ($PERCENT%)"
echo "=========================================="
