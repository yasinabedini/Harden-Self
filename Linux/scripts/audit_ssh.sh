#!/bin/bash
################################################################################
# Script Name:  audit_ssh.sh
# Author:       yasinabedini
# GitHub:       https://github.com/yasinabedini
# Purpose:      Simple SSH security audit
# Version:      3.0 (Simplified)
# Date:         2025-11-13
################################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Config
SSHD_CONFIG="/etc/ssh/sshd_config"

PASS=0
FAIL=0

echo "=========================================="
echo "    SSH Security Audit"
echo "=========================================="
echo ""

# Check 1: SSH installed
if command -v sshd >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} SSH installed"
    ((PASS++))
else
    echo -e "${RED}✗${NC} SSH not installed"
    ((FAIL++))
fi

# Check 2: PermitRootLogin no
if grep -qE "^\s*PermitRootLogin\s+no" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Root login disabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Root login not disabled"
    ((FAIL++))
fi

# Check 3: PasswordAuthentication no
if grep -qE "^\s*PasswordAuthentication\s+no" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Password authentication disabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Password authentication enabled"
    ((FAIL++))
fi

# Check 4: PubkeyAuthentication yes
if grep -qE "^\s*PubkeyAuthentication\s+yes" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Public key authentication enabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Public key authentication not enabled"
    ((FAIL++))
fi

# Check 5: PermitEmptyPasswords no
if grep -qE "^\s*PermitEmptyPasswords\s+no" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Empty passwords disabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Empty passwords not disabled"
    ((FAIL++))
fi

# Check 6: Protocol 2
if ! grep -qE "^\s*Protocol\s+1" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} SSH Protocol 2"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Old SSH Protocol 1 enabled"
    ((FAIL++))
fi

# Check 7: MaxAuthTries
if grep -qE "^\s*MaxAuthTries\s+[1-3]" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} MaxAuthTries ≤ 3"
    ((PASS++))
else
    echo -e "${RED}✗${NC} MaxAuthTries not configured properly"
    ((FAIL++))
fi

# Check 8: ClientAliveInterval
if grep -qE "^\s*ClientAliveInterval\s+[1-9]" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} ClientAliveInterval configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} ClientAliveInterval not configured"
    ((FAIL++))
fi

# Check 9: ClientAliveCountMax
if grep -qE "^\s*ClientAliveCountMax\s+[0-2]" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} ClientAliveCountMax ≤ 2"
    ((PASS++))
else
    echo -e "${RED}✗${NC} ClientAliveCountMax not configured"
    ((FAIL++))
fi

# Check 10: X11Forwarding no
if grep -qE "^\s*X11Forwarding\s+no" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} X11 Forwarding disabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} X11 Forwarding not disabled"
    ((FAIL++))
fi

# Check 11: Modern Ciphers
if grep -qE "^\s*Ciphers\s+.*aes.*gcm" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Modern ciphers configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Modern ciphers not configured"
    ((FAIL++))
fi

# Check 12: Modern MACs
if grep -qE "^\s*MACs\s+.*hmac-sha2" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Modern MACs configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Modern MACs not configured"
    ((FAIL++))
fi

# Check 13: Modern KexAlgorithms
if grep -qE "^\s*KexAlgorithms\s+" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} KexAlgorithms configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} KexAlgorithms not configured"
    ((FAIL++))
fi

# Check 14: AllowUsers or AllowGroups
if grep -qE "^\s*(AllowUsers|AllowGroups)" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} User/Group restrictions configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} No user/group restrictions"
    ((FAIL++))
fi

# Check 15: Banner configured
if grep -qE "^\s*Banner\s+" "$SSHD_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Login banner configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Login banner not configured"
    ((FAIL++))
fi

TOTAL=$((PASS + FAIL))
PERCENT=$((PASS * 100 / TOTAL))

echo ""
echo "=========================================="
echo "  Score: $PASS/$TOTAL ($PERCENT%)"
echo "=========================================="
