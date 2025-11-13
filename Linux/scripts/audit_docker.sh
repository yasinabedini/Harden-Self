#!/bin/bash
################################################################################
# Script Name:  audit_docker.sh
# Author:       yasinabedini
# GitHub:       https://github.com/yasinabedini
# Purpose:      Simple Docker security audit
# Version:      3.0 (Simplified)
# Date:         2025-11-13
################################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

echo "=========================================="
echo "    Docker Security Audit"
echo "=========================================="
echo ""

# Check 1: Docker installed
if command -v docker >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Docker installed"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Docker not installed"
    ((FAIL++))
    exit 1
fi

# Check 2: Docker daemon running
if systemctl is-active --quiet docker 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Docker daemon running"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Docker daemon not running"
    ((FAIL++))
fi

# Check 3: Userland proxy disabled
if docker info 2>/dev/null | grep -q "userland-proxy: false"; then
    echo -e "${GREEN}✓${NC} Userland proxy disabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Userland proxy not disabled"
    ((FAIL++))
fi

# Check 4: Live restore enabled
if docker info 2>/dev/null | grep -q "live-restore: true"; then
    echo -e "${GREEN}✓${NC} Live restore enabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Live restore not enabled"
    ((FAIL++))
fi

# Check 5: Content trust enabled
if [ "$DOCKER_CONTENT_TRUST" = "1" ]; then
    echo -e "${GREEN}✓${NC} Content trust enabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Content trust not enabled"
    ((FAIL++))
fi

# Check 6: Docker socket permissions (660 or 600)
if [ -S /var/run/docker.sock ]; then
    PERMS=$(stat -c %a /var/run/docker.sock 2>/dev/null)
    if [[ "$PERMS" =~ ^(660|600)$ ]]; then
        echo -e "${GREEN}✓${NC} Docker socket permissions secure"
        ((PASS++))
    else
        echo -e "${RED}✗${NC} Docker socket permissions insecure"
        ((FAIL++))
    fi
else
    echo -e "${RED}✗${NC} Docker socket not found"
    ((FAIL++))
fi

# Check 7: No containers running as root
ROOT_CONTAINERS=$(docker ps -q 2>/dev/null | xargs -r docker inspect --format='{{.Config.User}}' 2>/dev/null | grep -c "^$")
if [ "$ROOT_CONTAINERS" -eq 0 ] 2>/dev/null; then
    echo -e "${GREEN}✓${NC} No containers running as root"
    ((PASS++))
else
    echo -e "${RED}✗${NC} $ROOT_CONTAINERS containers running as root"
    ((FAIL++))
fi

# Check 8: No privileged containers
PRIV_CONTAINERS=$(docker ps -q 2>/dev/null | xargs -r docker inspect --format='{{.HostConfig.Privileged}}' 2>/dev/null | grep -c "true")
if [ "$PRIV_CONTAINERS" -eq 0 ] 2>/dev/null; then
    echo -e "${GREEN}✓${NC} No privileged containers"
    ((PASS++))
else
    echo -e "${RED}✗${NC} $PRIV_CONTAINERS privileged containers found"
    ((FAIL++))
fi

# Check 9: Resource limits configured
NO_MEMORY_LIMIT=$(docker ps -q 2>/dev/null | xargs -r docker inspect --format='{{.HostConfig.Memory}}' 2>/dev/null | grep -c "^0$")
if [ "$NO_MEMORY_LIMIT" -eq 0 ] 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Memory limits configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} $NO_MEMORY_LIMIT containers without memory limit"
    ((FAIL++))
fi

# Check 10: No containers with --net=host
HOST_NET=$(docker ps -q 2>/dev/null | xargs -r docker inspect --format='{{.HostConfig.NetworkMode}}' 2>/dev/null | grep -c "host")
if [ "$HOST_NET" -eq 0 ] 2>/dev/null; then
    echo -e "${GREEN}✓${NC} No containers using host network"
    ((PASS++))
else
    echo -e "${RED}✗${NC} $HOST_NET containers using host network"
    ((FAIL++))
fi

# Check 11: AppArmor enabled
if docker info 2>/dev/null | grep -q "apparmor"; then
    echo -e "${GREEN}✓${NC} AppArmor enabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} AppArmor not enabled"
    ((FAIL++))
fi

# Check 12: Seccomp enabled
if docker info 2>/dev/null | grep -q "seccomp"; then
    echo -e "${GREEN}✓${NC} Seccomp enabled"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Seccomp not enabled"
    ((FAIL++))
fi

# Check 13: No containers with --cap-add=ALL
CAP_ALL=$(docker ps -q 2>/dev/null | xargs -r docker inspect --format='{{.HostConfig.CapAdd}}' 2>/dev/null | grep -c "ALL")
if [ "$CAP_ALL" -eq 0 ] 2>/dev/null; then
    echo -e "${GREEN}✓${NC} No containers with all capabilities"
    ((PASS++))
else
    echo -e "${RED}✗${NC} $CAP_ALL containers with all capabilities"
    ((FAIL++))
fi

# Check 14: Docker daemon log level (info)
if docker info 2>/dev/null | grep -qE "Logging Driver: (json-file|syslog|journald)"; then
    echo -e "${GREEN}✓${NC} Logging driver configured"
    ((PASS++))
else
    echo -e "${RED}✗${NC} Logging driver not configured"
    ((FAIL++))
fi

# Check 15: TLS enabled for Docker daemon
if ps aux | grep dockerd | grep -q "\-\-tlsverify"; then
    echo -e "${GREEN}✓${NC} TLS enabled for daemon"
    ((PASS++))
else
    echo -e "${RED}✗${NC} TLS not enabled for daemon"
    ((FAIL++))
fi

TOTAL=$((PASS + FAIL))
PERCENT=$((PASS * 100 / TOTAL))

echo ""
echo "=========================================="
echo "  Score: $PASS/$TOTAL ($PERCENT%)"
echo "=========================================="
