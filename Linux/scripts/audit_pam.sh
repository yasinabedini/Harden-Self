#!/bin/bash
################################################################################
# Script Name:  audit_pam.sh
# Author:       yasinabedini
# GitHub:       https://github.com/yasinabedini
# Purpose:      Audit PAM (Pluggable Authentication Modules) configuration
# Version:      2.0 (Optimized)
# Date:         2025-11-13
################################################################################

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
readonly PAM_DIR="/etc/pam.d"
readonly PWQUALITY_CONF="/etc/security/pwquality.conf"
readonly LOGIN_DEFS="/etc/login.defs"
readonly FAILLOCK_CONF="/etc/security/faillock.conf"
readonly LOG_DIR="/var/log/pam_audit"
readonly TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
readonly LOG_FILE="${LOG_DIR}/pam_audit_${TIMESTAMP}.log"

# Counters
SCORE=0
TOTAL=0
WARNINGS=0
CRITICAL_FAILS=0

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

################################################################################
# Functions
################################################################################

log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

print_header() {
    log "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    log "${BLUE}║     PAM (Pluggable Authentication Modules) Audit           ║${NC}"
    log "${BLUE}╠════════════════════════════════════════════════════════════╣${NC}"
    log "${BLUE}║ Date: $(date +'%Y-%m-%d %H:%M:%S')                        ║${NC}"
    log "${BLUE}║ System: $(hostname)                                       ║${NC}"
    log "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    log ""
}

check_file_exists() {
    local file="$1"
    local desc="$2"
    
    ((TOTAL++))
    
    if [[ -f "$file" ]]; then
        log "${GREEN}[✓]${NC} ${desc} exists"
        log "    Location: ${file}"
        ((SCORE++))
        return 0
    else
        log "${RED}[✗]${NC} ${desc} not found"
        log "    Expected: ${file}"
        ((CRITICAL_FAILS++))
        return 1
    fi
    log ""
}

check_pwquality_setting() {
    local desc="$1"
    local setting="$2"
    local operator="$3"
    local expected="$4"
    local severity="${5:-CRITICAL}"
    
    ((TOTAL++))
    
    if [[ ! -f "$PWQUALITY_CONF" ]]; then
        log "${RED}[✗]${NC} ${desc} - pwquality.conf not found"
        return
    fi
    
    local value
    value=$(grep -E "^\s*${setting}\s*=" "$PWQUALITY_CONF" 2>/dev/null | tail -1 | cut -d'=' -f2 | tr -d ' ' || echo "not_set")
    
    local pass=0
    if [[ "$value" != "not_set" ]]; then
        case "$operator" in
            ">=")
                [[ "$value" -ge "$expected" ]] && pass=1
                ;;
            "<=")
                [[ "$value" -le "$expected" ]] && pass=1
                ;;
            "=")
                [[ "$value" -eq "$expected" ]] && pass=1
                ;;
        esac
    fi
    
    if [[ $pass -eq 1 ]]; then
        log "${GREEN}[✓]${NC} ${desc}"
        log "    Setting: ${setting} = ${value}"
        ((SCORE++))
    else
        if [[ "$severity" == "CRITICAL" ]]; then
            log "${RED}[✗]${NC} ${desc}"
            ((CRITICAL_FAILS++))
        else
            log "${YELLOW}[!]${NC} ${desc}"
            ((WARNINGS++))
        fi
        log "    Current: ${setting} = ${value}"
        log "    Expected: ${setting} ${operator} ${expected}"
        log "    Remediation: Edit ${PWQUALITY_CONF} and set '${setting} = ${expected}'"
    fi
    log ""
}

check_faillock_setting() {
    local desc="$1"
    local setting="$2"
    local expected="$3"
    
    ((TOTAL++))
    
    # Check faillock.conf first (modern)
    if [[ -f "$FAILLOCK_CONF" ]]; then
        local value
        value=$(grep -E "^\s*${setting}\s*=" "$FAILLOCK_CONF" 2>/dev/null | tail -1 | cut -d'=' -f2 | tr -d ' ' || echo "not_set")
        
        if [[ "$value" == "$expected" ]] || [[ "$value" != "not_set" && "$expected" == "configured" ]]; then
            log "${GREEN}[✓]${NC} ${desc}"
            log "    Setting: ${setting} = ${value}"
            ((SCORE++))
        else
            log "${RED}[✗]${NC} ${desc}"
            log "    Current: ${setting} = ${value}"
            log "    Expected: ${expected}"
            log "    Remediation: Edit ${FAILLOCK_CONF} and set '${setting} = ${expected}'"
            ((CRITICAL_FAILS++))
        fi
    else
        # Check for pam_faillock in PAM files (legacy)
        if grep -r "pam_faillock" "$PAM_DIR" >/dev/null 2>&1; then
            log "${YELLOW}[!]${NC} ${desc} - Using legacy pam_faillock"
            log "    Recommendation: Migrate to ${FAILLOCK_CONF}"
            ((WARNINGS++))
        else
            log "${RED}[✗]${NC} ${desc} - Neither faillock.conf nor pam_faillock found"
            log "    Remediation: Install and configure pam_faillock"
            ((CRITICAL_FAILS++))
        fi
    fi
    log ""
}

check_pam_module() {
    local desc="$1"
    local module="$2"
    local config_file="$3"
    local expected_line="$4"
    
    ((TOTAL++))
    
    if [[ ! -f "$PAM_DIR/$config_file" ]]; then
        log "${RED}[✗]${NC} ${desc} - ${config_file} not found"
        return
    fi
    
    if grep -qE "$module" "$PAM_DIR/$config_file" 2>/dev/null; then
        log "${GREEN}[✓]${NC} ${desc}"
        local line
        line=$(grep -E "$module" "$PAM_DIR/$config_file" | head -1)
        log "    Configuration: ${line}"
        ((SCORE++))
    else
        log "${RED}[✗]${NC} ${desc}"
        log "    Module: ${module} not found in ${config_file}"
        log "    Remediation: Add '${expected_line}' to ${PAM_DIR}/${config_file}"
        ((CRITICAL_FAILS++))
    fi
    log ""
}

check_login_defs() {
    local desc="$1"
    local setting="$2"
    local operator="$3"
    local expected="$4"
    
    ((TOTAL++))
    
    if [[ ! -f "$LOGIN_DEFS" ]]; then
        log "${RED}[✗]${NC} ${desc} - login.defs not found"
        return
    fi
    
    local value
    value=$(grep -E "^\s*${setting}\s+" "$LOGIN_DEFS" 2>/dev/null | awk '{print $2}' || echo "not_set")
    
    local pass=0
    if [[ "$value" != "not_set" ]]; then
        case "$operator" in
            ">=")
                [[ "$value" -ge "$expected" ]] && pass=1
                ;;
            "<=")
                [[ "$value" -le "$expected" ]] && pass=1
                ;;
            "=")
                [[ "$value" -eq "$expected" ]] && pass=1
                ;;
        esac
    fi
    
    if [[ $pass -eq 1 ]]; then
        log "${GREEN}[✓]${NC} ${desc}"
        log "    Setting: ${setting} = ${value}"
        ((SCORE++))
    else
        log "${YELLOW}[!]${NC} ${desc}"
        log "    Current: ${setting} = ${value}"
        log "    Expected: ${setting} ${operator} ${expected}"
        log "    Remediation: Edit ${LOGIN_DEFS} and set '${setting} ${expected}'"
        ((WARNINGS++))
    fi
    log ""
}

check_deprecated_module() {
    local desc="$1"
    local deprecated_module="$2"
    
    ((TOTAL++))
    
    if grep -r "$deprecated_module" "$PAM_DIR" >/dev/null 2>&1; then
        log "${RED}[✗]${NC} ${desc}"
        local files
        files=$(grep -rl "$deprecated_module" "$PAM_DIR" | tr '\n' ', ' | sed 's/,$//')
        log "    Deprecated Module: ${deprecated_module}"
        log "    Found in: ${files}"
        log "    Remediation: Replace with modern equivalent (e.g., pam_faillock)"
        ((CRITICAL_FAILS++))
    else
        log "${GREEN}[✓]${NC} ${desc}"
        log "    No deprecated module '${deprecated_module}' found"
        ((SCORE++))
    fi
    log ""
}

check_password_history() {
    ((TOTAL++))
    
    if grep -qE "pam_pwhistory.so.*remember=" "$PAM_DIR/common-password" 2>/dev/null || \
       grep -qE "pam_unix.so.*remember=" "$PAM_DIR/common-password" 2>/dev/null; then
        local history
        history=$(grep -E "remember=" "$PAM_DIR/common-password" | grep -oP 'remember=\K[0-9]+' | head -1)
        
        if [[ "$history" -ge 5 ]]; then
            log "${GREEN}[✓]${NC} Password History Enforced"
            log "    Remember: ${history} passwords"
            ((SCORE++))
        else
            log "${YELLOW}[!]${NC} Password History Too Short"
            log "    Current: remember=${history}"
            log "    Recommended: remember=5 or higher"
            ((WARNINGS++))
        fi
    else
        log "${RED}[✗]${NC} Password History Not Configured"
        log "    Remediation: Add 'remember=5' to pam_unix.so or pam_pwhistory.so"
        ((CRITICAL_FAILS++))
    fi
    log ""
}

check_umask_setting() {
    ((TOTAL++))
    
    if grep -qE "session.*pam_umask.so" "$PAM_DIR/common-session" 2>/dev/null; then
        log "${GREEN}[✓]${NC} Umask Module Configured"
        local line
        line=$(grep -E "session.*pam_umask.so" "$PAM_DIR/common-session" | head -1)
        log "    Configuration: ${line}"
        ((SCORE++))
    else
        log "${YELLOW}[!]${NC} Umask Module Not Found"
        log "    Recommendation: Add 'session optional pam_umask.so' to common-session"
        ((WARNINGS++))
    fi
    log ""
}

generate_summary() {
    local percentage=$((SCORE * 100 / TOTAL))
    
    log ""
    log "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    log "${BLUE}║                    AUDIT SUMMARY                           ║${NC}"
    log "${BLUE}╠════════════════════════════════════════════════════════════╣${NC}"
    log "${BLUE}║ Total Checks:       ${TOTAL}                                ║${NC}"
    log "${BLUE}║ Passed:             ${GREEN}${SCORE}${NC}                                 ║${NC}"
    log "${BLUE}║ Failed (Critical):  ${RED}${CRITICAL_FAILS}${NC}                                 ║${NC}"
    log "${BLUE}║ Warnings:           ${YELLOW}${WARNINGS}${NC}                                 ║${NC}"
    log "${BLUE}╠════════════════════════════════════════════════════════════╣${NC}"
    
    if [[ $percentage -ge 90 ]]; then
        log "${BLUE}║ Security Score:     ${GREEN}${percentage}%${NC} - Excellent                   ║${NC}"
    elif [[ $percentage -ge 75 ]]; then
        log "${BLUE}║ Security Score:     ${YELLOW}${percentage}%${NC} - Good                        ║${NC}"
    elif [[ $percentage -ge 50 ]]; then
        log "${BLUE}║ Security Score:     ${YELLOW}${percentage}%${NC} - Needs Improvement           ║${NC}"
    else
        log "${BLUE}║ Security Score:     ${RED}${percentage}%${NC} - Critical Issues             ║${NC}"
    fi
    
    log "${BLUE}╠════════════════════════════════════════════════════════════╣${NC}"
    log "${BLUE}║ Log File: ${LOG_FILE}${NC}"
    log "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
}

################################################################################
# Main Audit Checks
################################################################################

main() {
    # Check if script is run as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
    
    print_header
    
    # Check essential files
    log "${YELLOW}[1] CONFIGURATION FILES${NC}"
    log ""
    check_file_exists "$PWQUALITY_CONF" "Password Quality Configuration"
    check_file_exists "$LOGIN_DEFS" "Login Definitions File"
    check_file_exists "$PAM_DIR/common-password" "PAM Password Configuration"
    check_file_exists "$PAM_DIR/common-auth" "PAM Authentication Configuration"
    
    # Password Complexity Requirements
    log "${YELLOW}[2] PASSWORD COMPLEXITY REQUIREMENTS${NC}"
    log ""
    check_pwquality_setting "Minimum Password Length" "minlen" ">=" "14" "CRITICAL"
    check_pwquality_setting "Digit Requirement" "dcredit" "<=" "-1" "CRITICAL"
    check_pwquality_setting "Uppercase Requirement" "ucredit" "<=" "-1" "CRITICAL"
    check_pwquality_setting "Lowercase Requirement" "lcredit" "<=" "-1" "CRITICAL"
    check_pwquality_setting "Special Character Requirement" "ocredit" "<=" "-1" "CRITICAL"
    check_pwquality_setting "Maximum Consecutive Characters" "maxrepeat" "<=" "3" "MEDIUM"
    check_pwquality_setting "Maximum Sequential Characters" "maxsequence" "<=" "3" "MEDIUM"
    check_password_history
    
    # Account Lockout Policy
    log "${YELLOW}[3] ACCOUNT LOCKOUT POLICY${NC}"
    log ""
    check_deprecated_module "No Deprecated pam_tally2" "pam_tally2"
    check_faillock_setting "Faillock Deny Threshold" "deny" "5"
    check_faillock_setting "Faillock Unlock Time" "unlock_time" "900"
    check_faillock_setting "Fail Interval Window" "fail_interval" "900"
    
    # PAM Modules Check
    log "${YELLOW}[4] PAM MODULES CONFIGURATION${NC}"
    log ""
    check_pam_module "Password Quality Module" "pam_pwquality.so" "common-password" \
        "password requisite pam_pwquality.so retry=3"
    check_pam_module "Unix Password Module" "pam_unix.so" "common-password" \
        "password [success=1 default=ignore] pam_unix.so obscure sha512"
    check_pam_module "Faillock Module (Auth)" "pam_faillock.so" "common-auth" \
        "auth required pam_faillock.so preauth"
    
    # Login Settings
    log "${YELLOW}[5] LOGIN & AGING SETTINGS${NC}"
    log ""
    check_login_defs "Password Maximum Age" "PASS_MAX_DAYS" "<=" "90"
    check_login_defs "Password Minimum Age" "PASS_MIN_DAYS" ">=" "1"
    check_login_defs "Password Warning Age" "PASS_WARN_AGE" ">=" "7"
    check_login_defs "Login Retries" "LOGIN_RETRIES" "<=" "3"
    check_login_defs "Login Timeout" "LOGIN_TIMEOUT" "<=" "60"
    
    # Additional Security
    log "${YELLOW}[6] ADDITIONAL SECURITY MEASURES${NC}"
    log ""
    check_umask_setting
    
    # Check for root account lockout exception
    ((TOTAL++))
    if grep -qE "pam_faillock.so.*even_deny_root" "$PAM_DIR/common-auth" 2>/dev/null; then
        log "${GREEN}[✓]${NC} Root Account Lockout Enabled"
        log "    Setting: even_deny_root is configured"
        ((SCORE++))
    else
        log "${YELLOW}[!]${NC} Root Account Excluded from Lockout"
        log "    Recommendation: Add 'even_deny_root' to pam_faillock.so (use with caution)"
        ((WARNINGS++))
    fi
    log ""
    
    # Generate final summary
    generate_summary
}

################################################################################
# Execute Main Function
################################################################################

main "$@"

exit 0
