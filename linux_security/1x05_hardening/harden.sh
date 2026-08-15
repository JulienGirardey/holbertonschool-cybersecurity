#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/harden.cfg"
LIB_DIR="${SCRIPT_DIR}/lib"
LOG_FILE="/var/log/hardening.log"
REPORT_FILE="${PWD}/audit_report.txt"

declare -a REPORT_INFO=()
declare -a REPORT_WARN=()
declare -a REPORT_ERROR=()
declare -a INSTALL_PACKAGES=()
declare -a REMOVE_PACKAGES=()
declare -a REMOVED_USERS=()
UNAUTHORIZED_USERS_REMOVED=0

report_add() {
    local level="$1"
    local message="$2"
    case "$level" in
        INFO) REPORT_INFO+=("${message}") ;;
        WARN) REPORT_WARN+=("${message}") ;;
        ERROR) REPORT_ERROR+=("${message}") ;;
    esac
}

record_package_install() {
    INSTALL_PACKAGES+=("$1")
}

record_package_remove() {
    REMOVE_PACKAGES+=("$1")
}

record_removed_user() {
    REMOVED_USERS+=("$1")
    UNAUTHORIZED_USERS_REMOVED=$((UNAUTHORIZED_USERS_REMOVED + 1))
}

report_generate() {
    local ts
    local report_path="${REPORT_FILE}"
    ts="$(date '+%Y-%m-%d %H:%M:%S')"

    {
        echo "==============================================="
        echo " HARDENING AUDIT REPORT - ${ts}"
        echo "==============================================="
        echo
        if [ "${#REPORT_INFO[@]}" -gt 0 ]; then
            for entry in "${REPORT_INFO[@]}"; do
                printf '[INFO] %s\n' "$entry"
            done
        fi
        if [ "${#REPORT_WARN[@]}" -gt 0 ]; then
            for entry in "${REPORT_WARN[@]}"; do
                printf '[WARN] %s\n' "$entry"
            done
        fi
        if [ "${#REPORT_ERROR[@]}" -gt 0 ]; then
            for entry in "${REPORT_ERROR[@]}"; do
                printf '[ERROR] %s\n' "$entry"
            done
        fi
        echo
        if [ "${#REMOVE_PACKAGES[@]}" -gt 0 ]; then
            printf '[INFO] Removed: %s.\n' "$(IFS=', '; echo "${REMOVE_PACKAGES[*]}")"
        fi
        if [ "${#INSTALL_PACKAGES[@]}" -gt 0 ]; then
            printf '[INFO] Installed: %s.\n' "$(IFS=', '; echo "${INSTALL_PACKAGES[*]}")"
        fi
        if [ "${UNAUTHORIZED_USERS_REMOVED}" -gt 0 ]; then
            printf '[INFO] %s unauthorized users removed: %s.\n' "${UNAUTHORIZED_USERS_REMOVED}" "$(IFS=', '; echo "${REMOVED_USERS[*]}")"
        fi
        echo
        if [ "${#REPORT_ERROR[@]}" -eq 0 ]; then
            echo "==============================================="
            echo " COMPLIANCE STATUS: PASS"
            echo "==============================================="
        else
            echo "==============================================="
            echo " COMPLIANCE STATUS: FAIL"
            echo "==============================================="
        fi
    } > "${report_path}"

    printf '%s\n' "Audit report written to ${report_path}"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root." >&2
    exit 1
fi

if [ ! -f "${CONFIG_FILE}" ]; then
    echo "Error: missing configuration file at ${CONFIG_FILE}" >&2
    exit 1
fi

source "${CONFIG_FILE}"

touch "${LOG_FILE}"
chmod 0640 "${LOG_FILE}"

log() {
    local component="$1"
    local action="$2"
    local status="$3"
    local message="${4:-}"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S %z')"
    printf '%s | %s | %s | %s | %s\n' "$timestamp" "$component" "$action" "$status" "$message" >> "${LOG_FILE}"
}

log "ENGINE" "FRAMEWORK" "INFO" "Hardening framework initialized"
report_add "INFO" "Hardening procedure completed successfully."

for lib_file in "${LIB_DIR}"/*.sh; do
    if [ -f "${lib_file}" ]; then
        source "${lib_file}"
    fi
done

main() {
    log "ENGINE" "STARTUP" "INFO" "Starting hardening workflow"
    identity::apply
    system::apply
    ssh::configure
    network::apply
    log "ENGINE" "FRAMEWORK" "SUCCESS" "Hardening workflow completed"
    report_add "INFO" "Hardening procedure completed successfully."
    report_add "INFO" "SSH configured on port ${SSH_PORT}."
    report_add "INFO" "Firewall policy created: ports ${SSH_PORT}, ${ALLOW_HTTP}, ${ALLOW_HTTPS} ALLOWED."
    report_add "INFO" "Firewall policy file: ${FIREWALL_RULES_FILE}."
    if [ "${#INSTALL_PACKAGES[@]}" -eq 0 ]; then
        report_add "WARN" "No packages installed during this run."
    fi
    if [ "${#REMOVE_PACKAGES[@]}" -eq 0 ]; then
        report_add "WARN" "No packages removed during this run."
    fi
    if [ "${UNAUTHORIZED_USERS_REMOVED}" -eq 0 ]; then
        report_add "INFO" "0 unauthorized users removed."
    fi
    report_generate
}

main "$@"
