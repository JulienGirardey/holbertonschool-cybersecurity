#!/bin/bash

identity::apply() {
    log "IDENTITY" "PASSWORD_POLICY" "INFO" "Applying identity hardening"

    if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
        apt-get update
        apt-get install -y libpam-pwquality
        log "IDENTITY" "PASSWORD_POLICY" "SUCCESS" "Installed libpam-pwquality"
    fi

    if ! grep -Eq 'pam_pwquality\.so.*minlen=12' "${COMMON_PASSWORD_FILE}"; then
        sed -i "/pam_unix\\.so/i password requisite pam_pwquality.so minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" "${COMMON_PASSWORD_FILE}"
        log "IDENTITY" "PASSWORD_POLICY" "SUCCESS" "Configured pwquality policy"
    else
        log "IDENTITY" "PASSWORD_POLICY" "INFO" "pwquality policy already configured"
    fi

    if [ -f "${PASS_MAX_DAYS_FILE}" ]; then
        if grep -Eq '^PASS_MAX_DAYS' "${PASS_MAX_DAYS_FILE}"; then
            sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS ${PASS_MAX_DAYS_VALUE}/" "${PASS_MAX_DAYS_FILE}"
        else
            printf 'PASS_MAX_DAYS %s\n' "${PASS_MAX_DAYS_VALUE}" >> "${PASS_MAX_DAYS_FILE}"
        fi
        log "IDENTITY" "PASSWORD_POLICY" "SUCCESS" "Updated PASS_MAX_DAYS to ${PASS_MAX_DAYS_VALUE}"
    fi

    if [ -f "${FAIL_LOCK_ATTEMPTS_FILE}" ]; then
        if grep -Eq '^deny\s*=' "${FAIL_LOCK_ATTEMPTS_FILE}"; then
            sed -i "s/^deny\s*=.*/deny = ${FAIL_LOCK_ATTEMPTS}/" "${FAIL_LOCK_ATTEMPTS_FILE}"
        else
            printf 'deny = %s\n' "${FAIL_LOCK_ATTEMPTS}" >> "${FAIL_LOCK_ATTEMPTS_FILE}"
        fi
        log "IDENTITY" "LOCKOUT" "SUCCESS" "Updated lockout policy to deny = ${FAIL_LOCK_ATTEMPTS}"
    fi

    while IFS=: read -r username x uid gid rest; do
        [ -n "${username}" ] || continue
        if [ "${uid}" -ge 1000 ] 2>/dev/null; then
            if ! id -nG "${username}" 2>/dev/null | grep -Eq '(^| )(sudo|wheel)( |$)'; then
                if [ "${username}" != "root" ]; then
                    userdel -r "${username}" >/dev/null 2>&1 || true
                    record_removed_user "${username}"
                    report_add "INFO" "Removed unauthorized user: ${username}."
                    log "IDENTITY" "CLEANUP" "SUCCESS" "Removed user ${username} with UID ${uid}"
                fi
            fi
        fi
    done < /etc/passwd

    if getent passwd root >/dev/null 2>&1; then
        passwd -l root >/dev/null 2>&1 || usermod -L root >/dev/null 2>&1 || true
        log "IDENTITY" "ACCOUNT" "SUCCESS" "Locked root password"
    fi
}

