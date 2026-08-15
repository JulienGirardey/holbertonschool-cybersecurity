#!/bin/bash

ssh::configure() {
    local sshd_config="/etc/ssh/sshd_config"
    local allow_users="${ALLOWED_SSH_USERS[*]}"

    log "SSH" "CONFIG" "INFO" "Hardening SSH configuration"

    if [ ! -f "${sshd_config}" ]; then
        log "SSH" "CONFIG" "ERROR" "Missing sshd_config at ${sshd_config}"
        return 1
    fi

    if grep -Eq '^#?Port ' "${sshd_config}"; then
        sed -i "s/^#\?Port .*/Port ${SSH_PORT}/" "${sshd_config}"
    else
        printf 'Port %s\n' "${SSH_PORT}" >> "${sshd_config}"
    fi

    if grep -Eq '^#?PermitRootLogin ' "${sshd_config}"; then
        sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "${sshd_config}"
    else
        printf 'PermitRootLogin no\n' >> "${sshd_config}"
    fi

    if grep -Eq '^#?PasswordAuthentication ' "${sshd_config}"; then
        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "${sshd_config}"
    else
        printf 'PasswordAuthentication no\n' >> "${sshd_config}"
    fi

    if grep -Eq '^#?PubkeyAuthentication ' "${sshd_config}"; then
        sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' "${sshd_config}"
    else
        printf 'PubkeyAuthentication yes\n' >> "${sshd_config}"
    fi

    if grep -Eq '^#?ChallengeResponseAuthentication ' "${sshd_config}"; then
        sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "${sshd_config}"
    else
        printf 'ChallengeResponseAuthentication no\n' >> "${sshd_config}"
    fi

    if grep -Eq '^AllowUsers ' "${sshd_config}"; then
        sed -i "s/^AllowUsers .*/AllowUsers ${allow_users}/" "${sshd_config}"
    else
        printf 'AllowUsers %s\n' "${allow_users}" >> "${sshd_config}"
    fi

    if sshd -t -f "${sshd_config}"; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl reload ssh >/dev/null 2>&1 || service ssh reload >/dev/null 2>&1 || /etc/init.d/ssh reload >/dev/null 2>&1 || true
        else
            service ssh reload >/dev/null 2>&1 || /etc/init.d/ssh reload >/dev/null 2>&1 || true
        fi
        log "SSH" "CONFIG" "SUCCESS" "SSH configuration hardened on port ${SSH_PORT}"
    else
        log "SSH" "CONFIG" "ERROR" "sshd configuration validation failed"
        return 1
    fi
}

