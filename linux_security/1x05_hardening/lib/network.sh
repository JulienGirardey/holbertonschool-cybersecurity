#!/bin/bash

network::apply() {
    log "NETWORK" "FIREWALL" "INFO" "Applying network hardening"

    mkdir -p "$(dirname "${FIREWALL_RULES_FILE}")"

    cat > "${FIREWALL_RULES_FILE}" <<EOF
DEFAULT_INPUT=deny
DEFAULT_OUTPUT=allow
ALLOW_TCP=${SSH_PORT}
ALLOW_TCP=${ALLOW_HTTP}
ALLOW_TCP=${ALLOW_HTTPS}
EOF
    log "NETWORK" "FIREWALL" "SUCCESS" "Persisted firewall policy to ${FIREWALL_RULES_FILE}"

    if [ -f "${SYSCTL_CONF_FILE}" ]; then
        if ! grep -Eq '^net\.ipv4\.ip_forward\s*=\s*0$' "${SYSCTL_CONF_FILE}"; then
            printf '\nnet.ipv4.ip_forward = 0\n' >> "${SYSCTL_CONF_FILE}"
        fi

        if ! grep -Eq '^net\.ipv4\.icmp_echo_ignore_all\s*=\s*1$' "${SYSCTL_CONF_FILE}"; then
            printf 'net.ipv4.icmp_echo_ignore_all = 1\n' >> "${SYSCTL_CONF_FILE}"
        fi
        log "NETWORK" "KERNEL" "SUCCESS" "Persisted kernel hardening in ${SYSCTL_CONF_FILE}"
    else
        log "NETWORK" "KERNEL" "ERROR" "Could not find ${SYSCTL_CONF_FILE}"
    fi
}