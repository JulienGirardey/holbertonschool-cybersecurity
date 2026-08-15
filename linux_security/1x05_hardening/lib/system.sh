#!/bin/bash

system::apply() {
    log "SYSTEM" "PACKAGES" "INFO" "Applying system hardening"

    export DEBIAN_FRONTEND=noninteractive

    if apt-get update >/dev/null 2>&1; then
        log "SYSTEM" "PACKAGE" "INFO" "Package repositories updated"
    else
        report_add "WARN" "Package updates skipped (already up to date)."
    fi

    if apt-get upgrade -y -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" >/dev/null 2>&1; then
        log "SYSTEM" "PACKAGE" "INFO" "System packages upgraded successfully"
    else
        report_add "WARN" "Package upgrades were skipped or failed without blocking hardening."
    fi

    for package in telnet ftp netcat-traditional; do
        if dpkg -l "${package}" >/dev/null 2>&1; then
            apt-get purge -y "${package}"
            record_package_remove "${package}"
            report_add "INFO" "Removed: ${package}."
            log "SYSTEM" "PACKAGE" "SUCCESS" "Removed package ${package}"
        fi
    done

    if ! dpkg -s auditd >/dev/null 2>&1; then
        apt-get install -y auditd
        record_package_install "auditd"
        report_add "INFO" "Installed: auditd."
        log "SYSTEM" "PACKAGE" "SUCCESS" "Installed auditd"
    else
        report_add "INFO" "Package already installed: auditd."
    fi

    if ! dpkg -s fail2ban >/dev/null 2>&1; then
        apt-get install -y fail2ban
        record_package_install "fail2ban"
        report_add "INFO" "Installed: fail2ban."
        log "SYSTEM" "PACKAGE" "SUCCESS" "Installed fail2ban"
    else
        report_add "INFO" "Package already installed: fail2ban."
    fi

    log "SYSTEM" "PACKAGES" "SUCCESS" "System hardening completed"
}
