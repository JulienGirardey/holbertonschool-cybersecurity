#!/bin/bash
# clean.sh - Hardening of the LogiCorp Gateway
#
# Deliverable for the LogiCorp gateway administrator.
#   ./clean.sh --dry-run   Audit only: shows what would be changed (no privileges needed)
#   sudo ./clean.sh        Applies the hardening (administrator, root privileges)
#
# Business constraints kept:
#   - FTP for Finance: served by the DMZ server through the VPN (firewall.sh);
#     the gateway vsftpd is disabled once that server answers, hardened until then
#   - SSH for IT: key-only is enforced only if an SSH key exists (no lockout)
#   - Database, web, DNS/DHCP and routing are not touched

set -u

# --- Mode selection ----------------------------------------------------------
DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
fi

if [ "$DRY_RUN" -eq 0 ] && [ "$EUID" -ne 0 ]; then
    echo "[!] Applying the hardening requires root: sudo $0" >&2
    echo "[i] To preview the changes without privileges: $0 --dry-run" >&2
    exit 1
fi

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
LOG="$WORKDIR/clean_hardening.log"
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

# Executes a privileged command, or only prints it in dry-run mode
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[DRY-RUN] would run: $*"
    else
        "$@" >/dev/null 2>&1
    fi
}

# Logs a success message, only when the change was really applied
ok() { [ "$DRY_RUN" -eq 1 ] || log "[+] $*"; }

# write_file <path> <mode>: writes stdin to the file (only shown in dry-run mode)
write_file() {
    local content
    content="$(cat)"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[DRY-RUN] would write $1 (mode $2):"
        printf '%s\n' "$content" | sed 's/^/        | /' | tee -a "$LOG"
    else
        printf '%s\n' "$content" > "$1" && chmod "$2" "$1"
    fi
}

# Keeps a copy of the original file, never overwritten by a later run
backup_once() {
    if [ -f "$1.bak" ]; then
        log "[i] Backup already exists: $1.bak (not overwritten)"
    else
        run cp -p "$1" "$1.bak" && ok "Backup created: $1.bak"
    fi
}

# set_option <file> <key> <separator> <value>
# Replaces the active "key" line, or inserts it at the top of the file.
# '|' is the sed delimiter because values can contain '/' (paths).
set_option() {
    local file="$1" key="$2" sep="$3" value="$4"
    if grep -qE "^\s*${key}[[:space:]=]" "$file"; then
        run sed -i -E "s|^\s*${key}[[:space:]=].*|${key}${sep}${value}|" "$file" \
            && ok "$key set to $value in $file"
    else
        run sed -i "1i ${key}${sep}${value}" "$file" \
            && ok "$key added to $file"
    fi
}

# set_sshd_option <name> <value>
# sshd keeps the FIRST value it reads: the same option is disabled in drop-in files
set_sshd_option() {
    local f
    set_option "$SSHD_CONFIG" "$1" " " "$2"
    for f in "$SSH_DIR"/sshd_config.d/*.conf; do
        if [ -f "$f" ] && grep -qE "^\s*$1[[:space:]]" "$f"; then
            run sed -i -E "s|^\s*($1[[:space:]].*)|# \1  (disabled by clean.sh)|" "$f" \
                && ok "$1 disabled in $f"
        fi
    done
}

[ "$DRY_RUN" -eq 1 ] && log "=== DRY-RUN mode: no change will be made ==="

# --- 1. Remove or disable unnecessary services --------------------------------

# Snapshot of listening ports BEFORE hardening (evidence for the report)
ss -tulpn > "$WORKDIR/ports_before.txt" 2>/dev/null

# Cleartext / legacy remote-access services: no reason to exist on a gateway.
# They are purged (package + config removed).
# Audit findings: inetd.service enabled at boot, telnetd installed.
# vsftpd is NOT purged: it was the Finance FTP during the audit (handled below).
PURGE_PKGS=(
    openbsd-inetd inetutils-inetd xinetd
    telnetd inetutils-telnetd telnet
    proftpd-basic pure-ftpd tftpd-hpa
    rsh-server rsh-client rsh-redone-server
    nis talk talkd
)

# Processes to kill if still alive (containers may run them outside systemd)
KILL_PROCS=(inetd xinetd in.telnetd)

# Services useless on a gateway. They are stopped, disabled at boot and masked.
# Database, web, DNS and DHCP services are left alone: they may serve the business.
DISABLE_SVCS=(
    inetd.service
    avahi-daemon.service avahi-daemon.socket
    cups.service cups.socket cups-browsed.service
    bluetooth.service
    rpcbind.service rpcbind.socket
    nfs-server.service
    smbd.service nmbd.service
    snmpd.service
)

log "=== [1] Removing unnecessary packages ==="
for pkg in "${PURGE_PKGS[@]}"; do
    # dpkg -s is read-only: works without privileges
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        run apt-get purge -y "$pkg" \
            && ok "Purged package: $pkg" \
            || log "[!] Failed to purge: $pkg"
    fi
done
run apt-get autoremove -y

log "=== [1] Disabling unnecessary services ==="
for svc in "${DISABLE_SVCS[@]}"; do
    # Skip units that do not exist on this system
    if systemctl list-unit-files "$svc" --no-legend 2>/dev/null | grep -q .; then
        run systemctl disable --now "$svc"
        run systemctl mask "$svc"
        ok "Disabled and masked: $svc"
    fi
done

for proc in "${KILL_PROCS[@]}"; do
    if pgrep -x "$proc" >/dev/null 2>&1; then
        run pkill -x "$proc" && ok "Killed leftover process: $proc"
    fi
done

log "=== [1] FTP for Finance ==="
VSFTPD_CONF="/etc/vsftpd.conf"
FTP_USERLIST="/etc/vsftpd.userlist"
FINANCE_GROUP="finance"
# Finance FTP accounts, space separated (empty: members of FINANCE_GROUP)
FTP_USERS="${FTP_USERS:-}"
# FTP server in the DMZ (firewall.sh: FTP_HOST). Once it answers, the gateway FTP
# is no longer needed; until then it is kept (hardened) so Finance keeps working.
FTP_HOST="10.50.60.40"
GATEWAY_FTP="${GATEWAY_FTP:-no}"

if [ "$GATEWAY_FTP" = "no" ] \
    && systemctl list-unit-files vsftpd.service --no-legend 2>/dev/null | grep -q . \
    && timeout 3 bash -c "</dev/tcp/$FTP_HOST/21" 2>/dev/null; then
    log "[i] DMZ FTP server $FTP_HOST answers: the gateway FTP is no longer needed"
    run systemctl disable --now vsftpd.service
    run systemctl mask vsftpd.service
    ok "Disabled and masked: vsftpd.service"
elif [ -f "$VSFTPD_CONF" ]; then
    if [ "$GATEWAY_FTP" = "no" ]; then
        log "[!] DMZ FTP server $FTP_HOST unreachable: gateway vsftpd kept (hardened) so Finance keeps FTP"
    fi
    backup_once "$VSFTPD_CONF"
    # listen and listen_ipv6 cannot both be YES: IPv4 only
    set_option "$VSFTPD_CONF" listen "=" YES
    set_option "$VSFTPD_CONF" listen_ipv6 "=" NO
    set_option "$VSFTPD_CONF" anonymous_enable "=" NO
    set_option "$VSFTPD_CONF" local_enable "=" YES
    set_option "$VSFTPD_CONF" write_enable "=" YES
    # Each user is locked in their home directory
    set_option "$VSFTPD_CONF" chroot_local_user "=" YES
    set_option "$VSFTPD_CONF" allow_writeable_chroot "=" YES
    set_option "$VSFTPD_CONF" xferlog_enable "=" YES
    # Fixed passive range, same as firewall.sh (FTP_PASV)
    set_option "$VSFTPD_CONF" pasv_enable "=" YES
    set_option "$VSFTPD_CONF" pasv_min_port "=" 30000
    set_option "$VSFTPD_CONF" pasv_max_port "=" 30100

    # Only Finance accounts may log in (members + users whose primary group is finance)
    FINANCE_USERS="$( {
        printf '%s\n' $FTP_USERS
        getent group "$FINANCE_GROUP" | cut -d: -f4 | tr ',' '\n'
        gid="$(getent group "$FINANCE_GROUP" | cut -d: -f3)"
        [ -n "$gid" ] && getent passwd | awk -F: -v g="$gid" '$4 == g {print $1}'
    } | grep -v '^$' | sort -u )"

    # A listed account that does not exist is a typo: it would lock Finance out
    for user in $FINANCE_USERS; do
        getent passwd "$user" >/dev/null || log "[!] FTP user '$user' does not exist"
    done

    if [ -n "$FINANCE_USERS" ]; then
        printf '%s\n' "$FINANCE_USERS" | write_file "$FTP_USERLIST" 644
        set_option "$VSFTPD_CONF" userlist_enable "=" YES
        set_option "$VSFTPD_CONF" userlist_deny "=" NO
        set_option "$VSFTPD_CONF" userlist_file "=" "$FTP_USERLIST"
        log "[i] FTP restricted to:" $FINANCE_USERS
    else
        log "[!] No Finance account found (group '$FINANCE_GROUP' missing, FTP_USERS empty):"
        log "[!]   FTP user list NOT enforced (it would block Finance). Set FTP_USERS to restrict it"
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        log "[DRY-RUN] would run: systemctl restart vsftpd (original config restored if it fails)"
    else
        systemctl restart vsftpd >/dev/null 2>&1
        sleep 1
        if systemctl is-active --quiet vsftpd; then
            ok "vsftpd restarted with the hardened config"
        else
            cp -p "$VSFTPD_CONF.bak" "$VSFTPD_CONF"
            systemctl restart vsftpd >/dev/null 2>&1
            log "[!] vsftpd failed with the new config: original config restored"
        fi
    fi
else
    log "[i] vsftpd not installed: nothing to secure"
fi

# --- 2. Harden SSH configuration (no root, key-only) -------------------------
SSH_DIR="/etc/ssh"
SSHD_CONFIG="$SSH_DIR/sshd_config"
KEYS="/home/*/.ssh/authorized_keys"
KEY_FOUND=0

log "=== [2] Hardening SSH configuration ==="
backup_once "$SSHD_CONFIG"

# Copy of the current state, restored if the new config is invalid
ROLLBACK_DIR=""
if [ "$DRY_RUN" -eq 0 ]; then
    ROLLBACK_DIR="$(mktemp -d)"
    cp -a "$SSHD_CONFIG" "$ROLLBACK_DIR/"
    [ -d "$SSH_DIR/sshd_config.d" ] && cp -a "$SSH_DIR/sshd_config.d" "$ROLLBACK_DIR/"
fi

# Anti-lockout: key-only login needs at least one user with an authorized key
for f in $KEYS; do
    if [ -s "$f" ]; then
        log "[i] SSH key found: $f"
        KEY_FOUND=1
    fi
done

# "no root": always safe, IT logs in with a named account
set_sshd_option PermitRootLogin no
set_sshd_option PubkeyAuthentication yes
set_sshd_option PermitEmptyPasswords no
set_sshd_option MaxAuthTries 3
set_sshd_option LoginGraceTime 30
set_sshd_option X11Forwarding no
set_sshd_option ClientAliveInterval 300
set_sshd_option ClientAliveCountMax 2

write_file /etc/issue.net 644 <<'EOF'
Authorized access only. All activity is logged and monitored.
EOF
set_sshd_option Banner /etc/issue.net

# "key-only": only when a key exists, otherwise IT would be locked out
if [ "$KEY_FOUND" -eq 1 ]; then
    log "[i] Key-only login is safe"
    set_sshd_option PasswordAuthentication no
    set_sshd_option KbdInteractiveAuthentication no
    set_sshd_option AuthenticationMethods publickey
else
    log "[!] No SSH key found: password login kept to avoid a lockout"
    log "[!] Deploy the IT keys first (ssh-copy-id user@gateway), then re-run clean.sh"
fi

# Never reload a broken config: sshd would refuse new connections
if [ "$DRY_RUN" -eq 1 ]; then
    log "[DRY-RUN] would run: sshd -t (previous config restored if invalid), then reload ssh"
elif sshd -t; then
    systemctl reload ssh >/dev/null 2>&1 \
        || kill -HUP "$(cat /run/sshd.pid 2>/dev/null)" 2>/dev/null
    ok "SSH config valid and reloaded (open sessions are kept)"
    log "[i] Effective SSH settings:"
    sshd -T 2>/dev/null \
        | grep -E '^(permitrootlogin|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication) ' \
        | tee -a "$LOG"
else
    cp -a "$ROLLBACK_DIR/sshd_config" "$SSHD_CONFIG"
    if [ -d "$ROLLBACK_DIR/sshd_config.d" ]; then
        rm -rf "$SSH_DIR/sshd_config.d" && cp -a "$ROLLBACK_DIR/sshd_config.d" "$SSH_DIR/"
    fi
    log "[!] Invalid SSH config: previous config restored, sshd NOT reloaded"
fi
[ -n "$ROLLBACK_DIR" ] && rm -rf "$ROLLBACK_DIR"

# --- 3. Configure secure defaults ---------------------------------------------
log "=== [3] Configuring secure defaults ==="

# Kernel/network: anti-spoofing, no ICMP redirects, SYN flood protection.
# ip_forward stays at 1: the gateway routes the business traffic.
SYSCTL_FILE="/etc/sysctl.d/99-logicorp-hardening.conf"
write_file "$SYSCTL_FILE" 644 <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
if [ "$DRY_RUN" -eq 1 ]; then
    log "[DRY-RUN] would run: sysctl -p $SYSCTL_FILE"
elif sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
    ok "Kernel settings applied"
else
    log "[!] Some kernel settings are read-only here (container): file kept for next boot"
fi

# Password policy and default permissions of new files (others get nothing)
backup_once /etc/login.defs
set_option /etc/login.defs PASS_MAX_DAYS " " 90
set_option /etc/login.defs PASS_MIN_DAYS " " 1
set_option /etc/login.defs PASS_WARN_AGE " " 7
set_option /etc/login.defs UMASK " " 027

# No core dumps: they can leak passwords and keys from memory
write_file /etc/security/limits.d/99-no-core.conf 644 <<'EOF'
* hard core 0
EOF

# Permissions of sensitive files
for entry in "644 /etc/passwd" "644 /etc/group" "640 /etc/shadow" "640 /etc/gshadow" \
             "600 /etc/crontab" "700 /root"; do
    mode="${entry%% *}"
    path="${entry#* }"
    if [ -e "$path" ]; then
        run chmod "$mode" "$path" && ok "$path set to $mode"
    fi
done

# Root password was found during the audit: lock it if admins can use sudo
SUDO_MEMBERS="$(getent group sudo | cut -d: -f4)"
if [ -n "$SUDO_MEMBERS" ]; then
    run passwd -l root && ok "root password locked (admins use sudo: $SUDO_MEMBERS)"
else
    log "[!] root password NOT locked: no sudo member, IT would lose admin rights"
    log "[!] The root password was found during the audit: change it now (passwd root)"
fi

# Snapshot AFTER hardening, to compare with ports_before.txt
if [ "$DRY_RUN" -eq 0 ]; then
    ss -tulpn > "$WORKDIR/ports_after.txt" 2>/dev/null
    log "[i] Listening ports diff (before -> after):"
    diff "$WORKDIR/ports_before.txt" "$WORKDIR/ports_after.txt" | tee -a "$LOG"
fi

log "=== Done. Full log: $LOG ==="
