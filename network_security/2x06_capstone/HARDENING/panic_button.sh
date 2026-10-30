#!/bin/bash
# panic_button.sh - Firewall safety net for the LogiCorp Gateway (dead man's switch)
#
# Run it BEFORE firewall.sh. If the new rules lock you out, the previous
# firewall state is restored automatically when the timer expires.
#
#   sudo ./panic_button.sh arm [minutes]   Save the current rules, start the timer (default: 5)
#   sudo ./firewall.sh apply               Apply the new rules
#        ... test SSH / VPN / FTP from a NEW session ...
#   sudo ./panic_button.sh disarm          Everything works: cancel the timer
#   sudo ./panic_button.sh fire            Restore the previous rules right now
#   ./panic_button.sh status               Show whether the timer is armed
# Add --dry-run to any command to only show what it would do.

set -u

# --- Arguments ----------------------------------------------------------------
DRY_RUN=0
ARGS=()
for arg in "$@"; do
    if [ "$arg" = "--dry-run" ]; then
        DRY_RUN=1
    else
        ARGS+=("$arg")
    fi
done
ACTION="${ARGS[0]:-status}"
MINUTES="${ARGS[1]:-5}"

if [ "$DRY_RUN" -eq 0 ] && [ "$ACTION" != "status" ] && [ "$EUID" -ne 0 ]; then
    echo "[!] This action requires root: sudo $0 $ACTION" >&2
    echo "[i] To preview it without privileges: $0 $ACTION --dry-run" >&2
    exit 1
fi

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
SELF="$WORKDIR/$(basename "$0")"
LOG="$WORKDIR/panic_button.log"
STATE_DIR="/var/backups/panic_button"
SNAPSHOT="$STATE_DIR/ruleset-before.nft"
RULES_FILE="/etc/nftables.conf"          # same file as firewall.sh
UNIT="panic-button"
PID_FILE="/run/panic_button.pid"

# --- Helpers (same as clean.sh) ----------------------------------------------
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

has_systemd() { command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; }

# Stops a pending timer (systemd transient timer, or background sleep)
cancel_timer() {
    if has_systemd; then
        systemctl stop "$UNIT.timer" >/dev/null 2>&1
        systemctl reset-failed "$UNIT.service" >/dev/null 2>&1
    fi
    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null
        rm -f "$PID_FILE"
    fi
}

# --- Actions ------------------------------------------------------------------
cmd_arm() {
    if ! [[ "$MINUTES" =~ ^[0-9]+$ ]] || [ "$MINUTES" -lt 1 ]; then
        log "[!] Invalid delay: '$MINUTES' (minutes, at least 1)"
        exit 1
    fi
    if ! command -v nft >/dev/null 2>&1; then
        log "[!] nftables is not installed: nothing to protect"
        exit 1
    fi

    log "=== Arming the panic button ($MINUTES min) ==="
    # The current rules are the last known working state: taken BEFORE firewall.sh
    run mkdir -p "$STATE_DIR"
    run chmod 700 "$STATE_DIR"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[DRY-RUN] would save the current rules (nft list ruleset) to $SNAPSHOT"
    elif { echo "flush ruleset"; nft list ruleset; } > "$SNAPSHOT"; then
        chmod 600 "$SNAPSHOT"
        ok "Current rules saved: $SNAPSHOT"
    else
        log "[!] Could not save the current rules: do NOT apply the firewall"
        exit 1
    fi

    cancel_timer
    if has_systemd; then
        run systemd-run --unit="$UNIT" --on-active="${MINUTES}m" /bin/bash "$SELF" fire
    elif [ "$DRY_RUN" -eq 1 ]; then
        log "[DRY-RUN] would start a background timer: sleep $((MINUTES * 60)), then $SELF fire"
    else
        nohup bash -c "sleep $((MINUTES * 60)); exec /bin/bash '$SELF' fire" >/dev/null 2>&1 &
        echo $! > "$PID_FILE"
    fi

    # A safety net that failed to start must stop the whole procedure
    if [ "$DRY_RUN" -eq 0 ] && ! cmd_is_armed; then
        log "[!] The timer did not start: do NOT apply the firewall"
        exit 1
    fi
    ok "ARMED: previous rules restored in $MINUTES min unless you run: sudo $SELF disarm"
    log "[i] Now apply the firewall, then test SSH / VPN / FTP from a NEW session"
}

cmd_disarm() {
    log "=== Disarming the panic button ==="
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[DRY-RUN] would stop the timer ($UNIT.timer or $PID_FILE)"
        return
    fi
    cancel_timer
    ok "Disarmed: the new firewall rules are kept"
    log "[i] Snapshot kept for a manual rollback: sudo $SELF fire"
}

cmd_fire() {
    log "=== PANIC BUTTON: restoring the previous firewall rules ==="
    # Called by the timer itself: only the PID file is cleaned, never our own unit
    [ "$DRY_RUN" -eq 0 ] && rm -f "$PID_FILE"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "[DRY-RUN] would run: nft -f $SNAPSHOT (or nft flush ruleset if missing)"
        log "[DRY-RUN] would copy $SNAPSHOT to $RULES_FILE (same rules after a reboot)"
        return
    fi

    if [ -s "$SNAPSHOT" ] && nft -f "$SNAPSHOT" >/dev/null 2>&1; then
        ok "Previous rules restored from $SNAPSHOT"
        cp "$SNAPSHOT" "$RULES_FILE" && chmod 600 "$RULES_FILE"
    else
        # Last resort: no filtering at all, but access is back
        nft flush ruleset
        printf 'flush ruleset\n' > "$RULES_FILE"
        log "[!] No usable snapshot: ALL rules flushed (no filtering until fixed)"
    fi
    # firewall.sh enabled nftables at boot: the file above is what a reboot loads
    command -v wall >/dev/null 2>&1 \
        && echo "PANIC BUTTON: firewall rolled back, see $LOG" | wall 2>/dev/null
}

cmd_is_armed() {
    if has_systemd && systemctl is-active --quiet "$UNIT.timer"; then
        return 0
    fi
    [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

cmd_status() {
    if cmd_is_armed; then
        log "[i] ARMED: the previous rules will be restored when the timer expires"
        has_systemd && systemctl list-timers "$UNIT.timer" --no-pager 2>/dev/null | sed -n '2p'
    else
        log "[i] Not armed"
    fi
}

# --- Main ---------------------------------------------------------------------
[ "$DRY_RUN" -eq 1 ] && log "=== DRY-RUN mode: no change will be made ==="

case "$ACTION" in
    arm)    cmd_arm ;;
    disarm) cmd_disarm ;;
    fire)   cmd_fire ;;
    status) cmd_status ;;
    *)
        echo "Usage: sudo $0 {arm [minutes]|disarm|fire|status} [--dry-run]" >&2
        exit 1
        ;;
esac
