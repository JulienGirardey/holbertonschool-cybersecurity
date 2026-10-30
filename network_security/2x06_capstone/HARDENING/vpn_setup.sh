#!/bin/bash
# vpn_setup.sh - WireGuard secure access for the LogiCorp Gateway
#
# Deliverable for the LogiCorp gateway administrator.
#   ./vpn_setup.sh --dry-run   Shows what would be done (no privileges needed)
#   sudo ./vpn_setup.sh        Deploys the VPN (administrator, root privileges)
#
#   - IT admins: VPN access to the gateway (SSH) and the internal networks (LAN_NETS)
#   - Finance:   VPN access to the FTP server in the DMZ only (FTP-over-VPN)
# Client configs are generated in /etc/wireguard/clients/. They contain private
# keys: hand them over securely and never commit them.
#
# Values aligned with firewall.sh (VPN ranges, WireGuard port, FTP server).
# Order: clean.sh, vpn_setup.sh, panic_button.sh arm, firewall.sh apply.

set -u

# --- Settings (aligned with firewall.sh) -------------------------------------
WG_IF="wg0"
WG_PORT="51820"
WAN_IF="eth1"                   # firewall.sh: WAN
WG_NET="10.8.0"                 # VPN subnet: 10.8.0.0/24
WG_SERVER_IP="$WG_NET.1"
# Public address the clients connect to: WAN address, else the default route source
# (override: sudo WG_ENDPOINT=x.x.x.x ./vpn_setup.sh)
WG_ENDPOINT="${WG_ENDPOINT:-$(ip -4 -o addr show dev "$WAN_IF" 2>/dev/null \
    | awk '{split($4, a, "/"); print a[1]; exit}')}"
WG_ENDPOINT="${WG_ENDPOINT:-$(ip -4 route get 1.1.1.1 2>/dev/null \
    | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')}"
# Internal networks IT reaches through the VPN, comma separated
# (firewall.sh does not forward admin traffic yet: empty = gateway only)
LAN_NETS="${LAN_NETS:-}"
# Clients as "name:last byte of the VPN IP"
# firewall.sh: VPN_ADMINS = .10-.19, VPN_ACCOUNTANTS = .100-.149
ADMIN_CLIENTS=("it-admin1:10")
FINANCE_CLIENTS=("finance1:100")
# FTP server in the DMZ (firewall.sh: FTP_HOST, FTP_PORT, FTP_PASV)
FTP_HOST="10.50.60.40"
FTP_PORT="21"
FTP_PASV="30000-30100"

WG_DIR="/etc/wireguard"
KEY_DIR="$WG_DIR/keys"
CLIENT_DIR="$WG_DIR/clients"

# --- Mode selection ----------------------------------------------------------
DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
fi

if [ "$DRY_RUN" -eq 0 ] && [ "$EUID" -ne 0 ]; then
    echo "[!] Deploying the VPN requires root: sudo $0" >&2
    echo "[i] To preview the changes without privileges: $0 --dry-run" >&2
    exit 1
fi

# --- Helpers (same as clean.sh) ----------------------------------------------
WORKDIR="$(cd "$(dirname "$0")" && pwd)"
LOG="$WORKDIR/vpn_setup.log"
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

# Generates a key pair once: re-running the script keeps the existing keys
gen_keys() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[DRY-RUN] would generate (if missing): $KEY_DIR/$1.key and $1.pub"
    elif [ ! -f "$KEY_DIR/$1.key" ]; then
        (umask 077; wg genkey > "$KEY_DIR/$1.key")
        wg pubkey < "$KEY_DIR/$1.key" > "$KEY_DIR/$1.pub"
        ok "Keys generated for $1"
    else
        log "[i] Keys already exist for $1 (kept)"
    fi
}

# key_of <name> <key|pub>: prints a key, or a placeholder in dry-run mode
# (private keys never appear in the logs)
key_of() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "<$2 of $1>"
    else
        cat "$KEY_DIR/$1.$2"
    fi
}

[ "$DRY_RUN" -eq 1 ] && log "=== DRY-RUN mode: no change will be made ==="

# --- 1. Install WireGuard -----------------------------------------------------
log "=== [1] Installing WireGuard ==="
if command -v wg >/dev/null 2>&1; then
    log "[i] wireguard-tools already installed"
else
    run apt-get install -y wireguard-tools \
        && ok "wireguard-tools installed" \
        || { log "[!] wireguard-tools installation failed"; exit 1; }
fi

if [ -z "$WG_ENDPOINT" ]; then
    WG_ENDPOINT="GATEWAY_PUBLIC_IP"
    log "[!] Public IP not detected: edit Endpoint in the client configs (or set WG_ENDPOINT)"
fi

# --- 2. Keys ------------------------------------------------------------------
log "=== [2] Generating keys ==="
run mkdir -p "$KEY_DIR" "$CLIENT_DIR"
run chmod 700 "$WG_DIR" "$KEY_DIR" "$CLIENT_DIR"
gen_keys server
for client in "${ADMIN_CLIENTS[@]}" "${FINANCE_CLIENTS[@]}"; do
    gen_keys "${client%%:*}"
done

# --- 3. Server configuration --------------------------------------------------
log "=== [3] Writing server configuration ==="
# The private key is loaded from its file: it never appears in wg0.conf
SERVER_CONF="[Interface]
Address = $WG_SERVER_IP/24
ListenPort = $WG_PORT
PostUp = wg set %i private-key $KEY_DIR/server.key"

# add_peer <name:byte> <role>
add_peer() {
    SERVER_CONF="$SERVER_CONF

[Peer]
# ${1%%:*} ($2)
PublicKey = $(key_of "${1%%:*}" pub)
AllowedIPs = $WG_NET.${1##*:}/32"
}
for client in "${ADMIN_CLIENTS[@]}"; do
    add_peer "$client" "IT"
done
for client in "${FINANCE_CLIENTS[@]}"; do
    add_peer "$client" "Finance"
done
printf '%s\n' "$SERVER_CONF" | write_file "$WG_DIR/$WG_IF.conf" 600

# --- 4. Client configurations -------------------------------------------------
log "=== [4] Generating client configurations ==="
# IT: VPN subnet (gateway SSH) + internal networks. Finance: the FTP server only.
ADMIN_ALLOWED="$WG_NET.0/24${LAN_NETS:+, $LAN_NETS}"
FINANCE_ALLOWED="$FTP_HOST/32"

# write_client <name:byte> <allowed IPs> <role>
write_client() {
    local name="${1%%:*}"
    write_file "$CLIENT_DIR/$name.conf" 600 <<EOF
# LogiCorp VPN - $name ($3)
[Interface]
PrivateKey = $(key_of "$name" key)
Address = $WG_NET.${1##*:}/32

[Peer]
PublicKey = $(key_of server pub)
Endpoint = $WG_ENDPOINT:$WG_PORT
AllowedIPs = $2
PersistentKeepalive = 25
EOF
    ok "Client config: $CLIENT_DIR/$name.conf"
}
for client in "${ADMIN_CLIENTS[@]}"; do
    write_client "$client" "$ADMIN_ALLOWED" "IT"
done
for client in "${FINANCE_CLIENTS[@]}"; do
    write_client "$client" "$FINANCE_ALLOWED" "Finance"
done

# --- 5. Start the VPN ---------------------------------------------------------
log "=== [5] Starting the VPN ==="
run systemctl enable "wg-quick@$WG_IF"
run systemctl restart "wg-quick@$WG_IF"

if [ "$DRY_RUN" -eq 0 ]; then
    if ip link show "$WG_IF" >/dev/null 2>&1; then
        ok "WireGuard up: $WG_IF ($WG_SERVER_IP), port $WG_PORT/udp"
    else
        log "[!] $WG_IF is down: see 'journalctl -u wg-quick@$WG_IF' (WireGuard kernel module missing?)"
        log "[!] Do NOT apply firewall.sh: SSH is only allowed through the VPN"
    fi
fi

# --- 6. FTP-over-VPN for Finance ----------------------------------------------
log "=== [6] FTP-over-VPN for Finance ==="
# Finance clients only route the FTP server through the tunnel; the gateway
# forwards it (ip_forward = 1, firewall.sh forward rule for VPN_ACCOUNTANTS)
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then
    log "[i] IP forwarding enabled: Finance VPN -> $FTP_HOST is routed"
else
    log "[!] IP forwarding is off: run clean.sh first (net.ipv4.ip_forward = 1)"
fi
log "[i] Finance FTP: $FTP_HOST:$FTP_PORT, passive $FTP_PASV (VPN only)"
log "[i] The FTP server must route $WG_NET.0/24 back through the gateway"

# --- Summary ------------------------------------------------------------------
log "=== Done ==="
log "[i] Hand over the client configs from $CLIENT_DIR securely (they contain private keys)"
log "[i] Matching firewall.sh rules: $WG_PORT/udp on $WAN_IF; SSH from VPN_ADMINS on $WG_IF;"
log "[i]   VPN_ACCOUNTANTS -> $FTP_HOST tcp $FTP_PORT + $FTP_PASV"
