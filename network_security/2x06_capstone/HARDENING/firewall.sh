#!/bin/bash
# =====================================================================
# firewall.sh - LogiCorp Gateway Firewall
# Firewall managed with nftables
#
# Usage:
#   sudo ./firewall.sh check
#   sudo ./firewall.sh apply
#   sudo ./firewall.sh status
# =====================================================================

set -euo pipefail

# 1. Network configuration

WAN="eth1"
TRUNK="eth2"
VPN="wg0"

# VLAN interfaces
V_OFFICE="${TRUNK}.10"
V_FINANCE="${TRUNK}.20"
V_GUEST="${TRUNK}.30"
V_DB="${TRUNK}.50"
V_DMZ="${TRUNK}.60"

# Internal network subnets
NET_OFFICE="10.50.10.0/24"
NET_FINANCE="10.50.20.0/24"
NET_GUEST="10.50.30.0/24"
NET_DB="10.50.50.0/24"
NET_DMZ="10.50.60.0/24"

# VPN configuration
VPN_ADMINS="10.8.0.10-10.8.0.19"
VPN_ACCOUNTANTS="10.8.0.100-10.8.0.149"
WG_PORT="51820"

# FTP server in the DMZ
FTP_HOST="10.50.60.40"
FTP_PORT="21"
FTP_PASV="30000-30100"

# Firewall configuration paths
RULES_FILE="/etc/nftables.conf"
SYSCTL_FILE="/etc/sysctl.d/99-logicorp-gateway.conf"

# OUTPUT policy:
# drop = only explicitly authorized outgoing traffic is allowed.
OUTPUT_POLICY="drop"


# 2. Generate nftables rules

build_rules() {

cat <<EOF
#!/usr/sbin/nft -f

# Remove existing nftables rules
flush ruleset

# ================================================================
# FILTER TABLE
# ================================================================

table inet logicorp {

    # ------------------------------------------------------------
    # INPUT : Traffic destined for the gateway itself
    # ------------------------------------------------------------

    chain input {
        type filter hook input priority 0; policy drop;

        # Drop invalid packets
        ct state invalid drop

        # Allow established and related connections
        ct state established,related accept

        # Allow local loopback traffic
        iifname "lo" accept

        # Block FTP and SSH from the WAN
        iifname "${WAN}" tcp dport { 21, 22 } limit rate 5/second log prefix "FW-WAN-21-22: "
        iifname "${WAN}" tcp dport { 21, 22 } drop

        # Block SSH attempts from VPN accountants
        iifname "${VPN}" ip saddr ${VPN_ACCOUNTANTS} tcp dport 22 limit rate 5/second log prefix "FW-SSH-ACCOUNTANTS: "
        iifname "${VPN}" ip saddr ${VPN_ACCOUNTANTS} tcp dport 22 drop

        # Allow ICMP IPv4 and IPv6 for network diagnostics
        ip protocol icmp accept
        meta l4proto ipv6-icmp accept

        # Allow WireGuard traffic from the Internet
        iifname "${WAN}" udp dport ${WG_PORT} accept

        # Allow SSH to the gateway only for VPN administrators
        iifname "${VPN}" ip saddr ${VPN_ADMINS} tcp dport 22 ct state new accept

        # Allow DHCP requests from Office, Finance and Guest VLANs
        iifname { "${V_OFFICE}", "${V_FINANCE}", "${V_GUEST}" } udp sport 68 udp dport 67 accept

        # Log other unauthorized incoming packets
        limit rate 5/second log prefix "FW-INPUT-DROP: "
    }


    # ------------------------------------------------------------
    # FORWARD : Traffic passing through the gateway
    # ------------------------------------------------------------

    chain forward {
        type filter hook forward priority 0; policy drop;

        # Drop invalid packets
        ct state invalid drop

        # Allow established and related connections
        ct state established,related accept

        # VPN accountants -> FTP server in the DMZ
        # FTP control connection and passive data connections
        iifname "${VPN}" ip saddr ${VPN_ACCOUNTANTS} oifname "${V_DMZ}" ip daddr ${FTP_HOST} tcp dport { ${FTP_PORT}, ${FTP_PASV} } ct state new accept

        # Finance VLAN -> FTP server in the DMZ
        # Enable this rule only if local Finance users also need FTP access.
        # iifname "${V_FINANCE}" oifname "${V_DMZ}" ip daddr ${FTP_HOST} tcp dport { ${FTP_PORT}, ${FTP_PASV} } ct state new accept

        # VPN administrators -> internal servers
        # SSH destinations must be defined and validated before enabling.
        # Do not authorize SSH to the entire internal network by default.

        # Block connections initiated from the DMZ
        iifname "${V_DMZ}" limit rate 5/second log prefix "FW-DMZ-INITIATED: "
        iifname "${V_DMZ}" drop

        # Block Guest access to internal network zones
        iifname "${V_GUEST}" oifname { "${V_OFFICE}", "${V_FINANCE}", "${V_DB}", "${V_DMZ}" } limit rate 5/second log prefix "FW-GUEST-INTERNAL: "
        iifname "${V_GUEST}" oifname { "${V_OFFICE}", "${V_FINANCE}", "${V_DB}", "${V_DMZ}" } drop

        # Allow HTTPS access to the Internet from internal VLANs
        iifname { "${V_OFFICE}", "${V_FINANCE}", "${V_GUEST}" } oifname "${WAN}" tcp dport 443 ct state new accept

        # Allow DNS requests to the Internet
        iifname { "${V_OFFICE}", "${V_FINANCE}", "${V_GUEST}" } oifname "${WAN}" udp dport 53 ct state new accept
        iifname { "${V_OFFICE}", "${V_FINANCE}", "${V_GUEST}" } oifname "${WAN}" tcp dport 53 ct state new accept

        # Database access:
        # No database rule is enabled until the target address,
        # database service and authorized source zones are confirmed.

        # Log other unauthorized forwarded packets
        limit rate 5/second log prefix "FW-FORWARD-DROP: "
    }


    # ------------------------------------------------------------
    # OUTPUT : Traffic generated by the gateway
    # ------------------------------------------------------------

    chain output {
        type filter hook output priority 0; policy ${OUTPUT_POLICY};

        # Allow local loopback traffic
        oifname "lo" accept

        # Drop invalid packets
        ct state invalid drop

        # Allow established and related connections
        ct state established,related accept

        # Allow DHCP responses to Office, Finance and Guest VLANs
        oifname { "${V_OFFICE}", "${V_FINANCE}", "${V_GUEST}" } udp sport 67 udp dport 68 accept

        # Allow ICMP IPv4 and IPv6
        ip protocol icmp accept
        meta l4proto ipv6-icmp accept

        # Allow DNS requests from the gateway
        oifname "${WAN}" udp dport 53 accept
        oifname "${WAN}" tcp dport 53 accept

        # Allow NTP synchronization
        oifname "${WAN}" udp dport 123 accept

        # Allow HTTP/HTTPS for updates and external services
        oifname "${WAN}" tcp dport { 80, 443 } accept

        # Log other unauthorized outgoing packets
        limit rate 5/second log prefix "FW-OUTPUT-DROP: "
    }
}


# ================================================================
# NAT TABLE
# ================================================================

table ip nat {

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;

        # Masquerade internal VLAN traffic when leaving through the WAN
        oifname "${WAN}" ip saddr {
            ${NET_OFFICE},
            ${NET_FINANCE},
            ${NET_GUEST}
        } masquerade
    }
}
EOF

}


# 3. Kernel network settings

write_sysctl() {

cat > "${SYSCTL_FILE}" <<'EOF'
# Enable IPv4 packet forwarding
net.ipv4.ip_forward = 1

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Disable sending ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable IPv6 forwarding
net.ipv6.conf.all.forwarding = 0
EOF

}


# 4. Utility functions

require_root() {

    if [ "$(id -u)" -ne 0 ]; then
        echo "ERROR: This script must be executed as root (sudo)." >&2
        exit 1
    fi

}


check_dependencies() {

    command -v nft >/dev/null 2>&1 \
        || { echo "ERROR: nftables is not installed."; exit 1; }

}


# 5. Check configuration without applying it

cmd_check() {

    check_dependencies

    local tmp
    tmp="$(mktemp)"

    trap 'rm -f "${tmp}"' RETURN

    build_rules > "${tmp}"

    nft -c -f "${tmp}"

    echo "Firewall syntax is valid."
    echo "No firewall rules have been applied."

}


# 6. Apply firewall configuration

cmd_apply() {

    require_root
    check_dependencies

    local tmp
    tmp="$(mktemp)"

    trap 'rm -f "${tmp}"' RETURN

    # Generate firewall configuration
    build_rules > "${tmp}"

    # Validate syntax before applying anything
    nft -c -f "${tmp}"

    echo "Firewall configuration validated."

    # Backup existing configuration
    if [ -f "${RULES_FILE}" ]; then
        cp -a "${RULES_FILE}" "${RULES_FILE}.bak"
        echo "Previous configuration backed up."
    fi

    # Install new nftables configuration
    install -m 600 "${tmp}" "${RULES_FILE}"

    # Configure kernel network settings
    write_sysctl
    sysctl -q -p "${SYSCTL_FILE}"

    # Apply firewall rules
    nft -f "${RULES_FILE}"

    echo "Firewall rules successfully applied."

    # Enable nftables at startup when systemd is available
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl enable nftables >/dev/null 2>&1 || true
        echo "nftables service enabled at startup."
    else
        echo "systemd not detected."
        echo "Configure firewall loading at startup manually."
    fi

    echo ""
    echo "IMPORTANT: Verify network access before closing your current session."

}


# 7. Display current firewall rules

cmd_status() {

    require_root
    check_dependencies

    nft list ruleset

}


# 8. Main command

case "${1:-apply}" in

    check)
        cmd_check
        ;;

    apply)
        cmd_apply
        ;;

    status)
        cmd_status
        ;;

    *)
        echo "Usage: sudo ./firewall.sh [check|apply|status]"
        exit 1
        ;;

esac
