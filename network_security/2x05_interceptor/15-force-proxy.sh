#!/bin/bash
VPN_NET="10.200.0.0/24"
PROXY_IP="10.200.0.1"
OUT_IF="eth0"

nft add table ip filter
nft add chain ip filter forward '{ type filter hook forward priority 0; }'
nft add chain ip filter output '{ type filter hook output priority 0; }'

# Allow the proxy itself to make outbound connections
nft add rule ip filter output ip saddr "$PROXY_IP" accept
nft add rule ip filter forward ip saddr "$PROXY_IP" accept

# Block direct HTTP and HTTPS from VPN clients (except to the proxy)
nft add rule ip filter forward ip saddr "$VPN_NET" ip daddr != "$PROXY_IP" oif "$OUT_IF" tcp dport 80 drop
nft add rule ip filter forward ip saddr "$VPN_NET" ip daddr != "$PROXY_IP" oif "$OUT_IF" tcp dport 443 drop
