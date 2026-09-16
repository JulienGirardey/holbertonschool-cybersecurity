#!/bin/bash

# 1. Fichiers de lease dhclient
result=$(grep -h "dhcp-server-identifier" /var/lib/dhcp/*.leases 2>/dev/null | tail -n1 | awk '{print $3}' | tr -d ';')

# 2. Fallback : nmcli
if [ -z "$result" ]; then
    result=$(nmcli -g DHCP4.OPTION dev show 2>/dev/null | tr '|' '\n' | grep "dhcp_server_identifier" | awk -F' = ' '{print $2}' | tr -d ' ')
fi

# 3. Fallback : journalctl
if [ -z "$result" ]; then
    result=$(journalctl -u NetworkManager 2>/dev/null | grep -i "dhcp" | grep -oE "server identifier [0-9.]+" | tail -n1 | awk '{print $NF}')
fi

echo "$result"