#!/bin/bash
scp ./skeleton.conf engineer@192.168.252.2:~/
./2-panic.sh
nft -f /etc/nftables.conf
nft list ruleset
