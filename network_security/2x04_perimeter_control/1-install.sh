#!/bin/bash
apt update
apt install nftables
systemctl enable --no-start nftables
apt install wireguard wireguard-tools
