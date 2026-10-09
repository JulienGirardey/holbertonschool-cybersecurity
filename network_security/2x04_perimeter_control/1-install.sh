#!/bin/bash
apt update
apt install nftables
systemctl enable nftables --no-start
apt install wireguard wireguard-tools
