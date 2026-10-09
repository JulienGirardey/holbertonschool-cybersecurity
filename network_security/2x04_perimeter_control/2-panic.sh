#!/bin/bash
sudo nft flush ruleset
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
echo "$0" | at now + 5 minutes
