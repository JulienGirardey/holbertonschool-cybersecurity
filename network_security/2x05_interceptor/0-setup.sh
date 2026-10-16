#!/bin/bash
apt update
apt install squid
systemctl enable squid --no-start
scp /etc/squid/squid.conf.bak
