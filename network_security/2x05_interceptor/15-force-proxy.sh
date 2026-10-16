#!/bin/bash
nft add rule $1 input '{
    tcp dport 80 drop
    tcp dport 443 drop
    ip saddr 10.200.0.0/24 accept
}'
