#!/bin/bash
awk '!/^#/ && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { for(i=2;i<=NF;i++) if ($i=="localhost") { printf "%s", $1; exit } }' /etc/hosts