#!/bin/bash
start=$(date -d "-30 minutes" +%s)
awk -v start="$start" '/sshd/ {date_log = $1 " " $2 " " $3; commande = "date -d \"" date_log "\" +%s"; commande | getline timestamp} timestamp>=start {print $0}' "$1"
