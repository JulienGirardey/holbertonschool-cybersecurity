#!/bin/bash
IFS='.' read -r a b c d <<< "$1"; ip=$(( (a<<24)+(b<<16)+(c<<8)+d )); mask=$(( 0xffffffff << (32-$2) & 0xffffffff )); net=$(( ip & mask )); bc=$(( net | (~mask & 0xffffffff) )); f=$((net+1)); l=$((bc-1)); printf "%d.%d.%d.%d - %d.%d.%d.%d" $((f>>24&255)) $((f>>16&255)) $((f>>8&255)) $((f&255)) $((l>>24&255)) $((l>>16&255)) $((l>>8&255)) $((l&255))
