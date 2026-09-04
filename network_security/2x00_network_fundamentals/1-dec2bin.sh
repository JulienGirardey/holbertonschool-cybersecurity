#!/bin/bash
for num in {1..127}; do binnum=$(echo "obase=2;$num" | bc); printf "%08d\n" "$binnum"; done
