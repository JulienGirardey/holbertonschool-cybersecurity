#!/bin/bash
for byte in `echo $1 | tr "." " "`; do printf "%08d." "$(echo "obase=2;$byte" | bc)"; done | sed 's/\.$//'
