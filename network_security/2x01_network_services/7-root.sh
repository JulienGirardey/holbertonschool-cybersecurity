#!/bin/bash
dig +trace -4 "$1" 2>/dev/null | grep -m1 "root-servers\.net)" | sed -E 's/^.*from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)#.*/\1/'