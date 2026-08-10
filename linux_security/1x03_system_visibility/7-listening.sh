#!/bin/bash
ss -lnt4 | awk 'NR>1 split($4,a,":") { print a[2] }' | sort -n
