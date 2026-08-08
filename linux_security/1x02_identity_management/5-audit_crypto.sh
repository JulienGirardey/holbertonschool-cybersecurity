#!/bin/bash
awk -F: '$2 ~ /^\$1\$/ {print $1}' "$1"
