#!/bin/bash
FILE="$2"
if ! dpkg -s "$1" >/dev/null 2>&1; then
    apt-get update
    apt-get install -y $1
fi
sed -i '/pam_unix\.so/i password requisite pam_pwquality.so minlen=12 minclass=3' "$FILE"
