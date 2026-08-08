#!/bin/bash
if dpkg -s "$1" >/dev/null 2>&1; then
    echo "$1 is installed."
else
    apt-get update
    apt-get install "$1"
fi
sed -i 's/^#\s*minlen\s*=.*/# minlen = 12/; s/^#\s*minclass\s*=.*/# minclass = 3/' /etc/security/pwquality.conf
pam-auth-update --package
