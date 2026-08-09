#!/bin/bash
username="$1"
KEY="$2"
useradd -m "$username"
passwd -l "$username"
mkdir -m 700 "/home/$username/.ssh/"
printf '%s\n' "$KEY" > "/home/$username/.ssh/authorized_keys"
chmod 600 "/home/$username/.ssh/authorized_keys"
chown -R "$username:$username" "/home/$username/.ssh"
