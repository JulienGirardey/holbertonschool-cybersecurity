#!/bin/bash
journalctl -u sshd --since "30min ago" $1
