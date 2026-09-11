#!/bin/bash
if ip route get $1 | grep -q "via"; then
    echo "REMOTE"
else
    echo "LOCAL"
fi