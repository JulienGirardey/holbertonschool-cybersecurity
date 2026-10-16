#!/bin/bash
if squid -k parse; then
    systemctl reload squid
else
    exit 1
fi
