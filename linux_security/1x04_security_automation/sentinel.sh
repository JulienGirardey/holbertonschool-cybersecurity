#!/bin/bash
[ -f "sentinel.conf" ] || exit 1; source "sentinel.conf"; [ -n "${SERVICES+x}" ] && [ -n "${FILES_TO_WATCH+x}" ] || exit 1
check_services() {
    for index in "${SERVICES[@]}"; do
        if [ "pgrep -f $index" ]; then
            echo "OK: $index is running"
        else
            eval "$index"
            if [ "pgrep -f $index" ]; then
                echo "FIXED: Restarted $index"
            else
                echo "Error: " <2
            fi
        fi 
    done
}

check_services