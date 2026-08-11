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

check_integrity() {
    for file in "${FILES_TO_WATCH[@]}"; do
        GOLDEN="/var/backups/sentinel/$(basename "$file").gold"
        LIVE_HASH=$(md5sum "$file" | awk '{print $1}')
        GOLD_HASH=$(md5sum "$GOLDEN" | awk '{print $1}')
        if [ "$LIVE_HASH" = "$GOLD_HASH" ]; then
            echo "OK: $file integrity verified"
        else
            cp "$GOLDEN" "$file"
            echo "FIXED: Restored $file"
        fi
    done
}

check_integrity