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

check_ports() {
    ss -tlnp | awk 'NR>1 {print $4, $6}' | while read -r local_address process_info; do
        port="${local_address##*:}"

        if [[ "$process_info" =~ pid=([0-9]+) ]]; then
            pid="${BASH_REMATCH[1]}"

            allowed=false
            for p in "${ALLOWED_PORTS[@]}"; do
                if [[ "$port" -eq "$p" ]]; then
                    allowed=true
                    break
                fi
            done

            if [ "$allowed" = false ]; then
                kill -9 "$pid" 2>/dev/null
                echo "ALERT: Killed rogue process on port $port"
            fi
        fi
    done
}

check_ports

log() {
    timestamp=$(date -u +%FT%TZ)
    local component="$1"
    local target="$2"
    local status="$3"
    local details="$4"
    local timestamp
    echo "{\"timestamp\": \"$timestamp\", \"target\": \"$target\", \"status\": \"$status\", \"details\": \"$details\"}" >> /var/log/sentiel.log
}

log
