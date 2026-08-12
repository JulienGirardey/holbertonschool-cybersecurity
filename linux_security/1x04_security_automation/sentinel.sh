#!/bin/bash
[ -f "sentinel.conf" ] || exit 1; source "sentinel.conf"; [ -n "${SERVICES+x}" ] && [ -n "${FILES_TO_WATCH+x}" ] || exit 1

log() {
    local component="$1"
    local target="$2"
    local status="$3"
    local details="$4"
    local timestamp
    timestamp=$(date -u +%FT%TZ)
    echo "{\"timestamp\": \"$timestamp\", \"component\": \"$component\", \"target\": \"$target\", \"status\": \"$status\", \"details\": \"$details\"}" >> /var/log/sentinel.log
}

check_services() {
    for index in "${SERVICES[@]}"; do
        if [ "pgrep -f $index" ]; then
            echo "OK: $index is running"
            log "SERVICE" "$index" "OK" "$index is running"
        else
            eval "$index"
            if [ "pgrep -f $index" ]; then
                echo "FIXED: Restarted $index"
                log "SERVICE" "$index" "FIXED" "Restarted $index"
            else
                echo "Error: " <2
                log "SERVICE" "$index" "Error" "NOT RUN"
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
            log "INTEGRITY" "$file" "OK" "$file integrity verified"
        else
            cp "$GOLDEN" "$file"
            echo "FIXED: Restored $file"
            log "INTEGRITY" "$file" "FIXED" "Restored $file"
        fi
    done
}

check_integrity

check_ports() {
    for port in $(ss -lntp | awk 'NR>1{split($4, a, ":"); print a[2]}'); do
        allowed=false
        for allowed_port in "${ALLOWED_PORTS[@]}"; do
            if [ "$port" = "$allowed_port" ]; then
                allowed=true
            fi
        done
        if [ "$allowed" = false ]; then
            ss -K sport = :$port &>/dev/null
            echo "ALERT: Killed rogue process on port $port"
            log "PORT" "$port" "ALERT" "Killed rogue process on port $port"
        fi
    done
}

check_ports

