#!/bin/bash
ARG="$1"
if [ ! -d "$ARG" ]; then
    exit 1
fi
mkdir -p "$ARG"/backups
find "$ARG" -type f -name "*.log" | while read -r file; do
    if [ $(stat -c%s "$file") -gt 1024 ]; then
        gzip "$file"
        mv "$file.gz" "$ARG"/backups/
    else
        echo "Skipping small file: $file"
    fi
done
