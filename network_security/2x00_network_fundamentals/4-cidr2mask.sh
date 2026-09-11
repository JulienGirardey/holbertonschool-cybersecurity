#!/bin/bash

# Validate that an argument was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <CIDR_value> (e.g., 24)"
    exit 1
fi

cidr=$1

# Validate that the input is an integer between 0 and 32
if ! [[ "$cidr" =~ ^[0-9]+$ ]] || [ "$cidr" -lt 0 ] || [ "$cidr" -gt 32 ]; then
    echo "Error: CIDR must be an integer between 0 and 32."
    exit 1
fi

# Calculate the dotted decimal mask
mask=""
for i in 1 2 3 4; do
    if [ "$cidr" -ge 8 ]; then
        octet=255
        cidr=$((cidr - 8))
    elif [ "$cidr" -gt 0 ]; then
        octet=$(( 256 - (2 ** (8 - cidr)) ))
        cidr=0
    else
        octet=0
    fi
    
    if [ $i -eq 1 ]; then
        mask="$octet"
    else
        mask="$mask.$octet"
    fi
done

echo "$mask"