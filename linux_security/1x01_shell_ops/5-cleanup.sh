#!/bin/bash
while read line; do
    if id line; then
        usermod -L $line
    else
        echo "User $line not found"
    fi
done < $1
