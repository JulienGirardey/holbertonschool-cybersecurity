#!/bin/bash
if [ -f "$1/kern.log" ]; then
    grep 'segfault' "$1/kern.log"
fi

if [ -f "$1/messages" ]; then
    grep 'segfault' "$1/messages"
fi
