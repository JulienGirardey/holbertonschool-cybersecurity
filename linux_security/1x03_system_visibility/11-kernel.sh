#!/bin/bash
[ -f "$1/kern.log" ] && grep 'segfault' "$1/kern.log"
[ -f "$1/messages" ] && grep 'segfault' "$1/messages"
