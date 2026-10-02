#!/bin/bash
tshark -r "$1" -Y 'ip.addr == 10.10.10.50' -T fields -e frame.time | sed -n '1p;$p'
