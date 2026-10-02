#!/bin/bash
tshark -r "$1" -Y 'icmp && frame.len > 100' -T fields -e ip.src
