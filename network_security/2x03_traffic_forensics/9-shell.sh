#!/bin/bash
tshark -r "$1" -Y "tcp.payload contains \"uid=0\" or tcp.payload contains \"root\"" -T fields -e tcp.dstport
