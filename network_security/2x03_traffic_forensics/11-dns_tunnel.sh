#!/bin/bash
tshark -r "$1" -T fields -e 'dns.qry.name.len' | awk 50
