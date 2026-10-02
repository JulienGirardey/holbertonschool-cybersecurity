#!/bin/bash
tshark -r "$1" "dns.qry.name.len > 50 and ip.addr == 10.10.10.50"