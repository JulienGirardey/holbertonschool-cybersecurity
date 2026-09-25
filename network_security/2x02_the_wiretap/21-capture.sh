#!/bin/bash
tcpdump -i eth1 -w capture.pcap "(icmp and host 10.42.0.1) or (tcp port 80 and host 10.42.196.84)"
