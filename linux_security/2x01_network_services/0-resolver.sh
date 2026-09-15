#!/bin/bash
grep "^nameserver" /etc/resolv.conf | head -n1 | awk '{print $2}'