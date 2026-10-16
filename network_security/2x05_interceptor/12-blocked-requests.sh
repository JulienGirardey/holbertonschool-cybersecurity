#!/bin/bash
grep "/403 " /var/log/squid/access.log | awk '{print $1, $3, $7}'
