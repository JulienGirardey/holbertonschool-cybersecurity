#!/bin/bash
ps -eo pid,pcpu,comm --sort=-%cpu | awk 'NR == 2 {print $1, $3}'
