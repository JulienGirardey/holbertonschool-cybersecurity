#!/bin/bash
ps -eo pid,pcpu,comm --sort=-pcpu | awk 'NR==2 {print $1, $3}'
