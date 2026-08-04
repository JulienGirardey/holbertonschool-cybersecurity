#!/bin/bash
ls -l $1 | awk '{print $3}' | sort -nr | uniq -c | head -1
