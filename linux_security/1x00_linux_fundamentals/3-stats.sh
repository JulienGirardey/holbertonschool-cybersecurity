#!/bin/bash
ls -l $1 | awk '{print $3}' | uniq -c | sort -nr | head -1
