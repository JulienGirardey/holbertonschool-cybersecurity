#!/bin/bash
ls -l $1 | awk '{print $3}' | sort | uniq -cd | head -1
