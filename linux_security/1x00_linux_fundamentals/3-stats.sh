#!/bin/bash
ls -l $1 | awk '{print $3}' | uniq -cd | head -1
