#!/bin/bash
awk -F:  '$3 < 1000 && $1 != "root" && $7~/(sh|bash)$/ {print $1}' $1