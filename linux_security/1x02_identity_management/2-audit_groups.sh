#!/bin/bash
awk -F: '$3 >= 1000 && $7~/(disk|docker|shadow)$/ {print $1:}'