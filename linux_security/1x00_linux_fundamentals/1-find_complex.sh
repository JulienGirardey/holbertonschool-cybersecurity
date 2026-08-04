#!/bin/bash
find $1 -type f -atime -1 -size +1M ! -name "*.gz" -print 2> /dev/null