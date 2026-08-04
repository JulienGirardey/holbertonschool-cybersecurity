#!/bin/bash
find $1 -type f -mtime -7 -size +1M ! -name "*.gz" -print 2> /dev/null
