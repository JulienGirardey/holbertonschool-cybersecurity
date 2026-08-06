#!/bin/bash
find $1 -type f -name "*.log" -print0 | xargs -0 -I {} mv {} {}.old
