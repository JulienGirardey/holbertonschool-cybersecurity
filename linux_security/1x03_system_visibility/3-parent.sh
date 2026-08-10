#!/bin/bash
ps -eo ppid $1 | awk 'NR>1 {print $1}'
