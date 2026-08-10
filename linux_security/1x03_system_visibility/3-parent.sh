#!/bin/bash
ps -o ppid= -p $1 | awk 'NR>1 {print $1}'
