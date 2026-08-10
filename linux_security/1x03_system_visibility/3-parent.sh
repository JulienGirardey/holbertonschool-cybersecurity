#!/bin/bash
ps -o ppid= $1 | awk 'NR>1 {print $1}'
