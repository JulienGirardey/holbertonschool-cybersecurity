#!/bin/bash
ps -u -p $1 | awk 'NR>1 {print $1}'
