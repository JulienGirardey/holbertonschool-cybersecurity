#!/bin/bash
ps -eo pid,state | grep -w Z | awk '{print $2}'
