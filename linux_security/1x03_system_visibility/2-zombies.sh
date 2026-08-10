#!/bin/bash
ps -e | grep -w Z | awk '{print $2}'
