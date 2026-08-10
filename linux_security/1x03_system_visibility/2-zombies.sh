#!/bin/bash
ps -eo | grep -w Z | awk '{print $2}'
