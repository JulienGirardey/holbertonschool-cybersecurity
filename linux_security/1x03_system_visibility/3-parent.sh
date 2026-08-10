#!/bin/bash
ps -o ppid= -p $1 | tr -d ' '
