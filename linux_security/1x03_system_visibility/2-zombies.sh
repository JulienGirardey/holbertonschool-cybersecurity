#!/bin/bash
ps -eo pid,state | awk '$2=="Z" {print $1}'
