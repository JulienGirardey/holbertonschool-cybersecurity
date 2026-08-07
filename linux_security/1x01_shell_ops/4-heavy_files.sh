#!/bin/bash
ls -l $1 | awk '$5 > 1024 {print $9}'
