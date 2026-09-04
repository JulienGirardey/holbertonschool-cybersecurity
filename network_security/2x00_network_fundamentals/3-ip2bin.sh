#!/bin/bash
CONV=({0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1})
ip=""
for byte in `echo ${1} | tr "." " "`; do
    ip="${ip}.${CONV[${byte}]}"
done
echo ${ip:1}
