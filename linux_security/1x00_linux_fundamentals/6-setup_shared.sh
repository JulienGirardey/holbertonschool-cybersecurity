#!/bin/bash
mkdir -p $1 && chown root:$2 $1 && chmod g+s,+t,g+rwx $1
