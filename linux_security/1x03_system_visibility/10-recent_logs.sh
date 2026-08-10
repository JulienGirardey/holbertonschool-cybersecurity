#!/bin/bash
date --since '30min ago' | cat $1 | grep 'sshd'
