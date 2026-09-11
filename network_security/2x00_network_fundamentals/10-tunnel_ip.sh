#!/bin/bash
ip addr show tun0 | awk '/inet / {print $2}' | cut -d/ -f1