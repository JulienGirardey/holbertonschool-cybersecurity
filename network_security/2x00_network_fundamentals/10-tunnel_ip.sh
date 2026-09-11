#!/bin/bash
ip addr | awk '/inet / {print $2}' | cut -d/ -f1