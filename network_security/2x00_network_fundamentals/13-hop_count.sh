#!/bin/bash
traceroute $1 2>/dev/null | tail -1 | awk '{print $1}'