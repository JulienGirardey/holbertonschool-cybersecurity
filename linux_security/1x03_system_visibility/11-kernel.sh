#!/bin/bash
[ -f "$1" ] && grep segfault "$1"
