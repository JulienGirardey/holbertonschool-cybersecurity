#!/bin/bash
tshark -r "$1" -z io,phs -q
