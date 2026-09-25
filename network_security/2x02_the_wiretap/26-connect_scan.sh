#!/bin/bash
nmap -sT -p 22,23,80 "$1"
