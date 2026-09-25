#!/bin/bash
sudo nmap -Ss -p 22,23,80 "$1"
