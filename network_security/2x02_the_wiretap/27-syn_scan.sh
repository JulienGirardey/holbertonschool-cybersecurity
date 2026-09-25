#!/bin/bash
sudo nmap -sS -p 22,23,80 "$1"
