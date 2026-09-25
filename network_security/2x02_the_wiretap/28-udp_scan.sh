#!/bin/bash
sudo nmap -sU -p 53,161 "$1"
