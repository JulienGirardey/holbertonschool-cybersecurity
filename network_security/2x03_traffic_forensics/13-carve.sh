#!/bin/bash
tshark -r "$1" --export-object http,directory && md5sum
