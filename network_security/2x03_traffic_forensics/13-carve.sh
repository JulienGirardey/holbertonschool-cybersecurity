#!/bin/bash
tshark -r "$1" --export-object http, && md5sum
