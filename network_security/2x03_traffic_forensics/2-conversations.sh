#!/bin/bash
tshark -r "$1" -q -z conv,tcp
