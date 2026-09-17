#!/bin/bash
dig +short "$1" SOA | awk '{print $1}'
