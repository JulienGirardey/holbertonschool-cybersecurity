#!/bin/bash
dig +short "$1" CNAME | head -n1