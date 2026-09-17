#!/bin/bash
dig +short @$1 $2 A | head -n1