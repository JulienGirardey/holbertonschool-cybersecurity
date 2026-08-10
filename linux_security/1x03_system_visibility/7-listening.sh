#!/bin/bash
ss -lnt4 | awk '$4 && ^: {print $1}'
