#!/bin/bash
ss -lnt4 | awk 'NR>1'
