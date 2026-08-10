#!/bin/bash
lsof -iTCP:$1 -sTCP:LISTEN -n -P
