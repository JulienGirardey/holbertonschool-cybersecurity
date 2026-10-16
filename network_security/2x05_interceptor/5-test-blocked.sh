#!/bin/bash
curl -s -o /dev/null -w "403" -x ${PROXY:-http://localhost:3128} ${URL:-http://blocked.malware.com}
