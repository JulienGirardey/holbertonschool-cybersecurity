#!/bin/bash
# expected : 403
curl -s -o /dev/null -w "%{http_code}\n" -x "${PROXY:-http://localhost:3128}" "${URL:-http://blocked.malware.com}"
