#!/bin/bash
sed -E 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/[REDACTED_IP]/g' $1
