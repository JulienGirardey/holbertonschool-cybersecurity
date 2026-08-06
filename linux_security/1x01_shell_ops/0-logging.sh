#!/bin/bash
exec > $1 2>&1; echo "Starting Task"; echo "Doing Work"; echo "Error: Work Failed" >&2
