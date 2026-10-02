#!/bin/bash
tshark -r "$1" http.request.uri.(UNION|SELECT|union|select) -T fields -e http.request.uri
