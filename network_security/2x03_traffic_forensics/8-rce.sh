#!/bin/bash
tshark -r "$1" -Y 'http.request.uri contains "/bin/sh"' -T fields -e frame.number
