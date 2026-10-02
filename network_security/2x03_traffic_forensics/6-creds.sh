#!/bin/bash
tshark -r "$1" -Y urlencoded-form -T fields -e urlencoded-form.value
