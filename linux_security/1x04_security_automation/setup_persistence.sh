#!/bin/bash
cp .*sentinel.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sentinel.timer
