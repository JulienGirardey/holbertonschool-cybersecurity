#!/bin/bash
cp sentinel.service sentinel.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sentinel.timer
