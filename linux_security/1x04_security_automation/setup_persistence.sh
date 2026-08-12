#!/bin/bash
cp sentinel.service /etc/systemd/system/
cp sentinel.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable sentinel.timer
