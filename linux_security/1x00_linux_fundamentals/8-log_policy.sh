#!/bin/bash
mkdir -p $1
chown root:$2 $1
chmod 2750 $1
cat > /etc/logrotate.d/app << EOF
$1/*.log {
weekly
rotate 4
missingok
notifempty
compress
create 0640 root $2
}
EOF
