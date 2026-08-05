#!/bin/bash
cat > /usr/local/bin/audit-read-secret << 'EOF'
#!/bin/bash
cat /var/www/html/secret_config.php
EOF
chmod +x /usr/local/bin/audit-read-secret
echo "$1 ALL=(root) NOPASSWD: /usr/local/bin/audit-read-secret" > /etc/sudoers.d/audit
