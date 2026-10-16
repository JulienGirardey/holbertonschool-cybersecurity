#!/bin/bash
mkdir /etc/squid/ssl_cert
openssl req -key domain.key -new -x509 -days 365 -out domain.crt
