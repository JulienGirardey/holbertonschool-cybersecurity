#!/bin/bash
nft add rule inet filter input ip saddr 10.200.0.0/24 accept
tcp port 3128 accept
