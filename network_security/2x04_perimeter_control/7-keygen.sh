#!/bin/bash
wg genkey > server_private | wg pubkey > server_public
