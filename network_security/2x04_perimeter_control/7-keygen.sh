#!/bin/bash
wg genkey > server_private | wg pubkey > server_public
wg genkey > client_private | wg pubkey > client_public
