# Hardening framework

This project implements a modular Linux hardening automation workflow.

## Architecture

- Entry point: `harden.sh`
- Configuration: `config/harden.cfg`
- Logic modules: `lib/identity.sh`, `lib/network.sh`, `lib/ssh.sh`, `lib/system.sh`

## Requirements enforced

- Root-only execution guard
- Centralized configuration values
- Modular library design instead of monolithic logic
- Timestamped logging to `/var/log/hardening.log`
- First log entry: `Hardening framework initialized`

## Usage

```bash
sudo ./harden.sh
```

The script loads the configuration from the config directory, logs each action, and applies the hardening steps in a maintainable, safe order.