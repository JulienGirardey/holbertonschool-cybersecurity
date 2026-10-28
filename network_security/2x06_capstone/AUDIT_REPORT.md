# AUDIT\_REPORT.md — LogiCorp Gateway

Structure per section: what the documentation claims / what was found (with evidence) / verdict.

## Scope & method

Audit conducted as the `student` user, without root privileges (root out of scope: not mentioned in the brief, and discovered as a vulnerability — see section 5).

The target is a **container** hosted on AWS/ECS, not a classic VM: kernel shared with the host, restricted system capabilities, no systemd. This limits some checks (firewall, AppArmor), marked "not verifiable live".

Throughout the report, a distinction is made between:

- the **LogiCorp scenario** (what is planted for the exercise, to be audited);
- the **lab infrastructure** (the host provider's plumbing and the school's tools: `eth0`, ttyd, openvscode-server), out of scope but flagged.

## 1. System Information

**Doc:** the brief specifies neither the OS nor the kernel. No reference to compare against — inventory only.

**Found:** Ubuntu 22.04 (jammy); Linux kernel 6.1.188 (host kernel, shared by the container); hostname = ECS task identifier (`d70f...-...`); uptime = container age, not the "gateway" age. Commands: `cat /etc/os-release`, `uname -a`, `hostname`, `uptime`.

**Verdict:** inventory recorded. The kernel and hostname belong to the host provider, not the scenario.

## 2. Network Topology

**Doc:** Document D (the intern's diagram, flagged "likely wrong"): `eth0` = WAN, `eth1` = LAN. Document C: "FLAT NETWORK, same subnet 192.168.1.x".

**Found:**

- `eth1` holds IP `10.42.166.24/16` and the default route → it is the **egress interface** (WAN) and also the local network. Egress proven by `curl` + `ip route get 1.1.1.1` (via `10.42.0.1 dev eth1`).
- `eth0` holds a link-local address `169.254.x.x` (non-routable, RFC 3927), no default route → link to the host provider's infrastructure, **not a WAN**.
- Real subnet: `10.42.0.0/16`, not `192.168.1.x` (the latter exists on no interface).
- LAN and WAN on the same interface `eth1`: **flat** network, no segmentation. Commands: `ip a`, `ip r`, `ip route get`, `ip neigh`.

**Verdict:** documentation partly wrong — `eth0`/`eth1` roles reversed, subnet non-existent. However, the "flat" nature of the network is confirmed (and `network.conf` says `NETWORK_MODE=FLAT`).

## 3. Attack Surface

**Doc:** Document C — SSH open to the whole Internet, FTP in cleartext. No other exposure mentioned.

**Found:** 4 listening ports, all on `0.0.0.0` (all interfaces), firewall flushed → genuinely reachable. Command: `ss -tulnp` (processes visible as root).

| Port | Processus | PID | Categoryrie | Documented? |
| --- | --- | --- | --- | --- |
| 22 | sshd | 89 | LogiCorp scenarionario LogiCorp | yes |
| 21 | vsftpd | 63 | LogiCorp scenarionario LogiCorp | yes |
| 3000 | node → openvscode-server | 105 | Lab infrara labo | no |
| 3001 | ttyd | 91 | Lab infrara labo | no |

**Verdict:** SSH and FTP confirmed exposed. Ports 3000/3001 belong to the lab infrastructure (the school's editor + web console), flagged but out of scenario.

## 4. Security Controls

**Doc:** Document C — "No Firewall active". Target: "Default Deny" policy.

**Found:**

- **Firewall**: `run.sh` runs `nft flush ruleset` at every boot → no rules. Direct read impossible even as root (`CAP_NET_ADMIN` missing from the container, proven by `capsh --print` → `!cap_net_admin`). Established via the config.
- **Suricata** (IDS): config `/etc/suricata/` and `fast.log` present, but **no active process** (`ps aux`) and no startup in `run.sh`. The `fast.log` is written by hand by `run.sh`, not by the IDS.
- **SELinux / AppArmor**: SELinux absent (normal on Ubuntu); AppArmor not installed (`aa-status` not found) and module not exposed (`/sys/module/apparmor` absent). Not verifiable live (container, kernel not controlled).

**Verdict:** "No firewall active" confirmed. No real intrusion detection despite appearances. No MAC verifiable.

## 5. User Accounts

**Doc:** Document C — SSH open, "Root enabled". The internal policy (`security.policy`) says "root login should never happen".

**Found:** (commands `cat /etc/passwd`, `cat /etc/ssh/sshd_config`, `ls -la /root/.ssh/`)

| Item | Finding | Verdict |
| --- | --- | --- |
| Accounts with a shell | root + student only | clean |
| Duplicate UID 0 | none | clean |
| `telnetd` account + package | installed (`/usr/sbin/in.telnetd`), service inactive | finding — obsolete leftover, unencrypted, undocumented |
| `PermitRootLogin` | `yes` | finding — confirms the doc, violates `security.policy` |
| `PasswordAuthentication` | `yes` | finding — brute-force target |
| `PermitEmptyPasswords` | absent → default `no` | compliant |
| student SSH keys | the 2 intranet keys, nothing foreign | clean |
| root SSH keys | `/root/.ssh/` not readable (permission denied) | compliant (protected) |

**Verdict:** root login confirmed (contradicts the internal policy). Telnet finding as a bonus. Accounts otherwise clean.

## 6. Running Services

**Doc:** the brief does not list the services; it describes SSH, FTP and the absence of a firewall. To be cross-checked against reality.

**Found:** (command `ps -ef --forest`)

- **PID 1 = `/bin/sh -c ...`** (not systemd) → container; all services are started by `/etc/run.sh`.
- Active: `sshd` (22), `vsftpd` (21), `cron` (77) — LogiCorp scenario; `ttyd` + `openvscode-server` — lab infra.
- The **cron backdoor is visible live**: PIDs 333-338 show the `curl http://192.168.1.200/ping` calls launched by cron, stuck in timeout and piling up every minute.
- Inactive, to flag: Telnet (installed), Suricata (config present).

**Verdict:** real services inventoried. No systemd (container): expected, not a defect.

## 7. Scheduled Tasks

**Doc:** nothing in the brief. But section ACC-06 of the GAP\_ANALYSIS expects a search for attacker persistence (cron jobs, keys, backdoors) after the incident.

**Found:** (commands `cat /etc/cron.d/logicorp`, `cat /etc/crontab`, `ls /etc/cron.*`)

- **Critical finding — cron backdoor**: `/etc/cron.d/logicorp` runs, as root and **every minute** (`* * * * *`), `curl http://192.168.1.200/ping`. Beacon behaviour ("calling home") typical of a backdoor. Target not routable from `10.42.x.x` → the request fails, but the mechanism is present and designed for the LogiCorp network (`192.168.1.x`). File dated 12 Feb 2026, readable by `student`.
- **Noise discarded**: `/etc/crontab` + `cron.hourly/daily/weekly/monthly` = standard Ubuntu maintenance tasks (`apt-compat`, `dpkg`, `logrotate`, `man-db`).

**Verdict:** persistence backdoor confirmed (illustrates ACC-06). To be removed.

## 8. Discrepancies — doc vs réalité

The client's diagram (Document D) was announced as unreliable; the audit confirms this and additionally reveals undocumented elements.

| # | What the doc says | Reality found | Type |
| --- | --- | --- | --- |
| D1 | `eth0` = WAN, `eth1` = LAN | reversed: `eth1` = egress + LAN, `eth0` = link-local infra link | doc wrong |
| D2 | Subnet `192.168.1.x` | real `10.42.0.0/16`; `192.168.1.x` absent from interfaces | doc wrong (lab env.) |
| D3 | Flat network | confirmed (all on `eth1`, `network.conf` = `NETWORK_MODE=FLAT`) | doc correct |
| D4 | SSH open, root enabled | confirmed (`PermitRootLogin yes`), + violates `security.policy` | doc correct |
| D5 | FTP in cleartext | confirmed (vsftpd:21 active, exposed on `0.0.0.0`) | doc correct |
| D6 | No firewall | confirmed (`nft flush` at boot) | doc correct |
| D7 | — (undocumented) | **cron backdoor** as root every minute to `192.168.1.200` | undocumented |
| D8 | — (undocumented) | **Telnet server** installed (inactive) | undocumented |
| D9 | — (undocumented) | `/etc/logicorp/` files world-readable (db.conf exposes the database) | undocumented |
| D10 | "no IDS" (MON-04) | Suricata config present but **IDS inactive**, logs falsified | doc correct (trap) |
