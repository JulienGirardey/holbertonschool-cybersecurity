# DEFENSE: LogiCorp Gateway Hardening

Answers to the Senior Architect's review of the LogiCorp Gateway design and enforcement.
Every claim maps to a delivered artifact: `HARDENING/clean.sh`, `HARDENING/firewall.sh`,
`HARDENING/vpn_setup.sh`, `HARDENING/panic_button.sh`, `VALIDATION/tests.sh`.

---

## Challenge 1: Risk Acceptance

> *"You kept FTP running, even tunneled over VPN. FTP is inherently insecure. Why not force the client to upgrade to SFTP?"*

### Business constraint analysis

The engagement requirement was explicit: **"FTP must continue working for Finance."** Forcing SFTP now would mean:

| Impact of an immediate switch to SFTP | Consequence |
|---|---|
| Finance tools and scripts are built around FTP | client software changes, re-testing of every transfer workflow |
| Partners and accounting tools exchange files over FTP | coordination with third parties outside LogiCorp's control |
| Users need new clients, new credentials (keys) and training | change management that cannot fit in the enforcement window |
| A failed cut-over blocks payments and reporting | direct business loss, higher than the residual risk below |

Breaking a finance-critical workflow to fix a protocol weakness would replace a security risk with a certain operational outage. The right engineering answer is to **make FTP safe to keep for now**, then **plan its retirement**.

### Risk mitigation measures implemented

The weakness of FTP is cleartext credentials and data. We removed every path where that cleartext crosses an untrusted network:

| Control | Implementation | Artifact |
|---|---|---|
| **Encrypted transport** | FTP is only reachable through WireGuard (Curve25519 key exchange, ChaCha20-Poly1305 encryption). Cleartext never crosses the Internet. | `vpn_setup.sh` |
| **No exposure on the WAN** | 21/tcp (and 22/tcp) dropped and logged on the WAN interface (`FW-WAN-21-22`) | `firewall.sh` |
| **Least privilege per role** | Finance VPN range `10.8.0.100-149` may only reach `10.50.60.40` on 21 and 30000-30100. Client `AllowedIPs` is limited to that single host (split tunnel). | `firewall.sh`, `vpn_setup.sh` |
| **No pivot from FTP users** | SSH from the Finance VPN range is dropped and logged (`FW-SSH-ACCOUNTANTS`) | `firewall.sh` |
| **FTP moved off the gateway** | The service runs in the DMZ, which cannot initiate connections (`FW-DMZ-INITIATED`): a compromised FTP server cannot reach other zones. The gateway vsftpd is disabled as soon as the DMZ server answers. | `firewall.sh`, `clean.sh` |
| **Server hardening** (while the gateway FTP is kept) | no anonymous access, users chrooted in their home, allow-list of Finance accounts, transfer logging, fixed passive range | `clean.sh` |
| **Strong, revocable identities** | one WireGuard key pair per user: a lost laptop is revoked by removing one `[Peer]` | `vpn_setup.sh` |
| **Continuous verification** | firewall rules, stopped services and VPN state are checked automatically | `tests.sh` |

### Residual risk acknowledgment

| Residual risk | Likelihood | Impact | Why it remains |
|---|---|---|---|
| Cleartext FTP between the gateway and the DMZ server (after the tunnel ends) | Low | Medium | sniffing requires a foothold in the DMZ segment, which is isolated and cannot initiate traffic |
| FTP credentials are passwords (reuse, phishing) | Medium | Medium | protocol limitation; reduced by the VPN key as a second factor ("something you have") |
| Stolen device with a valid VPN config | Low | Medium | WireGuard keys have no passphrase; mitigated by per-user revocation |
| No application-layer integrity for transferred files | Low | Medium | FTP limitation; integrity is provided in transit by WireGuard |

Overall, the risk moves from **Critical** (cleartext FTP and root SSH exposed on the gateway) to **Low/Medium**, which is accepted **temporarily**, with an owner and a deadline.

### Recommendation for Phase 2

1. **Deploy SFTP** on the DMZ server (OpenSSH `internal-sftp`, chroot, key authentication) **in parallel** with FTP.
2. **Migrate Finance workflows** user by user, then partners, with a test period.
3. **Decommission FTP**: remove 21 and 30000-30100 from `firewall.sh` and add a `tests.sh` check that fails if port 21 is open anywhere.
4. Interim option, if SFTP is delayed: **FTPS** (explicit TLS) to remove the remaining cleartext inside the DMZ.

The risk acceptance should be signed by the LogiCorp business owner (Finance), with a target date for step 3.

---

## Challenge 2: Firewall Strategy

> *"Explain your segmentation logic. How does it specifically prevent the lateral movement that caused the previous breach?"*

### Zone definitions and trust levels

| Zone | Interface / network | Trust | Role |
|---|---|---|---|
| Internet (WAN) | `eth1` | **None** | hostile by default |
| Guest | `eth2.30` - 10.50.30.0/24 | **Untrusted** | visitors, unmanaged devices: Internet only |
| DMZ | `eth2.60` - 10.50.60.0/24 | **Low** | exposed services (FTP 10.50.60.40): assumed compromisable |
| Office | `eth2.10` - 10.50.10.0/24 | **Medium** | managed workstations |
| Finance | `eth2.20` - 10.50.20.0/24 | **Medium/High** | sensitive users and data |
| Database | `eth2.50` - 10.50.50.0/24 | **High** | crown jewels: nothing enters by default |
| VPN Finance | `wg0` - 10.8.0.100-149 | **Restricted** | authenticated users, FTP only |
| VPN Admins | `wg0` - 10.8.0.10-19 | **High** | authenticated IT, only management path |
| Gateway itself | all interfaces | **Highest** | the enforcement point: management only from VPN Admins |

The principle is that **trust is never inherited from the network location**. Each flow between zones must be explicitly allowed.

### Traffic flow restrictions

All three chains (`input`, `forward`, `output`) have a **default DROP policy**. Only these flows are allowed:

| From | To | Allowed | Everything else |
|---|---|---|---|
| Internet | Gateway | WireGuard 51820/udp only | dropped, 21/22 logged |
| VPN Admins | Gateway | SSH (key-only, no root) | dropped |
| VPN Finance | DMZ FTP server | 21 + 30000-30100 to 10.50.60.40 only | dropped, SSH attempts logged |
| Office, Finance, Guest | Internet | HTTPS 443, DNS 53 (with NAT) | dropped and logged |
| Guest | Office, Finance, DB, DMZ | **nothing** | dropped and logged |
| DMZ | anywhere | **cannot initiate any connection** | dropped and logged |
| Any zone | Database | **nothing until the authorized sources are confirmed** | dropped and logged |
| Gateway | Internet | DNS, NTP, HTTP/HTTPS (updates) only | dropped and logged (egress filtering) |

Database access is deliberately closed until LogiCorp confirms the authorized source systems, service and port. Adding them is a single explicit rule (source zone → DB host:port), never a subnet-wide opening. Systems inside the Database VLAN keep communicating directly (layer 2), so they are not affected by this.

### How the attack path is now blocked

The audit showed a gateway that was both **easy to enter** and **free to move through**:

| Step of the previous attack path | Weakness found in the audit | What blocks it now |
|---|---|---|
| 1. Initial access | SSH open with `PermitRootLogin yes` and `PasswordAuthentication yes`; the root password was recovered | SSH dropped on the WAN; only reachable from VPN Admins; `PermitRootLogin no`, key-only authentication |
| 2. Credential theft | Cleartext FTP (`vsftpd` on `*:21`), legacy `inetd` and `telnetd` installed | FTP only inside WireGuard; telnet and inetd purged; legacy services masked |
| 3. Privilege | Direct root login on the gateway | No root login; root password lock once a named sudo admin exists |
| 4. Lateral movement | The compromised gateway could reach every internal zone | Forward chain default DROP: each zone pair must be explicitly allowed; Guest and DMZ cannot reach internal zones; Database closed |
| 5. Exfiltration / C2 | Unrestricted outbound traffic | Output chain default DROP: the gateway only talks DNS, NTP and HTTP(S) |
| 6. Persistence unnoticed | No regression checks | Drops logged with prefixes (`FW-*`); `tests.sh` fails on any unexpected ACCEPT rule or restarted service |

Even if an attacker compromises a host (for example the FTP server in the DMZ, or a guest device), **the next hop is denied by default**. Lateral movement now requires breaking the gateway itself, which no longer exposes anything to the WAN except WireGuard.

### Defense in depth principles applied

| Layer | Control |
|---|---|
| Perimeter | WAN default deny, a single exposed port (WireGuard, which does not answer unauthenticated packets) |
| Identity | WireGuard per-user keys, SSH keys, no root login, no shared accounts |
| Segmentation | VLAN zones + forward default deny + per-role VPN ranges |
| Host | unnecessary services removed or masked, kernel hardening (anti-spoofing, no redirects, SYN cookies), password policy, no core dumps |
| Egress | output default deny on the gateway |
| Detection | logged drops with explicit prefixes, FTP transfer logs |
| Assurance | `tests.sh` regression checks after every change; `panic_button.sh` for safe changes |

No single control is trusted alone: a mistake in one layer (for example a too broad rule) is caught by another (the identity check, or the allow-list in `tests.sh`).

---

## Challenge 3: Resilience

> *"The Gateway is still a Single Point of Failure. What happens if it goes down?"*

### Scope acknowledgment

High availability was **out of scope** for this engagement, which covered auditing the gateway, designing its security, enforcing it and validating it. We agree that the gateway is a Single Point of Failure, and we document it here as an **accepted, known risk** rather than an oversight.

### Current risk exposure

If the gateway goes down:

| Service | Impact |
|---|---|
| Internet access for all VLANs | **lost** (no routing, no NAT) |
| Inter-VLAN traffic (Office → DMZ, etc.) | **lost** |
| VPN: IT remote administration and Finance FTP | **lost** |
| DHCP for Office, Finance and Guest | new leases fail; existing leases keep working until they expire |
| Traffic inside a single VLAN | **unaffected** (switched, not routed) |
| Security posture | **not degraded**: a gateway that is down blocks traffic, it does not open it ("fail-closed") |

**Current recovery capability:** the whole configuration is code (`clean.sh`, `firewall.sh`, `vpn_setup.sh`) and is validated by `tests.sh`. A replacement host can be rebuilt by running the scripts in order. Two things must be backed up **offline and encrypted**, or every VPN client must receive a new configuration: the WireGuard keys (`/etc/wireguard/keys`) and the client list.

### High-level Phase 2 plan for HA

| Step | Action |
|---|---|
| 1 | **Second gateway** (active/passive), built with the same scripts. The infrastructure-as-code approach makes both nodes identical by design. |
| 2 | **VRRP with keepalived**: virtual IPs on the WAN and on each VLAN. Hosts keep the same default gateway when the backup takes over. |
| 3 | **conntrackd**: synchronizes the connection states, so established sessions survive a failover. |
| 4 | **WireGuard on the virtual IP**, with the same server keys on both nodes: clients reconnect without any change. |
| 5 | **DHCP failover** (Kea HA or ISC failover). |
| 6 | **Monitoring and alerting** on both nodes; `tests.sh` run on both after every change; failover tested every quarter. |
| 7 | Optional: second WAN uplink and redundant switches, to remove the remaining single points. |

### Cost-benefit analysis

| | Option A: accept the risk + fast rebuild | Option B: active/passive HA |
|---|---|---|
| Investment | spare host (cold standby) + offline backup of keys | second gateway, extra switch ports, about 3-5 days of engineering |
| Running cost | quarterly rebuild test | maintenance of 2 nodes, failover tests, monitoring |
| Recovery time | **hours** (rebuild with the scripts) | **seconds** (VRRP failover) |
| Complexity added | low | medium (state sync, split-brain risk to manage) |

**Decision rule** (annualized loss expectancy):

```
Annual cost of outages  = expected outages per year × outage duration (hours) × cost of one hour of downtime
HA is justified if       : (annual cost of outages without HA − with HA) > annual cost of the HA solution
```

The cost of one hour of downtime must come from LogiCorp: lost logistics operations, delayed payments, SLA penalties. As soon as one hour of outage costs more than a few days of engineering plus one appliance per year, Option B pays for itself. For a logistics company whose operations and finance flows depend on this gateway, this is very likely.

**Recommendation:** apply Option A immediately, since it costs almost nothing (offline key backup, spare host, documented rebuild). Then budget Option B in Phase 2, together with the SFTP migration.
