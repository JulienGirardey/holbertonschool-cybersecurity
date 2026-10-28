# Gap Analysis Report — LogiCorp Gateway Remediation

## 1. Executive Summary

LogiCorp's network currently has no internal barriers: a single unprotected gateway exposes administrative access to the entire Internet, and the critical shipping database sits on the same network as guest Wi-Fi devices. Combined with invoices and passwords travelling unencrypted over the Internet, this means one compromised device or stolen password can lead directly to the company's most critical data. We recommend an immediate containment phase this week, followed by network segmentation and encrypted remote access, all of which can be delivered without changing the legacy accounting software.

---
<br>

## 2. Current State Assessment

### 2.1 What the documentation tells us

Current State

- Single Linux Gateway (`eth0` WAN, `eth1` LAN) behind a modem, one switch serving all devices
- Flat network, single subnet `192.168.1.x`
- None. Office PC, Finance PC, Guest Wi-Fi and critical Database share the same L2 segment
- No firewall active
- SSH exposed to the whole Internet, root login enabled
- Cleartext FTP used by remote Accounting staff to upload invoices; client software cannot be changed
- Single point of failure (out of scope)
- None; the existing diagram is considered unreliable
- Security incident last week; contained but impact unknown
- No dedicated security administrator for ~10 years; organic growth


### 2.2 Documentation reliability

The As-Is diagram was drawn by a former intern and is flagged as likely inaccurate. The following points are **unverified** and must be confirmed on the live system:

- Whether the modem operates in bridge mode or performs routing/NAT itself (potential double NAT or bypass path).
- Whether the Wi-Fi access point is actually behind the gateway, or connected to the modem directly.
- The number of physical interfaces on the gateway and whether the switch supports VLANs (802.1Q).
- Where the FTP server runs (on the gateway itself or on an internal host).
- Which hosts and ports actually use the Database.
- Whether undocumented services, port forwards or devices exist.

---
<br>

## 3. Critical Gaps Identified

### 3.1 Network Architecture Gaps

|  | Current State | Gap / Risk |
|----|---|---|
| **NET-01** | Flat network, all devices in `192.168.1.x` | Any compromised device can reach every other device, including the Database (lateral movement). |
| **NET-02** | Guest Wi-Fi on the same segment as business systems | Untrusted, unmanaged devices have direct network access to the critical Database. |
| **NET-03** | Critical Database reachable by every host | The client's core business asset is not isolated, contrary to the CEO's explicit requirement. |
| **NET-04** | No DMZ; publicly needed services (e.g. FTP) hosted inside the LAN or on the gateway | Compromise of an exposed service gives immediate access to the internal network. |
| **NET-05** | No reliable documentation or asset inventory | Changes cannot be planned safely; high risk of breaking production or missing a hidden path. |
| **NET-06** | Single gateway, single point of failure | Accepted risk for this engagement; to be documented and revisited. |

### 3.2 Access Control Gaps

|  | Current State | Gap / Risk |
|----|---|---|
| **ACC-01** | No firewall active | Every service on every host is reachable; no control over traffic between zones or from the Internet. |
| **ACC-02** | SSH open to the entire Internet | Permanent exposure to brute-force and exploitation attempts; probable initial access vector of last week's incident. |
| **ACC-03** | Root login over SSH enabled | No accountability; a single password compromise grants full control of the gateway. |
| **ACC-04** | Authentication method unknown (password auth assumed) | Credentials can be guessed or reused. |
| **ACC-05** | Remote Accounting staff reach FTP directly from the Internet | FTP service exposed to the whole Internet. |
| **ACC-06** | No integrity verification after the incident | Attacker persistence (backdoor accounts, SSH keys, cron jobs, modified binaries) may still be present. Hardening a compromised host is not sufficient. |

### 3.3 Encryption Gaps

|  | Current State | Gap / Risk |
|---|---|---|
| **ENC-01** | FTP in cleartext over the Internet | Accounting credentials and invoices (financial data) can be intercepted and replayed. |
| **ENC-02** | No VPN for remote users or administrators | No encrypted, authenticated entry point into the network. |
| **ENC-03** | Database traffic encryption unknown | Internal interception possible, aggravated by the flat network and guest access. |

### 3.4 Monitoring Gaps

|  | Current State | Gap / Risk |
|---|---|---|
| **MON-01** | No firewall, therefore no traffic logs | Attacks and policy violations are invisible. |
| **MON-02** | No evidence of authentication log review | Brute force and unauthorised access are not detected. |
| **MON-03** | No centralised or off-box logging | Logs stored only on the gateway can be erased by an attacker who compromises it. |
| **MON-04** | No alerting or intrusion detection | Last week's incident may have gone unnoticed for a long period; recurrence would too. |
| **MON-05** | Incident scope and root cause unknown | Unknown what was accessed or exfiltrated; lessons cannot be applied. |

---
<br>

## 4. Risk Matrix

Severity combines **likelihood** (how easily the gap can be exploited) and **impact** (consequence for LogiCorp's business).

![alt text](Risk_matrix.png)


---
<br>

## 5. Preliminary Recommendations

Recommendations are phased to respect the constraint **"Do NOT break production"** and the end-of-week deployment.

### Phase 0: Containment & Discovery

1. **Verify gateway integrity**: review user accounts, `authorized_keys`, cron jobs, running services, listening ports and recently modified files. If compromise is confirmed or cannot be excluded, plan a **rebuild** rather than hardening.
2. **Rotate all credentials** (root, user accounts, FTP accounts, Database accounts).
3. **Map real traffic flows** (listening services, active connections, captures) to build a flow matrix of what production actually needs.
4. **Correct the As-Is diagram** with verified data (modem mode, Wi-Fi placement, interfaces, VLAN support).
5. **Back up the current configuration** and define a **rollback plan** and maintenance window.

### Phase 1: Quick Wins (low risk to production)

1. **Harden SSH**: disable root login, enforce key-only authentication, install brute-force protection, restrict source IPs.
2. **Enable logging** of authentication events and forward logs off the gateway.

### Phase 2: Perimeter Firewall (end of week deployment)

1. Deploy a **stateful firewall** with **Default Deny** on INPUT and FORWARD.
2. Allow only flows identified in the flow matrix, plus return traffic (`ESTABLISHED,RELATED`).
3. Run new rules in **log mode before drop mode** where possible to catch missed legitimate flows.
4. Handle FTP specifics (passive-mode port range or FTP connection tracking helper).

### Phase 3: Secure Remote Access

1. Deploy a **VPN** (WireGuard or OpenVPN) on the gateway.
2. Accounting staff connect to the VPN, then use their **unchanged FTP client** through the encrypted tunnel. The legacy software is untouched, the business constraint is respected, and FTP is no longer exposed to the Internet.
3. Administrative SSH is reachable **only from the VPN**.
4. If the legacy client supports **FTPS**, enable it as defence in depth.

### Phase 4: Network Segmentation

1. Create separate zones (via VLANs or additional interfaces, depending on hardware):
   - **LAN — Office / Finance**
   - **Restricted — Database**, reachable only by authorised hosts on its service port
   - **Guest Wi-Fi**, Internet access only
   - **DMZ**, only if a service genuinely needs public exposure
2. Apply inter-zone rules following least privilege.

### Phase 5: Monitoring & Governance

1. Centralised logging and basic alerting on failed logins and denied traffic.
2. Maintain network documentation, flow matrix and change log.
3. Formal post-incident review; plan for redundancy (currently out of scope).

