#!/bin/bash
# tests.sh - Compliance check of the LogiCorp Gateway (security as code)
#
# Automated regression tests of the hardening (clean.sh, vpn_setup.sh, firewall.sh).
#   sudo ./tests.sh    Full check
#   ./tests.sh         Checks that need root are reported as [SKIP]
# Exit code: 0 if every check passed, 1 otherwise (usable in CI / after each change).

set -u

# --- Expected state (aligned with HARDENING/firewall.sh and vpn_setup.sh) -----
WAN="eth1"
VPN="wg0"
WG_PORT="51820"
WG_ADDR="10.8.0.1/24"
VPN_NET="10.8.0.0/24"
VPN_ADMINS="10.8.0.10-10.8.0.19"
VPN_ACCOUNTANTS="10.8.0.100-10.8.0.149"
FTP_HOST="10.50.60.40"
FW_TABLE="logicorp"

# VLAN interface, subnet, expected gateway address prefix
VLANS=(
    "eth2.10 10.50.10.0/24 10.50.10."
    "eth2.20 10.50.20.0/24 10.50.20."
    "eth2.30 10.50.30.0/24 10.50.30."
    "eth2.50 10.50.50.0/24 10.50.50."
    "eth2.60 10.50.60.0/24 10.50.60."
)

# Accounts allowed to use sudo, space separated (override: EXPECTED_SUDO_USERS="a b")
EXPECTED_SUDO_USERS="${EXPECTED_SUDO_USERS:-}"
# The gateway routes the VLANs and the VPN: forwarding is required
REQUIRE_FORWARDING=1
# FTP is served by the DMZ server: the gateway must not run its own FTP
GATEWAY_FTP="${GATEWAY_FTP:-no}"

UNNECESSARY_SVCS=(inetd avahi-daemon cups cups-browsed bluetooth rpcbind nfs-server smbd nmbd snmpd)
LEGACY_PKGS=(openbsd-inetd inetutils-inetd xinetd telnetd inetutils-telnetd rsh-server rsh-redone-server nis talkd)

# Every ACCEPT rule of the firewall must match one of these patterns (firewall.sh)
EXPECTED_ACCEPT=(
    'ct state established,related accept'
    'iifname "lo" accept'
    'oifname "lo" accept'
    'ip protocol icmp accept'
    'meta l4proto ipv6-icmp accept'
    "iifname \"$WAN\" udp dport $WG_PORT accept"
    "iifname \"$VPN\" ip saddr ${VPN_ADMINS//./\\.} tcp dport 22 ct state new accept"
    'udp sport 68 udp dport 67 accept'
    'udp sport 67 udp dport 68 accept'
    "ip saddr ${VPN_ACCOUNTANTS//./\\.} .*ip daddr ${FTP_HOST//./\\.} tcp dport .* ct state new accept"
    "oifname \"$WAN\" tcp dport 443 ct state new accept"
    "oifname \"$WAN\" (udp|tcp) dport 53 (ct state new )?accept"
    "oifname \"$WAN\" udp dport 123 accept"
    "oifname \"$WAN\" tcp dport \\{ 80, 443 \\} accept"
)

# --- Output helpers -----------------------------------------------------------
PASSED=0
TOTAL=0
SKIPPED=0
if [ -t 1 ]; then
    GREEN=$'\e[32m'; RED=$'\e[31m'; YELLOW=$'\e[33m'; RESET=$'\e[0m'
else
    GREEN=""; RED=""; YELLOW=""; RESET=""
fi

pass() { PASSED=$((PASSED + 1)); TOTAL=$((TOTAL + 1)); echo "${GREEN}[PASS]${RESET} $*"; }
fail() { TOTAL=$((TOTAL + 1)); echo "${RED}[FAIL]${RESET} $*"; }
skip() { SKIPPED=$((SKIPPED + 1)); echo "${YELLOW}[SKIP]${RESET} $* (needs root)"; }
section() { echo; echo "=== $* ==="; }

# check <pass message> <fail message> <command...>
check() {
    local ok_msg="$1" ko_msg="$2"
    shift 2
    if "$@" >/dev/null 2>&1; then
        pass "$ok_msg"
    else
        fail "$ko_msg"
    fi
}

IS_ROOT=0
[ "$EUID" -eq 0 ] && IS_ROOT=1

# --- Firewall status ----------------------------------------------------------
section "Firewall"

check "nftables enabled at boot" "Expected nftables to be enabled at boot" \
    systemctl is-enabled --quiet nftables

if [ "$IS_ROOT" -eq 1 ] && command -v nft >/dev/null 2>&1; then
    RULESET="$(nft list table inet "$FW_TABLE" 2>/dev/null)"
    NAT_RULESET="$(nft list table ip nat 2>/dev/null)"

    # chain_policy <chain>: policy of a base chain of the LogiCorp table
    chain_policy() {
        printf '%s\n' "$RULESET" | awk -v c="$1" '
            $1 == "chain" && $2 == c { found = 1 }
            found && match($0, /policy [a-z]+/) { print substr($0, RSTART + 7, RLENGTH - 7); exit }'
    }
    for chain in input forward output; do
        policy="$(chain_policy "$chain")"
        if [ "$policy" = "drop" ]; then
            pass "Firewall default ${chain^^} policy is DROP"
        else
            fail "Firewall default ${chain^^} policy is '${policy:-missing}', expected DROP"
        fi
    done

    has_rule() { printf '%s\n' "$RULESET" | grep -qE "$1"; }
    check "WireGuard $WG_PORT/udp allowed on $WAN" "Expected rule: WireGuard $WG_PORT/udp on $WAN" \
        has_rule "iifname \"$WAN\" udp dport $WG_PORT accept"
    check "SSH to the gateway allowed only from VPN admins" "Expected rule: SSH from VPN admins on $VPN" \
        has_rule "iifname \"$VPN\" ip saddr ${VPN_ADMINS//./\\.} tcp dport 22 .*accept"
    check "SSH and FTP dropped from the WAN" "Expected rule: drop 21/22 from $WAN" \
        has_rule "iifname \"$WAN\" tcp dport \\{ 21, 22 \\} drop"
    check "Finance VPN allowed to the FTP server $FTP_HOST" "Expected rule: VPN accountants -> $FTP_HOST" \
        has_rule "ip saddr ${VPN_ACCOUNTANTS//./\\.} .*ip daddr ${FTP_HOST//./\\.} tcp dport .*accept"
    check "NAT masquerade on $WAN" "Expected NAT masquerade rule on $WAN" \
        grep -qE "oifname \"$WAN\" .*masquerade" <<< "$NAT_RULESET"

    # Any ACCEPT rule that does not match the expected list is a finding
    UNEXPECTED=""
    ACCEPT_COUNT=0
    while IFS= read -r rule; do
        [ -z "$rule" ] && continue
        ACCEPT_COUNT=$((ACCEPT_COUNT + 1))
        matched=0
        for pattern in "${EXPECTED_ACCEPT[@]}"; do
            if grep -qE "$pattern" <<< "$rule"; then
                matched=1
                break
            fi
        done
        [ "$matched" -eq 0 ] && UNEXPECTED="$UNEXPECTED"$'\n'"       -> $rule"
    done < <(printf '%s\n' "$RULESET" | grep -E '(^|[[:space:]])accept([[:space:]]|$)' \
                | grep -v 'policy accept' | sed -E 's/^[[:space:]]+//')

    if [ "$ACCEPT_COUNT" -eq 0 ]; then
        fail "No ACCEPT rule found: is the '$FW_TABLE' table loaded?"
    elif [ -z "$UNEXPECTED" ]; then
        pass "No unexpected ACCEPT rules ($ACCEPT_COUNT reviewed)"
    else
        fail "Unexpected ACCEPT rules found:$UNEXPECTED"
    fi
else
    for c in "default policies are DROP" "required rules exist" "no unexpected ACCEPT rules"; do
        skip "Firewall: $c"
    done
fi

# --- Service status -----------------------------------------------------------
section "Services"

# Effective SSH settings: sshd -T (root), else the first active line of the config
SSHD_T=""
[ "$IS_ROOT" -eq 1 ] && SSHD_T="$(sshd -T 2>/dev/null)"

# sshd_value <option> <default>
sshd_value() {
    local value=""
    if [ -n "$SSHD_T" ]; then
        value="$(awk -v k="${1,,}" '$1 == k {print $2; exit}' <<< "$SSHD_T")"
    else
        value="$(grep -hiE "^\s*$1\s" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
            | head -n 1 | awk '{print tolower($2)}')"
    fi
    echo "${value:-$2}"
}

check "SSH service is running" "Expected SSH service to be running" \
    pgrep -x sshd
check "SSH is listening on port 22" "Expected SSH to listen on port 22" \
    grep -q LISTEN <<< "$(ss -ltn 'sport = :22')"

MAX_TRIES="$(sshd_value MaxAuthTries 6)"
if [ "$MAX_TRIES" -le 3 ] 2>/dev/null; then
    pass "SSH MaxAuthTries is $MAX_TRIES"
else
    fail "SSH MaxAuthTries is $MAX_TRIES, expected 3 or less"
fi
check "SSH empty passwords refused" "Expected PermitEmptyPasswords no" \
    test "$(sshd_value PermitEmptyPasswords no)" = "no"
check "SSH X11 forwarding disabled" "Expected X11Forwarding no" \
    test "$(sshd_value X11Forwarding no)" = "no"

check "VPN interface $VPN is UP" "Expected VPN interface $VPN to be UP" \
    grep -qE '[<,]UP[,>]' <<< "$(ip -o link show "$VPN" 2>/dev/null)"
check "VPN starts at boot (wg-quick@$VPN)" "Expected wg-quick@$VPN to be enabled at boot" \
    systemctl is-enabled --quiet "wg-quick@$VPN"
if [ "$IS_ROOT" -eq 1 ] && command -v wg >/dev/null 2>&1; then
    check "VPN accepting connections on $WG_PORT/udp" "Expected $VPN to listen on $WG_PORT/udp" \
        test "$(wg show "$VPN" listen-port 2>/dev/null)" = "$WG_PORT"
    PEERS="$(wg show "$VPN" peers 2>/dev/null | grep -c .)"
    if [ "$PEERS" -ge 1 ]; then
        pass "VPN has $PEERS client(s) configured"
    else
        fail "Expected at least one VPN client configured on $VPN"
    fi
else
    check "VPN accepting connections on $WG_PORT/udp" "Expected a UDP listener on $WG_PORT" \
        grep -q ":$WG_PORT" <<< "$(ss -lun "sport = :$WG_PORT")"
    skip "VPN clients configured"
fi

for svc in "${UNNECESSARY_SVCS[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        fail "Expected service '$svc' to be stopped"
    elif systemctl list-unit-files "$svc.service" --no-legend 2>/dev/null | grep -q .; then
        pass "Unnecessary service '$svc' is stopped"
    fi
done

if [ "$GATEWAY_FTP" = "no" ]; then
    check "Gateway FTP stopped (FTP served by the DMZ)" "Expected service 'vsftpd' to be stopped" \
        test "$(systemctl is-active vsftpd 2>/dev/null)" != "active"
fi

INSTALLED=""
for pkg in "${LEGACY_PKGS[@]}"; do
    dpkg -s "$pkg" >/dev/null 2>&1 && INSTALLED="$INSTALLED $pkg"
done
if [ -z "$INSTALLED" ]; then
    pass "No legacy cleartext service installed (telnet, rsh, inetd...)"
else
    fail "Legacy packages still installed:$INSTALLED"
fi
check "Nothing listening on telnet port 23" "Expected no listener on port 23 (telnet)" \
    test -z "$(ss -ltnH 'sport = :23')"

# --- Access control -----------------------------------------------------------
section "Access control"

ROOT_LOGIN="$(sshd_value PermitRootLogin prohibit-password)"
check "SSH root login disabled" "SSH root login is '$ROOT_LOGIN', expected 'no'" \
    test "$ROOT_LOGIN" = "no"

PASSWORD_AUTH="$(sshd_value PasswordAuthentication yes)"
KBD_AUTH="$(sshd_value KbdInteractiveAuthentication yes)"
PUBKEY_AUTH="$(sshd_value PubkeyAuthentication yes)"
if [ "$PASSWORD_AUTH" = "no" ] && [ "$KBD_AUTH" = "no" ] && [ "$PUBKEY_AUTH" = "yes" ]; then
    pass "Only key-based SSH authentication allowed"
else
    fail "Key-only SSH not enforced (Password=$PASSWORD_AUTH, KbdInteractive=$KBD_AUTH, Pubkey=$PUBKEY_AUTH)"
fi

check "Only root has UID 0" "Accounts other than root have UID 0" \
    test "$(awk -F: '$3 == 0 {print $1}' /etc/passwd)" = "root"

# Members of the admin groups vs the expected list
SUDO_MEMBERS="$(for g in sudo admin wheel; do getent group "$g" | cut -d: -f4; done \
    | tr ',' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/ $//')"
EXPECTED_SORTED="$(printf '%s\n' $EXPECTED_SUDO_USERS | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/ $//')"
if [ "$SUDO_MEMBERS" = "$EXPECTED_SORTED" ]; then
    pass "Correct users have sudo access (${SUDO_MEMBERS:-none})"
else
    fail "Sudo members are '${SUDO_MEMBERS:-none}', expected '${EXPECTED_SORTED:-none}'"
fi

if [ "$IS_ROOT" -eq 1 ]; then
    # User rules written directly in the sudoers files (outside the groups)
    SUDOERS_USERS="$(grep -hE '^[[:space:]]*[^#%@[:space:]]' /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
        | awk '$1 != "Defaults" && $1 != "root" && $1 !~ /_Alias$/ {print $1}' | sort -u | tr '\n' ' ')"
    UNEXPECTED_SUDOERS=""
    for user in $SUDOERS_USERS; do
        [[ " $EXPECTED_SUDO_USERS " == *" $user "* ]] || UNEXPECTED_SUDOERS="$UNEXPECTED_SUDOERS $user"
    done
    check "No unexpected user rule in sudoers" "Unexpected sudoers entries:$UNEXPECTED_SUDOERS" \
        test -z "$UNEXPECTED_SUDOERS"
    check "No account with an empty password" "Accounts with an empty password found" \
        test -z "$(awk -F: '$2 == "" {print $1}' /etc/shadow)"
else
    skip "No unexpected user rule in sudoers"
    skip "No account with an empty password"
fi

# --- Network configuration ----------------------------------------------------
section "Network"

if [ "$REQUIRE_FORWARDING" -eq 1 ]; then
    check "IP forwarding is enabled" "Expected IP forwarding enabled (gateway)" \
        test "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1"
fi

check "$WAN has an IPv4 address" "Expected an IPv4 address on $WAN" \
    grep -q 'inet ' <<< "$(ip -4 -o addr show dev "$WAN" 2>/dev/null)"
check "$VPN has address $WG_ADDR" "Expected address $WG_ADDR on $VPN" \
    grep -qF "inet $WG_ADDR" <<< "$(ip -4 -o addr show dev "$VPN" 2>/dev/null)"
for vlan in "${VLANS[@]}"; do
    read -r iface net prefix <<< "$vlan"
    check "$iface has an address in $net" "Expected an address in $net on $iface" \
        grep -qF "inet $prefix" <<< "$(ip -4 -o addr show dev "$iface" 2>/dev/null)"
done

check "Default route goes through $WAN" "Expected the default route via $WAN" \
    grep -q "dev $WAN" <<< "$(ip -4 route show default)"
check "Route to the VPN $VPN_NET via $VPN" "Expected route $VPN_NET via $VPN" \
    grep -q "dev $VPN" <<< "$(ip -4 route show "$VPN_NET")"
for vlan in "${VLANS[@]}"; do
    read -r iface net prefix <<< "$vlan"
    check "Route to $net via $iface" "Expected route $net via $iface" \
        grep -q "dev $iface" <<< "$(ip -4 route show "$net")"
done

# --- Result -------------------------------------------------------------------
echo
echo "RESULT: $PASSED/$TOTAL checks passed"
[ "$SKIPPED" -gt 0 ] && echo "        $SKIPPED checks skipped: run with sudo for a full check"
[ "$PASSED" -eq "$TOTAL" ]
