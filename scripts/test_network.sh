#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Ingot — V6 Networking Interop Suite (Plan Phase 6: 6.1 IPAM, 6.2 live
# connect/disconnect, 6.3 aliases + internal networks, 6.4 ports,
# 6.5 DNS options)
# Requires the root daemon on /run/ingot/ingot.sock. Leaves zero residue:
# no containers, no test networks, no leases, no veths.
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }
info() { echo -e "${BLUE}==>${NC} ${BOLD}$1${NC}"; }
warn() { echo -e "${YELLOW}WARN:${NC} $1"; }
fail() { echo -e "${RED}✗ FAIL:${NC} $1"; exit 1; }

DOCKER_BIN="${DOCKER_BIN:-/tmp/dk}"
[ -x "$DOCKER_BIN" ] || fail "Docker CLI wrapper not found at $DOCKER_BIN"

LEASES=/var/lib/ingot/ipam-leases.json
leases() { python3 -c "import json; print(sum(len(v) for v in json.load(open('$LEASES'))['allocated'].values()))"; }
buckets() { python3 -c "import json; print(len(json.load(open('$LEASES'))['allocated']))"; }
veths() { ip -o link show | grep -c "veth-" || true; }

cleanup() {
    $DOCKER_BIN rm -f v6-a v6-b v6-c v6-int v6-ctl v6-dup >/dev/null 2>&1 || true
    $DOCKER_BIN rm -f v6-p v6-q v6-lo v6-all >/dev/null 2>&1 || true
    $DOCKER_BIN rm -f v6-dns v6-dnsb v6-reg v6-srch V6-Upper >/dev/null 2>&1 || true
    $DOCKER_BIN rm -f v6-r >/dev/null 2>&1 || true
    $DOCKER_BIN network rm v6t v6int v6x v6rmv >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "======================================================================"
echo " Ingot V6 Networking Suite (Phases 6.1 – 6.5)"
echo "======================================================================"

# --- 6.1: baseline hygiene -------------------------------------------------
[ "$(leases)" = "0" ] || fail "6.1: expected 0 leases at baseline, got $(leases)"

# --- fixtures ---------------------------------------------------------------
$DOCKER_BIN network create --subnet 10.89.0.0/24 v6t >/dev/null
$DOCKER_BIN network create --subnet 10.90.0.0/24 --internal v6int >/dev/null
$DOCKER_BIN run -d --name v6-a --network v6t --network-alias webalias busybox:latest sleep 120 >/dev/null
$DOCKER_BIN run -d --name v6-b --network v6t --ip 10.89.0.50 busybox:latest sleep 120 >/dev/null

# --- 6.3: create-time alias resolves ----------------------------------------
if $DOCKER_BIN exec v6-b nslookup webalias 2>/dev/null | grep -q "10.89.0."; then
    pass "6.3: create-time --network-alias resolves between containers"
else
    fail "6.3: create-time alias webalias did not resolve"
fi

# --- 6.3: create-time static IP honored --------------------------------------
if $DOCKER_BIN exec v6-b ip addr show | grep -q "inet 10.89.0.50/"; then
    pass "6.3: create-time --ip honored on first start"
else
    fail "6.3: static IP 10.89.0.50 not configured"
fi

# --- 6.3: duplicate static IP fails closed at start --------------------------
if $DOCKER_BIN run -d --name v6-dup --network v6t --ip 10.89.0.50 busybox:latest sleep 5 >/dev/null 2>&1; then
    $DOCKER_BIN rm -f v6-dup >/dev/null 2>&1 || true
    fail "6.3: duplicate static IP started (expected start failure)"
else
    $DOCKER_BIN rm -f v6-dup >/dev/null 2>&1 || true
    pass "6.3: duplicate static IP refused at start"
fi

# --- 6.3: same-bridge L2 stays local ------------------------------------------
A_IP=$($DOCKER_BIN exec v6-a ip -o -4 addr show eth0 | awk '{print $4}' | cut -d/ -f1)
if $DOCKER_BIN exec v6-b ping -c1 -W2 "$A_IP" >/dev/null 2>&1; then
    pass "6.3: same-bridge container-to-container reachability"
else
    fail "6.3: same-bridge ping to $A_IP failed"
fi

# --- 6.3: internal network egress denial --------------------------------------
$DOCKER_BIN run -d --name v6-int --network v6int busybox:latest sleep 120 >/dev/null
$DOCKER_BIN run -d --name v6-ctl --network v6t busybox:latest sleep 120 >/dev/null
# intra-network still works on internal
if $DOCKER_BIN exec v6-int ping -c1 -W2 10.90.0.1 >/dev/null 2>&1; then
    pass "6.3: internal network gateway reachable (bridge-local)"
else
    fail "6.3: internal gateway unreachable"
fi
# control proves the external target is reachable without containment
if $DOCKER_BIN exec v6-ctl ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
    if $DOCKER_BIN exec v6-int ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
        fail "6.3: internal container reached external IP (egress not denied)"
    else
        pass "6.3: internal container cannot reach external IP"
    fi
else
    warn "6.3: no external route from control container; external-egress proof skipped"
fi
# rule-level proof (environment-independent): no MASQUERADE for the
# internal subnet, DROP guards on its bridge.
INT_BR=$(ip -o -4 addr show | grep "10.90.0.1/" | awk '{print $2}' | head -1)
[ -n "$INT_BR" ] || fail "6.3: internal bridge address missing"
if sudo iptables -t nat -S POSTROUTING | grep -q "10.90.0.0/24"; then
    fail "6.3: MASQUERADE present for internal subnet"
else
    pass "6.3: no MASQUERADE for internal subnet"
fi
# NOTE: iptables canonicalizes negation order (`-o br ! -i br` is
# stored as `! -i br -o br`), so match the canonical display form.
# Reads can also lose a transient race with the daemon's concurrent
# writes (xtables lock): retry briefly. A genuinely absent rule still
# fails after the retries.
forward_has() {
    sudo iptables -S FORWARD | grep -q "\-i $INT_BR ! \-o $INT_BR \-j DROP" \
    && sudo iptables -S FORWARD | grep -q "! \-i $INT_BR \-o $INT_BR \-j DROP"
}
FOUND=0
for _ in $(seq 1 10); do
    if forward_has 2>/dev/null; then FOUND=1; break; fi
    sleep 0.2
done
if [ "$FOUND" = "1" ]; then
    pass "6.3: FORWARD containment rules present for internal bridge ($INT_BR)"
else
    fail "6.3: FORWARD containment rules missing for $INT_BR"
fi
# internal DNS still resolves member names
if $DOCKER_BIN exec v6-int nslookup v6-int 2>/dev/null | grep -q "10.90.0."; then
    pass "6.3: internal network name resolution works"
else
    fail "6.3: internal DNS failed"
fi
$DOCKER_BIN rm -f v6-int v6-ctl >/dev/null

# --- 6.2: live connect/disconnect roundtrip ------------------------------------
$DOCKER_BIN network connect --alias extra v6t v6-a 2>/dev/null && fail "6.2: duplicate connect accepted" || true
pass "6.2: duplicate connect rejected"
if $DOCKER_BIN stop v6-a >/dev/null && $DOCKER_BIN network connect v6t v6-a 2>/dev/null; then
    fail "6.2: connect to stopped container accepted"
else
    pass "6.2: connect to stopped container rejected"
fi
$DOCKER_BIN start v6-a >/dev/null
$DOCKER_BIN network create --subnet 10.91.0.0/24 v6x >/dev/null
$DOCKER_BIN network connect --alias extra v6x v6-a >/dev/null
[ "$($DOCKER_BIN exec v6-a ip addr show | grep -c 'inet 10.91')" = "1" ] \
    || fail "6.2: second endpoint missing eth address"
# Alias resolves for members of its own network (v6x-primary container)…
$DOCKER_BIN run -d --name v6-c --network v6x busybox:latest sleep 120 >/dev/null
$DOCKER_BIN exec v6-c nslookup extra 2>/dev/null | grep -q "10.91" \
    || fail "6.2: alias not resolvable on its own network"
pass "6.2: alias resolves on its own network"
# …and stays invisible to outsiders (v6-b is on v6t only).
$DOCKER_BIN exec v6-b nslookup extra 2>/dev/null | grep -q "10.91" \
    && fail "6.2: alias leaked across networks" || pass "6.2: alias scoped to its network"
$DOCKER_BIN rm -f v6-c >/dev/null
BEFORE=$(leases)
$DOCKER_BIN network disconnect v6x v6-a >/dev/null
[ "$($DOCKER_BIN exec v6-a ip addr show | grep -c 'inet 10.91')" = "0" ] \
    || fail "6.2: disconnect left the address configured"
[ "$(leases)" = "$((BEFORE - 1))" ] \
    || fail "6.2: disconnect did not release exactly one lease"
pass "6.2: live connect/disconnect roundtrip with lease release"

# --- 6.2: restart rewires, keeps static IP --------------------------------------
$DOCKER_BIN stop v6-b >/dev/null && $DOCKER_BIN start v6-b >/dev/null
if $DOCKER_BIN exec v6-b ip addr show | grep -q "inet 10.89.0.50/"; then
    pass "6.2: restart rewires recorded endpoints, static IP kept"
else
    fail "6.2: static IP lost across restart"
fi

# --- 6.4: port ranges expand ----------------------------------------------------
# NOTE: busybox httpd daemonizes without -f (exiting the container), so
# listeners run foreground (-f) as the container command.
$DOCKER_BIN run -d --name v6-p -p 18090-18091:90-91 busybox:latest \
    httpd -f -p 90 -h /tmp >/dev/null
sleep 2
PORTS_OUT=$($DOCKER_BIN inspect v6-p --format '{{.NetworkSettings.Ports}}') \
    || fail "6.4: inspect v6-p failed"
echo "$PORTS_OUT" | grep -q "18090" || fail "6.4: range host port 18090 missing: $PORTS_OUT"
echo "$PORTS_OUT" | grep -q "18091" || fail "6.4: range host port 18091 missing: $PORTS_OUT"
pass "6.4: port range expands to per-port bindings"
[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 127.0.0.1:18090)" != "000" ] \
    || fail "6.4: no dataplane on 18090"
pass "6.4: range-published port serves traffic"

# --- 6.4: conflict names the occupier -------------------------------------------
Q_OUT=$($DOCKER_BIN run -d --name v6-q -p 18090:90 busybox:latest sleep 60 2>&1) && fail "6.4: conflicting publish accepted" || true
echo "$Q_OUT" | grep -q "v6-p" || fail "6.4: conflict did not name v6-p: $Q_OUT"
pass "6.4: port conflict fails closed naming the occupier"
$DOCKER_BIN rm -f v6-q >/dev/null 2>&1 || true

# --- 6.4: HostIp loopback-only ----------------------------------------------------
$DOCKER_BIN run -d --name v6-lo -p 127.0.0.1:18092:92 busybox:latest \
    httpd -f -p 92 -h /tmp >/dev/null
sleep 2
[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 127.0.0.1:18092)" != "000" ] \
    || fail "6.4: loopback-bound port unreachable via loopback"
LAN_IP=$(hostname -I | awk '{print $1}')
if [ "$LAN_IP" != "127.0.0.1" ] && [ -n "$LAN_IP" ]; then
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$LAN_IP:18092")" = "000" ] \
        || fail "6.4: loopback-bound port reachable externally ($LAN_IP)"
    pass "6.4: HostIp 127.0.0.1 binding is loopback-only"
else
    warn "6.4: no LAN address; loopback-external check skipped"
fi

# --- 6.4: publish-all --------------------------------------------------------------
$DOCKER_BIN run -d --name v6-all -P --expose 93 busybox:latest \
    httpd -f -p 93 -h /tmp >/dev/null
sleep 2
ALL_PORTS=$($DOCKER_BIN inspect v6-all --format '{{.NetworkSettings.Ports}}') \
    || fail "6.4: inspect v6-all failed"
EPHEMERAL=$(echo "$ALL_PORTS" | grep -oE '93/tcp:\[\{[^}]*' | grep -oE '[0-9]{4,5}' | head -1 || true)
[ -n "$EPHEMERAL" ] || fail "6.4: -P published nothing for exposed 93: $ALL_PORTS"
[ "$EPHEMERAL" -ge 32768 ] && [ "$EPHEMERAL" -le 60999 ] \
    || fail "6.4: -P port $EPHEMERAL outside ephemeral range"
[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "127.0.0.1:$EPHEMERAL")" != "000" ] \
    || fail "6.4: -P ephemeral port has no dataplane"
pass "6.4: publish-all maps exposed ports to ephemeral host ports ($EPHEMERAL)"

# --- 6.4: create-time validation ------------------------------------------------------
$DOCKER_BIN create -p notaport:80 busybox:latest >/dev/null 2>&1 \
    && fail "6.4: bad port accepted" || pass "6.4: malformed port rejected at create"
$DOCKER_BIN create -p 8080:80/sctp busybox:latest >/dev/null 2>&1 \
    && fail "6.4: sctp accepted" || pass "6.4: sctp rejected at create (no dataplane)"

# --- 6.5: explicit --dns wins, search/options render -------------------------------
$DOCKER_BIN run -d --name v6-dns --network v6t --dns 8.8.8.8 \
    --dns-search svc --dns-option ndots:2 busybox:latest sleep 120 >/dev/null
RESOLV=$($DOCKER_BIN exec v6-dns cat /etc/resolv.conf)
echo "$RESOLV" | grep -q "^nameserver 8.8.8.8" \
    || fail "6.5: explicit --dns missing from resolv.conf: $RESOLV"
echo "$RESOLV" | grep -q "^search svc" \
    || fail "6.5: --dns-search missing from resolv.conf: $RESOLV"
echo "$RESOLV" | grep -q "^options ndots:2" \
    || fail "6.5: --dns-option missing from resolv.conf: $RESOLV"
pass "6.5: explicit --dns/--dns-search/--dns-option render in resolv.conf"
# Explicit --dns also wins on the default bridge (docker parity: before,
# bridge containers always inherited the host file).
$DOCKER_BIN run -d --name v6-dnsb --dns 8.8.8.8 busybox:latest sleep 120 >/dev/null
$DOCKER_BIN exec v6-dnsb cat /etc/resolv.conf | grep -q "^nameserver 8.8.8.8" \
    || fail "6.5: explicit --dns ignored on default bridge"
pass "6.5: explicit --dns wins on the default bridge"

# --- 6.5: server-side search expansion ----------------------------------------------
# busybox/musl stubs cannot expand `search` client-side, so the embedded
# server expands single-label queries against the querier's own domains.
$DOCKER_BIN run -d --name v6-reg --network v6t --network-alias db.v6dom \
    busybox:latest sleep 120 >/dev/null
$DOCKER_BIN run -d --name v6-srch --network v6t --dns-search v6dom \
    busybox:latest sleep 120 >/dev/null
if $DOCKER_BIN exec v6-srch nslookup db 2>/dev/null | grep -q "10.89.0."; then
    pass "6.5: bare name resolves via the querier's search domain"
else
    fail "6.5: bare 'db' did not expand to db.v6dom"
fi
# musl ping cannot expand `search` client-side: success here proves the
# expansion happened server-side.
if $DOCKER_BIN exec v6-srch ping -c1 -W3 db >/dev/null 2>&1; then
    pass "6.5: musl ping resolves via server-side search expansion"
else
    fail "6.5: ping db failed for the search-domain container"
fi
# No cross-talk: a container without that search domain must not resolve it.
if $DOCKER_BIN exec v6-b nslookup db 2>/dev/null | grep -q "10.89.0."; then
    fail "6.5: search expansion leaked to a container without the domain"
else
    pass "6.5: search expansion scoped to the querying container"
fi

# --- 6.5: case-insensitive names ------------------------------------------------------
$DOCKER_BIN run -d --name V6-Upper --network v6t busybox:latest sleep 120 >/dev/null
if $DOCKER_BIN exec v6-b nslookup v6-upper 2>/dev/null | grep -q "10.89.0."; then
    pass "6.5: uppercase container name resolves lowercase"
else
    fail "6.5: case-insensitive resolution failed"
fi

# --- 6.5: resolv.conf injection rejected at create --------------------------------------
$DOCKER_BIN create --dns not-an-ip busybox:latest >/dev/null 2>&1 \
    && fail "6.5: bad --dns accepted" || pass "6.5: bad --dns rejected at create"
$DOCKER_BIN create --dns-search "$(printf 'a\nnameserver 9.9.9.9')" busybox:latest >/dev/null 2>&1 \
    && fail "6.5: newline in --dns-search accepted" || pass "6.5: newline in --dns-search rejected at create"

# --- 6.7: in-use network rm fails closed ---------------------------------------------
$DOCKER_BIN network create --subnet 10.93.0.0/24 v6rmv >/dev/null
$DOCKER_BIN run -d --name v6-r --network v6rmv busybox:latest sleep 120 >/dev/null
if $DOCKER_BIN network rm v6rmv >/dev/null 2>&1; then
    fail "6.7: network rm succeeded with a running endpoint attached"
else
    pass "6.7: network rm refused with active endpoints"
fi
# Stopped containers still hold their endpoint record: still refused.
$DOCKER_BIN stop v6-r >/dev/null
if $DOCKER_BIN network rm v6rmv >/dev/null 2>&1; then
    fail "6.7: network rm succeeded with a stopped endpoint attached"
else
    pass "6.7: network rm refused with stopped endpoints"
fi
$DOCKER_BIN rm -f v6-r >/dev/null
$DOCKER_BIN network rm v6rmv >/dev/null \
    || fail "6.7: network rm failed once endpoints were gone"
pass "6.7: network rm succeeds once endpoints are gone"
# The pre-defined bridge is forbidden, not "not found".
BRIDGE_RM_OUT=$($DOCKER_BIN network rm bridge 2>&1 || true)
echo "$BRIDGE_RM_OUT" | grep -q "pre-defined" \
    && pass "6.7: pre-defined bridge rm forbidden" \
    || fail "6.7: bridge rm did not report pre-defined: $BRIDGE_RM_OUT"

# --- final hygiene --------------------------------------------------------------
cleanup
trap - EXIT
[ "$(leases)" = "0" ] || fail "final: $(leases) lease(s) stranded"
[ "$(buckets)" = "1" ] || fail "final: $(buckets) buckets remain (want 1)"
[ "$(veths)" = "0" ] || fail "final: veths stranded"
# Bridge dataplane rules must die with their networks (regression: rm
# used to strand FORWARD/MASQUERADE rules forever).
[ -z "$(sudo iptables -S FORWARD 2>/dev/null | grep -E 'br-[0-9a-f]{12}')" ] \
    || fail "final: FORWARD rules stranded"
[ -z "$(sudo iptables -t nat -S POSTROUTING 2>/dev/null | grep -E 'br-[0-9a-f]{12}')" ] \
    || fail "final: MASQUERADE rules stranded"
pass "final: zero residue (leases, buckets, veths, networks, containers, iptables)"

echo "======================================================================"
echo -e "${GREEN}${BOLD} ALL V6 NETWORKING TESTS PASSED${NC}"
echo "======================================================================"
