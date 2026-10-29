#!/usr/bin/env bash
# G3.9f: BGP CoreRouter × CoreRouter (and FRR) on the development host,
# without root and without the lab VM: everything runs in a user + network
# + mount namespace (`unshare --user --map-root-user`), with the official
# FRR 10.7.1 packages (deb.frrouting.org, SHA-256 checked against the
# repository index) extracted into the target dir, never installed.
#   scripts/bgp-crcr-userns.sh [case…]
# Cases (default: all, in this order):
#   ebgp ebgp6 mpbgp md5 filters extcomm announce nexthop-self rr maxprefix
#   restart gr bfd convergence scale
# Not in the default list: ospf-static (G3.9fe, OSPF redistributing the
# CoreRouter's static routes).
# SCALE_N=<n> changes the 100 000 prefixes of `scale`. Results: a table at
# the end and $W/results.txt; exit 1 if any case failed.
#
# Topology (namespaces inside the user namespace):
#
#   R3 (FRR, AS 65003) eth0 ── ether5 CR1 (AS 65000) ether1 ── ether1 CR2 (AS 65000 / 65002)
#                                         ether2 ── ether2 (a second path)
#   R4 (FRR, AS 65000) eth0 ── ether3 CR1;  R4 cl0 ── ether4 CR1 (100.64.39.0/24)
#                                           R4 cl1 ── ether3 CR2 (100.64.40.0/24)
# Links 10.39.<n>.0/30 and fd39:<n>::/64 (CR1 is .1): 2 R3, 4 R4, 5 and 6
# CR2. Loopbacks 10.255.39.<n>/32: CR1 2, R3 3, R4 4, CR2 5.
set -euo pipefail
[ -z "${TRACE:-}" ] || set -x
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
FRR_DIR=$CARGO_TARGET_DIR/frr-10.7.1
W=${W:-${TMPDIR:-/tmp}/crg39f-host}

if [ -z "${CRG39F_INNER:-}" ]; then
  # Outside: the FRR packages and the release binaries, then the namespace.
  if [ ! -x "$FRR_DIR/root/usr/lib/frr/bgpd" ]; then
    mkdir -p "$FRR_DIR"
    B=https://deb.frrouting.org/frr/pool/frr-stable
    while read -r sum path; do
      f=$FRR_DIR/${path##*/}
      [ -f "$f" ] || curl -sSfL -o "$f" "$B/$path"
      echo "$sum  $f" | sha256sum -c --quiet || { rm -f "$f"; echo "FAIL: checksum of $path"; exit 1; }
      dpkg-deb -x "$f" "$FRR_DIR/root"
    done <<'PKGS'
05d17ad3abe56df9090f6637dfad9cd3fd84987df34ee2cd6e8d6928c730ec4b f/frr/frr_10.7.1-0~ubuntu24.04.1_amd64.deb
03ffcf092652aa41a5f474de2a24902fc21502e2fe1c70ff22c15f7859ad166f liby/libyang3/libyang3_3.13.6-1~ubuntu24.04u1_amd64.deb
PKGS
  fi
  # jq 1.7.1 (the official static build) when the host has none.
  if ! command -v jq >/dev/null; then
    mkdir -p "$CARGO_TARGET_DIR/jq"
    j=$CARGO_TARGET_DIR/jq/jq
    [ -f "$j" ] || curl -sSfL -o "$j" https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64
    echo "5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5  $j" | sha256sum -c --quiet || { rm -f "$j"; echo "FAIL: checksum of jq"; exit 1; }
    chmod +x "$j"
    export PATH=$CARGO_TARGET_DIR/jq:$PATH
  fi
  (cd "$ROOT" && cargo build -q --release -p corerouter-daemon -p corerouter-cli)
  rm -rf "$W"; mkdir -p "$W"
  exec unshare --user --map-root-user --net --mount --fork --kill-child \
    env CRG39F_INNER=1 W="$W" bash "$0" "$@"
fi

# --- inside: private /run, /etc and /var/lib so FRR runs as "root" ----------
mount -t tmpfs tmpfs /run
mkdir -p /run/hostetc
cp -a /etc/alternatives /etc/passwd /etc/nsswitch.conf /etc/ld.so.cache /etc/hosts /etc/localtime /etc/protocols /etc/services /run/hostetc/ 2>/dev/null || true
{ cat /etc/group; echo 'frr:x:0:'; echo 'frrvty:x:0:'; } > /run/hostetc/group
mount -t tmpfs tmpfs /etc
cp -a /run/hostetc/. /etc/
mount -t tmpfs tmpfs /var/lib
mkdir -p /var/run/frr /etc/frr /var/lib/frr /run/netns
export LD_LIBRARY_PATH=$FRR_DIR/root/usr/lib/x86_64-linux-gnu:$FRR_DIR/root/usr/lib/x86_64-linux-gnu/frr
FRR=$FRR_DIR/root/usr/lib/frr
bin=$CARGO_TARGET_DIR/release
CASES=("$@")
[ ${#CASES[@]} -gt 0 ] || CASES=(ebgp ebgp6 mpbgp md5 filters extcomm announce nexthop-self rr maxprefix restart gr bfd convergence scale)
FAILED=0
: > "$W/results.txt"
result() { # result <case> <OK|FAIL|INFO> <text>
  printf '%-13s %-4s %s\n' "$1" "$2" "$3" | tee -a "$W/results.txt"
  [ "$2" != FAIL ] || FAILED=1
}

# The vty client (the protocol hal-frr and vtysh speak; vtysh itself wants
# PAM, which a private /etc does not have).
cat > "$W/vty.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.settimeout(60)
rc = 0
for cmd in ["enable"] + sys.argv[2:]:
    s.sendall(cmd.encode() + b"\0")
    buf = b""
    while not (len(buf) >= 4 and buf[-4:-1] == b"\0\0\0"):
        d = s.recv(1 << 20)
        if not d: break
        buf += d
    sys.stdout.write(buf[:-4].decode(errors="replace"))
    if buf[-1:] not in (b"\0", b"\x0a"): rc = buf[-1] if buf else 1
sys.exit(rc)
PY
# vt <ns> <command…>: bgpd of that namespace (several: one session).
vt() { local ns=$1; shift; python3 -I "$W/vty.py" "/var/run/frr/$ns/bgpd.vty" "$@"; }
vtc() { local ns=$1; shift; vt "$ns" 'configure terminal' "$@" >/dev/null; }
vtz() { local ns=$1; shift; python3 -I "$W/vty.py" "/var/run/frr/$ns/zebra.vty" "$@"; }

cleanup() {
  local p
  for p in "$W"/*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true; done
  pkill -f -- "frr/[a-z]+ -N " 2>/dev/null || true
}
trap cleanup EXIT

# --- topology ---------------------------------------------------------------
NSS="c1 c2 r3 r4"
for ns in $NSS; do
  ip netns add $ns
  ip -n $ns link set lo up
  ip netns exec $ns sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
done
pair() { # pair <ns a> <if a> <ns b> <if b>
  ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"
  ip -n "$1" link set "$2" up
  ip -n "$3" link set "$4" up
}
pair c1 ether1 c2 ether1
pair c1 ether2 c2 ether2
pair c1 ether3 r4 eth0
pair c1 ether4 r4 cl0
pair c1 ether5 r3 eth0
pair c2 ether3 r4 cl1
ip -n r3 addr add 10.39.2.2/30 dev eth0
ip -n r3 addr add 10.255.39.3/32 dev lo
ip -n r4 addr add 10.39.4.2/30 dev eth0
ip -n r4 addr add 10.255.39.4/32 dev lo
ip -n r4 addr add 100.64.39.2/24 dev cl0
ip -n r4 addr add 100.64.40.2/24 dev cl1
ip -n r4 route add 10.39.0.0/16 via 10.39.4.1
ip -n r4 route add blackhole 192.0.2.0/24

# --- FRR ----------------------------------------------------------------------
# frr_start <ns> <daemons…>: the daemons of a namespace; bgpd.conf from $W/<ns>.bgpd.
frr_start() {
  local ns=$1 p; shift
  mkdir -p "/etc/frr/$ns" "/var/lib/frr/$ns" "/var/run/frr/$ns"
  for p in zebra bgpd ospfd staticd bfdd; do : > "/etc/frr/$ns/$p.conf"; done
  [ -f "$W/$ns.bgpd" ] && cp "$W/$ns.bgpd" "/etc/frr/$ns/bgpd.conf"
  for p in "$@"; do
    case $p in
      mgmtd|staticd) ip netns exec "$ns" "$FRR/$p" -N "$ns" -u root -g root -d --limit-fds 4096 ;;
      bfdd) ip netns exec "$ns" "$FRR/bfdd" -N "$ns" -u root -g root -d --limit-fds 4096 \
              -f "/etc/frr/$ns/bfdd.conf" --dplaneaddr "unix:/var/run/frr/$ns/bfdd_dplane.sock" ;;
      *) ip netns exec "$ns" "$FRR/$p" -N "$ns" -u root -g root -d --limit-fds 4096 -f "/etc/frr/$ns/$p.conf" ;;
    esac </dev/null >>"$W/frr-$ns.log" 2>&1
    sleep 0.5
  done
}
cat > "$W/r3.bgpd" <<'EOF'
router bgp 65003
 bgp router-id 10.255.39.3
 no bgp ebgp-requires-policy
 no bgp default ipv4-unicast
 neighbor 10.39.2.1 remote-as 65000
 address-family ipv4 unicast
  redistribute kernel
  neighbor 10.39.2.1 activate
 exit-address-family
exit
EOF
cat > "$W/r4.bgpd" <<'EOF'
router bgp 65000
 bgp router-id 10.255.39.4
 no bgp default ipv4-unicast
 neighbor 10.39.4.1 remote-as 65000
 neighbor 10.39.4.1 shutdown
 address-family ipv4 unicast
  network 192.0.2.0/24
  neighbor 10.39.4.1 activate
 exit-address-family
exit
EOF
frr_start r3 zebra bgpd
frr_start r4 zebra bgpd
for n in 1 2; do frr_start "c$n" mgmtd zebra staticd bgpd ospfd bfdd; done

# --- the two CoreRouters ------------------------------------------------------
export COREROUTER_RUNTIME_DIR=$W/run
mkdir -p "$COREROUTER_RUNTIME_DIR"
cr() { local n=$1; shift; ip netns exec "c$n" "$bin/corerouter-cli" --connect "127.0.0.1:799$n" run "$@"; }
cr1() { cr 1 "$@"; }
cr2() { cr 2 "$@"; }
start_daemon() { # start_daemon <1|2>
  local n=$1
  for _ in $(seq 50); do [ -S "/var/run/frr/c$n/bfdd_dplane.sock" ] && break; sleep 0.2; done
  ip netns exec "c$n" "$bin/corerouter-daemon" --backend linux --manage 'ether*' \
    --config-dir "$W/cfg$n" --control "799$n" --frr "/var/run/frr/c$n" --no-discovery \
    >> "$W/daemon$n.log" 2>&1 &
  echo $! > "$W/daemon$n.pid"
  for _ in $(seq 150); do cr "$n" routing.backend.get >/dev/null 2>&1 && break; sleep 0.2; done
}
start_daemon 1
start_daemon 2

now_ms() { date +%s%3N; }
wait_for() { # wait_for <timeout s> <command…>: poll every 100 ms; prints the ms waited
  local t=$1; shift
  local t0; t0=$(now_ms)
  while ! "$@" >/dev/null 2>&1; do
    [ $(( $(now_ms) - t0 )) -lt $(( t * 1000 )) ] || { echo -1; return 1; }
    sleep 0.1
  done
  echo $(( $(now_ms) - t0 ))
}
cr_sess() { cr "$1" routing.bgp.session.list | jq -c --arg c "$2" '[.[] | select(.connection == $c)][0] // {}'; }
cr_up() { [ "$(cr_sess "$1" "$2" | jq -r '.established // false')" = true ]; }
cr_state() { cr_sess "$1" "$2" | jq -c '{state, reason, last_error}'; }
k_route() { ip -n "$1" route show "$2" 2>/dev/null | grep -o 'via [0-9.]*' | head -1 || true; }
k_route6() { ip -n "$1" -6 route show "$2" 2>/dev/null | grep -o 'via [0-9a-f:]*' | head -1 || true; }
k_has() { [ -n "$(k_route "$1" "$2")" ]; }
k_has6() { [ -n "$(k_route6 "$1" "$2")" ]; }
k_none() { ! k_has "$1" "$2"; }
k_via() { [ "$(k_route "$1" "$2")" = "via $3" ]; }
bgp_count() { ip -n "$1" route show proto bgp | wc -l; }
cr_rx() { # cr_rx <n> <connection> <prefix>: the route as routing.bgp.route.list shows it
  local out i
  for i in $(seq 30); do
    out=$(cr "$1" routing.bgp.route.list "{\"connection\":\"$2\",\"prefix\":\"$3\",\"match\":\"exact\",\"refresh\":$([ "$i" = 1 ] && echo true || echo false)}" 2>/dev/null) || true
    [ "$(jq -r '.state // ""' <<< "$out")" = loading ] || break
    sleep 0.3
  done
  jq -c '[.rows[]? | select(.filtered | not)][0] // {}' <<< "$out"
}
# The best path in bgpd's table (after the inbound policy): routing.bgp.route.list
# shows received routes before it, and FRR's received-routes JSON carries no
# communities (G3.2g).
bgp_path() { # bgp_path <ns> <prefix>
  vt "$1" "show bgp $([[ $2 == *:* ]] && echo ipv6 || echo ipv4) unicast $2 json" |
    jq -c '[.paths[]? | select(.bestpath.overall // false)][0] // {} | {as_path: .aspath.string, med: .metric, local_pref: .locPrf, communities: .community.string, large: .largeCommunity.string, ext: .extendedCommunity.string, originator: .originatorId}' 2>/dev/null || echo '{}'
}
dump() {
  local n
  for n in 1 2; do
    echo "--- CR$n sessions"; cr "$n" routing.bgp.session.list | jq -c '.[] | {connection, remote_address, state, reason, last_error, prefix_count, prefix_sent}'
    echo "--- c$n bgpd"; vt "c$n" 'show running-config' | sed -n '/^router bgp/,/^exit/p' | head -50
  done
}

# --- base config ----------------------------------------------------------------
addr() { cr "$1" ip.address.add "{\"address\":\"$2\",\"interface\":\"$3\"}" >/dev/null; }
cr1 interface.loopback.add '{"name":"lo"}' >/dev/null
cr2 interface.loopback.add '{"name":"lo"}' >/dev/null
addr 1 10.39.5.1/30 ether1; addr 1 fd39:5::1/64 ether1
addr 1 10.39.6.1/30 ether2
addr 1 10.39.4.1/30 ether3
addr 1 100.64.39.1/24 ether4; addr 1 fd39:64::1/64 ether4
addr 1 10.39.2.1/30 ether5
addr 1 10.255.39.2/32 lo
addr 2 10.39.5.2/30 ether1; addr 2 fd39:5::2/64 ether1
addr 2 10.39.6.2/30 ether2
addr 2 100.64.40.1/24 ether3; addr 2 fd39:40::1/64 ether3
addr 2 10.255.39.5/32 lo
cr1 routing.bgp.instance.set '{"asn":65000,"router_id":"10.255.39.2"}' >/dev/null
cr2 routing.bgp.instance.set '{"asn":65002,"router_id":"10.255.39.5"}' >/dev/null
for n in 1 2; do cr "$n" routing.filter.rule.add '{"chain":"all","rule":"accept"}' >/dev/null; done
cr1 ip.firewall.address-list.add '{"list":"bgp-out","address":"100.64.39.0/24"}' >/dev/null
cr1 ip.firewall.address-list.add '{"list":"bgp-out","address":"fd39:64::/64"}' >/dev/null
cr2 ip.firewall.address-list.add '{"list":"bgp-out","address":"100.64.40.0/24"}' >/dev/null
cr2 ip.firewall.address-list.add '{"list":"bgp-out","address":"fd39:40::/64"}' >/dev/null
crc() { cr "$1" routing.bgp.connection.add "$2" >/dev/null; }
crd() { cr "$1" routing.bgp.connection.remove "{\"id\":\"$2\"}" >/dev/null 2>&1 || true; }
# The eBGP pair CR1 (65000) — CR2 (65002) on link 5, the base of most cases.
pair_up() { # pair_up [extra json for both]
  local x=${1:-}
  [ -n "$x" ] || x='{}'
  crc 1 "$(jq -c '. + $x' --argjson x "$x" <<< '{"name":"cr2","remote_address":"10.39.5.2","remote_as":65002,"input_filter":"all","output_filter":"all","output_network":"bgp-out"}')"
  crc 2 "$(jq -c '. + $x' --argjson x "$x" <<< '{"name":"cr1","remote_address":"10.39.5.1","remote_as":65000,"input_filter":"all","output_filter":"all","output_network":"bgp-out"}')"
}
pair_down() { crd 1 cr2; crd 2 cr1; }

# --- cases ----------------------------------------------------------------------
case_ebgp() {
  local ms
  pair_up
  ms=$(wait_for 60 cr_up 1 cr2) && result ebgp OK "eBGP CR1 (65000) — CR2 (65002) Established in ${ms} ms" \
    || { result ebgp FAIL "no session: CR1 $(cr_state 1 cr2), CR2 $(cr_state 2 cr1)"; dump; pair_down; return; }
  result ebgp INFO "CR1 sees $(cr_sess 1 cr2 | jq -c '{state, hold_time, keepalive_time, afi, remote_id, remote_as}')"
  ms=$(wait_for 30 k_via c1 100.64.40.0/24 10.39.5.2) && result ebgp OK "output_network: CR2's 100.64.40.0/24 in CR1's kernel ${ms} ms later" \
    || result ebgp FAIL "CR1 kernel: '$(k_route c1 100.64.40.0/24)'"
  ms=$(wait_for 30 k_via c2 100.64.39.0/24 10.39.5.1) && result ebgp OK "CR1's 100.64.39.0/24 in CR2's kernel" \
    || result ebgp FAIL "CR2 kernel: '$(k_route c2 100.64.39.0/24)'"
  ip netns exec c2 ping -c 3 -i 0.2 -W 1 -I 100.64.40.1 100.64.39.1 >/dev/null \
    && result ebgp OK "ping between the clients' gateways" || result ebgp FAIL "ping 100.64.40.1 → 100.64.39.1"
  local r; r=$(cr_rx 1 cr2 100.64.40.0/24)
  [[ $r == *'"as_path"'* ]] && result ebgp OK "route.list: $(jq -c '{prefix, as_path, origin, next_hop, local_pref}' <<< "$r")" || result ebgp FAIL "route.list: $r"
  local adv
  cr1 routing.bgp.route.list '{"connection":"cr2","direction":"advertised","refresh":true}' >/dev/null
  for _ in $(seq 20); do adv=$(cr1 routing.bgp.route.list '{"connection":"cr2","direction":"advertised"}'); [ "$(jq -r .state <<< "$adv")" = loading ] || break; sleep 0.3; done
  [[ $(jq -c '[.rows[]?.prefix]' <<< "$adv") == *100.64.39.0/24* ]] && result ebgp OK "route.list advertised: $(jq -c '[.rows[]?.prefix]' <<< "$adv")" \
    || result ebgp FAIL "route.list advertised: $(jq -c '{state, error, rows: [.rows[]?.prefix]}' <<< "$adv")"
  # Only what the list names: the other connected networks stay out.
  k_has c2 10.39.4.0/30 && result ebgp FAIL "CR2 got CR1's 10.39.4.0/30 (not in bgp-out)" || result ebgp OK "connected networks outside bgp-out are not announced"
  # A new entry in the list is announced; removing it withdraws.
  local t0 id; t0=$(now_ms)
  id=$(cr1 ip.firewall.address-list.add '{"list":"bgp-out","address":"10.39.4.0/30"}' | jq -r .id)
  ms=$(wait_for 30 k_has c2 10.39.4.0/30) && result ebgp OK "address-list entry added: on CR2 $(( $(now_ms) - t0 )) ms after the command" \
    || result ebgp FAIL "new entry not announced"
  t0=$(now_ms)
  cr1 ip.firewall.address-list.remove "{\"id\":\"$id\"}" >/dev/null
  ms=$(wait_for 30 k_none c2 10.39.4.0/30) && result ebgp OK "entry removed: withdrawn from CR2 $(( $(now_ms) - t0 )) ms after the command" \
    || result ebgp FAIL "removed entry still on CR2"
  # A network in the list without a route is not sent (import-check, as
  # RouterOS: "only with a matching IGP route").
  cr1 ip.firewall.address-list.add '{"list":"bgp-out","address":"198.18.99.0/24"}' >/dev/null
  sleep 3
  k_has c2 198.18.99.0/24 && result ebgp FAIL "198.18.99.0/24 sent without a route to it" || result ebgp OK "listed network without a route is not sent"
  cr1 ip.route.add '{"dst_address":"198.18.99.0/24","gateway":"10.39.4.2"}' >/dev/null
  ms=$(wait_for 30 k_has c2 198.18.99.0/24) && result ebgp OK "…and is sent ${ms} ms after a static route to it appears" || result ebgp FAIL "198.18.99.0/24 not sent with its route"
  # output_redistribute static: what CR1 routes statically.
  cr1 routing.bgp.connection.set '{"id":"cr2","output_redistribute":"static"}' >/dev/null
  cr1 ip.route.add '{"dst_address":"198.18.98.0/24","gateway":"10.39.4.2"}' >/dev/null
  sleep 1
  result ebgp INFO "zebra sees the static route as: $(vtz c1 'show ip route 198.18.98.0/24 json' | jq -c '[."198.18.98.0/24"[]? | {protocol, selected, installed}]')"
  ms=$(wait_for 30 k_has c2 198.18.98.0/24) && result ebgp OK "output_redistribute=static: 198.18.98.0/24 on CR2 in ${ms} ms" || result ebgp FAIL "redistribute static: not on CR2"
  pair_down
  ms=$(wait_for 30 k_none c2 100.64.39.0/24) && result ebgp OK "connection removed: routes withdrawn in ${ms} ms" || result ebgp FAIL "routes kept after removal"
}

case_ebgp6() {
  crc 1 '{"name":"cr26","remote_address":"fd39:5::2","remote_as":65002,"afi":"ipv6","input_filter":"all","output_filter":"all","output_network":"bgp-out"}'
  crc 2 '{"name":"cr16","remote_address":"fd39:5::1","remote_as":65000,"afi":"ipv6","input_filter":"all","output_filter":"all","output_network":"bgp-out"}'
  local ms
  ms=$(wait_for 60 cr_up 1 cr26) && result ebgp6 OK "eBGP over IPv6, IPv6 NLRI: Established in ${ms} ms" || { result ebgp6 FAIL "no session: $(cr_state 1 cr26)"; dump; }
  ms=$(wait_for 30 k_has6 c1 fd39:40::/64) && result ebgp6 OK "CR1 has fd39:40::/64 $(k_route6 c1 fd39:40::/64)" || result ebgp6 FAIL "CR1: '$(k_route6 c1 fd39:40::/64)'"
  ms=$(wait_for 30 k_has6 c2 fd39:64::/64) && result ebgp6 OK "CR2 has fd39:64::/64 $(k_route6 c2 fd39:64::/64)" || result ebgp6 FAIL "CR2: '$(k_route6 c2 fd39:64::/64)'"
  k_has6 c2 fd39:5::/64 && result ebgp6 INFO "fd39:5::/64 also on CR2 (connected there)" || true
  crd 1 cr26; crd 2 cr16
}

case_mpbgp() {
  pair_up '{"afi":"ip,ipv6"}'
  local ms
  ms=$(wait_for 60 cr_up 1 cr2) && result mpbgp OK "IPv4 session with ip+ipv6 (RFC 4760): Established in ${ms} ms, afi $(cr_sess 1 cr2 | jq -c .afi)" \
    || { result mpbgp FAIL "no session: $(cr_state 1 cr2)"; dump; }
  ms=$(wait_for 30 k_has6 c2 fd39:64::/64) && result mpbgp OK "IPv6 over the IPv4 session: CR2 has fd39:64::/64 $(k_route6 c2 fd39:64::/64)" \
    || result mpbgp FAIL "CR2 IPv6: '$(k_route6 c2 fd39:64::/64)', bgpd $(vt c2 'show bgp ipv6 unicast fd39:64::/64 json' | jq -c '[.paths[]? | {valid, nexthops}]' 2>/dev/null)"
  result mpbgp INFO "next hop CR2 got (RFC 2545 §3: global, plus link-local on a shared link): $(vt c2 'show bgp ipv6 unicast fd39:64::/64 json' | jq -c '[.paths[]?.nexthops[]? | {ip, scope}]' 2>/dev/null)"
  pair_down
}

case_md5() {
  pair_up '{"tcp_md5_key":"g39f-md5"}'
  local ms
  ms=$(wait_for 60 cr_up 1 cr2) && result md5 OK "TCP MD5 (RFC 2385) on both CoreRouters: Established in ${ms} ms" || { result md5 FAIL "same key: $(cr_state 1 cr2)"; dump; }
  grep -rq g39f-md5 "$W/cfg1" "$W/cfg2" && result md5 FAIL "the key in clear text in a config dir" || result md5 OK "the key is sealed on disk"
  cr2 routing.bgp.connection.set '{"id":"cr1","tcp_md5_key":"wrong-key"}' >/dev/null
  cr1 routing.bgp.session.clear '{"connection":"cr2"}' >/dev/null 2>&1 || true
  sleep 8
  cr_up 1 cr2 && result md5 FAIL "wrong key: still Established" || result md5 OK "wrong key: down and stays down ($(cr_state 1 cr2))"
  cr2 routing.bgp.connection.set '{"id":"cr1","tcp_md5_key":"g39f-md5"}' >/dev/null
  ms=$(wait_for 120 cr_up 1 cr2) && result md5 OK "key fixed: back in ${ms} ms" || result md5 FAIL "key fixed: $(cr_state 1 cr2)"
  pair_down
}

case_filters() {
  cr1 routing.filter.rule.add '{"chain":"o1","rule":"if (dst in 100.64.39.0/24) { set bgp-med 77; set bgp-path-prepend 2; append bgp-communities 65000:10,no-export; append bgp-large-communities 65000:0:10; accept } reject"}' >/dev/null
  cr2 routing.filter.community-list.add '{"name":"from-cr1","communities":"65000:10"}' >/dev/null
  cr2 routing.filter.rule.add '{"chain":"i2","rule":"if (bgp-communities any-list from-cr1) { set bgp-local-pref 300; accept } reject"}' >/dev/null
  crc 1 '{"name":"cr2","remote_address":"10.39.5.2","remote_as":65002,"input_filter":"all","output_filter":"o1","output_network":"bgp-out"}'
  crc 2 '{"name":"cr1","remote_address":"10.39.5.1","remote_as":65000,"input_filter":"i2","output_filter":"all","output_network":"bgp-out"}'
  local ms r
  ms=$(wait_for 60 cr_up 1 cr2) || { result filters FAIL "no session"; pair_down; return; }
  wait_for 30 k_has c2 100.64.39.0/24 >/dev/null || true
  r=$(bgp_path c2 100.64.39.0/24)
  result filters INFO "CR2's bgpd has $r"
  [ "$(jq -r .med <<< "$r")" = 77 ] || result filters INFO "CR1 deferral: $(vt c1 'show bgp neighbors 10.39.5.2 json' | jq -c '."10.39.5.2".gracefulRestartInfo | {localGrMode, remoteGrMode, timers: .ipv4Unicast.timers, eor: .ipv4Unicast.endOfRibStatus}' 2>/dev/null); $(vt c1 'show bgp ipv4 unicast 100.64.39.0/24 json' | jq -c '[.paths[]? | {valid, best: .bestpath.overall}]' 2>/dev/null); CR1 running GR: $(vt c1 'show running-config' | grep -c graceful)"
  [ "$(jq -r .med <<< "$r")" = 77 ] && result filters OK "out: MED 77" || result filters FAIL "out: MED $(jq -c .med <<< "$r")"
  # G3.9fg: N copies in all over eBGP, as RouterOS.
  [ "$(jq -r .as_path <<< "$r")" = "65000 65000" ] && result filters OK "out: prepend 2 (65000 65000, RouterOS's count)" || result filters FAIL "out: as_path $(jq -c .as_path <<< "$r")"
  [[ $(jq -r .communities <<< "$r") == *65000:10* && $(jq -r .communities <<< "$r") == *no-export* ]] && result filters OK "out: communities 65000:10 and no-export (RFC 1997)" || result filters FAIL "communities $(jq -c .communities <<< "$r")"
  [[ $(jq -r .large <<< "$r") == *65000:0:10* ]] && result filters OK "out: large community 65000:0:10 (RFC 8092)" || result filters FAIL "large $(jq -c .large <<< "$r")"
  [ "$(jq -r .local_pref <<< "$r")" = 300 ] && result filters OK "in: community-list match → local-pref 300" || result filters FAIL "in: local_pref $(jq -c .local_pref <<< "$r")"
  result filters INFO "route.list (before the inbound policy, G3.2g): $(cr_rx 2 cr1 100.64.39.0/24 | jq -c '{med, local_pref, communities}')"
  vt c2 'show bgp ipv4 unicast 100.64.39.0/24' | grep -q 'not advertised to EBGP peer' && result filters OK "no-export honoured on CR2 (RFC 1997: not advertised to EBGP peers)" || result filters FAIL "no-export not flagged on CR2"
  k_has c2 fd39:64::/64 && result filters FAIL "IPv6 leaked through a reject chain" || true
  # Changing a chain: applies without a reset.
  local up0 id t0; up0=$(cr_sess 1 cr2 | jq -r .uptime_secs)
  id=$(cr1 routing.filter.rule.list '{"chain":"o1"}' | jq -r '.[0].id')
  t0=$(now_ms)
  cr1 routing.filter.rule.set "{\"id\":\"$id\",\"rule\":\"if (dst in 100.64.39.0/24) { set bgp-med 88; append bgp-communities 65000:10; accept } reject\"}" >/dev/null
  med88() { [ "$(bgp_path c2 100.64.39.0/24 | jq -r .med)" = 88 ]; }
  ms=$(wait_for 30 med88) \
    && result filters OK "changed out chain: MED 88 on CR2 $(( $(now_ms) - t0 )) ms after the commit, session kept (uptime $up0 → $(cr_sess 1 cr2 | jq -r .uptime_secs) s)" \
    || result filters FAIL "changed out chain: CR2 $(bgp_path c2 100.64.39.0/24)"
  pair_down
}

# G3.9fc: extended communities (RFC 4360) in the chains, both ways, on FRR.
case_extcomm() {
  cr1 routing.filter.rule.add '{"chain":"x-out","rule":"if (dst in 100.64.39.0/24) { append bgp-ext-communities rt:65000:7,soo:10.255.39.2:1 } accept"}' >/dev/null
  cr2 routing.filter.community-list.add '{"name":"vpn7","communities":"rt:65000:7"}' >/dev/null
  cr2 routing.filter.rule.add '{"chain":"x-in","rule":"if (bgp-ext-communities includes-list vpn7) { set bgp-local-pref 300 } if (bgp-ext-communities subset rt:65000:7,soo:10.255.39.2:1) { set bgp-med 9 } delete bgp-ext-communities soo; accept"}' >/dev/null
  crc 1 '{"name":"cr2","remote_address":"10.39.5.2","remote_as":65002,"input_filter":"all","output_filter":"x-out","output_network":"bgp-out"}'
  crc 2 '{"name":"cr1","remote_address":"10.39.5.1","remote_as":65000,"input_filter":"x-in","output_filter":"all","output_network":"bgp-out"}'
  local ms r t0
  ms=$(wait_for 60 cr_up 1 cr2) || { result extcomm FAIL "no session"; pair_down; return; }
  wait_for 30 k_has c2 100.64.39.0/24 >/dev/null || true
  sleep 1
  r=$(bgp_path c2 100.64.39.0/24)
  result extcomm INFO "CR2's bgpd has $r"
  [ "$(jq -r .ext <<< "$r")" = "RT:65000:7" ] && result extcomm OK "append rt+soo on CR1, delete soo on CR2: RT:65000:7 left" || result extcomm FAIL "ext on CR2: $(jq -c .ext <<< "$r")"
  [ "$(jq -r .local_pref <<< "$r")" = 300 ] && result extcomm OK "includes-list (rt:65000:7) → local-pref 300" || result extcomm FAIL "local_pref $(jq -c .local_pref <<< "$r")"
  [ "$(jq -r .med <<< "$r")" = 9 ] && result extcomm OK "subset rt:65000:7,soo:10.255.39.2:1 → MED 9" || result extcomm FAIL "med $(jq -c .med <<< "$r")"
  # route.explain answers "loading" first: ask until it is ready.
  local i; for i in $(seq 30); do
    r=$(cr2 routing.bgp.route.explain '{"prefix":"100.64.39.0/24"}' 2>/dev/null || echo '{}')
    [ "$(jq -r '.state // ""' <<< "$r")" = loading ] || break
    sleep 0.3
  done
  [[ $(jq -c '[.paths[]? | .ext_communities[]?]' <<< "$r") == *rt:65000:7* ]] && result extcomm OK "route.explain on CR2 shows ext_communities $(jq -c '[.paths[]? | .ext_communities]' <<< "$r")" \
    || result extcomm FAIL "route.explain on CR2: $(jq -c '{state, paths: [.paths[]? | {ext_communities}]}' <<< "$r")"
  # set replaces (FRR's set extcommunity adds: none first); subset fails then.
  local id; id=$(cr1 routing.filter.rule.list '{"chain":"x-out"}' | jq -r '.[0].id')
  t0=$(now_ms)
  cr1 routing.filter.rule.set "{\"id\":\"$id\",\"rule\":\"if (dst in 100.64.39.0/24) { append bgp-ext-communities soo:10.255.39.2:1; set bgp-ext-communities rt:65000:8,rt:1:1 } accept\"}" >/dev/null
  ext8() { [ "$(bgp_path c2 100.64.39.0/24 | jq -r .ext)" = "RT:1:1 RT:65000:8" ]; }
  ms=$(wait_for 30 ext8) && result extcomm OK "set replaces: RT:1:1 RT:65000:8 on CR2 $(( $(now_ms) - t0 )) ms after the commit (the soo appended before it is gone)" \
    || result extcomm FAIL "set: CR2 has $(bgp_path c2 100.64.39.0/24 | jq -c '{ext}')"
  r=$(bgp_path c2 100.64.39.0/24)
  [ "$(jq -r .local_pref <<< "$r")" != 300 ] && [ "$(jq -r .med <<< "$r")" != 9 ] && result extcomm OK "without rt:65000:7: no local-pref 300, and subset fails (rt:1:1 is not in it)" || result extcomm FAIL "after set: $r"
  result extcomm INFO "CR2 bgpd lists: $(vt c2 'show running-config' | grep -E '^bgp extcommunity-list' | tr '\n' ';')"
  pair_down
}

# G3.9fb: each connection sends only its own output_network and
# output_redistribute, as on RouterOS (FRR originates per instance).
case_announce() {
  cr1 ip.firewall.address-list.add '{"list":"to-r3","address":"10.255.39.2/32"}' >/dev/null
  pair_up
  crc 1 '{"name":"r3","remote_address":"10.39.2.2","remote_as":65003,"input_filter":"all","output_filter":"all","output_network":"to-r3","output_redistribute":"connected"}'
  local ms t0
  wait_for 60 cr_up 1 cr2 >/dev/null || { result announce FAIL "no session to CR2: $(cr_state 1 cr2)"; dump; }
  wait_for 60 cr_up 1 r3 >/dev/null || { result announce FAIL "no session to R3: $(cr_state 1 r3)"; dump; }
  r3_has() { ip -n r3 route show "$1" 2>/dev/null | grep -q "via 10.39.2.1"; }
  ms=$(wait_for 30 r3_has 10.255.39.2) && result announce OK "R3 gets its output_network (10.255.39.2/32)" || result announce FAIL "R3: $(ip -n r3 route show 10.255.39.2)"
  ms=$(wait_for 30 r3_has 10.39.4.0/30) && result announce OK "R3 gets its redistribute connected (10.39.4.0/30)" || result announce FAIL "R3: no 10.39.4.0/30"
  ms=$(wait_for 30 r3_has 100.64.39.0/24) && result announce OK "R3 gets 100.64.39.0/24 too: connected, though CR2's network line originates it" || result announce FAIL "R3: no 100.64.39.0/24"
  ms=$(wait_for 30 k_via c2 100.64.39.0/24 10.39.5.1) && result announce OK "CR2 gets its output_network (100.64.39.0/24)" || result announce FAIL "CR2: '$(k_route c2 100.64.39.0/24)'"
  sleep 3
  k_has c2 10.255.39.2 && result announce FAIL "CR2 got R3's network 10.255.39.2/32" || result announce OK "CR2 does not get R3's output_network (10.255.39.2/32)"
  k_has c2 10.39.4.0/30 && result announce FAIL "CR2 got a connected route it did not ask for" || result announce OK "CR2 does not get the connected routes R3 asked for (10.39.4.0/30)"
  result announce INFO "CR1 sends CR2: $(vt c1 'show bgp ipv4 unicast neighbors 10.39.5.2 advertised-routes json' | jq -c '[.advertisedRoutes // {} | keys[]]' 2>/dev/null)"
  if k_has c2 10.255.39.2; then
    echo "--- CR1 bgpd: CR-C maps and neighbors"
    vt c1 'show running-config' | grep -E -A4 'route-map CR-C|prefix-list CR-C|neighbor 10.39.5.2 route-map|neighbor 10.39.2.2 route-map' || true
  fi
  # CR2's connection asks for connected too: it gets them, without a reset.
  local up0; up0=$(cr_sess 1 cr2 | jq -r .uptime_secs)
  t0=$(now_ms)
  cr1 routing.bgp.connection.set '{"id":"cr2","output_redistribute":"connected"}' >/dev/null
  ms=$(wait_for 30 k_via c2 10.39.4.0/30 10.39.5.1) && result announce OK "redistribute connected on CR2's connection: 10.39.4.0/30 on CR2 $(( $(now_ms) - t0 )) ms after the commit (uptime $up0 → $(cr_sess 1 cr2 | jq -r .uptime_secs) s)" \
    || result announce FAIL "CR2: no 10.39.4.0/30 after redistribute connected"
  # The loopback 10.255.39.2/32 is connected too: R3's network line
  # originates it, and CR2's connection now redistributes connected.
  ms=$(wait_for 30 k_via c2 10.255.39.2 10.39.5.1) && result announce OK "CR2 now gets the loopback 10.255.39.2/32 as well: connected, though R3's network line originates it" \
    || result announce FAIL "CR2: no 10.255.39.2/32 after redistribute connected"
  crd 1 r3; pair_down
  cr1 ip.firewall.address-list.list '{"list":"to-r3"}' | jq -r '.[]?.id' | while read -r id; do cr1 ip.firewall.address-list.remove "{\"id\":\"$id\"}" >/dev/null; done
}

# R3 (eBGP, AS 65003) → CR1 → CR2 over iBGP with no IGP between them.
case_nexthop-self() {
  cr2 routing.bgp.instance.set '{"asn":65000,"router_id":"10.255.39.5"}' >/dev/null
  ip -n r3 route add blackhole 203.0.113.0/24
  crc 1 '{"name":"r3","remote_address":"10.39.2.2","remote_as":65003,"input_filter":"all","output_filter":"all"}'
  crc 1 '{"name":"cr2i","remote_address":"10.39.5.2","remote_as":65000,"output_network":"bgp-out"}'
  crc 2 '{"name":"cr1i","remote_address":"10.39.5.1","remote_as":65000,"output_network":"bgp-out"}'
  local ms
  ms=$(wait_for 60 cr_up 1 r3) && result nexthop-self OK "CR1 — R3 (FRR) eBGP in ${ms} ms" || result nexthop-self FAIL "R3: $(cr_state 1 r3)"
  ms=$(wait_for 60 cr_up 1 cr2i) && result nexthop-self OK "iBGP CR1 — CR2 in ${ms} ms" || result nexthop-self FAIL "iBGP: $(cr_state 1 cr2i)"
  wait_for 30 k_has c1 203.0.113.0/24 >/dev/null || result nexthop-self FAIL "CR1 lacks R3's 203.0.113.0/24"
  sleep 3
  local j; j=$(vt c2 'show bgp ipv4 unicast 203.0.113.0/24 json' | jq -c '[.paths[]? | {valid, nh: .nexthops[0].ip, acc: .nexthops[0].accessible}]' 2>/dev/null)
  k_has c2 203.0.113.0/24 && result nexthop-self FAIL "default: CR2 installed a route via an unreachable next hop ($j)" \
    || result nexthop-self OK "default (RFC 4271 §5.1.3, next hop kept on iBGP): CR2 has $j and installs nothing"
  local t0; t0=$(now_ms)
  cr1 routing.bgp.connection.set '{"id":"cr2i","nexthop_choice":"force-self"}' >/dev/null
  ms=$(wait_for 30 k_via c2 203.0.113.0/24 10.39.5.1) && result nexthop-self OK "force-self: CR2 installs it via 10.39.5.1 $(( $(now_ms) - t0 )) ms after the commit" \
    || result nexthop-self FAIL "force-self: '$(k_route c2 203.0.113.0/24)'"
  crd 1 r3; crd 1 cr2i; crd 2 cr1i
  ip -n r3 route del blackhole 203.0.113.0/24
  cr2 routing.bgp.instance.set '{"asn":65002,"router_id":"10.255.39.5"}' >/dev/null
}

# CR1 as route reflector (RFC 4456) for CR2 and R4 (FRR).
case_rr() {
  cr2 routing.bgp.instance.set '{"asn":65000,"router_id":"10.255.39.5"}' >/dev/null
  crc 1 '{"name":"cr2rr","remote_address":"10.39.5.2","remote_as":65000,"local_role":"ibgp-rr"}'
  crc 1 '{"name":"r4rr","remote_address":"10.39.4.2","remote_as":65000,"local_role":"ibgp-rr"}'
  crc 2 '{"name":"cr1","remote_address":"10.39.5.1","remote_as":65000,"output_network":"bgp-out"}'
  vtc r4 'router bgp 65000' 'no neighbor 10.39.4.1 shutdown'
  local ms j
  ms=$(wait_for 60 cr_up 1 cr2rr) || result rr FAIL "CR2 client: $(cr_state 1 cr2rr)"
  ms=$(wait_for 60 cr_up 1 r4rr) || result rr FAIL "R4 client: $(cr_state 1 r4rr)"
  ms=$(wait_for 30 bash -c "python3 -I $W/vty.py /var/run/frr/r4/bgpd.vty 'show bgp ipv4 unicast 100.64.40.0/24 json' | jq -e '.paths[0]' >/dev/null") || true
  j=$(vt r4 'show bgp ipv4 unicast 100.64.40.0/24 json' | jq -c '.paths[0] | {originatorId, clusterList: .clusterList.list, nh: .nexthops[0].ip}' 2>/dev/null)
  [[ $j == *'"originatorId":"10.255.39.5"'* && $j == *10.255.39.2* ]] && result rr OK "CR2 → CR1 (RR) → R4: ORIGINATOR_ID and CLUSTER_LIST $j" || result rr FAIL "R4 got $j"
  ms=$(wait_for 30 bash -c "python3 -I $W/vty.py /var/run/frr/c2/bgpd.vty 'show bgp ipv4 unicast 192.0.2.0/24 json' | jq -e '.paths[0]' >/dev/null") || true
  j=$(vt c2 'show bgp ipv4 unicast 192.0.2.0/24 json' | jq -c '.paths[0] | {originatorId, clusterList: .clusterList.list, nh: .nexthops[0].ip}' 2>/dev/null)
  [[ $j == *'"originatorId":"10.255.39.4"'* ]] && result rr OK "R4 → CR1 (RR) → CR2: $j" || result rr FAIL "CR2 got $j"
  local why; cr2 routing.bgp.route.explain '{"prefix":"192.0.2.0/24"}' >/dev/null 2>&1 || true; sleep 1
  why=$(cr2 routing.bgp.route.explain '{"prefix":"192.0.2.0/24"}' 2>/dev/null || true)
  result rr INFO "route.explain on CR2: $(jq -c '{state, paths: [.paths[]? | {originator_id, cluster_list_len, best}]}' <<< "$why")"
  local t0; t0=$(now_ms)
  cr1 routing.bgp.connection.set '{"id":"r4rr","local_role":"ibgp"}' >/dev/null
  ms=$(wait_for 30 bash -c "! python3 -I $W/vty.py /var/run/frr/r4/bgpd.vty 'show bgp ipv4 unicast 100.64.40.0/24 json' | jq -e '.paths[0]' >/dev/null") \
    && result rr OK "back to plain ibgp: R4 loses CR2's route $(( $(now_ms) - t0 )) ms later (iBGP split horizon, RFC 4271 §9.2)" || result rr FAIL "R4 still has it without reflection"
  crd 1 cr2rr; crd 1 r4rr; crd 2 cr1
  vtc r4 'router bgp 65000' 'neighbor 10.39.4.1 shutdown'
  cr2 routing.bgp.instance.set '{"asn":65002,"router_id":"10.255.39.5"}' >/dev/null
}

case_maxprefix() {
  local i
  for i in 1 2 3 4 5 6; do ip -n r3 route add blackhole "198.18.$i.0/24"; done
  crc 1 '{"name":"r3","remote_address":"10.39.2.2","remote_as":65003,"input_filter":"all","output_filter":"all","max_prefix_ipv4":3}'
  local ms
  # Wait for the Cease itself: the session first has to come up (R3's
  # connect timer, ~5 s when this case runs alone), and down alone proves
  # nothing.
  ms=$(wait_for 60 bash -c "ip netns exec c1 $bin/corerouter-cli --connect 127.0.0.1:7991 run routing.bgp.session.list | jq -e '.[] | select(.connection == \"r3\" and (.reason // \"\" | test(\"prefix\"; \"i\")))' >/dev/null") || true
  # Down is not enough: a session that never came up is down too.
  if cr_up 1 r3; then result maxprefix FAIL "6 > 3 and still Established"
  elif cr_state 1 r3 | grep -qi prefix; then result maxprefix OK "6 prefixes over max_prefix_ipv4=3 (shutdown): $(cr_state 1 r3)"
  else result maxprefix FAIL "down, but not for the prefix limit: $(cr_state 1 r3); CR1's bgpd: $(vt c1 'show bgp neighbors 10.39.2.2 json' | jq -c '."10.39.2.2" | {bgpState, lastResetDueTo, lastNotificationReason}' 2>/dev/null)"
  fi
  result maxprefix INFO "R3 saw: $(vt r3 'show bgp neighbors 10.39.2.1 json' | jq -c '."10.39.2.1" | {bgpState, lastNotificationReason, lastErrorCodeSubcode}' 2>/dev/null)"
  result maxprefix INFO "history: $(cr1 routing.bgp.session.history '{"connection":"r3"}' | jq -c '[.[0:2][] | {event, state, reason}]')"
  cr1 routing.bgp.connection.set '{"id":"r3","max_prefix_action":"warning"}' >/dev/null
  cr1 routing.bgp.session.clear '{"connection":"r3"}' >/dev/null 2>&1 || true
  # The prefix count right at Established is still 0: wait for the six
  # (warning keeps them all, over the limit).
  if ms=$(wait_for 60 cr_up 1 r3); then
    wait_for 15 bash -c "[ \"\$(ip netns exec c1 $bin/corerouter-cli --connect 127.0.0.1:7991 run routing.bgp.session.list | jq -r '.[] | select(.connection == \"r3\") | .prefix_count')\" = 6 ]" >/dev/null \
      && result maxprefix OK "warning: up in ${ms} ms, all 6 prefixes kept" \
      || result maxprefix FAIL "warning: up in ${ms} ms with $(cr_sess 1 r3 | jq -r .prefix_count) prefixes, not 6"
  else
    result maxprefix FAIL "warning: $(cr_state 1 r3)"
  fi
  crd 1 r3
  for i in 1 2 3 4 5 6; do ip -n r3 route del blackhole "198.18.$i.0/24"; done
}

# G3.9ff: graceful restart (RFC 4724). kill -9 of CR1's bgpd (no
# NOTIFICATION: the TCP session just drops) while CR2's clients ping CR1's,
# 20 ms apart, through the BGP routes; once without and once with
# graceful_restart on CR1's connection. bgpd is started again 3 s later
# (the daemon types its config back).
gr_round() { # gr_round <label> <graceful_restart json or empty>
  local label=$1 x=$2 ms t0 lost
  crc 1 "$(jq -c '. + $x' --argjson x "${x:-{\}}" <<< '{"name":"cr2","remote_address":"10.39.5.2","remote_as":65002,"input_filter":"all","output_filter":"all","output_network":"bgp-out"}')"
  crc 2 '{"name":"cr1","remote_address":"10.39.5.1","remote_as":65000,"input_filter":"all","output_filter":"all","output_network":"bgp-out"}'
  wait_for 60 cr_up 1 cr2 >/dev/null || { result gr FAIL "$label: no session"; pair_down; return; }
  wait_for 30 k_has c2 100.64.39.0/24 >/dev/null || true
  wait_for 30 k_has c1 100.64.40.0/24 >/dev/null || true
  sleep 2
  result gr INFO "$label: CR1 sees $(cr_sess 1 cr2 | jq -c '{gr_local, gr_remote, end_of_rib_received}'), CR2 sees $(cr_sess 2 cr1 | jq -c '{gr_local, gr_remote}')"
  ip netns exec c2 ping -i 0.02 -w 14 -I 100.64.40.1 100.64.39.1 > "$W/gr-ping-$label.txt" 2>&1 &
  local pp=$!
  sleep 1
  t0=$(now_ms)
  pkill -9 -f -- "frr/bgpd -N c1( |$)"
  # During the outage: is CR1's route still on CR2, and CR2's on CR1?
  local gone=""; gone=$(wait_for 3 k_none c2 100.64.39.0/24) || gone=""
  local kept1; k_has c1 100.64.40.0/24 && kept1=yes || kept1=no
  # bgpd down ~3 s in both rounds.
  [ -z "$gone" ] || sleep "$(awk -v g="$gone" 'BEGIN { printf "%.3f", (3000 - g) / 1000 }')"
  ip netns exec c1 "$FRR/bgpd" -N c1 -u root -g root -d --limit-fds 4096 -f /etc/frr/c1/bgpd.conf </dev/null >>"$W/frr-c1.log" 2>&1
  ms=$(wait_for 60 cr_up 1 cr2) || true
  wait "$pp" || true
  lost=$(grep -o '[0-9]* received' "$W/gr-ping-$label.txt" | grep -o '[0-9]*'); local sent; sent=$(grep -o '[0-9]* packets transmitted' "$W/gr-ping-$label.txt" | grep -o '^[0-9]*')
  local miss=$(( ${sent:-0} - ${lost:-0} ))
  result gr INFO "$label: CR2 $( [ -n "$gone" ] && echo "withdrew CR1's route ${gone} ms after the kill" || echo "kept CR1's route (stale) through the outage"); CR1's kernel kept CR2's route: $kept1; session back $(( $(now_ms) - t0 )) ms after the kill"
  result gr INFO "$label: ping 20 ms apart: $miss of $sent lost (~$(( miss * 20 )) ms without traffic)"
  echo "$label $miss $sent ${gone:-kept} $kept1" >> "$W/gr-summary.txt"
  crd 1 cr2; crd 2 cr1
  sleep 2
}
case_gr() {
  : > "$W/gr-summary.txt"
  gr_round without ''
  gr_round with '{"graceful_restart":true}'
  local wo w
  wo=$(awk '$1 == "without" {print $2}' "$W/gr-summary.txt"); w=$(awk '$1 == "with" {print $2}' "$W/gr-summary.txt")
  read -r _ _ _ gone kept < <(grep '^with ' "$W/gr-summary.txt")
  [ "$gone" = kept ] && [ "$kept" = yes ] && [ "${w:-999}" -le 5 ] \
    && result gr OK "graceful restart: bgpd killed and back in ~3 s, both routes kept; $w lost pings with it, $wo without" \
    || result gr FAIL "graceful restart: $(cat "$W/gr-summary.txt" | tr '\n' ';')"
}

case_restart() {
  pair_up
  local ms
  ms=$(wait_for 60 cr_up 1 cr2) || { result restart FAIL "no session"; pair_down; return; }
  wait_for 30 k_has c2 100.64.39.0/24 >/dev/null || true
  local up0; up0=$(cr_sess 2 cr1 | jq -r .uptime_secs)
  kill "$(cat "$W/daemon1.pid")"; sleep 1
  local t0; t0=$(now_ms)
  start_daemon 1
  local tr=$(( $(now_ms) - t0 ))
  sleep 5
  local up1; up1=$(cr_sess 2 cr1 | jq -r .uptime_secs)
  cr_up 2 cr1 && k_has c2 100.64.39.0/24 && [ "${up1:-0}" -ge "${up0:-0}" ] \
    && result restart OK "corerouter-daemon restarted (answering in ${tr} ms): the peer's session untouched (uptime $up0 → $up1 s)" \
    || result restart FAIL "daemon restart: CR2 $(cr_state 2 cr1) uptime $up0 → $up1, route '$(k_route c2 100.64.39.0/24)'"
  local t1 lost; t1=$(now_ms)
  pkill -f -- "frr/bgpd -N c1( |$)"
  lost=$(wait_for 30 k_none c2 100.64.39.0/24) || true
  result restart INFO "bgpd killed on CR1: CR2 withdraws 100.64.39.0/24 after ${lost} ms (no graceful restart configured; FRR is a helper only)"
  ip netns exec c1 "$FRR/bgpd" -N c1 -u root -g root -d --limit-fds 4096 -f /etc/frr/c1/bgpd.conf </dev/null >>"$W/frr-c1.log" 2>&1
  ms=$(wait_for 120 k_has c2 100.64.39.0/24) && result restart OK "bgpd started again (empty): the CoreRouter types its config back; CR2 has the route $(( $(now_ms) - t1 )) ms after the kill" \
    || { result restart FAIL "bgpd came back empty and stayed so ($(vt c1 'show running-config' | grep -c neighbor) neighbor lines)"; grep -iE "bgpd|frr" "$W/daemon1.log" | tail -5; }
  pair_down
}

case_bfd() {
  for n in 1 2; do cr "$n" routing.bfd.profile.add '{"name":"g39f","min_tx":100,"min_rx":100,"multiplier":3}' >/dev/null; done
  pair_up '{"bfd":"g39f"}'
  local ms
  ms=$(wait_for 60 cr_up 1 cr2) || { result bfd FAIL "no session"; pair_down; return; }
  ms=$(wait_for 30 bash -c "ip netns exec c1 $bin/corerouter-cli --connect 127.0.0.1:7991 run routing.bfd.session.list | jq -e '.sessions[] | select(.peer == \"10.39.5.2\" and .state == \"up\")' >/dev/null") \
    && result bfd OK "BFD 100 ms × 3 up between the CoreRouters: $(cr1 routing.bfd.session.list | jq -c '[.sessions[] | select(.peer == "10.39.5.2")][0] | {state, users, multiplier}')" \
    || result bfd FAIL "BFD: $(cr1 routing.bfd.session.list | jq -c '.')"
  result bfd INFO "bgpd: $(vt c1 'show bgp neighbors 10.39.5.2 json' | jq -c '."10.39.5.2".peerBfdInfo | {status, type, detectMultiplier}' 2>/dev/null)"
  wait_for 30 k_has c1 100.64.40.0/24 >/dev/null || true
  local t0; t0=$(now_ms)
  ip netns exec c2 tc qdisc add dev ether1 root netem loss 100%
  ms=$(wait_for 20 k_none c1 100.64.40.0/24) \
    && result bfd OK "silent loss on the link: CR1 withdraws CR2's route after ${ms} ms (detect 300 ms; hold time 180 s)" \
    || result bfd FAIL "silent loss: route still on CR1 after 20 s"
  ip netns exec c2 tc qdisc del dev ether1 root
  # session.list is a sample of the FRR poll: a 0.4 s outage can fall
  # between two; the route back in the kernel is what counts.
  ms=$(wait_for 90 k_has c1 100.64.40.0/24) && result bfd OK "loss over: CR2's route back in CR1's kernel in ${ms} ms" || result bfd FAIL "not back: $(cr_state 1 cr2)"
  sleep 3
  result bfd INFO "history (sampled each FRR poll): $(cr1 routing.bgp.session.history '{"connection":"cr2"}' | jq -c '[.[0:3][] | {event, state, reason}]')"
  pair_down
}

# Two eBGP sessions CR1—CR2 (links 5 and 6); CR2 prefers link 5 (lower
# peer address). Cut link 5 three ways, measure until CR2's kernel moves.
case_convergence() {
  for n in 1 2; do cr "$n" routing.bfd.profile.add '{"name":"g39f","min_tx":100,"min_rx":100,"multiplier":3}' >/dev/null 2>&1 || true; done
  local mode
  for mode in hold bfd linkdown; do
    local b=''; [ $mode = bfd ] && b=',"bfd":"g39f"'
    local c='"input_filter":"all","output_filter":"all","output_network":"bgp-out","hold_time":9'
    crc 1 "{\"name\":\"l5\",\"remote_address\":\"10.39.5.2\",\"remote_as\":65002,$c$b}"
    crc 1 "{\"name\":\"l6\",\"remote_address\":\"10.39.6.2\",\"remote_as\":65002,$c$b}"
    crc 2 "{\"name\":\"l5\",\"remote_address\":\"10.39.5.1\",\"remote_as\":65000,$c$b}"
    crc 2 "{\"name\":\"l6\",\"remote_address\":\"10.39.6.1\",\"remote_as\":65000,$c$b}"
    wait_for 60 cr_up 2 l5 >/dev/null || true; wait_for 60 cr_up 2 l6 >/dev/null || true
    wait_for 30 k_via c2 100.64.39.0/24 10.39.5.1 >/dev/null || true
    [ $mode = bfd ] && sleep 3
    if ! k_via c2 100.64.39.0/24 10.39.5.1; then
      result convergence FAIL "$mode: not on link 5 before the cut ($(k_route c2 100.64.39.0/24); l5 $(cr_state 2 l5), l6 $(cr_state 2 l6))"
    else
      local t0 ms; t0=$(now_ms)
      case $mode in
        linkdown) ip -n c1 link set ether1 down ;;
        *) ip netns exec c1 tc qdisc add dev ether1 root netem loss 100% ;;
      esac
      ms=$(wait_for 30 k_via c2 100.64.39.0/24 10.39.6.1) \
        && result convergence OK "$mode cut of link 5 (hold 9 s$([ $mode = bfd ] && echo ', BFD 100 ms × 3')): CR2 on link 6 after ${ms} ms" \
        || result convergence FAIL "$mode cut: CR2 '$(k_route c2 100.64.39.0/24)' after 30 s"
      case $mode in
        linkdown) ip -n c1 link set ether1 up ;;
        *) ip netns exec c1 tc qdisc del dev ether1 root ;;
      esac
    fi
    crd 1 l5; crd 1 l6; crd 2 l5; crd 2 l6
    sleep 2
  done
}

# 100 000 prefixes: R3 (FRR) → CR1 → CR2, with the time, the RSS and the
# CPU of each thread of the daemon, bgpd and zebra.
pid_of() { pgrep -f -- "frr/$1 -N $2( |$)" | head -1; }
cpu_threads() { # cpu_threads <pid>: "tid comm ticks" per thread
  local t
  for t in /proc/"$1"/task/*; do
    [ -r "$t/stat" ] || continue
    awk -v tid="${t##*/}" '{ sub(/^[0-9]+ \(/, ""); split($0, a, ") "); split(a[2], f, " "); gsub(/ /, "_", a[1]); print tid, a[1], f[12] + f[13] }' "$t/stat" 2>/dev/null
  done
}
cpu_report() { # cpu_report <before file> <pid> <ms>: the threads that ran, busiest first
  local hz; hz=$(getconf CLK_TCK)
  cpu_threads "$2" > "$W/cpu.after"
  awk -v hz="$hz" -v ms="$3" 'NR == FNR { b[$1] = $3; next } { d = $3 - b[$1]; if (d > 0) printf "%d %s %.0f%% (%.1fs)\n", d, $2, 100 * d / hz / (ms / 1000), d / hz }' "$1" "$W/cpu.after" \
    | sort -rn | cut -d' ' -f2- | head -8 | tr '\n' ';'
}
rss() { awk '/VmRSS|VmHWM/ {printf "%s %d MiB ", $1, $2/1024}' "/proc/$1/status"; }
case_scale() {
  local N=${SCALE_N:-100000}
  awk -v n="$N" 'BEGIN { for (i = 0; i < n; i++) printf "route add blackhole %d.%d.%d.0/24\n", 20 + int(i / 65536), int(i / 256) % 256, i % 256 }' > "$W/r3.batch"
  ip -n r3 -batch "$W/r3.batch"
  # zebra misses part of 100k kernel notifications sent at once (its netlink
  # buffer, which a user namespace cannot raise): it reads the table whole
  # at start, so restart R3's FRR on the loaded table.
  pkill -f -- "frr/[a-z]+ -N r3( |$)" || true
  sleep 1
  frr_start r3 zebra bgpd
  r3_ready() { [ "$(vtz r3 'show ip route summary json' | jq '[.routes[]? | select(.type == "kernel") | .rib] | add // 0')" -ge "$N" ]; }
  local ms0; ms0=$(wait_for 120 r3_ready) || true
  result scale INFO "R3 holds $(vtz r3 'show ip route summary json' | jq '[.routes[]? | select(.type == "kernel") | .rib] | add // 0') kernel routes (${ms0} ms after its restart)"
  local d1 b1 z1 d2 b2 z2
  d1=$(cat "$W/daemon1.pid"); b1=$(pid_of bgpd c1); z1=$(pid_of zebra c1)
  d2=$(cat "$W/daemon2.pid"); b2=$(pid_of bgpd c2); z2=$(pid_of zebra c2)
  result scale INFO "before — CR1: daemon $(rss "$d1"), bgpd $(rss "$b1"), zebra $(rss "$z1")"
  cpu_threads "$d1" > "$W/cpu.d1"; cpu_threads "$b1" > "$W/cpu.b1"; cpu_threads "$z1" > "$W/cpu.z1"
  local t0 ms el
  t0=$(now_ms)
  crc 1 '{"name":"r3","remote_address":"10.39.2.2","remote_as":65003,"input_filter":"all","output_filter":"all","max_prefix_ipv4":200000}'
  ms=$(wait_for 300 bash -c "[ \$(ip -n c1 route show proto bgp | wc -l) -ge $N ]") \
    && result scale OK "R3 (FRR) → CR1: $N prefixes in CR1's kernel ${ms} ms after the config" \
    || { result scale FAIL "after 300 s CR1's kernel has $(bgp_count c1)"; vt c1 'show bgp summary' | tail -6; vt r3 'show bgp summary' | tail -4; ip -n r3 route | wc -l; vtz r3 'show ip route summary' | tail -8; }
  el=$(( $(now_ms) - t0 ))
  result scale INFO "after — CR1: daemon $(rss "$d1"), bgpd $(rss "$b1"), zebra $(rss "$z1")"
  result scale INFO "CPU over ${el} ms — daemon: $(cpu_report "$W/cpu.d1" "$d1" "$el")"
  result scale INFO "CPU — bgpd: $(cpu_report "$W/cpu.b1" "$b1" "$el")"
  result scale INFO "CPU — zebra: $(cpu_report "$W/cpu.z1" "$z1" "$el")"
  cpu_threads "$d1" > "$W/cpu.d1"; cpu_threads "$b1" > "$W/cpu.b1"
  sleep 30
  result scale INFO "idle 30 s with $N — daemon: $(cpu_report "$W/cpu.d1" "$d1" 30000) bgpd: $(cpu_report "$W/cpu.b1" "$b1" 30000)"
  local tq st
  tq=$(now_ms); cr1 routing.bgp.session.list >/dev/null; result scale INFO "routing.bgp.session.list: $(( $(now_ms) - tq )) ms"
  tq=$(now_ms)
  for _ in $(seq 240); do st=$(cr1 routing.bgp.route.list '{"connection":"r3","limit":10}' | jq -r .state); [ "$st" = loading ] || break; sleep 0.25; done
  result scale INFO "routing.bgp.route.list (first page of $N): $(( $(now_ms) - tq )) ms, state $st, daemon $(rss "$d1")"
  tq=$(now_ms); cr1 routing.bgp.route.list '{"connection":"r3","prefix":"21.1.2.0/24","match":"exact"}' >/dev/null
  result scale INFO "route.list one prefix (cached): $(( $(now_ms) - tq )) ms"
  tq=$(now_ms); cr1 routing.bgp.route.summary >/dev/null; result scale INFO "route.summary: $(( $(now_ms) - tq )) ms"
  tq=$(now_ms); cr1 ip.route.page '{"limit":10}' >/dev/null 2>&1; result scale INFO "ip.route.page (10 of $N): $(( $(now_ms) - tq )) ms"
  # CR1 → CR2 (eBGP): CoreRouter to CoreRouter.
  result scale INFO "before — CR2: daemon $(rss "$d2"), bgpd $(rss "$b2"), zebra $(rss "$z2")"
  cpu_threads "$d2" > "$W/cpu.d2"; cpu_threads "$b2" > "$W/cpu.b2"; cpu_threads "$z2" > "$W/cpu.z2"
  t0=$(now_ms)
  pair_up '{"max_prefix_ipv4":200000}'
  ms=$(wait_for 300 bash -c "[ \$(ip -n c2 route show proto bgp | wc -l) -ge $N ]") \
    && result scale OK "CR1 → CR2: $N prefixes in CR2's kernel ${ms} ms after the config" \
    || result scale FAIL "CR2 has $(bgp_count c2) after 300 s"
  el=$(( $(now_ms) - t0 ))
  result scale INFO "after — CR2: daemon $(rss "$d2"), bgpd $(rss "$b2"), zebra $(rss "$z2")"
  result scale INFO "CR2 CPU over ${el} ms — daemon: $(cpu_report "$W/cpu.d2" "$d2" "$el")"
  result scale INFO "CR2 CPU — bgpd: $(cpu_report "$W/cpu.b2" "$b2" "$el")"
  result scale INFO "CR2 CPU — zebra: $(cpu_report "$W/cpu.z2" "$z2" "$el")"
  t0=$(now_ms)
  cr1 routing.bgp.session.clear '{"connection":"cr2"}' >/dev/null
  wait_for 60 bash -c "[ \$(ip -n c2 route show proto bgp | wc -l) -lt $N ]" >/dev/null || true
  ms=$(wait_for 300 bash -c "[ \$(ip -n c2 route show proto bgp | wc -l) -ge $N ]") \
    && result scale OK "session.clear CR1—CR2: $N back in CR2's kernel $(( $(now_ms) - t0 )) ms after the clear" \
    || result scale FAIL "after clear: CR2 has $(bgp_count c2)"
  t0=$(now_ms)
  crd 1 r3
  ms=$(wait_for 300 bash -c "[ \$(ip -n c2 route show proto bgp | wc -l) -lt 10 ]") \
    && result scale OK "R3 removed on CR1: $N withdrawn from CR1 and CR2's kernels in ${ms} ms" \
    || result scale FAIL "withdraw: CR1 $(bgp_count c1), CR2 $(bgp_count c2) left"
  pair_down
  sed 's/^route add/route del/' "$W/r3.batch" | ip -n r3 -batch - 2>/dev/null || true
}

# G3.9fe: OSPF between the two CoreRouters, CR1 redistributing a static route.
case_ospf-static() {
  for n in 1 2; do
    cr "$n" routing.ospf.instance.add "{\"name\":\"v2\",\"router_id\":\"10.255.39.$([ "$n" = 1 ] && echo 2 || echo 5)\"}" >/dev/null
    cr "$n" routing.ospf.area.add '{"name":"backbone","instance":"v2","area_id":"0.0.0.0"}' >/dev/null
    cr "$n" routing.ospf.interface-template.add '{"area":"backbone","interfaces":"ether1","type":"ptp","hello_interval":1,"dead_interval":4}' >/dev/null
  done
  cr1 ip.route.add '{"dst_address":"198.18.97.0/24","gateway":"10.39.4.2"}' >/dev/null
  cr1 routing.ospf.instance.set '{"id":"v2","redistribute":"static"}' >/dev/null
  local ms
  ms=$(wait_for 60 k_has c2 10.255.39.2/32) || true
  ms=$(wait_for 30 k_has c2 198.18.97.0/24) && result ospf-static OK "redistribute=static: CR1's static 198.18.97.0/24 on CR2 via OSPF in ${ms} ms" \
    || result ospf-static FAIL "redistribute=static: CR2 has no 198.18.97.0/24 ($(python3 -I "$W/vty.py" /var/run/frr/c1/ospfd.vty 'show running-config' | grep redistribute); zebra on CR1 sees $(vtz c1 'show ip route 198.18.97.0/24 json' | jq -c '[."198.18.97.0/24"[]?.protocol]'))"
  # A kernel route that is not a CoreRouter static (another program's)
  # must stay out with redistribute=static, and go with kernel.
  ip -n c1 route add 198.18.95.0/24 via 10.39.4.2 proto boot
  sleep 8
  k_has c2 198.18.95.0/24 && result ospf-static FAIL "redistribute=static leaks a kernel route that is no static (198.18.95.0/24)" \
    || result ospf-static OK "redistribute=static: a kernel route of another program stays out"
  local t0; t0=$(now_ms)
  cr1 ip.route.add '{"dst_address":"198.18.96.0/24","gateway":"10.39.4.2"}' >/dev/null
  ms=$(wait_for 30 k_has c2 198.18.96.0/24) && result ospf-static OK "a static added later reaches CR2 $(( $(now_ms) - t0 )) ms after the command" \
    || result ospf-static FAIL "a static added later is not announced"
  cr1 routing.ospf.instance.set '{"id":"v2","redistribute":"kernel"}' >/dev/null
  ms=$(wait_for 30 k_has c2 198.18.95.0/24) && result ospf-static OK "redistribute=kernel takes the other kernel route too (${ms} ms)" || result ospf-static FAIL "redistribute=kernel: 198.18.95.0/24 not on CR2"
}

for c in "${CASES[@]}"; do
  echo "=== $c ==="
  "case_$c" || result "$c" FAIL "the case stopped: exit $?"
done
echo
echo "=== results (CoreRouter $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo ?) × CoreRouter, FRR 10.7.1) ==="
cat "$W/results.txt"
for n in 1 2; do
  echo "--- daemon $n warnings ---"; grep -iE "warn|error|refused" "$W/daemon$n.log" | sed 's/^[^ ]* //' | sort | uniq -c | sort -rn | head -10 || true
done
exit $FAILED
