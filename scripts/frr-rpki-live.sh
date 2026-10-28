#!/usr/bin/env bash
# G3.2c: RPKI, the route lists and "Why this route?" against a real FRR
# (with bgpd_rpki: package frr-rpki-rtrlib, `cargo xtask vm-lab tools`) and a
# local RTR validator (hal-frr's example `rtr_server`, fixed VRPs: no
# internet). Runs as root inside the lab VM only:
#   cargo xtask vm-lab run -- scripts/frr-rpki-live.sh
# Two iBGP peers in namespaces announce 10.20.1.0/24 with local-pref 200 and
# 100 (the explain must say "local-pref"); peer 2 also announces
# 10.66.0.0/24, which a /16 ROA with max length 16 makes invalid (CoreRouter
# must drop it), and 10.30.2.0/24, valid.
# FRR_DEMO=<seconds>: no checks; the daemon (control 7982) stays up that
# long for screenshots (ssh -L from the host).
set -euo pipefail
# vm-lab run holds its lock on fd 9: a daemon started from here would
# inherit it and keep the VM locked after the round.
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
[ -f /usr/lib/x86_64-linux-gnu/frr/modules/bgpd_rpki.so ] \
  || { echo "FAIL: no bgpd_rpki (install frr-rpki-rtrlib: cargo xtask vm-lab tools)"; exit 1; }
sed -i "s/^bgpd=no/bgpd=yes/" /etc/frr/daemons
# bgpd loads the rpki module (FRR docs: `-M rpki` in bgpd_options).
grep -q '^bgpd_options=.*-M rpki' /etc/frr/daemons \
  || sed -i 's/^bgpd_options="\(.*\)"/bgpd_options="\1 -M rpki"/' /etc/frr/daemons
[ -f /etc/frr/frr.conf.crorig ] || cp -p /etc/frr/frr.conf /etc/frr/frr.conf.crorig
sed -i '/^ip prefix-list \(BIG\|L\|T\) /d; /^router bgp /,/^exit/d' /etc/frr/frr.conf.crorig
cp -p /etc/frr/frr.conf.crorig /etc/frr/frr.conf
systemctl reset-failed frr 2>/dev/null || true
systemctl restart frr

cargo build -q -p corerouter-daemon -p corerouter-cli
cargo build -q -p corerouter-hal-frr --example rtr_server
bin="${CARGO_TARGET_DIR:-target}/debug"

work=/tmp/crrpki
rm -rf "$work"; mkdir -p "$work"
cat > "$work/vrps.txt" <<'VRPS'
# prefix max_length asn
10.66.0.0/16 16 64502     # 10.66.0.0/24 is too specific: invalid
10.30.0.0/16 24 64502     # 10.30.2.0/24 from AS 64502: valid
2001:db8::/32 48 64500
VRPS
pkill -f "rtr_server 127.0.0.1:3323" 2>/dev/null || true
"$bin/examples/rtr_server" 127.0.0.1:3323 "$work/vrps.txt" > "$work/rtr.log" 2>&1 &
rtr=$!

pkill -f -- "-N crpeer" 2>/dev/null || true
for n in 2 3; do ip netns del crfrrpeer$n 2>/dev/null || true; done
ip link del crfrr-c 2>/dev/null || true; ip link del crfrr-e 2>/dev/null || true
# peer <n> <our veth> <their veth> <our addr> <their addr> <local-pref> <extra networks>
peer() {
  local n=$1
  ip netns add crfrrpeer$n
  ip link add "$2" type veth peer name "$3" netns crfrrpeer$n
  ip addr add "$4/30" dev "$2"; ip link set "$2" up
  ip -n crfrrpeer$n addr add "$5/30" dev "$3"; ip -n crfrrpeer$n link set "$3" up
  ip -n crfrrpeer$n link set lo up
  install -d -o frr -g frr /etc/frr/crpeer$n /var/run/frr/crpeer$n
  {
    echo "router bgp 65000"
    echo " bgp router-id $5"
    echo " no bgp network import-check"
    echo " neighbor $4 remote-as 65000"
    echo " address-family ipv4 unicast"
    echo "  network 10.20.1.0/24 route-map LP"
    for x in $7; do echo "  network $x"; done
    echo "  neighbor $4 route-map OUT out"
    echo " exit-address-family"
    echo "exit"
    echo "route-map LP permit 10"
    echo " set local-preference $6"
    echo " set community 65000:$n 65000:100"
    echo "exit"
    echo "route-map OUT permit 10"
    echo " set as-path prepend 6450$n 6450$n"
    echo "exit"
  } > /etc/frr/crpeer$n/bgpd.conf
  touch /etc/frr/crpeer$n/zebra.conf; chown frr:frr /etc/frr/crpeer$n/*.conf
  ip netns exec crfrrpeer$n /usr/lib/frr/zebra -N crpeer$n -d -f /etc/frr/crpeer$n/zebra.conf
  sleep 1
  ip netns exec crfrrpeer$n /usr/lib/frr/bgpd -N crpeer$n -d -f /etc/frr/crpeer$n/bgpd.conf
}
peer 2 crfrr-c crfrr-d 198.51.100.17 198.51.100.18 200 "10.66.0.0/24 10.30.2.0/24"
peer 3 crfrr-e crfrr-f 198.51.100.21 198.51.100.22 100 ""
for _ in $(seq 50); do [ -S /var/run/frr/bgpd.vty ] && break; sleep 0.2; done

export COREROUTER_RUNTIME_DIR=/tmp/crrpki-run
mkdir -p "$COREROUTER_RUNTIME_DIR"
port=${FRR_DEMO:+7982}; port=${port:-7983}
"$bin/corerouter-daemon" --control "$port" --frr /var/run/frr > "$work/daemon.log" 2>&1 &
dpid=$!
cleanup() {
  kill "$dpid" "$rtr" 2>/dev/null || true
  pkill -f -- "-N crpeer" || true
  for n in 2 3; do ip netns del crfrrpeer$n 2>/dev/null || true; done
}
trap cleanup EXIT
cli() { "$bin/corerouter-cli" --connect "127.0.0.1:$port" run "$@"; }
for _ in $(seq 50); do cli routing.backend.get >/dev/null 2>&1 && break; sleep 0.2; done
cli routing.bgp.instance.set '{"asn":65000,"router_id":"198.51.100.1"}' >/dev/null
cli routing.bgp.connection.add '{"name":"rr2","remote_address":"198.51.100.18","remote_as":65000}' >/dev/null
cli routing.bgp.connection.add '{"name":"rr3","remote_address":"198.51.100.22","remote_as":65000}' >/dev/null
cli routing.rpki.add '{"name":"lab","address":"127.0.0.1","port":3323,"refresh_interval":30}'

if [ -n "${FRR_DEMO:-}" ]; then
  echo "demo up for $FRR_DEMO s (control 127.0.0.1:$port in the VM)"
  sleep "$FRR_DEMO" || true
  exit 0
fi

# py <json> <python expression over j>
py() { python3 -c "import json,sys; j=json.loads(sys.argv[1]); print($2)" "$1"; }
wait_for() { # <what> <command…>: retry up to 60 s
  local what=$1; shift
  for _ in $(seq 120); do "$@" && return 0; sleep 0.5; done
  echo "FAIL: $what"; return 1
}
established() { [ "$(py "$(cli routing.bgp.session.list)" "sum(1 for s in j if s['established'])")" = 2 ]; }
synced() { [ "$(py "$(cli routing.rpki.session.list)" "j['sessions'][0]['state'] if j['sessions'] else ''")" = sync ]; }
frr_rpki() { vtysh -c "show rpki cache-connection" | grep -qi connected; }
status=0
check() {
  wait_for "the two iBGP sessions" established
  echo "OK: rr2 and rr3 established"
  wait_for "CoreRouter's RTR client in sync" synced
  echo "OK: RTR in sync: $(py "$(cli routing.rpki.session.list)" "j['sessions'][0]")"
  wait_for "bgpd's RTR session" frr_rpki
  echo "OK: bgpd: $(vtysh -c 'show rpki cache-connection' | tr '\n' ' ' | head -c 200)"
  echo "--- FRR running config (CoreRouter's part):"
  vtysh -c "show running-config" | sed -n '/^router bgp/,$p'
  if grep -q "differently from CoreRouter's render" "$work/daemon.log"; then
    echo "FAIL: FRR prints the RPKI render differently (typed again every sync):"
    grep "differently" "$work/daemon.log" | tail -2; return 1
  fi
  echo "OK: the render is FRR's canonical form"
  # The invalid route is dropped (soft-reconfiguration keeps it in the
  # Adj-RIB-In, flagged).
  gone() { ! vtysh -c "show bgp ipv4 unicast 10.66.0.0/24 json" | grep -q '"paths"'; }
  wait_for "10.66.0.0/24 (RPKI invalid) dropped by bgpd" gone
  echo "OK: bgpd dropped the invalid 10.66.0.0/24"
  list() { cli routing.bgp.route.list "{\"connection\":\"rr2\"$1}"; }
  ready() { [ "$(py "$(list "")" "j['state']")" = ready ]; }
  wait_for "rr2's received routes" ready
  local l; l=$(list "")
  echo "routes of rr2: $(py "$l" "[(r['prefix'], r['rpki'], r['filtered']) for r in j['rows']]")"
  echo "summary: $(py "$l" "j['summary']") (read in $(py "$l" "j['load_ms']") ms)"
  [ "$(py "$l" "[r for r in j['rows'] if r['prefix']=='10.66.0.0/24'][0]['rpki']")" = invalid ] || { echo "FAIL: 10.66.0.0/24 not invalid"; return 1; }
  [ "$(py "$l" "[r for r in j['rows'] if r['prefix']=='10.66.0.0/24'][0]['filtered']")" = True ] || { echo "FAIL: 10.66.0.0/24 not flagged filtered"; return 1; }
  [ "$(py "$l" "[r for r in j['rows'] if r['prefix']=='10.30.2.0/24'][0]['rpki']")" = valid ] || { echo "FAIL: 10.30.2.0/24 not valid"; return 1; }
  echo "OK: received list: 10.66.0.0/24 invalid and filtered, 10.30.2.0/24 valid"
  [ "$(py "$(list ',"rpki":"invalid"')" "j['total']")" = 1 ] || { echo "FAIL: rpki filter"; return 1; }
  [ "$(py "$(list ',"as_path":"^64502"')" "j['total']")" = 3 ] || { echo "FAIL: as_path search"; return 1; }
  echo "OK: searches by RPKI state and AS path"
  # Why this route? Two paths, local-pref 200 (rr2) and 100 (rr3).
  ex() { cli routing.bgp.route.explain '{"prefix":"10.20.1.0/24"}'; }
  exready() { [ "$(py "$(ex)" "j['state']")" = ready ]; }
  wait_for "the explanation" exready
  local e; e=$(ex)
  echo "explain: $(py "$e" "[(p['connection'], p['best'], p['local_pref'], (p['lost_at'] or {}).get('step'), p['selection_reason']) for p in j['paths']]") in $(py "$e" "j['load_ms']") ms"
  [ "$(py "$e" "[p for p in j['paths'] if p['best']][0]['connection']")" = rr2 ] || { echo "FAIL: best is not rr2"; return 1; }
  [ "$(py "$e" "[p for p in j['paths'] if not p['best']][0]['lost_at']['step']")" = local-pref ] || { echo "FAIL: the step is not local-pref"; return 1; }
  [ "$(py "$e" "j['agrees']")" = True ] || { echo "FAIL: our comparison disagrees with bgpd"; return 1; }
  echo "OK: explain: rr3's path lost at local-pref (200 > 100), as bgpd says"
  # The switch per connection: accept invalid on rr2, the route comes in.
  cli routing.rpki.invalid.set '{"connection":"rr2","invalid":"accept"}'
  back() { vtysh -c "show bgp ipv4 unicast 10.66.0.0/24 json" | grep -q '"paths"'; }
  wait_for "10.66.0.0/24 accepted with rpki_invalid=accept" back
  echo "OK: rpki_invalid=accept on rr2 lets the invalid route in"
  cli routing.rpki.invalid.set '{"connection":"rr2"}' >/dev/null
  wait_for "10.66.0.0/24 dropped again" gone
  echo "OK: back to reject"
  # Flap history.
  cli routing.bgp.session.clear '{"connection":"rr3"}' >/dev/null
  flapped() { [ "$(py "$(cli routing.bgp.session.history '{"connection":"rr3"}')" "len(j)")" -ge 1 ]; }
  wait_for "a flap in rr3's history" flapped
  echo "OK: history: $(py "$(cli routing.bgp.session.history '{"connection":"rr3"}')" "j[:2]")"
}
check || status=1
grep -iE "rpki|error" "$work/daemon.log" | tail -5 || true
exit $status
