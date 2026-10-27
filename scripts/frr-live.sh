#!/usr/bin/env bash
# G3.1: hal-frr against a real FRR and a real BGP peer. Runs as root inside
# the lab VM only (it starts FRR and a second bgpd in the namespace
# `crfrrpeer`, joined by a veth pair):
#   cargo xtask vm-lab run -- scripts/frr-live.sh
# FRR_DEMO=<seconds>: no tests; the daemon (control port 7981) runs with
# the two peers and a few connections for that long, for screenshots of
# Routing › BGP (a GUI on the host reaches it through `ssh -L`).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
sed -i "s/^bgpd=no/bgpd=yes/" /etc/frr/daemons
# Start from the package's frr.conf (frr-compare.sh's frr-reload.py rounds
# save theirs; an earlier round may have saved its test lines into the copy).
[ -f /etc/frr/frr.conf.crorig ] || cp -p /etc/frr/frr.conf /etc/frr/frr.conf.crorig
sed -i '/^ip prefix-list \(BIG\|L\|T\) /d; /^router bgp /,/^exit/d' /etc/frr/frr.conf.crorig
cp -p /etc/frr/frr.conf.crorig /etc/frr/frr.conf
systemctl reset-failed frr 2>/dev/null || true  # many rounds in a row hit start-limit
systemctl restart frr
# The peer: zebra + bgpd of FRR instance `crpeer` in its own namespace.
pkill -f -- "-N crpeer" 2>/dev/null || true
ip netns del crfrrpeer 2>/dev/null || true
ip netns del crfrrpeer2 2>/dev/null || true
ip link del crfrr-a 2>/dev/null || true
ip link del crfrr-c 2>/dev/null || true
ip netns add crfrrpeer
ip link add crfrr-a type veth peer name crfrr-b netns crfrrpeer
ip addr add 198.51.100.1/30 dev crfrr-a
ip link set crfrr-a up
ip -n crfrrpeer addr add 198.51.100.2/30 dev crfrr-b
ip -n crfrrpeer addr add 203.0.113.1/24 dev lo
ip -n crfrrpeer link set crfrr-b up
ip -n crfrrpeer link set lo up
install -d -o frr -g frr /etc/frr/crpeer /var/run/frr/crpeer
cat > /etc/frr/crpeer/bgpd.conf <<'CONF'
router bgp 65100
 bgp router-id 198.51.100.2
 no bgp ebgp-requires-policy
 neighbor 198.51.100.1 remote-as 65000
 address-family ipv4 unicast
  network 203.0.113.0/24
 exit-address-family
exit
CONF
touch /etc/frr/crpeer/zebra.conf
chown frr:frr /etc/frr/crpeer/*.conf
ip netns exec crfrrpeer /usr/lib/frr/zebra -N crpeer -d -f /etc/frr/crpeer/zebra.conf
sleep 1
ip netns exec crfrrpeer /usr/lib/frr/bgpd -N crpeer -d -f /etc/frr/crpeer/bgpd.conf
# G3.2a: the second peer, iBGP (AS 65000) with a TCP MD5 key and 20
# prefixes, in `crfrrpeer2` (instance `crpeer2`).
ip netns add crfrrpeer2
ip link add crfrr-c type veth peer name crfrr-d netns crfrrpeer2
ip addr add 198.51.100.17/30 dev crfrr-c
ip link set crfrr-c up
ip -n crfrrpeer2 addr add 198.51.100.18/30 dev crfrr-d
ip -n crfrrpeer2 link set crfrr-d up
ip -n crfrrpeer2 link set lo up
install -d -o frr -g frr /etc/frr/crpeer2 /var/run/frr/crpeer2
{
  echo "router bgp 65000"
  echo " bgp router-id 198.51.100.18"
  echo " no bgp network import-check"
  echo " neighbor 198.51.100.17 remote-as 65000"
  echo " neighbor 198.51.100.17 password Sup3rS3cret"
  echo " address-family ipv4 unicast"
  for i in $(seq 1 20); do echo "  network 10.20.$i.0/24"; done
  echo " exit-address-family"
  echo "exit"
} > /etc/frr/crpeer2/bgpd.conf
touch /etc/frr/crpeer2/zebra.conf
chown frr:frr /etc/frr/crpeer2/*.conf
ip netns exec crfrrpeer2 /usr/lib/frr/zebra -N crpeer2 -d -f /etc/frr/crpeer2/zebra.conf
sleep 1
ip netns exec crfrrpeer2 /usr/lib/frr/bgpd -N crpeer2 -d -f /etc/frr/crpeer2/bgpd.conf
for _ in $(seq 50); do [ -S /var/run/frr/bgpd.vty ] && break; sleep 0.2; done
status=0
if [ -n "${FRR_DEMO:-}" ]; then
  cargo build -q -p corerouter-daemon -p corerouter-cli
  bin="${CARGO_TARGET_DIR:-target}/debug"
  export COREROUTER_RUNTIME_DIR=/tmp/crfrr-run
  mkdir -p "$COREROUTER_RUNTIME_DIR"
  "$bin/corerouter-daemon" --control 7981 --frr /var/run/frr > /tmp/crfrr-daemon.log 2>&1 &
  dpid=$!
  cli() { "$bin/corerouter-cli" --connect 127.0.0.1:7981 run "$@"; }
  for _ in $(seq 50); do cli routing.backend.get >/dev/null 2>&1 && break; sleep 0.2; done
  cli routing.bgp.instance.set '{"asn":65000,"router_id":"198.51.100.1"}'
  cli routing.bgp.template.add '{"name":"transit","local_role":"ebgp-customer","hold_time":90,"afi":"ip,ipv6","max_prefix_ipv4":1200000,"max_prefix_ipv6":250000}'
  cli routing.bgp.template.add '{"name":"core","local_role":"ibgp","nexthop_choice":"force-self","max_prefix_ipv4":100}'
  cli routing.bgp.connection.add '{"name":"upstream1","remote_address":"198.51.100.2","remote_as":65100,"templates":"transit","comment":"trânsito A"}'
  cli routing.bgp.connection.add '{"name":"rr1","remote_address":"198.51.100.18","templates":"core","tcp_md5_key":"Sup3rS3cret","comment":"route reflector"}'
  cli routing.bgp.connection.add '{"name":"ix-sp","remote_address":"203.0.113.250","remote_as":26162,"templates":"transit","multihop":true}'
  cli routing.bgp.connection.add '{"name":"upstream2","remote_address":"2001:db8:ffff::1","remote_as":64500,"templates":"transit","disabled":true,"comment":"em manutenção"}'
  echo "demo up for $FRR_DEMO s (control 127.0.0.1:7981 in the VM)"
  sleep "$FRR_DEMO" || true
  kill "$dpid" || true
  pkill -f -- "-N crpeer" || true
  ip netns del crfrrpeer || true
  ip netns del crfrrpeer2 || true
  exit 0
fi
COREROUTER_FRR_LIVE=1 cargo test -p corerouter-hal-frr --test frr_live -- --nocapture || status=$?
if [ "$status" = 0 ]; then
  COREROUTER_FRR_LIVE=1 cargo test -p corerouter-hal-frr --test frr_bgp_live -- --nocapture || status=$?
fi

# End to end: the daemon with --frr, a commit from the CLI, FRR restarted.
if [ "$status" = 0 ]; then
  cargo build -q -p corerouter-daemon -p corerouter-cli
  bin="${CARGO_TARGET_DIR:-target}/debug"
  export COREROUTER_RUNTIME_DIR=/tmp/crfrr-run
  mkdir -p "$COREROUTER_RUNTIME_DIR"
  "$bin/corerouter-daemon" --control 7981 --frr /var/run/frr > /tmp/crfrr-daemon.log 2>&1 &
  dpid=$!
  cli() { "$bin/corerouter-cli" --connect 127.0.0.1:7981 run "$@"; }
  for _ in $(seq 50); do cli routing.backend.get >/dev/null 2>&1 && break; sleep 0.2; done
  e2e() {
    cli routing.bgp.instance.set '{"asn":65000,"router_id":"198.51.100.1"}'
    vtysh -c "show running-config" | grep -q "^router bgp 65000" || { echo "FAIL: commit did not reach bgpd"; return 1; }
    echo "OK: commit reached bgpd"
    systemctl reset-failed frr 2>/dev/null || true
    systemctl restart frr
    for _ in $(seq 40); do vtysh -c "show running-config" 2>/dev/null | grep -q "^router bgp 65000" && break; sleep 0.25; done
    vtysh -c "show running-config" | grep -q "^router bgp 65000" || { echo "FAIL: no resync after FRR restart"; return 1; }
    echo "OK: running config installed again after FRR restarted"
    cli routing.backend.get
    cli routing.bgp.session.list
    # G3.2a through the engine: the key sealed by the command reaches
    # bgpd in clear (the session comes up) and nowhere else.
    # field <connection> <key>: that field of the connection's session.
    field() { cli routing.bgp.session.list | python3 -c "import json,sys
for s in json.load(sys.stdin):
    if s.get('connection') == '$1': print(s.get('$2'))"; }
    until_field() { for _ in $(seq 120); do [ "$(field "$1" "$2")" = "$3" ] && return 0; sleep 0.5; done; return 1; }
    cli routing.bgp.connection.add '{"name":"up1","remote_address":"198.51.100.2","remote_as":65100}'
    cli routing.bgp.connection.add '{"name":"ibgp2","remote_address":"198.51.100.18","local_role":"ibgp","tcp_md5_key":"Sup3rS3cret","max_prefix_ipv4":100}'
    until_field ibgp2 established True || { echo "FAIL: ibgp2 (sealed MD5 key) did not come up"; cli routing.bgp.session.list; return 1; }
    echo "OK: the sealed TCP MD5 key reached bgpd and the session is up ($(field ibgp2 prefix_count) prefixes)"
    until_field up1 established True || { echo "FAIL: up1 did not come up"; return 1; }
    f1=$(field up1 flaps)
    cli routing.bgp.connection.set '{"id":"ibgp2","max_prefix_ipv4":10}'
    until_field ibgp2 established False || { echo "FAIL: max-prefix did not close ibgp2"; return 1; }
    echo "OK: max-prefix closed ibgp2: $(field ibgp2 reason) / $(field ibgp2 last_error)"
    [ "$(field up1 flaps)" = "$f1" ] && [ "$(field up1 established)" = True ] \
      || { echo "FAIL: up1 flapped ($f1 → $(field up1 flaps))"; return 1; }
    echo "OK: up1 stayed up while ibgp2 changed"
    cli routing.bgp.session.refresh '{"connection":"up1"}'
    cli routing.bgp.connection.list
    leak=0
    for f in /tmp/crfrr-daemon.log "$COREROUTER_RUNTIME_DIR"/*; do
      [ -f "$f" ] && grep -l "Sup3rS3cret" "$f" && leak=1
    done
    "$bin/corerouter-cli" --connect 127.0.0.1:7981 inspect | grep -q "Sup3rS3cret" && leak=1
    cli routing.bgp.connection.list | grep -q "Sup3rS3cret" && leak=1
    [ "$leak" = 0 ] || { echo "FAIL: the MD5 key leaked"; return 1; }
    echo "OK: the MD5 key is in no log, state, journal or answer"
  }
  e2e || status=1
  kill "$dpid" || true
  grep -iE "frr|route" /tmp/crfrr-daemon.log | tail -5 || true
fi
pkill -f -- "-N crpeer" || true
ip netns del crfrrpeer || true
ip netns del crfrrpeer2 || true
exit $status
