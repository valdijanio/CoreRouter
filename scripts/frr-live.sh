#!/usr/bin/env bash
# G3.1: hal-frr against a real FRR and a real BGP peer. Runs as root inside
# the lab VM only (it starts FRR and a second bgpd in the namespace
# `crfrrpeer`, joined by a veth pair):
#   cargo xtask vm-lab run -- scripts/frr-live.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
sed -i "s/^bgpd=no/bgpd=yes/" /etc/frr/daemons
systemctl restart frr
# The peer: zebra + bgpd of FRR instance `crpeer` in its own namespace.
pkill -f -- "-N crpeer" 2>/dev/null || true
ip netns del crfrrpeer 2>/dev/null || true
ip link del crfrr-a 2>/dev/null || true
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
for _ in $(seq 50); do [ -S /var/run/frr/bgpd.vty ] && break; sleep 0.2; done
status=0
COREROUTER_FRR_LIVE=1 cargo test -p corerouter-hal-frr --test frr_live -- --nocapture || status=$?

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
    systemctl restart frr
    for _ in $(seq 40); do vtysh -c "show running-config" 2>/dev/null | grep -q "^router bgp 65000" && break; sleep 0.25; done
    vtysh -c "show running-config" | grep -q "^router bgp 65000" || { echo "FAIL: no resync after FRR restart"; return 1; }
    echo "OK: running config installed again after FRR restarted"
    cli routing.backend.get
    cli routing.bgp.session.list
  }
  e2e || status=1
  kill "$dpid" || true
  grep -iE "frr|route" /tmp/crfrr-daemon.log | tail -5 || true
fi
pkill -f -- "-N crpeer" || true
ip netns del crfrrpeer || true
exit $status
