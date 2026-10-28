#!/usr/bin/env bash
# G3.6i: our engine as bfdd's data plane (G3.6b) with a real bgpd. Runs as
# root inside the lab VM only:
#   cargo xtask vm-lab run -- scripts/frr-bfd-dplane-live.sh
# The VM's FRR runs bfdd with --dplaneaddr; corerouter-daemon (--frr)
# connects to it and sends/receives every BFD packet. The peer is a zebra +
# bgpd + bfdd of FRR instance crbfdpeer in a namespace (eBGP, BFD 50 ms × 3).
# Each round drops the peer's BFD packets (BGP's TCP keeps going), so the
# session can only fall because BFD said so; the times come from FRR's own
# logs (microseconds) and the script's clock:
#   cut → bfdd hears Down from us → bgpd drops the session.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
ROUNDS=${ROUNDS:-5}
log=/var/log/frr/crlab.log
sed -i "s/^bgpd=no/bgpd=yes/; s/^bfdd=no/bfdd=yes/" /etc/frr/daemons
grep -q '^bfdd_options=.*--dplaneaddr' /etc/frr/daemons \
  || sed -i 's|^bfdd_options="\(.*\)"|bfdd_options="\1 --dplaneaddr unix:/var/run/frr/bfdd_dplane.sock"|' /etc/frr/daemons
grep '^bfdd_options' /etc/frr/daemons
[ -f /etc/frr/frr.conf.crorig ] || cp -p /etc/frr/frr.conf /etc/frr/frr.conf.crorig
cp -p /etc/frr/frr.conf.crorig /etc/frr/frr.conf
cat >> /etc/frr/frr.conf <<CONF
log file $log debugging
log timestamp precision 6
debug bfd distributed
debug bgp neighbor-events
CONF
rm -f "$log"
cleanup() {
  [ -n "${dpid:-}" ] && kill "$dpid" 2>/dev/null || true
  pkill -f -- "-N crbfdpeer" 2>/dev/null || true
  ip netns del crbfdpeer 2>/dev/null || true
  ip link del crbfd-l 2>/dev/null || true
  sed -i 's| --dplaneaddr unix:/var/run/frr/bfdd_dplane.sock||' /etc/frr/daemons
  cp -p /etc/frr/frr.conf.crorig /etc/frr/frr.conf
  systemctl reset-failed frr 2>/dev/null || true
  systemctl restart frr || true
}
trap cleanup EXIT
pkill -f -- "-N crbfdpeer" 2>/dev/null || true
ip netns del crbfdpeer 2>/dev/null || true
ip link del crbfd-l 2>/dev/null || true
systemctl reset-failed frr 2>/dev/null || true
systemctl restart frr
for _ in $(seq 50); do [ -S /var/run/frr/bfdd_dplane.sock ] && [ -S /var/run/frr/bgpd.vty ] && break; sleep 0.2; done
[ -S /var/run/frr/bfdd_dplane.sock ] || { echo "FAIL: bfdd has no data plane socket"; exit 1; }

ip netns add crbfdpeer
ip link add crbfd-l type veth peer name crbfd-p netns crbfdpeer
ip addr add 198.51.100.41/30 dev crbfd-l
ip link set crbfd-l up
ip -n crbfdpeer addr add 198.51.100.42/30 dev crbfd-p
ip -n crbfdpeer addr add 203.0.113.1/24 dev lo
ip -n crbfdpeer link set crbfd-p up
ip -n crbfdpeer link set lo up
d=/etc/frr/crbfdpeer
install -d -o frr -g frr "$d" /var/run/frr/crbfdpeer
: > "$d/zebra.conf"
cat > "$d/bfdd.conf" <<'CONF'
bfd
 profile lab
  receive-interval 50
  transmit-interval 50
  detect-multiplier 3
 exit
exit
CONF
cat > "$d/bgpd.conf" <<'CONF'
router bgp 65100
 bgp router-id 198.51.100.42
 no bgp ebgp-requires-policy
 neighbor 198.51.100.41 remote-as 65000
 neighbor 198.51.100.41 bfd profile lab
 neighbor 198.51.100.41 timers connect 5
 address-family ipv4 unicast
  network 203.0.113.0/24
 exit-address-family
exit
CONF
chown frr:frr "$d"/*.conf
ip netns exec crbfdpeer /usr/lib/frr/zebra -N crbfdpeer -d -f "$d/zebra.conf"
sleep 1
ip netns exec crbfdpeer /usr/lib/frr/bfdd -N crbfdpeer -d -f "$d/bfdd.conf"
ip netns exec crbfdpeer /usr/lib/frr/bgpd -N crbfdpeer -d -f "$d/bgpd.conf"

cargo build -q --release -p corerouter-daemon -p corerouter-cli
bin="${CARGO_TARGET_DIR:-target}/release"
export COREROUTER_RUNTIME_DIR=/tmp/crbfd-run
rm -rf "$COREROUTER_RUNTIME_DIR" /tmp/crbfd-cfg
mkdir -p "$COREROUTER_RUNTIME_DIR"
"$bin/corerouter-daemon" --control 7984 --frr /var/run/frr --config-dir /tmp/crbfd-cfg \
  > /tmp/crbfd-daemon.log 2>&1 &
dpid=$!
cli() { "$bin/corerouter-cli" --connect 127.0.0.1:7984 run "$@"; }
for _ in $(seq 50); do cli routing.backend.get >/dev/null 2>&1 && break; sleep 0.2; done
cli routing.bfd.profile.add '{"name":"lab","min_tx":50,"min_rx":50,"multiplier":3,"dampening":false}' >/dev/null
cli routing.bgp.instance.set '{"asn":65000,"router_id":"198.51.100.41"}' >/dev/null
cli routing.bgp.connection.add '{"name":"peer","remote_address":"198.51.100.42","remote_as":65100,"bfd":"lab"}' >/dev/null

state() { vtysh -c "show bgp neighbor 198.51.100.42 json" | jq -r '.["198.51.100.42"].bgpState'; }
bfd_ours() { cli routing.bfd.session.list | jq -r '.sessions[] | select(.peer == "198.51.100.42") | .state'; }
up() {
  for _ in $(seq 600); do
    [ "$(state)" = Established ] && [ "$(bfd_ours)" = up ] && return 0
    sleep 0.1
  done
  return 1
}
if ! up; then
  echo "FAIL: BGP + BFD did not come up"
  echo "bgp: $(state); ours: $(bfd_ours)"
  vtysh -c "show bfd peers" || true
  tail -30 /tmp/crbfd-daemon.log
  exit 1
fi
echo "OK: BGP Established and our BFD session up through bfdd's data plane"
vtysh -c "show bfd peers brief"
cli routing.bfd.session.list | jq -c '.sessions[] | {peer, state, users, profile, tx_interval_us, local_discr}'

ip netns exec crbfdpeer nft add table inet crlab
ip netns exec crbfdpeer nft add chain inet crlab out '{ type filter hook output priority 0; }'
status=0
for r in $(seq "$ROUNDS"); do
  sleep 3  # both sessions settled: a cut right after BFD came up is not the case measured
  t0=$(date +%s.%N)
  ip netns exec crbfdpeer nft add rule inet crlab out udp dport 3784 drop
  for _ in $(seq 1000); do [ "$(state)" != Established ] && break; sleep 0.01; done
  [ "$(state)" != Established ] || { echo "FAIL: round $r: BGP stayed up"; status=1; break; }
  sleep 0.5
  python3 - "$t0" "$log" "$r" <<'PY'
import sys, datetime
t0, path, r = float(sys.argv[1]), sys.argv[2], sys.argv[3]
def ts(line):
    try:
        return datetime.datetime.strptime(line[:26], "%Y/%m/%d %H:%M:%S.%f").timestamp()
    except ValueError:
        return None
bfdd = bgp = None
for line in open(path, errors="replace"):
    t = ts(line)
    if t is None or t < t0:
        continue
    if bfdd is None and "BFD" in line[:40] and ("state" in line.lower() or "down" in line.lower()):
        bfdd = (t, line.strip()[27:160])
    # debug bgp neighbor-events: the FSM leaving Established.
    if bgp is None and "198.51.100.42" in line and "Established" in line and ("->" in line or " to " in line):
        bgp = (t, line.strip()[27:200])
print(f"round {r}: cut → bfdd {((bfdd[0]-t0)*1000) if bfdd else float('nan'):.1f} ms "
      f"→ bgpd down {((bgp[0]-t0)*1000) if bgp else float('nan'):.1f} ms "
      f"(bfdd → bgpd {((bgp[0]-bfdd[0])*1000) if bfdd and bgp else float('nan'):.2f} ms)")
if bfdd: print("   bfdd:", bfdd[1])
if bgp: print("   bgpd:", bgp[1])
else:
    for line in open(path, errors="replace"):
        t = ts(line)
        if t is not None and t >= t0 and "BGP" in line[:40]:
            print("   bgp log:", line.strip()[27:200])
PY
  ip netns exec crbfdpeer nft flush chain inet crlab out
  up || { echo "FAIL: round $r: did not come back"; status=1; break; }
done
cli routing.bfd.history.list | jq -c '.[0:4][]?' 2>/dev/null || true
[ $status = 0 ] && echo "OK: $ROUNDS cuts, BGP fell with BFD every time and came back"
exit $status
