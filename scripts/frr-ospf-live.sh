#!/usr/bin/env bash
# G3.4: hal-frr's OSPF against a real FRR. Runs as root inside the lab VM
# only (cargo xtask vm-lab run -- scripts/frr-ospf-live.sh). Two OSPF
# peers, each a zebra + ospfd of its own FRR instance in a namespace,
# joined to the VM's FRR by a veth pair:
#   crospfpeer  (192.0.2.2, link 192.0.2.0/30): HMAC-SHA-256 key chain with
#               keys 1 and 2 (rotation without a drop);
#   crospfpeer2 (192.0.2.6, link 192.0.2.4/30): MTU 1400 against our 1500,
#               so the pair sticks in ExStart (RFC 2328 §10.6) and the
#               Diagnose must say so.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
sed -i "s/^ospfd=no/ospfd=yes/; s/^ospf6d=no/ospf6d=yes/" /etc/frr/daemons
[ -f /etc/frr/frr.conf.crorig ] || cp -p /etc/frr/frr.conf /etc/frr/frr.conf.crorig
cp -p /etc/frr/frr.conf.crorig /etc/frr/frr.conf
systemctl reset-failed frr 2>/dev/null || true
systemctl restart frr
cleanup() {
  pkill -f -- "-N crospf" 2>/dev/null || true
  ip netns del crospfpeer 2>/dev/null || true
  ip netns del crospfpeer2 2>/dev/null || true
  ip link del crospf-a 2>/dev/null || true
  ip link del crospf-c 2>/dev/null || true
}
cleanup
peer() { # <ns> <instance> <our if> <peer if> <our addr> <peer addr> <mtu> <conf>
  ip netns add "$1"
  ip link add "$3" type veth peer name "$4" netns "$1"
  ip addr add "$5" dev "$3"
  ip link set "$3" up
  ip -n "$1" addr add "$6" dev "$4"
  ip -n "$1" link set "$4" mtu "$7" up
  ip -n "$1" link set lo up
  install -d -o frr -g frr "/etc/frr/$2" "/var/run/frr/$2"
  printf '%s\n' "$8" > "/etc/frr/$2/ospfd.conf"
  touch "/etc/frr/$2/zebra.conf"
  chown frr:frr /etc/frr/"$2"/*.conf
  ip netns exec "$1" /usr/lib/frr/zebra -N "$2" -d -f "/etc/frr/$2/zebra.conf"
  sleep 1
  ip netns exec "$1" /usr/lib/frr/ospfd -N "$2" -d -f "/etc/frr/$2/ospfd.conf"
}
peer crospfpeer crospf crospf-a crospf-b 192.0.2.1/30 192.0.2.2/30 1500 "key chain k
 key 1
  key-string Sup3rS3cret
  cryptographic-algorithm hmac-sha-256
 exit
 key 2
  key-string N3wS3cret
  cryptographic-algorithm hmac-sha-256
 exit
exit
interface crospf-b
 ip ospf network point-to-point
 ip ospf authentication key-chain k
 ip ospf hello-interval 2
 ip ospf dead-interval 8
 ip ospf area 0.0.0.0
exit
router ospf
 ospf router-id 192.0.2.2
 redistribute connected
exit"
peer crospfpeer2 crospf2 crospf-c crospf-d 192.0.2.5/30 192.0.2.6/30 1400 "interface crospf-d
 ip ospf network point-to-point
 ip ospf hello-interval 2
 ip ospf dead-interval 8
 ip ospf area 0.0.0.0
exit
router ospf
 ospf router-id 192.0.2.6
exit"
for _ in $(seq 50); do [ -S /var/run/frr/ospfd.vty ] && break; sleep 0.2; done
status=0
COREROUTER_FRR_LIVE=1 cargo test -p corerouter-hal-frr --test frr_ospf_live -- --nocapture || status=$?
cleanup
exit $status
