#!/usr/bin/env bash
# G3.2b: `/routing filter` against a real FRR. Runs as root inside the lab
# VM only:
#   cargo xtask vm-lab run -- scripts/frr-policy-live.sh
# Two peers, each a zebra + bgpd of its own FRR instance in a namespace:
#   crpol  — eBGP AS 65200 at 198.51.100.34, sends 4 prefixes (one /25,
#            one marked 65200:666, one with 65200:100);
#   crpol2 — iBGP AS 65000 at 198.51.100.38, sends 10.30.1..5.0/24, which
#            this router passes on to crpol through the output chain.
# FRR_EXPLORE=1: only set the peers up, configure our side by hand and
# print what bgpd answers (the JSON the route reader parses).
set -euo pipefail
# vm-lab run holds its lock on fd 9: a daemon started from here would
# inherit it and keep the VM locked after the round.
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
sed -i "s/^bgpd=no/bgpd=yes/" /etc/frr/daemons
[ -f /etc/frr/frr.conf.crorig ] || cp -p /etc/frr/frr.conf /etc/frr/frr.conf.crorig
sed -i '/^ip prefix-list \(BIG\|L\|T\) /d; /^router bgp /,/^exit/d' /etc/frr/frr.conf.crorig
cp -p /etc/frr/frr.conf.crorig /etc/frr/frr.conf
systemctl reset-failed frr 2>/dev/null || true
systemctl restart frr

cleanup() {
  pkill -f -- "-N crpol" 2>/dev/null || true
  ip netns del crfrrpol 2>/dev/null || true
  ip netns del crfrrpol2 2>/dev/null || true
  ip link del crpol-a 2>/dev/null || true
  ip link del crpol-c 2>/dev/null || true
}
cleanup
trap cleanup EXIT

peer() { # name ns our-if peer-if our-addr peer-addr conf
  local name=$1 ns=$2 a=$3 b=$4 ours=$5 theirs=$6 conf=$7
  ip netns add "$ns"
  ip link add "$a" type veth peer name "$b" netns "$ns"
  ip addr add "$ours" dev "$a"
  ip link set "$a" up
  ip -n "$ns" addr add "$theirs" dev "$b"
  ip -n "$ns" link set "$b" up
  ip -n "$ns" link set lo up
  install -d -o frr -g frr "/etc/frr/$name" "/var/run/frr/$name"
  printf '%s\n' "$conf" > "/etc/frr/$name/bgpd.conf"
  touch "/etc/frr/$name/zebra.conf"
  chown frr:frr /etc/frr/"$name"/*.conf
  ip netns exec "$ns" /usr/lib/frr/zebra -N "$name" -d -f "/etc/frr/$name/zebra.conf"
  sleep 1
  ip netns exec "$ns" /usr/lib/frr/bgpd -N "$name" -d -f "/etc/frr/$name/bgpd.conf"
}

peer crpol crfrrpol crpol-a crpol-b 198.51.100.33/30 198.51.100.34/30 "\
route-map MARK666 permit 10
 set community 65200:666
exit
route-map MARK100 permit 10
 set community 65200:100 65200:200
 set large-community 65200:1:2
exit
router bgp 65200
 bgp router-id 198.51.100.34
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor 198.51.100.33 remote-as 65000
 address-family ipv4 unicast
  network 203.0.113.0/24 route-map MARK100
  network 198.18.0.0/15
  network 10.66.0.0/16 route-map MARK666
  network 192.0.2.128/25
 exit-address-family
exit"

peer crpol2 crfrrpol2 crpol-c crpol-d 198.51.100.37/30 198.51.100.38/30 "\
router bgp 65000
 bgp router-id 198.51.100.38
 no bgp network import-check
 neighbor 198.51.100.37 remote-as 65000
 address-family ipv4 unicast
$(for i in 1 2 3 4 5; do echo "  network 10.30.$i.0/24"; done)
 exit-address-family
exit"

for _ in $(seq 50); do [ -S /var/run/frr/bgpd.vty ] && break; sleep 0.2; done

if [ -n "${FRR_EXPLORE:-}" ]; then
  vtysh -c "configure terminal" \
    -c "route-map T permit 10" -c "exit" \
    -c "router bgp 65000" -c "bgp router-id 198.51.100.33" -c "no bgp default ipv4-unicast" \
    -c "neighbor 198.51.100.34 remote-as 65200" -c "neighbor 198.51.100.38 remote-as internal" \
    -c "address-family ipv4 unicast" \
    -c "neighbor 198.51.100.34 activate" -c "neighbor 198.51.100.34 soft-reconfiguration inbound" \
    -c "neighbor 198.51.100.38 activate" -c "neighbor 198.51.100.38 soft-reconfiguration inbound" \
    -c "exit-address-family" -c "exit"
  sleep 12
  if [ "${FRR_EXPLORE}" = 2 ]; then
    vtysh -c "configure terminal" -c "router bgp 65000" -c "address-family ipv4 unicast" \
      -c "neighbor 198.51.100.34 route-map T in" -c "exit-address-family" -c "exit"
    sleep 6
    for c in "show bgp ipv4 unicast neighbors 198.51.100.34 received-routes detail" \
      "show bgp ipv4 unicast detail json" "show bgp ipv4 unicast 203.0.113.0/24 json" \
      "show bgp ipv4 unicast neighbors 198.51.100.34 filtered-routes json" \
      "show bgp ipv4 unicast neighbors 198.51.100.34 received-routes wide"; do
      echo "===== $c"
      vtysh -c "$c" | head -c 5000
      echo
    done
    exit 0
  fi
  for c in "show bgp ipv4 unicast summary" \
    "show bgp ipv4 unicast neighbors 198.51.100.34 received-routes json" \
    "show bgp ipv4 unicast neighbors 198.51.100.34 received-routes detail json" \
    "show bgp ipv4 unicast neighbors 198.51.100.34 routes json" \
    "show bgp ipv4 unicast json" \
    "show bgp ipv4 unicast detail json" \
    "show bgp ipv4 unicast neighbors 198.51.100.34 advertised-routes json"; do
    echo "===== $c"
    vtysh -c "$c" | head -c 6000
    echo
  done
  echo "===== typed forms"
  vtysh -c "configure terminal" \
    -c "ip prefix-list CR-X seq 5 permit 0.0.0.0/0 ge 25" \
    -c "ip prefix-list CR-X seq 10 permit 0.0.0.0/0 ge 25 le 32" \
    -c "ip prefix-list CR-X seq 15 permit 10.0.0.0/8 le 32" \
    -c "ipv6 prefix-list CR-X seq 5 permit ::/0 le 128" \
    -c "bgp community-list standard CR-C seq 5 permit 65000:1 no-export 65535:666" \
    -c "bgp large-community-list standard CR-LC seq 5 permit 1:2:3 1:2:4" \
    -c "bgp as-path access-list CR-A seq 5 permit _6450[0-9]_" \
    -c "route-map CR-t permit 1" -c "description dst in 10.0.0.0/8" \
    -c "match ip address prefix-list CR-X" -c "set community 65000:9 no-export additive" \
    -c "set as-path prepend 65000 65000" -c "set large-community 1:2:3 additive" \
    -c "set comm-list CR-C delete" -c "set large-comm-list CR-LC delete" -c "set local-preference 150" -c "set metric 10" \
    -c "on-match goto 3" -c "exit" \
    -c "route-map CR-t permit 2" -c "match community CR-C exact-match" -c "match large-community CR-LC" \
    -c "match as-path CR-A" -c "match source-protocol bgp" -c "match ipv6 address prefix-list CR-X" -c "on-match next" -c "exit" \
    -c "route-map CR-t deny 65535" -c "exit"
  vtysh -c "show running-config" | sed -n '/prefix-list CR-/p; /community-list/p; /as-path access-list/p; /^route-map CR-t/,/^exit/p'
  echo "===== bgpd's own running config (filters)"
  vtysh -d bgpd -c "show running-config" | grep -E "CR-|^route-map" | head -40
  exit 0
fi

status=0
COREROUTER_FRR_LIVE=1 cargo test -p corerouter-hal-frr --test frr_policy_live -- --nocapture || status=$?
exit $status
