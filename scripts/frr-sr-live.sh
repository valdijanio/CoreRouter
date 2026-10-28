#!/usr/bin/env bash
# G3.4f/G3.4d: Segment Routing (and TI-LFA) over OSPF against a real FRR,
# with traffic through the labels. Runs as root inside the lab VM only:
#   cargo xtask vm-lab run -- scripts/frr-sr-live.sh [sr|frr|all]
# A square of four routers; R1 is the VM's FRR, driven by the test:
#
#   R1 (10.255.0.1 on lo) —crsr-a/b 10.0.12.0/30— R2 (ns crsr2)
#    |                                              |
#   crsr-h/g 10.0.14.0/30                          crsr-c/d 10.0.23.0/30
#    |                                              |
#   R4 (ns crsr4) ————crsr-f/e 10.0.34.0/30 (cost 20)———— R3 (ns crsr3)
#
# R2..R4 are a zebra + ospfd of their own FRR instance (-N), SR on, SID
# index = the last octet of the loopback. R1 → R3 goes by R2 (cost 20, the
# other way costs 30), so cutting R1–R2 has a backup through R4.
set -euo pipefail
# vm-lab run holds its lock on fd 9: a daemon started from here would
# inherit it and keep the VM locked after the round.
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
what=${1:-all}
modprobe mpls_router
modprobe mpls_iptunnel
sed -i "s/^ospfd=no/ospfd=yes/; s/^bfdd=no/bfdd=yes/" /etc/frr/daemons
[ -f /etc/frr/frr.conf.crorig ] || cp -p /etc/frr/frr.conf /etc/frr/frr.conf.crorig
cp -p /etc/frr/frr.conf.crorig /etc/frr/frr.conf
cleanup() {
  pkill -f -- "-N crsr" 2>/dev/null || true
  for ns in crsr2 crsr3 crsr4; do ip netns del $ns 2>/dev/null || true; done
  ip link del crsr-a 2>/dev/null || true
  ip link del crsr-h 2>/dev/null || true
  ip link del crsr-lo 2>/dev/null || true
  ip addr del 10.255.0.1/32 dev lo 2>/dev/null || true
  rm -rf /etc/frr/crsr2 /etc/frr/crsr3 /etc/frr/crsr4
}
cleanup
finish() {
  cleanup
  cp -p /etc/frr/frr.conf.crorig /etc/frr/frr.conf
  systemctl restart frr || true
}
trap finish EXIT
sysctl -qw net.mpls.platform_labels=1048575
# R1's loopback (10.255.0.1 on the kernel's lo, G3.4i) and the dummy
# crsr-lo (to show that ospfd refuses a SID there) are put by the test,
# through LinuxHal; cleanup() only takes back what a crash left.
for ns in crsr2 crsr3 crsr4; do
  ip netns add $ns
  ip -n $ns link set lo up
  ip netns exec $ns sysctl -qw net.mpls.platform_labels=1048575 net.ipv4.ip_forward=1
done
# link <ns-a> <if-a> <addr-a> <ns-b> <if-b> <addr-b> ("" is R1's namespace)
link() {
  local na=$1 ia=$2 aa=$3 nb=$4 ib=$5 ab=$6
  local ina=() inb=()
  [ -n "$na" ] && ina=(-n "$na")
  ip "${ina[@]}" link add "$ia" type veth peer name "$ib" netns "$nb"
  ip "${ina[@]}" addr add "$aa" dev "$ia"
  ip "${ina[@]}" link set "$ia" up
  ip -n "$nb" addr add "$ab" dev "$ib"
  ip -n "$nb" link set "$ib" up
  if [ -n "$na" ]; then ip netns exec "$na" sysctl -qw "net.mpls.conf.$ia.input=1"; else sysctl -qw "net.mpls.conf.$ia.input=1"; fi
  ip netns exec "$nb" sysctl -qw "net.mpls.conf.$ib.input=1"
}
link "" crsr-a 10.0.12.1/30 crsr2 crsr-b 10.0.12.2/30
link crsr2 crsr-c 10.0.23.1/30 crsr3 crsr-d 10.0.23.2/30
link crsr3 crsr-e 10.0.34.2/30 crsr4 crsr-f 10.0.34.1/30
link "" crsr-h 10.0.14.1/30 crsr4 crsr-g 10.0.14.2/30
sysctl -qw net.ipv4.ip_forward=1

# router <ns> <n> <interface:cost…>: zebra + ospfd with SR (and TI-LFA).
router() {
  local ns=$1 n=$2; shift 2
  local d=/etc/frr/$ns
  install -d -o frr -g frr "$d" "/var/run/frr/$ns"
  : > "$d/vtysh.conf"
  ip -n "$ns" addr add "10.255.0.$n/32" dev lo
  touch "$d/zebra.conf"
  {
    for ic in "$@"; do
      local i=${ic%%:*} c=${ic##*:}
      printf 'interface %s\n ip ospf network point-to-point\n ip ospf hello-interval 1\n' "$i"
      printf ' ip ospf dead-interval 4\n ip ospf cost %s\n ip ospf area 0.0.0.0\n' "$c"
      # BFD towards R1 (the silent-cut measurement of live_ti_lfa).
      [ "$i" = crsr-b ] && printf ' ip ospf bfd\n ip ospf bfd profile crfast\n'
      printf 'exit\n'
    done
    printf 'interface lo\n ip ospf area 0.0.0.0\n ip ospf passive\nexit\n'
    printf 'router ospf\n ospf router-id 10.255.0.%s\n capability opaque\n router-info area\n' "$n"
    printf ' segment-routing on\n segment-routing prefix 10.255.0.%s/32 index %s\n' "$n" "$n"
    printf ' fast-reroute ti-lfa\nexit\n'
  } > "$d/ospfd.conf"
  chown -R frr:frr "$d"
  ip netns exec "$ns" /usr/lib/frr/zebra -N "$ns" -d -f "$d/zebra.conf" --log "file:$d/zebra.log" </dev/null >/dev/null 2>&1
  for _ in $(seq 50); do [ -S "/var/run/frr/$ns/zserv.api" ] && break; sleep 0.1; done
  ip netns exec "$ns" /usr/lib/frr/ospfd -N "$ns" -d -f "$d/ospfd.conf" --log "file:$d/ospfd.log" </dev/null >/dev/null 2>&1
  printf 'bfd\n profile crfast\n  detect-multiplier 3\n  receive-interval 10\n  transmit-interval 10\n exit\nexit\n' > "$d/bfdd.conf"
  chown frr:frr "$d/bfdd.conf"
  ip netns exec "$ns" /usr/lib/frr/bfdd -N "$ns" -d -f "$d/bfdd.conf" --log "file:$d/bfdd.log" </dev/null >/dev/null 2>&1
}
# The VM's FRR first: its restart must not meet the instances below.
systemctl reset-failed frr 2>/dev/null || true
systemctl restart frr
for _ in $(seq 50); do [ -S /var/run/frr/ospfd.vty ] && [ -S /var/run/frr/zebra.vty ] && break; sleep 0.2; done
router crsr2 2 crsr-b:10 crsr-c:10
router crsr3 3 crsr-d:10 crsr-e:20
router crsr4 4 crsr-f:20 crsr-g:10
pgrep -fa -- "-N crsr" | sed 's/^/started: /'
status=0
case $what in
  sr) tests=(live_sr) ;;
  frr) tests=(live_ti_lfa) ;;
  sink) tests=() ;;
  *) tests=(live_sr live_ti_lfa) ;;
esac
for t in "${tests[@]}"; do
  COREROUTER_FRR_LIVE=1 cargo test -p corerouter-hal-frr --test frr_sr_live "$t" -- --nocapture --test-threads 1 || status=$?
done
if [ $status != 0 ]; then
  pgrep -fa -- "-N crsr" | sed 's/^/running: /' || true
  for ns in crsr2 crsr3 crsr4; do
    echo "--- $ns ---"
    ls /var/run/frr/$ns || true
    grep -v "BE-client\|NB_OP_CHANGE" /etc/frr/$ns/ospfd.log 2>/dev/null | grep -i -B2 -A3 "assert\|signal" | head -n 30 || true
    vtysh -N $ns -c "show ip ospf neighbor" -c "show ip ospf database segment-routing" -c "show ip route" 2>/dev/null || true
    ip -n $ns -f mpls route show || true
  done
  echo "--- R1 (the VM's FRR) ---"
  ip -f mpls route show || true
  echo "kernel: $(ip route show 10.255.0.3)"; ip nexthop show || true; ip route get 10.255.0.3 || true
  vtysh -c "show ip route ospf json" 2>/dev/null | head -c 4000 || true
  journalctl -u frr --since "-10min" --no-pager 2>/dev/null | grep -i "ospfd\|assert" | tail -n 30 || true
  vtysh -c "show ip ospf neighbor" -c "show ip ospf database segment-routing" -c "show ip route" \
    -c "show running-config" || true
fi
exit $status
