#!/usr/bin/env bash
# G3.5b: LSP ping and traceroute against real LDP labels. Runs as root
# inside the lab VM only:
#   flock vm/root.lock cargo xtask vm-lab run -- scripts/lsp-ping-live.sh
# Three routers in namespaces, each a zebra + ospfd + ldpd of its own FRR
# instance, kernel MPLS (mpls_router):
#   lsp1 (10.255.0.1) —10.0.12.0/24— lsp2 (10.255.0.2) —10.0.23.0/24— lsp3 (10.255.0.3)
# The test (crates/hal-linux/tests/lsp_live.rs) runs CoreRouter's responder
# in lsp2 and lsp3 and pings / traces 10.255.0.3/32 from lsp1. The plain
# ICMP ping over the same path is printed next to it for the latency.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
modprobe mpls_router
modprobe mpls_iptunnel
cleanup() {
  pkill -f -- "-N crlsp" 2>/dev/null || true
  for n in 1 2 3; do ip netns del "lsp$n" 2>/dev/null || true; done
}
cleanup
trap cleanup EXIT
for n in 1 2 3; do
  ip netns add "lsp$n"
  ip -n "lsp$n" link set lo up
  ip -n "lsp$n" addr add "10.255.0.$n/32" dev lo
  ip netns exec "lsp$n" sysctl -qw net.mpls.platform_labels=100000
done
link() { # <ns a> <if a> <addr a> <ns b> <if b> <addr b>
  ip -n "$1" link add "$2" type veth peer name "$5" netns "$4"
  ip -n "$1" addr add "$3" dev "$2"
  ip -n "$4" addr add "$6" dev "$5"
  ip -n "$1" link set "$2" up
  ip -n "$4" link set "$5" up
  ip netns exec "$1" sysctl -qw "net.mpls.conf.$2.input=1"
  ip netns exec "$4" sysctl -qw "net.mpls.conf.$5.input=1"
}
link lsp1 l12a 10.0.12.1/24 lsp2 l12b 10.0.12.2/24
link lsp2 l23a 10.0.23.2/24 lsp3 l23b 10.0.23.3/24
frr() { # <n> <interfaces…>
  local n=$1; shift
  local d="/etc/frr/crlsp$n" r="/var/run/frr/crlsp$n"
  install -d -o frr -g frr "$d" "$r"
  touch "$d/zebra.conf"
  {
    for i in "$@"; do printf 'interface %s\n ip ospf area 0\n ip ospf network point-to-point\n ip ospf hello-interval 1\n ip ospf dead-interval 4\nexit\n' "$i"; done
    printf 'interface lo\n ip ospf area 0\nexit\nrouter ospf\n ospf router-id 10.255.0.%s\nexit\n' "$n"
  } > "$d/ospfd.conf"
  {
    printf 'mpls ldp\n router-id 10.255.0.%s\n address-family ipv4\n  discovery transport-address 10.255.0.%s\n' "$n" "$n"
    for i in "$@"; do printf '  interface %s\n  exit\n' "$i"; done
    printf ' exit-address-family\nexit\n'
  } > "$d/ldpd.conf"
  chown frr:frr "$d"/*.conf
  ip netns exec "lsp$n" /usr/lib/frr/zebra -N "crlsp$n" -d -f "$d/zebra.conf"
  sleep 1
  ip netns exec "lsp$n" /usr/lib/frr/ospfd -N "crlsp$n" -d -f "$d/ospfd.conf"
  ip netns exec "lsp$n" /usr/lib/frr/ldpd -N "crlsp$n" -d -f "$d/ldpd.conf"
}
frr 1 l12a
frr 2 l12b l23a
frr 3 l23b
echo "waiting for LDP to label 10.255.0.3/32 in lsp1…"
for _ in $(seq 90); do
  ip -n lsp1 route show 10.255.0.3 | grep -q "encap mpls" && break
  sleep 1
done
ip -n lsp1 route show 10.255.0.3
ip -n lsp2 -f mpls route show
echo "ICMP ping over the same path (kernel echo):"
ip netns exec lsp1 ping -c 50 -i 0.02 -q 10.255.0.3 | tail -1
status=0
COREROUTER_LSP_LIVE=1 cargo test -p corerouter-hal-linux --test lsp_live -- --nocapture || status=$?
exit $status
