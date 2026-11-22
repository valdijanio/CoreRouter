#!/usr/bin/env bash
# G3.1: measure the ways of driving FRR (crates/hal-frr/examples/frr_compare.rs).
# Runs as root inside the lab VM only (it turns on bgpd, restores frr.conf and adds a
# dummy interface there):
#   cargo xtask vm-lab run -- scripts/frr-compare.sh [routes]
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
sed -i "s/^bgpd=no/bgpd=yes/" /etc/frr/daemons
# frr-reload.py saves frr.conf (`write`): start every round from the
# package's file, or the last round's prefix-lists come back on restart.
[ -f /etc/frr/frr.conf.crorig ] || cp -p /etc/frr/frr.conf /etc/frr/frr.conf.crorig
# (an earlier round may have saved its test lines into the copy)
sed -i '/^ip prefix-list \(BIG\|L\|T\) /d; /^router bgp /,/^exit/d' /etc/frr/frr.conf.crorig
cp -p /etc/frr/frr.conf.crorig /etc/frr/frr.conf
ip link add crfrr0 type dummy 2>/dev/null || true
ip addr replace 192.0.2.2/24 dev crfrr0
ip link set crfrr0 up
systemctl reset-failed frr 2>/dev/null || true  # many rounds in a row hit start-limit
systemctl restart frr
for _ in $(seq 50); do [ -S /var/run/frr/bgpd.vty ] && break; sleep 0.2; done
cargo build --release -q -p corerouter-hal-frr --example frr_compare
bin="${CARGO_TARGET_DIR:-target}/release/examples/frr_compare"
"$bin" /var/run/frr 0
# N /32 routes in the kernel's main table via 192.0.2.1 (zebra imports them;
# the deb has no sharpd).
routes="${1:-1000000}"
awk -v n="$routes" 'BEGIN { for (i = 0; i < n; i++)
  printf "route add 100.%d.%d.%d/32 via 192.0.2.1 proto static\n", 64 + int(i / 65536), int(i / 256) % 256, i % 256 }' > /tmp/crfrr-routes
start=$(date +%s.%N)
ip -batch /tmp/crfrr-routes
echo "kernel: $routes rotas em $(echo "$(date +%s.%N) - $start" | bc) s"
status=0
"${CARGO_TARGET_DIR:-target}/release/examples/frr_compare" /var/run/frr "$routes" routes-only || status=$?
sed 's/route add/route del/' /tmp/crfrr-routes > /tmp/crfrr-routes-del
ip -batch /tmp/crfrr-routes-del || true
exit $status
