#!/usr/bin/env bash
# G3.6i: our BFD engine against FRR's bfdd. Runs as root inside the lab VM
# only:
#   cargo xtask vm-lab run -- scripts/frr-bfd-live.sh [interop|load|all]
# Namespace crbfda runs the engine (the daemon's test binary, release);
# crbfdb runs a zebra + bfdd of their own FRR instance (-N crbfdb). One veth:
#   crbfd-a 10.76.0.1/15 + 10.77.0.1..10.77.3.250  <->  crbfd-b 10.76.0.2/15
# (one address of ours per load session: bfdd keys a single-hop session by
# the peer address, not by its local one). BFD_LOAD_SECS sets the steady-state window (default 15).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
what=${1:-all}
cleanup() {
  pkill -f -- "-N crbfdb" 2>/dev/null || true
  ip netns del crbfda 2>/dev/null || true
  ip netns del crbfdb 2>/dev/null || true
  rm -f /tmp/bfdd-crbfdb.conf
}
cleanup
trap cleanup EXIT

cargo build -q --release -p corerouter-daemon --tests
bin=$(cargo test -q --release -p corerouter-daemon --no-run --message-format=json 2>/dev/null \
  | jq -r 'select(.reason == "compiler-artifact" and .target.kind == ["bin"] and .profile.test) | .executable' \
  | grep corerouter_daemon | head -1)
[ -x "$bin" ] || { echo "FAIL: no daemon test binary"; exit 1; }

ip netns add crbfda
ip netns add crbfdb
ip -n crbfda link set lo up
ip -n crbfdb link set lo up
ip -n crbfda link add crbfd-a type veth peer name crbfd-b netns crbfdb
ip -n crbfda addr add 10.76.0.1/15 dev crbfd-a
ip -n crbfdb addr add 10.76.0.2/15 dev crbfd-b
for i in $(seq 0 999); do
  echo "addr add 10.77.$((i / 250)).$((i % 250 + 1))/15 dev crbfd-b"
done | sed 's/crbfd-b/crbfd-a/' | ip -n crbfda -batch -
ip -n crbfda link set crbfd-a up
ip -n crbfdb link set crbfd-b up

d=/etc/frr/crbfdb
install -d -o frr -g frr "$d" /var/run/frr/crbfdb
: > "$d/zebra.conf"
: > "$d/bfdd.conf"
: > "$d/vtysh.conf"
chown frr:frr "$d"/*.conf
ip netns exec crbfdb /usr/lib/frr/zebra -N crbfdb -d -f "$d/zebra.conf"
sleep 1
ip netns exec crbfdb /usr/lib/frr/bfdd -N crbfdb -d -f "$d/bfdd.conf"
for _ in $(seq 50); do [ -S /var/run/frr/crbfdb/bfdd.vty ] && break; sleep 0.2; done
echo "bfdd $(vtysh -N crbfdb -c 'show version' | head -1)"

status=0
run() {
  ip netns exec crbfda env BFDD_NS=crbfdb "$bin" --ignored --nocapture --test-threads 1 \
    --exact "$1" || status=$?
}
case $what in
  interop) run service::bfd::live_bfdd::bfdd_interop ;;
  load) run service::bfd::live_bfdd::bfdd_load ;;
  # Our engine against itself in the same VM (the baseline of docs/bfd.md).
  self) ip netns exec crbfda sh -c "ip link set lo up && \"$bin\" --ignored --nocapture \
          --test-threads 1 --exact service::bfd::tests::load" || status=$? ;;
  all)
    run service::bfd::live_bfdd::bfdd_interop
    # The interop test kills bfdd at the end: a fresh one for the load.
    pkill -f -- "bfdd -N crbfdb" 2>/dev/null || true
    sleep 0.5
    rm -f /var/run/frr/crbfdb/bfdd.vty /var/run/frr/crbfdb/bfdd.pid
    ip netns exec crbfdb /usr/lib/frr/bfdd -N crbfdb -d -f "$d/bfdd.conf"
    for _ in $(seq 50); do [ -S /var/run/frr/crbfdb/bfdd.vty ] && break; sleep 0.2; done
    run service::bfd::live_bfdd::bfdd_load
    ;;
esac
exit $status
