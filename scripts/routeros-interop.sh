#!/usr/bin/env bash
# G3.9: CoreRouter (linux backend + its FRR) against a real MikroTik
# RouterOS v7 CHR. Runs as root inside the lab VM only:
#   cargo xtask vm-lab run -- scripts/routeros-interop.sh [case…]
# Cases (default: all, in this order): ospf-ptp ospf-broadcast ospf-auth
#   ospf-mtu ospf-areas redistribute entry ldp mpls-ttl mpls-mtu bfd exit failover
#   stub-router ospfv3 prod (last: it restarts the CoreRouter on the
#   docs/producao-core.md blocks)
# HOLD=<s> keeps the lab up that long at the end (inspect it with
# `cargo xtask vm-lab ssh`). Results: a table at the end and
# /tmp/crg39/results.txt in the VM; exit 1 if any case failed.
#
# Topology (all inside the VM; the CoreRouter side lives in netns crcore,
# so the linux backend sees only its own ports, never the VM's NICs):
#
#   R3 (ns crr3, FRR) eth0 ──crb2── ether2 ┐
#                                          CHR (QEMU/KVM, RouterOS 7)
#   R4 (ns crr4, FRR) eth1 ──crb3── ether3 ┘ ether1 ──crb1── ether1 CoreRouter (ns crcore)
#   R4 eth0 ────────────────────────────────────────────────── ether2 CoreRouter
#   CHR ether4 ──crbm── 192.168.239.1 (REST from the VM's root namespace)
#
# Loopbacks: CHR 10.255.39.1, CoreRouter 10.255.39.2, R3 .3, R4 .4.
# R3 → R4 normally goes R3 → CHR → CoreRouter → R4 (cost 10+10+10); the
# direct CHR—R4 link (cost 1000) is the way around a dead CoreRouter.
set -euo pipefail
# vm-lab run holds its lock on fd 9: a daemon started from here would
# inherit it and keep the VM locked after the round.
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }

# The CHR image: the latest stable RouterOS v7 when this was written,
# checked against the .sha256 MikroTik publishes next to the zip.
ROS_VERSION=${ROS_VERSION:-7.25}
ROS_SHA256=${ROS_SHA256:-6b981288350de2a2c7a3218bd820ab702633b8cd6cd339f2bb34dda1f1a2550e}
CASES=("$@")
[ ${#CASES[@]} -gt 0 ] || CASES=(ospf-ptp ospf-broadcast ospf-auth ospf-mtu ospf-areas redistribute entry ldp mpls-ttl mpls-mtu bfd exit failover stub-router ospfv3 prod)
W=/tmp/crg39
CHR_DIR=/srv/lab/chr
PW=g39-lab-only
ROS=192.168.239.2
FAILED=0
mkdir -p "$W"
: > "$W/results.txt"

result() { # result <case> <OK|FAIL|INFO> <text>
  printf '%-16s %-4s %s\n' "$1" "$2" "$3" | tee -a "$W/results.txt"
  [ "$2" != FAIL ] || FAILED=1
}

# --- tools and image -------------------------------------------------------
if ! command -v qemu-system-x86_64 >/dev/null || ! command -v traceroute >/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    qemu-system-x86 qemu-utils unzip traceroute >/dev/null
fi
[ -e /dev/kvm ] || { echo "no /dev/kvm in the VM: nested virtualization is off"; exit 1; }
img=$CHR_DIR/chr-$ROS_VERSION.img
if [ ! -f "$img" ]; then
  mkdir -p "$CHR_DIR"
  zip=$CHR_DIR/chr-$ROS_VERSION.img.zip
  [ -f /srv/lab/inbox/chr-$ROS_VERSION.img.zip ] && cp /srv/lab/inbox/chr-$ROS_VERSION.img.zip "$zip"
  [ -f "$zip" ] || curl -sSfL -o "$zip" "https://download.mikrotik.com/routeros/$ROS_VERSION/chr-$ROS_VERSION.img.zip"
  echo "$ROS_SHA256  $zip" | sha256sum -c --quiet || { rm -f "$zip"; echo "FAIL: CHR zip checksum"; exit 1; }
  unzip -o -q "$zip" -d "$CHR_DIR"
fi

cargo build -q --release -p corerouter-daemon -p corerouter-cli
bin="$(realpath "${CARGO_TARGET_DIR:-target}")/release"

# --- teardown ---------------------------------------------------------------
cleanup() {
  [ -f "$W/qemu.pid" ] && kill "$(cat "$W/qemu.pid")" 2>/dev/null || true
  [ -f "$W/daemon.pid" ] && kill "$(cat "$W/daemon.pid")" 2>/dev/null || true
  pkill -f -- "-N crcore" 2>/dev/null || true
  pkill -f -- "-N crr3" 2>/dev/null || true
  pkill -f -- "-N crr4" 2>/dev/null || true
  for ns in crcore crr3 crr4; do ip netns del $ns 2>/dev/null || true; done
  for l in crb1 crb2 crb3 crbm crv1 crv2 crv3 crvm crt1 crt2 crt3 crt4; do
    ip link del $l 2>/dev/null || true
  done
  rm -f "$W/qemu.pid" "$W/daemon.pid"
}
finish() {
  local s=$?
  if [ -n "${HOLD:-}" ]; then echo "HOLD: lab up for $HOLD s"; sleep "$HOLD" || true; fi
  cleanup
  exit $s
}
cleanup
trap finish EXIT

# --- topology ---------------------------------------------------------------
modprobe mpls_router
modprobe mpls_iptunnel
for ns in crcore crr3 crr4; do
  ip netns add $ns
  ip -n $ns link set lo up
  ip netns exec $ns sysctl -qw net.ipv4.ip_forward=1 net.mpls.platform_labels=1048575 \
    net.ipv6.conf.all.forwarding=1
done
# bridge <name> <veth here> <veth there> <netns>: a segment between a CHR
# port (its tap joins later) and a namespace.
segment() {
  ip link add "$1" type bridge
  ip link set "$1" up
  ip link add "$2" type veth peer name "$3" netns "$4"
  ip link set "$2" master "$1" up
  ip -n "$4" link set "$3" up
}
segment crb1 crv1 ether1 crcore
segment crb2 crv2 eth0 crr3
segment crb3 crv3 eth1 crr4
ip link add crr4-e0 type veth peer name ether2 netns crcore
ip link set crr4-e0 netns crr4
ip -n crr4 link set crr4-e0 name eth0
ip -n crr4 link set eth0 up
ip -n crcore link set ether2 up
# The clients' port and a lab network, there before the daemon starts (a
# port added later is not adopted yet: G1.3b).
ip link add ether3 netns crcore type veth peer name cl0 netns crr4
ip link add ether4 netns crcore type veth peer name cl1 netns crr4
ip -n crr4 link set cl0 up
ip -n crr4 link set cl1 up
# Up before the first start: the seed copies a port's state (G1.18).
ip -n crcore link set ether3 up
ip -n crcore link set ether4 up
ip link add crbm type bridge
ip addr add 192.168.239.1/24 dev crbm
ip link set crbm up
ip -n crr3 addr add 10.39.2.2/30 dev eth0
ip -n crr3 addr add 10.255.39.3/32 dev lo
ip -n crr4 addr add 10.39.3.2/30 dev eth1
ip -n crr4 addr add 10.39.4.2/30 dev eth0
ip -n crr4 addr add 10.255.39.4/32 dev lo
for ns in crr3 crr4; do
  for i in $(ip -n $ns -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
    ip netns exec $ns sysctl -qw "net.mpls.conf.$i.input=1" 2>/dev/null || true
  done
done

# --- the CHR ---------------------------------------------------------------
cp "$img" "$W/chr.img"
qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -name chr-g39 \
  -drive file="$W/chr.img",format=raw,if=virtio \
  -netdev tap,id=e1,ifname=crt1,script=no,downscript=no -device virtio-net-pci,netdev=e1,mac=52:54:00:39:00:01 \
  -netdev tap,id=e2,ifname=crt2,script=no,downscript=no -device virtio-net-pci,netdev=e2,mac=52:54:00:39:00:02 \
  -netdev tap,id=e3,ifname=crt3,script=no,downscript=no -device virtio-net-pci,netdev=e3,mac=52:54:00:39:00:03 \
  -netdev tap,id=e4,ifname=crt4,script=no,downscript=no -device virtio-net-pci,netdev=e4,mac=52:54:00:39:00:04 \
  -serial unix:$W/chr.sock,server,nowait -monitor unix:$W/chr.mon,server,nowait \
  -display none -daemonize -pidfile "$W/qemu.pid"
ip link set crt1 master crb1 up
ip link set crt2 master crb2 up
ip link set crt3 master crb3 up
ip link set crt4 master crbm up

# The console: log in, take the first-login questions (license: not shown;
# a password), then type the bootstrap. Everything after that goes through
# the REST API on ether4.
cat > "$W/console.py" <<'PY'
import socket, sys, time, re
sock, pw = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX); s.connect(sock); s.settimeout(0.2)
buf = b""
def until(pat, t):
    global buf
    end = time.time() + t
    while time.time() < end:
        try:
            d = s.recv(65536)
            if d: buf += d
        except socket.timeout:
            pass
        m = re.search(pat, buf)
        if m: return m
    sys.exit("console: timeout waiting for %r; last: %r" % (pat, buf[-300:]))
t0 = time.time()
# Each Enter sent before the prompt shows is queued and lands later (on
# the password, the license question): wait for the boot to settle, then
# ask for a fresh prompt.
for _ in range(60):
    s.sendall(b"\r")
    try:
        until(rb"Login: $", 3); break
    except SystemExit:
        pass
time.sleep(1)
buf = b""
s.sendall(b"\r"); until(rb"Login: $", 10)
print("console: login prompt after %.1f s" % (time.time() - t0))
s.sendall(b"admin+cetw200\r"); until(rb"Password: $", 10)
buf = b""; s.sendall(b"\r")
# The password prompts are redrawn after every key ("\rnew password> ***"):
# answer each question once, in order.
until(rb"license\? \[Y/n\]: $", 30); buf = b""; s.sendall(b"n\r")
until(rb"new password> ?$", 20); buf = b""; s.sendall(pw.encode() + b"\r")
until(rb"repeat new password> ?$", 20); buf = b""; s.sendall(pw.encode() + b"\r")
until(rb"\] > ?$", 20)
for line in sys.stdin.read().splitlines():
    if not line.strip(): continue
    buf = b""
    s.sendall(line.encode() + b"\r")
    until(rb"\] > ?$", 20)
    out = buf.decode(errors="replace")
    if "failure" in out or "syntax error" in out or "bad command" in out:
        sys.exit("console: %s -> %s" % (line, out[-300:]))
print("console: bootstrap done after %.1f s" % (time.time() - t0))
PY
python3 -I "$W/console.py" "$W/chr.sock" "$PW" <<'ROS'
/system identity set name=chr-g39
/ip address add address=192.168.239.2/24 interface=ether4
/ip service set www disabled=no
ROS
for _ in $(seq 100); do curl -sf -m 2 -u "admin:$PW" "http://$ROS/rest/system/resource" >/dev/null && break; sleep 0.2; done

# ros <path>: GET /rest/<path> (JSON). rosx <script>: run RouterOS CLI lines
# (the same text an operator types; the doc shows them as they are here).
ros() { curl -sf -m 10 -u "admin:$PW" "http://$ROS/rest/$1"; }
rosx() {
  local out
  out=$(jq -n --arg s "$1" '{script: $s}' |
    curl -s -m 30 -u "admin:$PW" -H 'content-type: application/json' -d @- "http://$ROS/rest/execute")
  if echo "$out" | jq -e 'type == "object" and has("error")' >/dev/null 2>&1; then
    echo "RouterOS refused: $out" >&2
    return 1
  fi
  printf '%s' "$out"
}
echo "RouterOS: $(ros system/resource | jq -r '"\(.version) on \(.["architecture-name"]), \(.["cpu-count"]) CPU"')"

# --- R3 and R4: plain FRR instances (zebra, ospfd, ospf6d, ldpd, bfdd) -------
frr_node() { # frr_node <ns> <router-id> <ospf+ldp interfaces…>  (iface:cost)
  local ns=$1 id=$2; shift 2
  local d=/etc/frr/$ns
  install -d -o frr -g frr "$d" "/var/run/frr/$ns"
  : > "$d/zebra.conf"; : > "$d/vtysh.conf"
  {
    for ic in "$@"; do
      local i=${ic%%:*} c=${ic#*:}
      printf 'interface %s\n ip ospf network point-to-point\n ip ospf hello-interval 1\n' "$i"
      printf ' ip ospf dead-interval 4\n ip ospf area 0.0.0.0\n ip ospf cost %s\n' "$c"
      printf ' ip ospf bfd\n ip ospf bfd profile g39\nexit\n'
    done
    printf 'interface lo\n ip ospf area 0.0.0.0\n ip ospf passive\nexit\n'
    printf 'router ospf\n ospf router-id %s\nexit\n' "$id"
  } > "$d/ospfd.conf"
  {
    printf 'mpls ldp\n router-id %s\n address-family ipv4\n' "$id"
    printf '  discovery transport-address %s\n' "$id"
    for ic in "$@"; do printf '  interface %s\n' "${ic%%:*}"; done
    printf ' exit-address-family\nexit\n'
  } > "$d/ldpd.conf"
  printf 'bfd\n profile g39\n  receive-interval 300\n  transmit-interval 300\n exit\nexit\n' > "$d/bfdd.conf"
  chown frr:frr "$d"/*.conf
  ip netns exec "$ns" /usr/lib/frr/zebra -N "$ns" -d -f "$d/zebra.conf"
  sleep 1
  for p in ospfd ldpd bfdd; do ip netns exec "$ns" /usr/lib/frr/$p -N "$ns" -d -f "$d/$p.conf"; done
}
frr_node crr3 10.255.39.3 eth0:10
frr_node crr4 10.255.39.4 eth0:10 eth1:1000
vt() { vtysh -N "$1" -c "$2"; }

# --- CoreRouter: its own FRR instance (bfdd with our engine as its data
# plane) and the daemon with the linux backend, both in netns crcore -------
d=/etc/frr/crcore
install -d -o frr -g frr "$d" /var/run/frr/crcore
: > "$d/zebra.conf"; : > "$d/vtysh.conf"
for p in bgpd ospfd ospf6d ldpd bfdd; do : > "$d/$p.conf"; done
chown frr:frr "$d"/*.conf
# The daemons the image starts (corerouter-init), mgmtd first.
start_cr_frr() {
  local d=/etc/frr/crcore
  ip netns exec crcore /usr/lib/frr/mgmtd -N crcore -d
  sleep 0.5
  ip netns exec crcore /usr/lib/frr/zebra -N crcore -d -f "$d/zebra.conf"
  sleep 1
  ip netns exec crcore /usr/lib/frr/staticd -N crcore -d
  for p in bgpd ospfd ospf6d ldpd; do ip netns exec crcore /usr/lib/frr/$p -N crcore -d -f "$d/$p.conf"; done
  ip netns exec crcore /usr/lib/frr/bfdd -N crcore -d -f "$d/bfdd.conf" \
    --dplaneaddr unix:/var/run/frr/crcore/bfdd_dplane.sock
  for _ in $(seq 50); do [ -S /var/run/frr/crcore/bfdd_dplane.sock ] && break; sleep 0.2; done
}
start_cr_frr
export COREROUTER_RUNTIME_DIR=$W/run
rm -rf "$COREROUTER_RUNTIME_DIR" "$W/cfg"
mkdir -p "$COREROUTER_RUNTIME_DIR"
start_daemon() {
  ip netns exec crcore "$bin/corerouter-daemon" --backend linux --manage 'ether*' \
    --config-dir "$W/cfg" --control 7990 --frr /var/run/frr/crcore --no-discovery \
    >> "$W/daemon.log" 2>&1 &
  echo $! > "$W/daemon.pid"
  for _ in $(seq 100); do cli routing.backend.get >/dev/null 2>&1 && break; sleep 0.2; done
}
cli() { ip netns exec crcore "$bin/corerouter-cli" --connect 127.0.0.1:7990 run "$@"; }
crsh() { ip netns exec crcore "$bin/corerouter-cli" --connect 127.0.0.1:7990 shell; }
: > "$W/daemon.log"
start_daemon
cli routing.backend.get | jq -c .

now_ms() { date +%s%3N; }
# wait_for <timeout s> <command…>: poll every 100 ms; prints the ms waited.
wait_for() {
  local t=$1; shift
  local t0; t0=$(now_ms)
  while ! "$@" >/dev/null 2>&1; do
    [ $(( $(now_ms) - t0 )) -lt $(( t * 1000 )) ] || { echo -1; return 1; }
    sleep 0.1
  done
  echo $(( $(now_ms) - t0 ))
}
# The adjacency on the CoreRouter—CHR link as each side sees it.
cr_nbr() { cli routing.ospf.neighbor.list | jq -r --arg r "${1:-10.255.39.1}" '[.rows[] | select(.router_id == $r)][0] // {} | .state // "none"'; }
cr_nbr_json() { cli routing.ospf.neighbor.list | jq -c --arg r "${1:-10.255.39.1}" '[.rows[] | select(.router_id == $r)][0] // {}'; }
ros_nbr() { ros routing/ospf/neighbor | jq -r --arg r "${1:-10.255.39.2}" '[.[] | select(.["router-id"] == $r)][0] // {} | .state // "none"'; }
ros_nbr_json() { ros routing/ospf/neighbor | jq -c --arg r "${1:-10.255.39.2}" '[.[] | select(.["router-id"] == $r)][0] // {}'; }
converged() { full_both && via_cr 10.255.39.4/32; }
full_both() { [ "$(cr_nbr)" = Full ] && [ "$(ros_nbr | tr A-Z a-z)" = full ]; }
via_cr() { [[ $(ros_route "$1") == 10.39.1.2* ]]; }
ros_route() { ros "ip/route?dst-address=$1" | jq -r '[.[] | select(.active == "true")][0] // {} | "\(.gateway // "-") \(.["routing-table"] // "") \(.distance // "")"'; }

# --- base config on both sides ----------------------------------------------
rosx '/interface bridge add name=lo0
/ip address add address=10.255.39.1/32 interface=lo0
/ip address add address=10.39.1.1/30 interface=ether1
/ip address add address=10.39.2.1/30 interface=ether2
/ip address add address=10.39.3.1/30 interface=ether3
/routing ospf instance add name=v2 router-id=10.255.39.1
/routing ospf area add name=backbone instance=v2 area-id=0.0.0.0
/routing ospf interface-template add area=backbone interfaces=ether1 type=ptp hello-interval=1s dead-interval=4s cost=10 comment=cr
/routing ospf interface-template add area=backbone interfaces=ether2 type=ptp hello-interval=1s dead-interval=4s cost=10
/routing ospf interface-template add area=backbone interfaces=ether3 type=ptp hello-interval=1s dead-interval=4s cost=1000
/routing ospf interface-template add area=backbone interfaces=lo0 passive' >/dev/null

cli interface.loopback.add '{"name":"lo"}' >/dev/null
cli ip.address.add '{"address":"10.39.1.2/30","interface":"ether1"}' >/dev/null
cli ip.address.add '{"address":"10.39.4.1/30","interface":"ether2"}' >/dev/null
cli ip.address.add '{"address":"10.255.39.2/32","interface":"lo"}' >/dev/null
cli routing.ospf.instance.add '{"name":"v2","router_id":"10.255.39.2"}' >/dev/null
cli routing.ospf.area.add '{"name":"backbone","instance":"v2","area_id":"0.0.0.0"}' >/dev/null
T1=$(cli routing.ospf.interface-template.add '{"area":"backbone","interfaces":"ether1","type":"ptp","hello_interval":1,"dead_interval":4,"cost":10,"comment":"to CHR"}' | jq -r .id)
T2=$(cli routing.ospf.interface-template.add '{"area":"backbone","interfaces":"ether2","type":"ptp","hello_interval":1,"dead_interval":4,"cost":10,"comment":"to R4"}' | jq -r .id)
cli routing.ospf.interface-template.add '{"area":"backbone","interfaces":"lo","passive":true}' >/dev/null
echo "CoreRouter templates: CHR $T1, R4 $T2"
tset() { cli routing.ospf.interface-template.set "$(jq -c --arg id "$T1" '. + {id: $id}' <<< "$1")" >/dev/null; }
rset() { rosx "/routing ospf interface-template set [find comment=cr] $1" >/dev/null; }
runset() { local p; for p in "$@"; do rosx "/routing ospf interface-template unset [find comment=cr] $p" >/dev/null; done; }

# --- cases -------------------------------------------------------------------
dump() {
  echo "--- dump: CHR interfaces"; ros interface | jq -c '.[] | {name, "mac-address", running}'
  echo "--- CHR OSPF neighbors"; ros routing/ospf/neighbor | jq -c '.[] | {instance, "router-id", address, state}'
  echo "--- CHR routes"; ros ip/route | jq -c '.[] | {"dst-address", gateway, active, ospf}' | head -20
  for ns in crr3 crr4; do echo "--- $ns"; vt $ns 'show ip ospf neighbor' | tail -n +2; vt $ns 'show ip route' | grep -E '^[OC]' ; done
  echo "--- CR neighbors"; cli routing.ospf.neighbor.list | jq -c '.rows[] | {router_id, state, interface}'
  echo "--- CR routes"; cli routing.ospf.route.list '{"instance":"v2"}' | jq -c '.rows[]' | head
  echo "--- crcore kernel"; ip -n crcore route; ip -n crcore addr | grep inet
  echo "--- router LSAs (R4's view)"; vt crr4 'show ip ospf database router' | grep -E 'Link State ID|Advertising|Link connected|Link ID|Link Data|TOS 0 Metric|Number of'
  echo "--- CHR router LSAs"; ros 'routing/ospf/lsa?type=router' | jq -r '.[] | "\(.originator) \(.body)"'
  echo "--- crcore ospfd"; vt crcore 'show ip ospf interface ether1' | head -30; vt crcore 'show running-config' | sed -n '/^interface/,$p'
}
case_ospf-ptp() {
  local ms
  ms=$(wait_for 60 full_both) || { result ospf-ptp FAIL "no Full: CR $(cr_nbr), CHR $(ros_nbr)"; return; }
  result ospf-ptp OK "Full on both sides ${ms} ms after the CoreRouter config (hello 1 s)"
  result ospf-ptp INFO "CR sees $(cr_nbr_json | jq -c '{state, role, interface, address, bfd}')"
  result ospf-ptp INFO "CHR sees $(ros_nbr_json | jq -c '{state, address, adjacency, priority}')"
  # CHR says Full while it still loads our LSAs (seen: 4 s in Loading);
  # what counts is traffic: R4's loopback through the CoreRouter.
  local r rm
  rm=$(wait_for 60 via_cr 10.255.39.4/32) || true
  r=$(ros_route 10.255.39.4/32)
  [[ $r == 10.39.1.2* ]] && result ospf-ptp OK "CHR: 10.255.39.4/32 via the CoreRouter $((ms + rm)) ms after the config ($r)" \
    || result ospf-ptp FAIL "CHR: 10.255.39.4/32 is '$r', not via 10.39.1.2"
  wait_for 30 cr_route_via_chr >/dev/null || true
  local c; c=$(cli routing.ospf.route.list '{"instance":"v2","find":"10.255.39.3"}' | jq -c '.rows[0] | {prefix, cost, nexthops}')
  [[ $c == *10.39.1.1* ]] && result ospf-ptp OK "CR: route to R3 via CHR $c" || result ospf-ptp FAIL "CR: route to R3 $c"
  ip netns exec crr3 ping -c 3 -i 0.2 -W 1 -I 10.255.39.3 10.255.39.4 >/dev/null \
    && result ospf-ptp OK "R3 → CHR → CoreRouter → R4 ping" || { result ospf-ptp FAIL "R3 → R4 ping"; dump; }
}

case_ospf-broadcast() {
  tset '{"type":"broadcast","priority":0}'
  rset 'type=broadcast'
  local ms
  ms=$(wait_for 90 full_both) || { result ospf-broadcast FAIL "no Full: CR $(cr_nbr), CHR $(ros_nbr)"; }
  [ "$ms" = -1 ] || result ospf-broadcast OK "broadcast, CoreRouter priority 0: Full in ${ms} ms"
  local cr ro
  cr=$(cr_nbr_json); ro=$(ros_nbr_json)
  result ospf-broadcast INFO "CR sees CHR as $(jq -c '{state, role, label, priority}' <<< "$cr")"
  result ospf-broadcast INFO "CHR sees CR as $(jq -c '{state, priority, dr, bdr}' <<< "$ro")"
  local iface; iface=$(cli routing.ospf.interface.list | jq -c '.rows[] | select(.interface == "ether1") | {network_type, state, dr, bdr}')
  result ospf-broadcast INFO "CR ether1: $iface"
  [[ $iface == *DROther* || $iface == *'"state":"DROther"'* || $iface == *drother* ]] \
    && result ospf-broadcast OK "CoreRouter stays DROther (never DR/BDR)" \
    || { [[ $(jq -r .dr <<< "$ro") == 10.39.1.1 ]] && result ospf-broadcast OK "CHR is DR, CoreRouter is not elected" \
         || result ospf-broadcast FAIL "election: $iface / $ro"; }
  tset '{"type":"ptp","priority":null}'
  rset 'type=ptp'
  wait_for 60 via_cr 10.255.39.4/32 >/dev/null || result ospf-broadcast FAIL "back to ptp: no route via the CoreRouter"
}

case_ospf-auth() {
  local alg ms
  for alg in md5 sha1 sha256 sha384 sha512; do
    local err
    if ! err=$(cli routing.ospf.interface-template.set "{\"id\":\"$T1\",\"auth\":\"$alg\",\"auth_id\":7,\"auth_key\":\"g39-$alg-key\"}" 2>&1); then
      if grep -q "Configuration failed" <<< "$err"; then
        result ospf-auth INFO "$alg: this FRR build refuses it; the commit fails and nothing is half-applied ($(grep -o 'FRR ospfd refused[^.]*' <<< "$err" | head -1))"
      else
        result ospf-auth FAIL "$alg: $err"
      fi
      continue
    fi
    rset "auth=$alg auth-id=7 auth-key=g39-$alg-key"
    # A changed key drops the adjacency only at the dead interval: give
    # it that before asking for Full.
    sleep 6
    if ms=$(wait_for 60 converged); then
      result ospf-auth OK "$alg (key id 7): Full and routing through the CoreRouter $((ms + 6000)) ms after the change on both"
    else
      result ospf-auth FAIL "$alg: CR $(cr_nbr), CHR $(ros_nbr)"
      cli routing.ospf.neighbor.diagnose '{"interface":"ether1"}' | jq -c '.findings' | head -c 600; echo
    fi
  done
  # A wrong key must keep the adjacency down, and say why.
  rset "auth=sha256 auth-id=7 auth-key=wrong-key"
  tset '{"auth":"sha256","auth_id":7,"auth_key":"g39-right-key"}'
  sleep 8
  local st; st="$(cr_nbr)/$(ros_nbr)"
  [[ $st != Full/* ]] && result ospf-auth OK "wrong key: no adjacency (CR/CHR: $st)" \
    || result ospf-auth FAIL "wrong key still Full"
  result ospf-auth INFO "CR diagnose: $(cli routing.ospf.neighbor.diagnose '{"interface":"ether1"}' | jq -c '[.findings[] | select(.level != "ok") | .message][0:2]')"
  tset '{"auth":null,"auth_id":null,"auth_key":null}'
  runset auth auth-id auth-key
  wait_for 60 via_cr 10.255.39.4/32 >/dev/null || result ospf-auth FAIL "back without auth: no route via the CoreRouter"
}

case_ospf-mtu() {
  cli interface.set '{"name":"ether1","mtu":1400}' >/dev/null
  # The DBD carries the MTU (RFC 2328 §10.6): CHR (1500) should refuse
  # ours? No: a router drops a DBD whose MTU is larger than its own; CHR
  # gets 1400 < 1500 and accepts, we get 1500 > 1400 and drop.
  # Force a new adjacency so the DBD exchange runs again.
  rset 'disabled=yes'; sleep 2; rset 'disabled=no'
  sleep 15
  result ospf-mtu INFO "MTU 1400 (CR) vs 1500 (CHR) after 15 s: CR sees $(cr_nbr), CHR sees $(ros_nbr)"
  result ospf-mtu INFO "CR diagnose: $(cli routing.ospf.neighbor.diagnose '{"interface":"ether1"}' | jq -c '[.findings[] | select(.level != "ok") | .message][0:2]')"
  [ "$(cr_nbr)" != Full ] && result ospf-mtu OK "MTU mismatch keeps the adjacency out of Full (RFC 2328 §10.6), as expected" \
    || result ospf-mtu INFO "MTU mismatch reached Full"
  tset '{"mtu_ignore":true}'
  local ms
  if ms=$(wait_for 60 full_both); then
    result ospf-mtu OK "mtu_ignore on the CoreRouter alone: Full in ${ms} ms (RouterOS v7 has no mtu-ignore)"
  else
    result ospf-mtu INFO "mtu_ignore on the CoreRouter alone: CR $(cr_nbr), CHR $(ros_nbr)"
  fi
  tset '{"mtu_ignore":false}'
  cli interface.set '{"name":"ether1","mtu":1500}' >/dev/null
  rset 'disabled=yes'; sleep 2; rset 'disabled=no'
  wait_for 60 via_cr 10.255.39.4/32 >/dev/null || result ospf-mtu FAIL "back to 1500: no route via the CoreRouter"
}

case_ospf-areas() {
  local ty ms
  cli routing.ospf.area.add '{"name":"a1","instance":"v2","area_id":"0.0.0.1"}' >/dev/null
  rosx '/routing ospf area add name=a1 instance=v2 area-id=0.0.0.1' >/dev/null
  for ty in default stub nssa; do
    cli routing.ospf.area.set "{\"id\":\"a1\",\"type\":\"$ty\"}" >/dev/null
    rosx "/routing ospf area set [find name=a1] type=$ty" >/dev/null
    tset '{"area":"a1"}'; rset 'area=a1'
    if ms=$(wait_for 60 full_both); then
      result ospf-areas OK "area 0.0.0.1 $ty on both: Full in ${ms} ms"
    else
      result ospf-areas FAIL "area $ty: CR $(cr_nbr), CHR $(ros_nbr)"
    fi
  done
  # A type mismatch (E/N bits, RFC 2328 §10.5, RFC 3101 §2.3) must not form.
  cli routing.ospf.area.set '{"id":"a1","type":"stub"}' >/dev/null
  rosx '/routing ospf area set [find name=a1] type=default' >/dev/null
  sleep 8
  local st; st="$(cr_nbr)/$(ros_nbr)"
  [[ $st != Full/* ]] && result ospf-areas OK "stub vs default: no adjacency (CR/CHR: $st)" \
    || result ospf-areas FAIL "stub vs default formed ($st)"
  result ospf-areas INFO "CR diagnose: $(cli routing.ospf.neighbor.diagnose '{"interface":"ether1"}' | jq -c '[.findings[] | select(.level != "ok") | .message][0:2]')"
  tset '{"area":"backbone"}'; rset 'area=backbone'
  cli routing.ospf.area.remove '{"id":"a1"}' >/dev/null
  rosx '/routing ospf area remove [find name=a1]' >/dev/null
  wait_for 60 via_cr 10.255.39.4/32 >/dev/null || result ospf-areas FAIL "back to the backbone: no route via the CoreRouter"
}

case_redistribute() {
  # The test clients' subnet on ether3 (announced: passive template) and a
  # lab network on ether4 (never announced unless asked).
  cli ip.address.add '{"address":"100.64.39.1/24","interface":"ether3"}' >/dev/null || result redistribute FAIL "address on ether3"
  cli ip.address.add '{"address":"198.18.39.1/24","interface":"ether4"}' >/dev/null || result redistribute FAIL "address on ether4"
  cli routing.ospf.interface-template.add '{"area":"backbone","interfaces":"ether3","passive":true,"comment":"clientes de teste"}' >/dev/null
  wait_for 30 via_cr 100.64.39.0/24 >/dev/null || true
  local a b
  a=$(ros_route 100.64.39.0/24); b=$(ros_route 198.18.39.0/24)
  [[ $a == 10.39.1.2* ]] && result redistribute OK "clients' subnet 100.64.39.0/24 reaches CHR via the CoreRouter" \
    || result redistribute FAIL "100.64.39.0/24 on CHR: '$a'"
  [[ $b == "- "* ]] && result redistribute OK "198.18.39.0/24 (not asked) stays out of CHR" \
    || result redistribute FAIL "198.18.39.0/24 leaked to CHR: '$b'"
  # Redistribute connected, but only what the chain accepts.
  cli routing.filter.rule.add '{"chain":"ospf-out","rule":"if (dst == 198.18.39.0/24) { accept }"}' >/dev/null
  cli routing.filter.rule.add '{"chain":"ospf-out","rule":"reject"}' >/dev/null
  cli routing.ospf.instance.set '{"id":"v2","redistribute":"connected","out_filter_chain":"ospf-out"}' >/dev/null
  # ospfd applies a changed route-map after its delay timer (5 s).
  local ms
  ms=$(wait_for 30 via_cr 198.18.39.0/24) || true
  b=$(ros_route 198.18.39.0/24)
  local ext; ext=$(ros 'routing/ospf/lsa' | jq -r '[.[] | select(.originator == "10.255.39.2" and .type != "router") | "\(.type) \(.id)"] | join(",")')
  [[ $b == 10.39.1.2* ]] && result redistribute OK "redistribute connected + chain: 198.18.39.0/24 on CHR ${ms} ms after the commit (externals from CR: $ext)" \
    || result redistribute FAIL "198.18.39.0/24 after redistribute: '$b' (externals: $ext)"
  [[ $ext != *10.39.4.0* && $ext != *100.64.39.0* ]] && result redistribute OK "the chain kept every other connected network out" \
    || result redistribute FAIL "extra externals: $ext"
  cli routing.ospf.instance.set '{"id":"v2","redistribute":[],"out_filter_chain":null}' >/dev/null
}

# The production start (docs/producao-core.md): every link of the
# CoreRouter at cost 65535 — nobody transits it (CHR → R4 stays on the
# direct link), but what it announces (the clients' subnet) is reachable.
case_entry() {
  [ -n "$(cli routing.ospf.interface-template.list | jq -r '.[] | select(.comment == "clientes de teste") | .id')" ] || {
    cli ip.address.add '{"address":"100.64.39.1/24","interface":"ether3"}' >/dev/null
    cli routing.ospf.interface-template.add '{"area":"backbone","interfaces":"ether3","passive":true,"comment":"clientes de teste"}' >/dev/null
  }
  tset '{"cost":65535}'
  cli routing.ospf.interface-template.set "{\"id\":\"$T2\",\"cost\":65535}" >/dev/null
  local ms
  ms=$(wait_for 30 not_via_cr) || true
  local r c
  r=$(ros_route 10.255.39.4/32); c=$(ros_route 100.64.39.0/24)
  [[ $r == 10.39.3.2* ]] && result entry OK "cost 65535: CHR → R4 leaves the CoreRouter ($r), ${ms} ms after the commit" \
    || result entry FAIL "cost 65535: CHR → R4 is '$r'"
  [[ $c == 10.39.1.2* ]] && result entry OK "the clients' subnet still goes to the CoreRouter ($c)" \
    || result entry FAIL "100.64.39.0/24 on CHR: '$c'"
  ip netns exec crr3 ping -c 3 -i 0.2 -W 1 -I 10.255.39.3 100.64.39.1 >/dev/null \
    && result entry OK "R3 reaches a client gateway on the CoreRouter" || result entry FAIL "R3 → 100.64.39.1"
  tset '{"cost":10}'
  cli routing.ospf.interface-template.set "{\"id\":\"$T2\",\"cost\":10}" >/dev/null
  wait_for 30 via_cr 10.255.39.4/32 >/dev/null || result entry FAIL "back to cost 10"
}
cr_route_via_chr() { cli routing.ospf.route.list '{"instance":"v2","find":"10.255.39.3"}' | jq -e '.rows[0].nexthops[0].address == "10.39.1.1"'; }
not_via_cr() { ! via_cr 10.255.39.4/32; }

# The way out: the CHR-facing template passive (hellos stop; BFD goes
# AdminDown, RFC 5880 §6.8.16) or the whole instance disabled.
case_exit() {
  local label
  for label in passive disable; do
    wait_for 60 via_cr 10.255.39.4/32 >/dev/null || true
    sleep 3
    ip netns exec crr3 ping -D -i 0.01 -W 1 -I 10.255.39.3 10.255.39.4 > "$W/ping-exit-$label.txt" 2>&1 &
    local pp=$! t0 t0ms ms
    sleep 2
    t0=$(date +%s.%N); t0ms=$(now_ms)
    if [ $label = passive ]; then tset '{"passive":true}'
    else cli routing.ospf.instance.set '{"id":"v2","disabled":true}' >/dev/null; fi
    wait_for 60 not_via_cr >/dev/null || true
    ms=$(( $(now_ms) - t0ms ))
    sleep 8
    kill -INT $pp; wait $pp 2>/dev/null || true
    result exit INFO "$label: CHR routes around the CoreRouter $ms ms after the command (REST poll); holes: $(gaps "$t0" "$W/ping-exit-$label.txt")"
    if [ $label = passive ]; then tset '{"passive":false}'
    else cli routing.ospf.instance.set '{"id":"v2","disabled":false}' >/dev/null; fi
  done
  wait_for 60 via_cr 10.255.39.4/32 >/dev/null || result exit FAIL "back in: no route via the CoreRouter"
}

ldp_on=0
ldp_up() {
  [ $ldp_on = 1 ] && return
  ldp_on=1
  cli mpls.ldp.add '{"lsr_id":"10.255.39.2"}' >/dev/null
  cli mpls.ldp.interface.add '{"interface":"ether1"}' >/dev/null
  cli mpls.ldp.interface.add '{"interface":"ether2"}' >/dev/null
  rosx '/mpls ldp add afi=ip lsr-id=10.255.39.1 transport-addresses=10.255.39.1
/mpls ldp interface add interface=ether1
/mpls ldp interface add interface=ether2
/mpls ldp interface add interface=ether3' >/dev/null
}
ldp_ok() { [ "$(cli mpls.ldp.neighbor.list | jq -r '[.[] | select(.lsr_id == "10.255.39.1")][0].operational')" = true ]; }
cr_ldp() { cli mpls.ldp.neighbor.list | jq -r '[.[] | select(.lsr_id == "10.255.39.1")][0] // {} | "\(.state // "none") \(.operational // false)"'; }
ros_ldp() { ros mpls/ldp/neighbor | jq -r '[.[] | select((.peer // "") | startswith("10.255.39.2"))][0] // {} | "\(.["operational"] // "none") \(.["transport"] // "")"'; }
mpls_routes() { ip -n crcore -f mpls route | grep -q .; }
cr_label() { cli mpls.forwarding-table.page "{\"find\":\"$1\"}" | jq -c --arg f "$1" '[.rows[] | select((.fec // "") | startswith($f))][0] // {} | {fec, in_label, out_label, nexthop, interface}'; }

case_ldp() {
  ldp_up
  local ms
  ms=$(wait_for 90 ldp_ok) \
    && result ldp OK "LDP session CoreRouter—CHR operational in ${ms} ms" \
    || result ldp FAIL "LDP: CR '$(cr_ldp)' CHR '$(ros_ldp)'"
  result ldp INFO "CR neighbor: $(cli mpls.ldp.neighbor.list | jq -c '[.[] | {lsr_id, state, transport, labels, in_use}]')"
  result ldp INFO "CHR neighbors: $(ros mpls/ldp/neighbor | jq -c '[.[] | {peer, transport, "operational", "addresses"}]' | head -c 500)"
  # LDP waits ~10 s after the session for the initial label exchange.
  wait_for 40 mpls_routes >/dev/null || true
  sleep 3
  local l3 l4
  l3=$(cr_label 10.255.39.3/32); l4=$(cr_label 10.255.39.4/32)
  [[ $(jq -r .out_label <<< "$l3") =~ ^[0-9]+$ ]] && result ldp OK "CR → R3 (via CHR) with CHR's label: $l3" \
    || result ldp FAIL "CR: no label from CHR for R3: $l3"
  result ldp INFO "CR → R4 (adjacent, implicit null): $l4"
  local rf; rf=$(ros mpls/forwarding-table | jq -c '[.[] | select((.prefix // .fec // "") | test("10.255.39.(2|4)")) | {fec: (.prefix // .fec), label, "out-labels": (.["out-labels"] // .["out-label"]), nexthops: (.nexthops // .["nh"] // .interface)}]')
  [[ $rf == *10.255.39.4* ]] && result ldp OK "CHR has labels for the CoreRouter's FECs: $rf" \
    || result ldp FAIL "CHR forwarding table: $rf"
  # End to end: R3 → R4 crosses CHR (swap) and the CoreRouter (pop):
  # labeled frames on the CHR—CoreRouter link, both ways.
  timeout 8 tcpdump -nni crv1 -c 6 'mpls' > "$W/mpls.pcap.txt" 2>/dev/null &
  local tp=$!
  sleep 1
  ip netns exec crr3 ping -c 5 -i 0.2 -W 1 -I 10.255.39.3 10.255.39.4 > "$W/ping-mpls.txt" 2>&1 \
    && result ldp OK "R3 → R4 ping through CHR and CoreRouter: $(grep -o '[0-9]* received' "$W/ping-mpls.txt")" \
    || result ldp FAIL "R3 → R4 ping: $(tail -2 "$W/ping-mpls.txt" | tr '\n' ' ')"
  wait $tp 2>/dev/null || true
  local n; n=$(grep -c "MPLS" "$W/mpls.pcap.txt" || true)
  [ "$n" -ge 2 ] && result ldp OK "labeled packets on the CHR—CoreRouter link: $n (e.g. $(grep -m1 -o 'MPLS (label [0-9]*' "$W/mpls.pcap.txt"))" \
    || result ldp FAIL "no labeled packet on the CHR—CoreRouter link ($(head -3 "$W/mpls.pcap.txt" | tr '\n' ' '))"
  grep -m4 MPLS "$W/mpls.pcap.txt" | cut -c1-160 || true
  # Traceroute from R3 (UDP): does each hop answer, with labels?
  result ldp INFO "traceroute R3 → R4: $(ip netns exec crr3 traceroute -n -q1 -w1 -s 10.255.39.3 10.255.39.4 2>&1 | tail -n +2 | tr -s ' ' | tr '\n' ';')"
  # MPLS MTU: a 1500-byte IP packet plus a label on 1500-byte links.
  if ip netns exec crr3 ping -c 2 -W 1 -M do -s 1472 -I 10.255.39.3 10.255.39.4 >/dev/null 2>&1; then
    result ldp INFO "1500-byte DF ping R3 → R4 through the LSP: passes"
  else
    result ldp INFO "1500-byte DF ping R3 → R4 through the LSP: lost (1504 bytes with the label on 1500-byte links: raise the link MTU or lower the client MTU)"
  fi
  # Our LSP ping (RFC 8029) at CHR's loopback, and at R4 through CHR.
  local tid
  tid=$(cli tool.mpls.ping.start '{"fec":"10.255.39.1/32","count":3,"interval_ms":200}' | jq -r .task_id)
  sleep 4
  result ldp INFO "CR LSP ping 10.255.39.1/32 (CHR): $(cli tool.task.poll "{\"id\":$tid,\"text\":true}" | jq -r '(.summary_lines // []) | join(" ")' | head -c 300)"
  tid=$(cli tool.mpls.ping.start '{"fec":"10.255.39.3/32","count":3,"interval_ms":200}' | jq -r .task_id)
  sleep 4
  result ldp INFO "CR LSP ping 10.255.39.3/32 (R3, through CHR): $(cli tool.task.poll "{\"id\":$tid,\"text\":true}" | jq -r '(.summary_lines // []) | join(" ")' | head -c 300)"
}

# G3.9d: traceroutes that cross the CoreRouter as a labeled hop. CHR pushes
# the CoreRouter's LDP label for R4's loopback (propagate-ttl: the IP TTL
# goes into the label); at TTL 1 it expires at the CoreRouter, whose kernel
# drops it silently. Our responder sends the time exceeded with the label
# stack (RFC 4950), which RouterOS shows as MPLS:L=…
ros_trace() { # ros_trace <dst> <src>: one probe per hop, as JSON
  jq -n --arg a "$1" --arg s "$2" '{address: $a, "src-address": $s, count: "1", "use-dns": "no", timeout: "1s"}' |
    curl -s -m 30 -u "admin:$PW" -H 'content-type: application/json' -d @- "http://$ROS/rest/tool/traceroute"
}
cr_hop() { # cr_hop <json>: the CoreRouter's hop (10.39.1.2, ether1) as text
  jq -r '[.[] | select((.address // "") == "10.39.1.2")][0] // {} | "\(.address // "-") \(.status // "") loss=\(.loss // "")"' <<< "$1"
}
case_mpls-ttl() {
  ldp_up
  wait_for 90 ldp_ok >/dev/null || { result mpls-ttl FAIL "LDP: CR '$(cr_ldp)' CHR '$(ros_ldp)'"; return; }
  wait_for 40 mpls_routes >/dev/null || true
  sleep 3
  result mpls-ttl INFO "CR label for R4: $(cr_label 10.255.39.4/32)"
  # Before: what the Linux forwarder alone does.
  cli mpls.settings.set '{"icmp_ttl_exceeded":false}' >/dev/null
  sleep 3
  local t; t=$(ros_trace 10.255.39.4 10.255.39.1)
  echo "$t" > "$W/trace-off.json"
  result mpls-ttl INFO "CHR traceroute, icmp_ttl_exceeded=no: $(jq -c '[.[] | {address, status, loss}]' <<< "$t" | head -c 400)"
  [ "$(cr_hop "$t" | cut -d' ' -f1)" = - ] \
    && result mpls-ttl OK "without the setting the CoreRouter hop is silent (the kernel drops it)" \
    || result mpls-ttl INFO "the CoreRouter hop answered without the setting: $(cr_hop "$t")"
  # After.
  cli mpls.settings.set '{"icmp_ttl_exceeded":true}' >/dev/null
  sleep 3
  t=$(ros_trace 10.255.39.4 10.255.39.1)
  echo "$t" > "$W/trace-on.json"
  result mpls-ttl INFO "CHR traceroute: $(jq -c '[.[] | {address, status, loss}]' <<< "$t" | head -c 400)"
  local hop; hop=$(cr_hop "$t")
  [[ $hop == 10.39.1.2*MPLS* ]] && result mpls-ttl OK "CHR traceroute shows the CoreRouter hop with its label: $hop" \
    || result mpls-ttl FAIL "CHR traceroute, CoreRouter hop: '$hop'"
  [ "$(jq -r '[.[] | select((.address // "") == "10.255.39.4")] | length' <<< "$t")" -ge 1 ] \
    && result mpls-ttl OK "and goes on to R4" || result mpls-ttl FAIL "R4 missing from the CHR traceroute"
  # From R3 (Linux traceroute -e prints the RFC 4950 object), two labels
  # deep in the CHR's core: R3 → CHR (swap) → CoreRouter (pop) → R4.
  local lt; lt=$(ip netns exec crr3 traceroute -n -e -q1 -w1 -s 10.255.39.3 10.255.39.4 2>&1 | tail -n +2 | tr -s ' ')
  result mpls-ttl INFO "traceroute R3 → R4: $(tr '\n' ';' <<< "$lt")"
  grep -q '10.39.1.2.*MPLS' <<< "$lt" && result mpls-ttl OK "R3's traceroute shows the CoreRouter hop with its label" \
    || result mpls-ttl FAIL "R3's traceroute, no labeled CoreRouter hop"
  sleep 2 # the counters reach the session once a second
  result mpls-ttl INFO "CR icmp_counters: $(cli mpls.settings.get | jq -c .icmp_counters)"
  [ "$(cli mpls.settings.get | jq '.icmp_counters.sent // 0')" -ge 2 ] \
    && result mpls-ttl OK "the CoreRouter counted its errors" || result mpls-ttl FAIL "icmp_counters.sent < 2"
}

# G3.9da: Path MTU Discovery through the LSP. With the CoreRouter—R4 link
# at 1400, a 1450-octet DF packet from R3 reaches the CoreRouter labeled
# (CHR pushed the CoreRouter's label for R4) and does not fit when popped:
# the kernel drops it silently. Our responder sends fragmentation needed
# with MTU 1400 (one label in, none out).
ros_ping() { # ros_ping <dst> <src> <size>: DF pings from the CHR, as JSON
  jq -n --arg a "$1" --arg s "$2" --arg z "$3" '{address: $a, "src-address": $s, count: "2", size: $z, "do-not-fragment": "", interval: "300ms"}' |
    curl -s -m 30 -u "admin:$PW" -H 'content-type: application/json' -d @- "http://$ROS/rest/ping"
}
r3_ping() { # r3_ping <size>: DF ping R3 → R4 (payload size)
  ip netns exec crr3 ping -c 3 -i 0.3 -W 1 -M do -s "$1" -I 10.255.39.3 10.255.39.4 2>&1 || true
}
case_mpls-mtu() {
  ldp_up
  wait_for 90 ldp_ok >/dev/null || { result mpls-mtu FAIL "LDP: CR '$(cr_ldp)' CHR '$(ros_ldp)'"; return; }
  wait_for 40 mpls_routes >/dev/null || true
  sleep 3
  ip -n crr4 link set eth0 mtu 1400
  cli interface.set '{"name":"ether2","mtu":1400}' >/dev/null
  ip -n crr3 route flush cache 2>/dev/null || true
  # Before: the Linux forwarder alone.
  cli mpls.settings.set '{"icmp_too_big":false}' >/dev/null
  sleep 3
  local p; p=$(r3_ping 1422)
  result mpls-mtu INFO "icmp_too_big=no, R3 1450-octet DF ping: $(tail -2 <<< "$p" | tr '\n' ' ')"
  grep -q 'Frag needed' <<< "$p" && result mpls-mtu INFO "answered without the setting: $(grep -m1 'Frag needed' <<< "$p")" \
    || result mpls-mtu OK "without the setting the 1450-octet DF ping vanishes (PMTUD black hole)"
  # After.
  cli mpls.settings.set '{"icmp_too_big":true}' >/dev/null
  sleep 3
  ip -n crr3 route flush cache 2>/dev/null || true
  p=$(r3_ping 1422)
  local f; f=$(grep -m1 'Frag needed' <<< "$p" || true)
  [[ $f == *10.39.1.2*"mtu = 1400"* ]] && result mpls-mtu OK "R3 gets fragmentation needed from the CoreRouter: $f" \
    || result mpls-mtu FAIL "R3, no fragmentation needed with mtu 1400: $(head -4 <<< "$p" | tr '\n' ' ')"
  result mpls-mtu INFO "R3 route to R4: $(ip -n crr3 route get 10.255.39.4 | head -1)"
  r3_ping 1372 | grep -q ' 0% packet loss' && result mpls-mtu OK "1400-octet DF packets now cross the LSP" \
    || result mpls-mtu FAIL "1400-octet DF ping R3 → R4 lost"
  # The CHR's own ping (RouterOS shows how it reads the error).
  local rp; rp=$(ros_ping 10.255.39.4 10.255.39.1 1450)
  echo "$rp" > "$W/ros-ping-mtu.json"
  result mpls-mtu INFO "CHR 1450-octet DF ping: $(jq -c '[.[] | {host, status, size}]' <<< "$rp" 2>/dev/null | head -c 300)"
  grep -qi 'fragment\|too large\|mtu' <<< "$rp" && result mpls-mtu OK "the CHR's ping reports the too-big error" \
    || result mpls-mtu INFO "the CHR's ping shows no too-big status"
  sleep 2 # the counters reach the session once a second
  result mpls-mtu INFO "CR icmp_counters: $(cli mpls.settings.get | jq -c .icmp_counters)"
  [ "$(cli mpls.settings.get | jq '.icmp_counters.too_big_sent // 0')" -ge 1 ] \
    && result mpls-mtu OK "the CoreRouter counted its too-big errors" || result mpls-mtu FAIL "icmp_counters.too_big_sent < 1"
  cli interface.set '{"name":"ether2","mtu":1500}' >/dev/null
  ip -n crr4 link set eth0 mtu 1500
}

bfd_on=0
bfd_up() {
  [ $bfd_on = 1 ] && return
  bfd_on=1
  # 300 ms × 3 first; the case then goes to 100 ms (stable since G3.9b).
  cli routing.bfd.profile.add '{"name":"g39","min_tx":300,"min_rx":300,"multiplier":3,"dampening":false}' >/dev/null
  tset '{"bfd":"g39"}'
  cli routing.ospf.interface-template.set "{\"id\":\"$T2\",\"bfd\":\"g39\"}" >/dev/null
  rosx '/routing bfd configuration add interfaces=ether1,ether3 min-rx=300ms min-tx=300ms multiplier=3' >/dev/null
  rset 'use-bfd=yes'
  rosx '/routing ospf interface-template set [find interfaces=ether3] use-bfd=yes' >/dev/null
}
bfd_downs() { cli routing.bfd.history.list '{"peer":"10.39.1.1","limit":2000}' | jq '[.[] | select(.to == "down")] | length'; }
set_bfd_ms() { # set_bfd_ms <ms> [multiplier]
  local m=${2:-3}
  cli routing.bfd.profile.set "{\"id\":\"g39\",\"min_tx\":$1,\"min_rx\":$1,\"multiplier\":$m}" >/dev/null
  rosx "/routing bfd configuration set [find] min-rx=$1ms min-tx=$1ms multiplier=$m" >/dev/null
  local ns
  for ns in crr3 crr4; do
    vtysh -N $ns -c 'configure terminal' -c 'bfd' -c 'profile g39' -c "receive-interval $1" \
      -c "transmit-interval $1" -c "detect-multiplier $m" >/dev/null
  done
}
bfd_ok() { [ "$(cr_bfd "$1")" = up ]; }
ros_bfd_downs() { ros log | jq --arg r "$1" '[.[] | select(.message | test("router-id: " + $r + " .*bfd down"))] | length'; }
ros_bfd_up() { [ "$(ros_bfd)" = up ]; }
cr_bfd() { cli routing.bfd.session.list | jq -r --arg p "${1:-10.39.1.1}" '[.sessions[] | select(.peer == $p)][0] // {} | .state // "none"'; }
ros_bfd() { ros routing/bfd/session | jq -r '[.[] | select((.["remote-address"] // "") | startswith("10.39.1.2"))][0] // {} | .state // "none"'; }

case_bfd() {
  bfd_up
  local ms
  ms=$(wait_for 60 bfd_ok 10.39.1.1) \
    && result bfd OK "BFD CoreRouter—CHR up in ${ms} ms (our engine as bfdd's data plane, asked by ospfd)" \
    || result bfd FAIL "BFD: CR '$(cr_bfd)', CHR '$(ros_bfd)'; bfdd: $(vt crcore 'show bfd peers brief' | tail -n +4 | tr -s ' ' | tr '\n' ';')"
  result bfd INFO "CR session: $(cli routing.bfd.session.list | jq -c '[.sessions[] | select(.peer == "10.39.1.1") | {state, remote_state, tx_interval_us, remote_min_rx_us, multiplier, remote_multiplier, detect_time_us, users}][0]')"
  result bfd INFO "CHR session: $(ros routing/bfd/session | jq -c '[.[] | {"remote-address", state, "desired-tx-interval", "required-min-rx", "remote-min-rx", multiplier, "hold-time"}][0]')"
  wait_for 30 ros_bfd_up >/dev/null && result bfd OK "CHR's BFD sees the session up" || result bfd FAIL "CHR BFD: $(ros_bfd)"
  # Stable? Then the same at 100 ms × 3: a new session (OSPF drops and
  # comes back) against a timer change of a session already up.
  local f0 f1
  sleep 15
  f0=$(bfd_downs); sleep 30; f1=$(bfd_downs)
  result bfd INFO "300 ms × 3: $((f1 - f0)) BFD downs in 30 s with the session up"
  set_bfd_ms 100
  sleep 10; f0=$(bfd_downs); sleep 30; f1=$(bfd_downs)
  [ $((f1 - f0)) = 0 ] && result bfd OK "100 ms × 3, changed with the session up (Poll): no downs in 30 s" \
    || result bfd FAIL "100 ms × 3, changed with the session up (Poll): $((f1 - f0)) downs in 30 s"
  # New sessions on both of CHR's BFD links: to us and to R4 (FRR bfdd).
  local r0 r1
  r0=$(ros_bfd_downs 10.255.39.4)
  rosx '/routing ospf interface-template set [find use-bfd=yes] use-bfd=no' >/dev/null; sleep 6
  rosx '/routing ospf interface-template set [find comment=cr] use-bfd=yes
/routing ospf interface-template set [find interfaces=ether3] use-bfd=yes' >/dev/null
  sleep 5; f0=$(bfd_downs); sleep 30; f1=$(bfd_downs)
  r1=$(ros_bfd_downs 10.255.39.4)
  # G3.9b: RouterOS keeps sending at ~1 s right after Up; our detect
  # time holds the slow rate until a packet proves the new one.
  [ $((f1 - f0)) = 0 ] && result bfd OK "100 ms × 3, new session: CoreRouter—CHR no downs in 30 s" \
    || result bfd FAIL "100 ms × 3, new session: CoreRouter—CHR $((f1 - f0)) downs in 30 s"
  result bfd INFO "100 ms × 3, new session: CHR—R4 (FRR bfdd) $((r1 - r0)) 'bfd down' in CHR's log; CR session $(cli routing.bfd.session.list | jq -c '[.sessions[] | select(.peer == "10.39.1.1") | {state, detect_time_us, rx_gap_p99_us, flaps_24h}][0]')"
  # Which profile survives a new session: RouterOS sends at ~1 s right
  # after Up, so the detect time has to cover that.
  local m
  for m in 3 4; do
    set_bfd_ms 300 "$m"
    r0=$(ros_bfd_downs 10.255.39.4)
    rosx '/routing ospf interface-template set [find use-bfd=yes] use-bfd=no' >/dev/null; sleep 6
    rosx '/routing ospf interface-template set [find comment=cr] use-bfd=yes
/routing ospf interface-template set [find interfaces=ether3] use-bfd=yes' >/dev/null
    sleep 5; f0=$(bfd_downs); sleep 30; f1=$(bfd_downs)
    r1=$(ros_bfd_downs 10.255.39.4)
    result bfd INFO "300 ms × $m, new session: CoreRouter—CHR $((f1 - f0)) downs in 30 s; CHR—R4 (FRR bfdd) $((r1 - r0))"
  done
  wait_for 60 bfd_ok 10.39.1.1 >/dev/null || result bfd FAIL "300 ms × 4: BFD not up"
  wait_for 30 bfd_ok 10.39.4.2 >/dev/null \
    && result bfd OK "BFD CoreRouter—R4 (FRR bfdd) up" || result bfd FAIL "BFD with R4: $(cr_bfd 10.39.4.2)"
}

# outage <label> <cut> <restore>: R3 pings R4's loopback every 10 ms
# through CHR and the CoreRouter; the cut kills the CoreRouter and traffic
# must go CHR → R4 directly (cost 1000). Each hole in the replies is
# printed (start after the cut, length); the restore must not open one.
gaps() { # gaps <t0> <ping -D output>: holes > 50 ms, relative to t0
  python3 -I - "$1" "$2" <<'PY'
import re, sys
t0 = float(sys.argv[1]); last = None; out = []
for line in open(sys.argv[2]):
    m = re.match(r"\[(\d+\.\d+)\].*icmp_seq=", line)
    if not m: continue
    t = float(m.group(1))
    if last is not None and t - last > 0.05: out.append("%+.2f s: %d ms" % (last - t0, (t - last) * 1000))
    last = t
print("; ".join(out) if out else "none")
PY
}
outage() {
  local label=$1 cut=$2 restore=$3
  wait_for 60 via_cr 10.255.39.4/32 >/dev/null || true
  sleep 3
  ip netns exec crr3 ping -D -i 0.01 -W 1 -I 10.255.39.3 10.255.39.4 > "$W/ping-$label.txt" 2>&1 &
  local pp=$!
  sleep 2
  local t0 t0ms; t0=$(date +%s.%N); t0ms=$(now_ms)
  eval "$cut"
  local tdown=-1 troute=-1 i
  for i in $(seq 300); do
    [ $tdown != -1 ] || [ "$(ros_nbr)" != none ] || tdown=$(( $(now_ms) - t0ms ))
    if ros_route 10.255.39.4/32 | grep -q '^10.39.3.2'; then troute=1; break; fi
    sleep 0.05
  done
  sleep 6
  local tr; tr=$(date +%s.%N)
  eval "$restore"
  local ms
  ms=$(wait_for 90 via_cr 10.255.39.4/32) || true
  sleep 20
  kill -INT $pp; wait $pp 2>/dev/null || true
  local sent recv
  sent=$(grep -o '[0-9]* packets transmitted' "$W/ping-$label.txt" | cut -d' ' -f1)
  recv=$(grep -o '[0-9]* received' "$W/ping-$label.txt" | cut -d' ' -f1)
  result failover INFO "$label: CHR dropped the CoreRouter's adjacency $tdown ms after the cut; CHR rerouted via R4: $([ $troute = 1 ] && echo yes || echo no)"
  result failover INFO "$label: holes in the pings (time after the cut: length): $(gaps "$t0" "$W/ping-$label.txt")"
  result failover INFO "$label: restored at +$(awk "BEGIN { printf \"%.2f\", $tr - $t0 }") s; traffic back through the CoreRouter $ms ms later; $((sent - recv)) of $sent pings lost in all"
  result failover INFO "$label: CR BFD flaps in this round: $(cli routing.bfd.history.list '{"peer":"10.39.1.1","limit":500}' | jq --argjson t "$t0ms" '[.[] | select(.at_ms >= $t and .to == "down")] | length')"
}
nft_dead() {
  ip netns exec crcore nft -f - <<'NFT'
table inet crdead {
  chain i { type filter hook input priority -300; iif "lo" accept; drop; }
  chain f { type filter hook forward priority -300; drop; }
  chain o { type filter hook output priority -300; oif "lo" accept; drop; }
}
table netdev crdead1 {
  chain i { type filter hook ingress device "ether1" priority -500; drop; }
}
table netdev crdead2 {
  chain i { type filter hook ingress device "ether2" priority -500; drop; }
}
NFT
}
nft_alive() {
  ip netns exec crcore nft delete table inet crdead
  ip netns exec crcore nft delete table netdev crdead1
  ip netns exec crcore nft delete table netdev crdead2
}
mon() { python3 -I - "$W/chr.mon" "$1" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); time.sleep(0.2); s.recv(4096)
s.sendall((sys.argv[2] + "\n").encode()); time.sleep(0.2)
PY
}

case_failover() {
  ldp_up
  bfd_up
  wait_for 60 bfd_ok 10.39.1.1 >/dev/null || true
  # Silent: the CoreRouter stops forwarding and answering, links stay up.
  outage silent-bfd nft_dead nft_alive
  # Carrier lost: CHR's port and R4's port see the link go down.
  outage carrier "mon 'set_link e1 off'; ip -n crcore link set ether2 down" \
    "mon 'set_link e1 on'; ip -n crcore link set ether2 up"
  # Silent without BFD: only OSPF's dead interval (4 s here, 40 s default).
  rset 'use-bfd=no'
  rosx '/routing ospf interface-template set [find interfaces=ether3] use-bfd=no' >/dev/null
  tset '{"bfd":null}'
  cli routing.ospf.interface-template.set "{\"id\":\"$T2\",\"bfd\":null}" >/dev/null
  vtysh -N crr4 -c 'configure terminal' -c 'interface eth0' -c 'no ip ospf bfd' >/dev/null
  outage silent-no-bfd nft_dead nft_alive
  bfd_on=0
}

# G3.9c: stub router (RFC 6987). R3 pings R4's loopback every 10 ms; the
# best path crosses the CoreRouter (CHR → CR → R4, cost 30 against the
# direct CHR → R4 at 1000). Measured: the pings lost when the CoreRouter
# is drained and undrained with traffic on it, and when it comes back from
# a reboot with and without `on-startup` (the reboot: carrier lost on both
# ports, FRR and the daemon killed, routes flushed; then the links come
# back and everything starts again, as after a power cycle).
lost_after() { # lost_after <t> <ping -D output>: pings lost after time t
  python3 -I - "$1" "$2" <<'PY'
import re, sys
t = float(sys.argv[1]); prev = None; lost = 0
for line in open(sys.argv[2]):
    m = re.match(r"\[(\d+\.\d+)\].*icmp_seq=(\d+)", line)
    if not m: continue
    at, seq = float(m.group(1)), int(m.group(2))
    if prev is not None and at >= t: lost += max(0, seq - prev - 1)
    prev = seq
print(lost)
PY
}
cr_stub() { cli routing.ospf.instance.list | jq -r '.[] | select(.name == "v2") | .stub_state.state // "none"'; }
cr_stub_is() { [ "$(cr_stub)" = "$1" ]; }
ping_r3_r4() { ip netns exec crr3 ping -D -i 0.01 -W 1 -I 10.255.39.3 10.255.39.4 > "$1" 2>&1 & echo $!; }
# Writes the pings lost after power-on to $W/reboot-<label>.lost. Never
# call it inside $(…): the daemon and FRR it restarts inherit the pipe and
# the command substitution never sees EOF.
cr_reboot() { # cr_reboot <label>
  local label=$1 log="$W/ping-stub-$1.txt"
  wait_for 90 via_cr 10.255.39.4/32 >/dev/null || true
  sleep 3
  local pp; pp=$(ping_r3_r4 "$log")
  sleep 2
  local t0; t0=$(date +%s.%N)
  mon 'set_link e1 off'; ip -n crcore link set ether2 down
  kill -9 "$(cat "$W/daemon.pid")" 2>/dev/null || true
  pkill -9 -f -- "-N crcore" 2>/dev/null || true
  ip -n crcore route flush proto ospf 2>/dev/null || true
  ip -n crcore -f mpls route flush 2>/dev/null || true
  wait_for 30 not_via_cr >/dev/null || true
  sleep 5
  # Power back: the links first, then FRR, then the CoreRouter.
  local tr trms; tr=$(date +%s.%N); trms=$(now_ms)
  mon 'set_link e1 on'; ip -n crcore link set ether2 up
  start_cr_frr
  start_daemon
  local full via stub
  full=$(wait_for 90 full_both) || true
  stub=$(cr_stub)
  via=$(wait_for 150 via_cr 10.255.39.4/32) || true
  [ "$via" = -1 ] || via=$(( $(now_ms) - trms ))
  sleep 10
  kill -INT "$pp"; wait "$pp" 2>/dev/null || true
  local sent recv back
  sent=$(grep -o '[0-9]* packets transmitted' "$log" | cut -d' ' -f1)
  recv=$(grep -o '[0-9]* received' "$log" | cut -d' ' -f1)
  back=$(lost_after "$tr" "$log")
  result stub-router INFO "reboot $label: Full ${full} ms after power-on (stub state then: $stub); CHR back through the CoreRouter at ${via} ms; $back pings lost after power-on, $((sent - recv)) of $sent in all"
  result stub-router INFO "reboot $label: holes (time after the cut: length): $(gaps "$t0" "$log")"
  echo "$back" > "$W/reboot-$label.lost"
}
case_stub-router() {
  [ -n "$(cli routing.ospf.interface-template.list | jq -r '.[] | select(.comment == "clientes de teste") | .id')" ] || {
    cli ip.address.add '{"address":"100.64.39.1/24","interface":"ether3"}' >/dev/null
    cli routing.ospf.interface-template.add '{"area":"backbone","interfaces":"ether3","passive":true,"comment":"clientes de teste"}' >/dev/null
  }
  wait_for 90 via_cr 10.255.39.4/32 >/dev/null || { result stub-router FAIL "no path through the CoreRouter to start from: $(ros_route 10.255.39.4/32)"; return; }
  sleep 3
  # Drain and undrain with traffic on it.
  local pp t0 ms lost
  pp=$(ping_r3_r4 "$W/ping-stub-drain.txt")
  sleep 2
  t0=$(date +%s.%N)
  cli routing.ospf.instance.set '{"id":"v2","stub_router":true}' >/dev/null
  ms=$(wait_for 30 not_via_cr) || true
  local r c st
  r=$(ros_route 10.255.39.4/32); c=$(ros_route 100.64.39.0/24)
  st=$(wait_for 10 cr_stub_is administrative) && st=administrative || st=$(cr_stub)
  [[ $r == 10.39.3.2* ]] && result stub-router OK "drain: CHR → R4 leaves the CoreRouter ($r) ${ms} ms after the command; the daemon says $st" \
    || result stub-router FAIL "drain: CHR → R4 is '$r' (stub state $st)"
  [[ $c == 10.39.1.2* ]] && result stub-router OK "drain: the clients' subnet still goes to the CoreRouter ($c)" \
    || result stub-router FAIL "drain: 100.64.39.0/24 on CHR is '$c'"
  ip netns exec crr3 ping -c 3 -i 0.2 -W 1 -I 10.255.39.3 100.64.39.1 >/dev/null \
    && result stub-router OK "drain: R3 reaches a client gateway on the CoreRouter" || result stub-router FAIL "drain: R3 → 100.64.39.1"
  local metric
  metric=$(ros 'routing/ospf/lsa' | jq -r '[.[] | select(.originator == "10.255.39.2" and .type == "router")][0].body // ""' | tr '\n' ' ' | cut -c1-200)
  result stub-router INFO "drain: the CoreRouter's router-LSA on CHR: $metric"
  sleep 3
  lost=$(lost_after "$t0" "$W/ping-stub-drain.txt")
  result stub-router INFO "drain: $lost pings lost (10 ms apart); holes: $(gaps "$t0" "$W/ping-stub-drain.txt")"
  local t1; t1=$(date +%s.%N)
  cli routing.ospf.instance.set '{"id":"v2","stub_router":false}' >/dev/null
  ms=$(wait_for 30 via_cr 10.255.39.4/32) || true
  sleep 3
  kill -INT "$pp"; wait "$pp" 2>/dev/null || true
  lost=$(lost_after "$t1" "$W/ping-stub-drain.txt")
  [ "$ms" != -1 ] && result stub-router OK "undrain: CHR back through the CoreRouter ${ms} ms after the command; $lost pings lost" \
    || result stub-router FAIL "undrain: CHR → R4 is $(ros_route 10.255.39.4/32)"
  # A reboot without, then with on-startup. Set on a running instance it
  # must not drain now (ospfd arms it at an area's first router-LSA).
  local plain timed
  cr_reboot plain; plain=$(cat "$W/reboot-plain.lost" 2>/dev/null || echo "?")
  cli routing.ospf.instance.set '{"id":"v2","stub_router_on_startup":60}' >/dev/null
  sleep 5
  via_cr 10.255.39.4/32 && [ "$(cr_stub)" = off ] \
    && result stub-router OK "on-startup set on the running instance: no drain until the next start" \
    || result stub-router FAIL "on-startup on a running instance: stub $(cr_stub), CHR → R4 $(ros_route 10.255.39.4/32)"
  cr_reboot on-startup-60; timed=$(cat "$W/reboot-on-startup-60.lost" 2>/dev/null || echo "?")
  result stub-router INFO "pings lost after power-on: $plain without on-startup, $timed with on-startup 60 s"
  cli routing.ospf.instance.set '{"id":"v2","stub_router_on_startup":null}' >/dev/null
}

case_ospfv3() {
  cli ip.address.add '{"address":"2001:db8:39::2/128","interface":"lo"}' >/dev/null
  cli routing.ospf.instance.add '{"name":"v3","version":3,"router_id":"10.255.39.2"}' >/dev/null
  cli routing.ospf.area.add '{"name":"backbone6","instance":"v3","area_id":"0.0.0.0"}' >/dev/null
  cli routing.ospf.interface-template.add '{"area":"backbone6","interfaces":"ether1","type":"ptp","hello_interval":1,"dead_interval":4}' >/dev/null
  cli routing.ospf.interface-template.add '{"area":"backbone6","interfaces":"lo","passive":true}' >/dev/null
  rosx '/ipv6 address add address=2001:db8:39::1/128 interface=lo0 advertise=no
/routing ospf instance add name=v3 version=3 router-id=10.255.39.1
/routing ospf area add name=backbone6 instance=v3 area-id=0.0.0.0
/routing ospf interface-template add area=backbone6 interfaces=ether1 type=ptp hello-interval=1s dead-interval=4s
/routing ospf interface-template add area=backbone6 interfaces=lo0 passive' >/dev/null
  local ms
  v3full() { [ "$(cli routing.ospf.neighbor.list | jq -r '[.rows[] | select(.version == 3 and .router_id == "10.255.39.1")][0].state')" = Full ]; }
  ms=$(wait_for 60 v3full) && result ospfv3 OK "OSPFv3 Full in ${ms} ms" \
    || result ospfv3 FAIL "OSPFv3: CR $(cli routing.ospf.neighbor.list | jq -c '[.rows[] | select(.version == 3)]'), CHR $(ros routing/ospf/neighbor | jq -c '[.[] | select(.instance == "v3")]')"
  sleep 4
  local r; r=$(ros 'ipv6/route?dst-address=2001:db8:39::2/128' | jq -r '[.[] | select(.active == "true")][0].gateway // "-"')
  [ "$r" != - ] && result ospfv3 OK "CHR: 2001:db8:39::2/128 via $r" || result ospfv3 FAIL "CHR has no route to the CoreRouter's v6 loopback"
  ip netns exec crcore ip -6 route get 2001:db8:39::1 2>/dev/null | grep -q ether1 \
    && result ospfv3 OK "CR: 2001:db8:39::1 via ether1" || result ospfv3 FAIL "CR has no v6 route to CHR's loopback"
}

# docs/producao-core.md, as written: a CoreRouter with an empty config
# takes the "core-start" block through its terminal (/import: one atomic
# batch), CHR's port to it the "mikrotik-side" block; then the way out the
# document gives (transactional, diff, impact, commit).
doc_block() { awk -v m="lab:$1" 'index($0, m) {f=1; next} f && /^```text/ {g=1; next} g && /^```/ {exit} g' "$DOC"; }
case_prod() {
  DOC=${DOC:-docs/producao-core.md}
  doc_block core-start > "$W/core-start.rsc"
  doc_block mikrotik-side > "$W/mikrotik-side.rsc"
  [ -s "$W/core-start.rsc" ] && [ -s "$W/mikrotik-side.rsc" ] || { result prod FAIL "blocks not found in $DOC"; return; }
  kill "$(cat "$W/daemon.pid")"; sleep 2
  rm -rf "$W/cfg"
  start_daemon
  # CHR is the existing core: LDP already running (towards R3 and R4).
  if [ "$(ros mpls/ldp | jq length)" = 0 ]; then
    rosx '/mpls ldp add afi=ip lsr-id=10.255.39.1 transport-addresses=10.255.39.1
/mpls ldp interface add interface=ether2
/mpls ldp interface add interface=ether3' >/dev/null
  fi
  [ "$(ros routing/bfd/configuration | jq length)" != 0 ] \
    || rosx '/routing bfd configuration add interfaces=ether3 min-rx=300ms min-tx=300ms multiplier=3' >/dev/null
  # CHR: forget what the other cases set on ether1, keep BFD to R4.
  rosx '/routing ospf interface-template remove [find comment=cr]
/routing bfd configuration set [find] interfaces=ether3
/mpls ldp interface remove [find interface=ether1]' >/dev/null || true
  local t0 out
  t0=$(now_ms)
  out=$(printf '/import file=%s\n' "$W/core-start.rsc" | crsh 2>&1)
  grep -q "atomic batch" <<< "$out" && result prod OK "core-start block: $(grep -o 'imported [0-9]* command(s) as one atomic batch' <<< "$out")" \
    || { result prod FAIL "core-start block: $(tail -3 <<< "$out" | tr '\n' ' ')"; return; }
  rosx "$(cat "$W/mikrotik-side.rsc")" >/dev/null || { result prod FAIL "mikrotik-side block refused"; return; }
  local ms
  ms=$(wait_for 90 full_both) && result prod OK "Full ${ms} ms after both blocks (sha256, hello 10 s)" \
    || { result prod FAIL "no Full: CR $(cr_nbr), CHR $(ros_nbr)"; return; }
  ms=$(wait_for 60 bfd_ok 10.39.1.1) && result prod OK "BFD up ($(cli routing.bfd.session.list | jq -r '[.sessions[] | select(.peer == "10.39.1.1")][0] | "\(.tx_interval_us / 1000) ms × \(.multiplier)"'), dampening on)" || result prod FAIL "BFD: $(cr_bfd)"
  ms=$(wait_for 60 ldp_ok) && result prod OK "LDP operational" || result prod FAIL "LDP: $(cr_ldp)"
  ms=$(wait_for 60 via_cr 100.64.39.0/24) && result prod OK "clients' subnet on CHR via the CoreRouter" \
    || result prod FAIL "100.64.39.0/24 on CHR: $(ros_route 100.64.39.0/24)"
  local others; others=$(ros ip/route | jq -r '[.[] | select(.active == "true" and (.gateway // "" | startswith("10.39.1.2")))] | map(.["dst-address"]) | join(",")')
  [ "$others" = "100.64.39.0/24,10.255.39.2/32" ] || [ "$others" = "10.255.39.2/32,100.64.39.0/24" ] \
    && result prod OK "CHR sends only the loopback and the clients' subnet to the CoreRouter" \
    || result prod FAIL "CHR routes via the CoreRouter: $others"
  ip netns exec crr3 ping -c 3 -i 0.2 -W 1 -I 10.255.39.3 100.64.39.1 >/dev/null \
    && result prod OK "R3 reaches the clients' gateway through CHR" || result prod FAIL "R3 → 100.64.39.1"
  # The way out, as the document writes it.
  t0=$(now_ms)
  out=$(printf '/config mode set mode=transactional\n/routing ospf interface-template print\n/routing ospf interface-template set 0 passive=yes\n/config diff\n/routing ospf impact\n/config commit\n/config mode set mode=immediate\n' | crsh 2>&1)
  grep -q "dropping: ether1" <<< "$out" && result prod OK "impact before the commit: ether1's adjacency drops (Safe Mode advised)" \
    || result prod FAIL "impact: $(grep -A3 impact <<< "$out" | tr '\n' ' ')"
  ms=$(wait_for 60 not_via_cr_clients) && result prod OK "passive: the clients' subnet leaves CHR $(( $(now_ms) - t0 )) ms after the commit" \
    || result prod FAIL "still routed via the CoreRouter after passive"
}
not_via_cr_clients() { ! via_cr 100.64.39.0/24; }

for c in "${CASES[@]}"; do
  echo "=== $c ==="
  "case_$c" || result "$c" FAIL "the case stopped: exit $?"
done
echo
echo "=== results (RouterOS $ROS_VERSION CHR × CoreRouter $(git rev-parse --short HEAD 2>/dev/null || echo ?)) ==="
cat "$W/results.txt"
echo "--- CoreRouter log.print (last 25: what an operator sees) ---"
cli log.print '{"limit":25}' | jq -r '.[] | "\(.time) \(.topics | join(",")) \(.message)"' | cut -c1-200 || true
if [ $FAILED != 0 ]; then
  echo "--- CR daemon log (tail) ---"; tail -20 "$W/daemon.log"
  echo "--- CHR log (tail) ---"; ros log | jq -r '.[-25:][] | "\(.time) \(.topics) \(.message)"' || true
fi
exit $FAILED
