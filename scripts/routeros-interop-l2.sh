#!/usr/bin/env bash
# G3.9h: L2 and services of the CoreRouter (linux backend) against a real
# MikroTik RouterOS v7 CHR and against a second CoreRouter. Runs as root
# inside the lab VM only:
#   cargo xtask vm-lab run -- scripts/routeros-interop-l2.sh [case…]
# Cases (default: all, in this order): wire vlan qinq rsc mtu lldp arp tools dhcp
#   (prints, G3.9hl: only when named: print/export of /interface menus)
#   dhcp-client dhcp-relay dhcp6 dhcp6-client ra ntp dns nat cgnat bond
#   cr-dhcp cr-bond storm dns-qps
# NO_CHR=1 BIN=<release dir>: no CHR, only the CoreRouter × CoreRouter
# cases (cr-dhcp cr-bond storm dns-qps), e.g. on a host without root in a
# disposable namespace: unshare --user --map-root-user --net --mount --
# sh -c 'mount -t tmpfs none /run && mkdir /run/netns && W=<dir> NO_CHR=1
# BIN=<dir> scripts/routeros-interop-l2.sh'.
# HOLD=<s> keeps the lab up that long at the end. Results: a table at the
# end and /tmp/crg39h/results.txt in the VM; exit 1 if any case failed.
#
# Topology (all inside the VM). Each CHR tap is tied to a veth into the
# CoreRouter's namespace with tc mirred, a wire with nothing in between
# (a Linux bridge would swallow LACP: 802.1D never forwards
# 01:80:C2:00:00:02).
#
#   CHR ether1 ════ ether1 CoreRouter A (ns crcore) ether5 ──── ether1 CoreRouter B (ns crpeer)
#   CHR ether2 ════ ether2 A (bond)                 ether6 ──── ether2 B (bond)
#   CHR ether3 ════ ether3 A (bond)                 ether7 ──── ether3 B (bond)
#   CHR ether4 ──crbm── 192.168.239.1 (REST)        ether8 ──── cl0 (ns crcl: clients, BNG Blaster)
#
# Each service gets a VLAN on ether1 (A side) so the cases do not see
# each other: 10 DHCP (A server), 11 DHCP (CHR server), 12 DHCPv6 (A
# server), 13 DHCPv6 (CHR server), 14 RA, 20 DHCP relay, 30 plain VLAN.
set -euo pipefail
# vm-lab run holds its lock on fd 9: a daemon started from here would
# inherit it and keep the VM locked after the round.
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }

ROS_VERSION=${ROS_VERSION:-7.25}
ROS_SHA256=${ROS_SHA256:-6b981288350de2a2c7a3218bd820ab702633b8cd6cd339f2bb34dda1f1a2550e}
CASES=("$@")
[ ${#CASES[@]} -gt 0 ] || [ -z "${NO_CHR:-}" ] || CASES=(cr-dhcp cr-bond dhcp-conflict storm dns-qps)
[ ${#CASES[@]} -gt 0 ] || CASES=(wire vlan qinq rsc mtu lldp arp tools dhcp dhcp-client dhcp-relay dhcp-conflict dhcp6 dhcp6-client ra ntp dns nat cgnat bond cr-dhcp cr-bond storm dns-qps)
W=${W:-/tmp/crg39h}
CHR_DIR=/srv/lab/chr
PW=g39h-lab-only
ROS=192.168.239.2
FAILED=0
mkdir -p "$W"
: > "$W/results.txt"

result() { # result <case> <OK|FAIL|INFO> <text>
  printf '%-13s %-4s %s\n' "$1" "$2" "$3" | tee -a "$W/results.txt"
  [ "$2" != FAIL ] || FAILED=1
}

# --- tools and image -------------------------------------------------------
if [ -n "${NO_CHR:-}" ]; then
  for t in tcpdump iperf3 jq; do command -v $t >/dev/null || { echo "NO_CHR: $t missing"; exit 1; }; done
  bin=${BIN:?NO_CHR needs BIN=<dir with corerouter-daemon and corerouter-cli>}
else
need=()
for t in qemu-system-x86_64:qemu-system-x86 traceroute:traceroute tcpdump:tcpdump iperf3:iperf3 jq:jq ethtool:ethtool; do
  command -v "${t%%:*}" >/dev/null || need+=("${t#*:}")
done
[ ${#need[@]} = 0 ] || DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${need[@]}" unzip >/dev/null
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
fi

# --- teardown ---------------------------------------------------------------
NSS="crcore crpeer crcl"
cleanup() {
  [ -f "$W/qemu.pid" ] && kill "$(cat "$W/qemu.pid")" 2>/dev/null || true
  for f in "$W"/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; done
  for ns in $NSS; do
    ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
  done
  sleep 0.5
  for ns in $NSS; do
    ip netns pids $ns 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del $ns 2>/dev/null || true
  done
  ip link del crbm 2>/dev/null || true
  for l in crt1 crt2 crt3 crt4 crv1 crv2 crv3; do ip link del $l 2>/dev/null || true; done
  rm -f "$W"/*.pid
}
finish() {
  local s=$?
  if [ -n "${HOLD:-}" ]; then echo "HOLD: lab up for $HOLD s"; sleep "$HOLD" || true; fi
  [ -z "${WATCHDOG:-}" ] || { pkill -P "$WATCHDOG" 2>/dev/null; kill "$WATCHDOG" 2>/dev/null; } || true
  cleanup
  exit $s
}
cleanup
trap finish EXIT
trap 'exit 124' TERM INT
# One round at most MAX_SECS (the lab VM is shared: ~30 min a round). A
# bare `wait` would also wait for the daemons: only `wait <pid>` here.
( sleep "${MAX_SECS:-1800}"; echo "watchdog: ${MAX_SECS:-1800} s, ending the round" >&2; kill -TERM $$ ) 9>&- &
WATCHDOG=$!

# --- topology ---------------------------------------------------------------
modprobe bonding 2>/dev/null || true
modprobe 8021q 2>/dev/null || true
for ns in $NSS; do
  ip netns add $ns
  ip -n $ns link set lo up
done
for ns in crcore crpeer; do
  ip netns exec $ns sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
done
# veth <ns a> <name a> <ns b> <name b>
veth() { ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"; ip -n "$1" link set "$2" up; ip -n "$3" link set "$4" up; }
veth crcore ether5 crpeer ether1
veth crcore ether6 crpeer ether2
veth crcore ether7 crpeer ether3
veth crcore ether8 crcl cl0

if [ -z "${NO_CHR:-}" ]; then
cp "$img" "$W/chr.img"
# ether2/3 (the bond) report 1 Gbit/s full duplex: virtio-net says unknown,
# and the CHR's 802.3ad then keeps LACP off on them (no LACPDU sent).
qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -name chr-g39h \
  -drive file="$W/chr.img",format=raw,if=virtio \
  -netdev tap,id=e1,ifname=crt1,script=no,downscript=no -device virtio-net-pci,netdev=e1,mac=52:54:00:39:01:01 \
  -netdev tap,id=e2,ifname=crt2,script=no,downscript=no -device virtio-net-pci,netdev=e2,mac=52:54:00:39:01:02,speed=1000,duplex=full \
  -netdev tap,id=e3,ifname=crt3,script=no,downscript=no -device virtio-net-pci,netdev=e3,mac=52:54:00:39:01:03,speed=1000,duplex=full \
  -netdev tap,id=e4,ifname=crt4,script=no,downscript=no -device virtio-net-pci,netdev=e4,mac=52:54:00:39:01:04 \
  -serial unix:$W/chr.sock,server,nowait -monitor unix:$W/chr.mon,server,nowait \
  -display none -daemonize -pidfile "$W/qemu.pid"
# The CHR's first three ports are wired to the CoreRouter's ether1..3: a
# veth into crcore, and tc mirred both ways between tap and veth, so every
# frame passes (a bridge would keep LACP; the daemon does not adopt a tap,
# a tun it did not create).
for i in 1 2 3; do
  ip link add crv$i type veth peer name ether$i netns crcore
  ip link set crv$i up; ip link set crt$i up
  ip -n crcore link set ether$i up
  # A veth leaves the UDP/TCP checksum of the kernel's own sockets for the
  # NIC to fill (CHECKSUM_PARTIAL); through tc mirred into the CHR's tap it
  # arrives unfilled and RouterOS drops it (the unicast DHCP renewal, DNS,
  # NTP). A real NIC fills it: compute it in software on the lab wire.
  ip netns exec crcore ethtool -K ether$i tx off >/dev/null 2>&1 || echo "ethtool -K ether$i tx off failed" >&2
  for pair in "crt$i crv$i" "crv$i crt$i"; do
    set -- $pair
    tc qdisc add dev "$1" ingress
    tc filter add dev "$1" parent ffff: matchall action mirred egress redirect dev "$2"
  done
done
ip link add crbm type bridge
ip addr add 192.168.239.1/24 dev crbm
ip link set crbm up
ip link set crt4 master crbm up
mon() { python3 -I -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2)' "$W/chr.mon" "$1"; }

# The console: log in, take the first-login questions, type the bootstrap.
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
/system identity set name=chr-g39h
/ip address add address=192.168.239.2/24 interface=ether4
/ip service set www disabled=no
ROS
for _ in $(seq 100); do curl -sf -m 2 -u "admin:$PW" "http://$ROS/rest/system/resource" >/dev/null && break; sleep 0.2; done
fi

# ros <path>: GET. rosp <path> <json>: POST (a command). rosx <script>:
# RouterOS CLI lines. rosput <expr>: the value of a :put.
ros() { curl -sf -m 10 -u "admin:$PW" "http://$ROS/rest/$1"; }
rosp() { curl -s -m 60 -u "admin:$PW" -H 'content-type: application/json' -d "$2" "http://$ROS/rest/$1"; }
rosx() {
  # `as-string`: run it and wait. Without it /rest/execute starts a background
  # job and returns, so two calls in a row race (an address added before its
  # VLAN exists).
  local out
  out=$(jq -n --arg s "$1" '{script: $s, "as-string": true}' |
    curl -s -m 30 -u "admin:$PW" -H 'content-type: application/json' -d @- "http://$ROS/rest/execute")
  if echo "$out" | jq -e 'type == "object" and (has("error") or ((.ret // "") | test("failure:|syntax error|bad command|no such item|expected end of command")))' >/dev/null 2>&1; then
    echo "RouterOS refused: $out" >&2
    return 1
  fi
  printf '%s' "$out"
}
rosput() { jq -n --arg s ":put ($1)" '{script: $s, "as-string": true}' |
  curl -s -m 30 -u "admin:$PW" -H 'content-type: application/json' -d @- "http://$ROS/rest/execute" | jq -r '.ret // .'; }
# ros_ping <address> [extra json]: received count of 5 pings from the CHR.
ros_ping() { local x=${2:-'{}'}; rosp ping "$(jq -nc --arg a "$1" --argjson x "$x" '{address: $a, count: "5", interval: "0.2"} + $x')" |
  jq -r '[.[] | select(.received != null)][-1].received // "0"'; }
echo "RouterOS: $(ros system/resource | jq -r '"\(.version) on \(.["architecture-name"]), \(.["cpu-count"]) CPU"')"

# --- the two CoreRouters ----------------------------------------------------
export COREROUTER_RUNTIME_DIR=$W/run
rm -rf "$COREROUTER_RUNTIME_DIR" "$W/cfg-a" "$W/cfg-b"
mkdir -p "$COREROUTER_RUNTIME_DIR"
# start_cr <ns> <port> <cfg> <log> [flags…]
start_cr() {
  local ns=$1 port=$2 cfg=$3 log=$4; shift 4
  ip netns exec "$ns" "$bin/corerouter-daemon" --backend linux --manage 'ether*' \
    --config-dir "$cfg" --control "$port" "$@" >> "$log" 2>&1 &
  echo $! > "$W/daemon-$ns.pid"
  for _ in $(seq 150); do
    ip netns exec "$ns" "$bin/corerouter-cli" --connect 127.0.0.1:$port run routing.backend.get >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "daemon in $ns did not answer"; tail -20 "$log"; return 1
}
cli() { ip netns exec crcore "$bin/corerouter-cli" --connect 127.0.0.1:7990 run "$@"; }
clib() { ip netns exec crpeer "$bin/corerouter-cli" --connect 127.0.0.1:7991 run "$@"; }
: > "$W/daemon-a.log"; : > "$W/daemon-b.log"
start_cr crcore 7990 "$W/cfg-a" "$W/daemon-a.log"
start_cr crpeer 7991 "$W/cfg-b" "$W/daemon-b.log" --no-discovery
# A password on admin (the local token still logs the CLI in): no
# "admin has no password" warning on every command.
cli user.set "{\"name\":\"admin\",\"password\":\"$PW\"}" >/dev/null 2>&1 || true
clib user.set "{\"name\":\"admin\",\"password\":\"$PW\"}" >/dev/null 2>&1 || true
cli system.identity.set '{"name":"cr-a"}' >/dev/null
clib system.identity.set '{"name":"cr-b"}' >/dev/null
DPID=$(cat "$W/daemon-crcore.pid")

now_ms() { date +%s%3N; }
wait_for() { # wait_for <timeout s> <command…>: prints the ms waited
  local t=$1; shift
  local t0; t0=$(now_ms)
  while ! "$@" >/dev/null 2>&1; do
    [ $(( $(now_ms) - t0 )) -lt $(( t * 1000 )) ] || { echo -1; return 1; }
    sleep 0.2
  done
  echo $(( $(now_ms) - t0 ))
}
# run_task <id> <params>: start a tool task and poll it to the end; prints
# the last poll (summary and events).
run_task() {
  local st id t0
  st=$(cli "$1" "$2") || { echo "{}"; return 1; }
  id=$(jq -r '.task_id // .id' <<< "$st")
  t0=$(now_ms)
  while :; do
    local p; p=$(cli tool.task.poll "{\"id\":$id,\"max\":256,\"text\":true}")
    if [ "$(jq -r .done <<< "$p")" = true ] || [ $(( $(now_ms) - t0 )) -gt 60000 ]; then echo "$p"; return 0; fi
    sleep 0.5
  done
}
cr_ping() { local x=${2:-'{}'}; run_task tool.ping.start "$(jq -nc --arg a "$1" --argjson x "$x" '{address: $a, count: 5, interval_ms: 200} + $x')"; }
cr_ping_ok() { # cr_ping_ok <address> [extra]: at least 4 of 5 answered
  local p; p=$(cr_ping "$@")
  local r; r=$(jq -r '[.summary // {} | .. | objects | select(has("received")) | .received][0] // empty' <<< "$p")
  [ -n "$r" ] || r=$(jq -r '[.events[] | select((.status // "") == "reply" or (.status // "") == "ok" or (.rtt_ms // null) != null)] | length' <<< "$p")
  [ "${r:-0}" -ge 4 ]
}
# Per-thread CPU of the A daemon: snapshot <file>; cpu_report <before> <after> <s>.
snapshot() { for t in /proc/$DPID/task/*; do awk -v n="$(cat "$t/comm")" '{print n, $14 + $15}' "$t/stat"; done | sort > "$1"; }
cpu_report() {
  awk -v s="$3" -v hz="$(getconf CLK_TCK)" 'NR==FNR {b[$1" "NR]=$2; bn[$1]+=$2; next} {an[$1]+=$2}
    END {for (k in an) {d=(an[k]-bn[k])/hz/s*100; if (d >= 1) printf "%s %.0f%%, ", k, d}}' "$1" "$2"
}

# --- base addressing --------------------------------------------------------
if [ -z "${NO_CHR:-}" ]; then
rosx '/interface bridge add name=lo0
/ip address add address=10.255.39.1/32 interface=lo0
/ip address add address=10.39.1.1/29 interface=ether1
/ip neighbor discovery-settings set discover-interface-list=all protocol=lldp,mndp,cdp' >/dev/null
cli ip.address.add '{"address":"10.39.1.2/29","interface":"ether1"}' >/dev/null
cli ip.route.add '{"dst_address":"10.255.39.1/32","gateway":"10.39.1.1"}' >/dev/null
fi
cli ip.address.add '{"address":"10.39.5.1/30","interface":"ether5"}' >/dev/null
clib ip.address.add '{"address":"10.39.5.2/30","interface":"ether1"}' >/dev/null
cli ip.address.add '{"address":"10.40.0.1/16","interface":"ether8"}' >/dev/null
ip -n crcl addr add 10.40.255.254/16 dev cl0

# cr_vlan <vid> <a addr> | ros_vlan <vid> <addr>: one VLAN on ether1, both ends.
cr_vlan() { cli interface.vlan.add "{\"name\":\"v$1\",\"parent\":\"ether1\",\"vlan_id\":$1}" >/dev/null
  [ -z "${2:-}" ] || cli ip.address.add "{\"address\":\"$2\",\"interface\":\"v$1\"}" >/dev/null; }
ros_vlan() { rosx "/interface vlan add name=v$1 vlan-id=$1 interface=ether1" >/dev/null
  [ -z "${2:-}" ] || rosx "/ip address add address=$2 interface=v$1" >/dev/null; }

# --- cases -------------------------------------------------------------------
wire_dump() {
  echo "--- wire: tc"; for d in crt1 crv1; do tc -s filter show dev $d ingress | grep -E 'mirred|Sent' | head -4; done
  echo "--- wire: counters"; ip -s -o link show crt1; ip -s -o link show crv1; ip -n crcore -s -o link show ether1
  echo "--- wire: CR ether1"; ip -n crcore -d addr show ether1; ip -n crcore neigh
  echo "--- wire: CHR"; ros interface | jq -c '.[] | {name, running, "rx-packet", "tx-packet"}'; ros ip/address | jq -c '.[] | {address, interface}'
  timeout 3 ip netns exec crcore tcpdump -c 5 -nei ether1 2>&1 | tail -6 || true
}
case_wire() {
  # The plain wire first: every other case stands on it.
  local ok=1
  wait_for 15 cr_ping_ok 10.39.1.1 >/dev/null && result wire OK "CoreRouter → CHR ping on ether1 (untagged)" || { result wire FAIL "CoreRouter → CHR untagged ping"; ok=0; }
  [ "$(ros_ping 10.39.1.2)" -ge 4 ] && result wire OK "CHR → CoreRouter ping on ether1" || { result wire FAIL "CHR → CoreRouter untagged ping"; ok=0; }
  [ $ok = 1 ] || wire_dump
  result wire INFO "CoreRouter tool.ping result: $(cr_ping 10.39.1.1 | jq -c '.summary' | cut -c1-300)"
}

case_vlan() {
  cr_vlan 30 10.39.30.2/24; ros_vlan 30 10.39.30.1/24
  local vok=1
  wait_for 10 cr_ping_ok 10.39.30.1 >/dev/null && result vlan OK "802.1Q vid 30: CoreRouter → CHR ping" || { result vlan FAIL "vid 30: CoreRouter → CHR ping"; vok=0; }
  [ "$(ros_ping 10.39.30.2)" -ge 4 ] && result vlan OK "802.1Q vid 30: CHR → CoreRouter ping" || { result vlan FAIL "vid 30: CHR → CoreRouter ping"; vok=0; }
  [ $vok = 1 ] || { ip -n crcore -d link show v30; ip -n crcore addr show v30; ros interface/vlan | jq -c .; wire_dump; }
  # The tag on the wire: TPID 0x8100, vid 30, priority 0.
  timeout 4 ip netns exec crcore tcpdump -c 2 -nei ether1 'vlan 30 and icmp' 2>/dev/null > "$W/vlan.txt" &
  local tp=$!; sleep 0.5; ros_ping 10.39.30.2 >/dev/null; wait $tp || true
  grep -q 'ethertype 802.1Q (0x8100).*vlan 30' "$W/vlan.txt" \
    && result vlan OK "on the wire: $(grep -o 'ethertype 802.1Q (0x8100).*vlan 30, p [0-9]' "$W/vlan.txt" | head -1 | cut -c1-120)" \
    || result vlan FAIL "no 0x8100/30 frame seen: $(head -2 "$W/vlan.txt")"
  # A frame with a tag nobody configured stays out (vid 31 only on the CHR).
  ros_vlan 31 10.39.31.1/24
  ip -n crcore addr add 10.39.31.2/24 dev ether1 2>/dev/null || true
  [ "$(ros_ping 10.39.31.2)" = 0 ] && result vlan OK "vid 31 (not configured on the CoreRouter): not answered on the untagged port" \
    || result vlan FAIL "vid 31 leaked into the untagged port"
  ip -n crcore addr del 10.39.31.2/24 dev ether1 2>/dev/null || true
  local l; l=$(cli interface.list '{"type":"vlan"}' | jq -c '[.[] | {name, parent, vlan_id, mtu, running}]')
  result vlan INFO "CoreRouter interface.list type=vlan: $l"
}

case_qinq() {
  # RouterOS: an S-tag is use-service-tag=yes (0x88a8); the C-tag a VLAN on it.
  ros_vlan 100; rosx '/interface vlan set v100 use-service-tag=yes' >/dev/null
  rosx '/interface vlan add name=c200 vlan-id=200 interface=v100
/ip address add address=10.39.200.1/24 interface=c200' >/dev/null
  local err
  if err=$(cli interface.vlan.add '{"name":"s100","parent":"ether1","vlan_id":100,"use_service_tag":true}' 2>&1); then
    cli interface.vlan.add '{"name":"c200","parent":"s100","vlan_id":200}' >/dev/null
    cli ip.address.add '{"address":"10.39.200.2/24","interface":"c200"}' >/dev/null
    wait_for 10 cr_ping_ok 10.39.200.1 >/dev/null && result qinq OK "802.1ad S-tag 100 + C-tag 200: CoreRouter → CHR ping" || result qinq FAIL "802.1ad 100/200 ping"
    [ "$(ros_ping 10.39.200.2)" -ge 4 ] && result qinq OK "802.1ad 100/200: CHR → CoreRouter ping" || result qinq FAIL "802.1ad 100/200: CHR → CoreRouter"
    # `vlan 100`, not `ether proto 0x88a8`: the veth strips the outer tag
    # into the packet's metadata (rx offload) and libpcap only sees its TPID there.
    timeout 4 ip netns exec crcore tcpdump -c 1 -nei ether1 'vlan 100' 2>/dev/null > "$W/qinq.txt" &
    local tp=$!; sleep 0.5; ros_ping 10.39.200.2 >/dev/null; wait $tp || true
    grep -q '0x88a8' "$W/qinq.txt" && result qinq OK "on the wire: $(grep -o '0x88a8.*vlan 100.*vlan 200' "$W/qinq.txt" | head -1 | cut -c1-120)" \
      || result qinq FAIL "no 0x88a8 frame: $(head -1 "$W/qinq.txt")"
  else
    result qinq FAIL "interface.vlan.add has no 802.1ad (use_service_tag): $(head -c 200 <<< "$err")"
  fi
  # Stacked 802.1Q (0x8100 outside too), what both also accept.
  ros_vlan 101; rosx '/interface vlan add name=c201 vlan-id=201 interface=v101
/ip address add address=10.39.201.1/24 interface=c201' >/dev/null
  cli interface.vlan.add '{"name":"v101","parent":"ether1","vlan_id":101}' >/dev/null
  cli interface.vlan.add '{"name":"c201","parent":"v101","vlan_id":201}' >/dev/null \
    && cli ip.address.add '{"address":"10.39.201.2/24","interface":"c201"}' >/dev/null \
    && wait_for 10 cr_ping_ok 10.39.201.1 >/dev/null && [ "$(ros_ping 10.39.201.2)" -ge 4 ] \
    && result qinq OK "stacked 802.1Q 101/201 (0x8100/0x8100): ping both ways" || result qinq FAIL "stacked 802.1Q 101/201"
}

case_rsc() {
  # G3.9hb: the CHR's own `/interface vlan export` (interface=, vlan-id=,
  # use-service-tag=, mtu=, disabled=, comment=, as RouterOS writes them)
  # pasted into the CoreRouter's terminal as it comes.
  rosx '/interface vlan add name=r40 vlan-id=40 interface=ether1 comment="cliente 40"
/interface vlan add name=r41 vlan-id=41 interface=ether1 disabled=yes mtu=1400
/interface vlan add name=s42 vlan-id=42 interface=ether1 use-service-tag=yes
/interface vlan add name=c43 vlan-id=43 interface=s42
/interface vlan export file=g39hb' >/dev/null
  sleep 1
  ros 'file?name=g39hb.rsc' | jq -r '.[0].contents // empty' > "$W/ros-vlan.rsc"
  [ -s "$W/ros-vlan.rsc" ] || { result rsc FAIL "no export from the CHR"; return; }
  # The export also carries what earlier cases left on the CHR (qinq's v101/c201,
  # which the CoreRouter has too): import only this case's VLANs. Join the
  # backslash-continued lines first, then keep the menu headers and our adds.
  sed -e ':a' -e '/\\$/{N;s/\\\n *//;ba' -e '}' "$W/ros-vlan.rsc" |
    grep -E '^/|name=(r4[01]|s42|c43)( |$)' > "$W/ros-vlan.own.rsc" && mv "$W/ros-vlan.own.rsc" "$W/ros-vlan.rsc"
  result rsc INFO "CHR export: $(grep -v '^#' "$W/ros-vlan.rsc" | tr '\n' ' ' | cut -c1-400)"
  local out
  out=$(printf '/import file=%s\n' "$W/ros-vlan.rsc" |
    ip netns exec crcore "$bin/corerouter-cli" --connect 127.0.0.1:7990 shell 2>&1) || true
  local got; got=$(cli interface.list '{"type":"vlan"}' |
    jq -c '[.[] | select(.name | test("^(r4[01]|s42|c43)$")) | {name, parent, vlan_id, use_service_tag, mtu, disabled, comment}] | sort_by(.name)')
  local want='[{"name":"c43","parent":"s42","vlan_id":43,"use_service_tag":false,"mtu":1500,"disabled":false,"comment":""},{"name":"r40","parent":"ether1","vlan_id":40,"use_service_tag":false,"mtu":1500,"disabled":false,"comment":"cliente 40"},{"name":"r41","parent":"ether1","vlan_id":41,"use_service_tag":false,"mtu":1400,"disabled":true,"comment":""},{"name":"s42","parent":"ether1","vlan_id":42,"use_service_tag":true,"mtu":1500,"disabled":false,"comment":""}]'
  [ "$got" = "$want" ] && result rsc OK "the CHR's VLAN export imports into the CoreRouter terminal: $got" \
    || result rsc FAIL "import: $(head -c 300 <<< "$out"); got $got"
}

case_mtu() {
  # Each side's VLAN MTU 1500 on a 1500 port: a full 1500-byte DF packet passes.
  [ "$(ros_ping 10.39.30.2 '{"size":"1500","do-not-fragment":""}')" -ge 4 ] \
    && result mtu OK "vid 30, 1500-byte DF ping CHR → CoreRouter (the port carries 1504-byte frames)" \
    || result mtu FAIL "vid 30: 1500-byte DF CHR → CoreRouter"
  cr_ping_ok 10.39.30.1 '{"size":1500,"do_not_fragment":true}' \
    && result mtu OK "vid 30, 1500-byte DF ping CoreRouter → CHR" || result mtu FAIL "vid 30: 1500-byte DF CoreRouter → CHR"
  # Jumbo: 9000 on both ports and on the VLAN (and on the lab wire: the
  # veth peer and the tap in the root namespace, 1500 by default, drop more).
  ip link set crv1 mtu 9100; ip link set crt1 mtu 9100
  rosx '/interface ethernet set ether1 mtu=9000 l2mtu=9014' >/dev/null 2>&1 || rosx '/interface ethernet set ether1 mtu=9000' >/dev/null || true
  rosx '/interface vlan set v30 mtu=9000' >/dev/null || true
  cli interface.set '{"name":"ether1","mtu":9000}' >/dev/null || result mtu FAIL "interface.set ether1 mtu 9000"
  cli interface.set '{"name":"v30","mtu":9000}' >/dev/null || result mtu FAIL "interface.set v30 mtu 9000"
  result mtu INFO "CHR ether1: $(ros interface/ethernet | jq -c '.[] | select(.name == "ether1") | {mtu, l2mtu: (.l2mtu // null), "max-l2mtu": (.["max-l2mtu"] // null)}'), v30: $(ros interface/vlan | jq -c '.[] | select(.name == "v30") | {mtu, l2mtu}')"
  result mtu INFO "CoreRouter: $(cli interface.list | jq -c '[.[] | select(.name == "ether1" or .name == "v30") | {name, mtu}]'), kernel: $(ip -n crcore -o link show ether1 | grep -o 'mtu [0-9]*')"
  [ "$(ros_ping 10.39.30.2 '{"size":"9000","do-not-fragment":""}')" -ge 4 ] \
    && result mtu OK "jumbo: 9000-byte DF ping over vid 30, CHR → CoreRouter" || result mtu FAIL "jumbo 9000 DF CHR → CoreRouter"
  cr_ping_ok 10.39.30.1 '{"size":9000,"do_not_fragment":true}' \
    && result mtu OK "jumbo: 9000-byte DF ping CoreRouter → CHR" || result mtu FAIL "jumbo 9000 DF CoreRouter → CHR"
  # Mismatch: CHR VLAN at 1400, CoreRouter 9000; a 1450 DF ping from the
  # CoreRouter is dropped by the CHR (an L2 MTU mismatch is silent, as
  # 802.3 says nothing about it), and the CoreRouter's MTU probe finds 1400.
  rosx '/interface vlan set v30 mtu=1400' >/dev/null
  local m; m=$(run_task tool.ping.mtu '{"address":"10.39.30.1","max_size":9000}' 2>/dev/null | jq -c '.summary // {}' || echo '{}')
  result mtu INFO "mismatch (CHR v30 at 1400): tool.ping.mtu to the CHR says $m"
  rosx '/interface vlan set v30 mtu=1500
/interface ethernet set ether1 mtu=1500' >/dev/null || true
  ip link set crv1 mtu 1500; ip link set crt1 mtu 1500
  cli interface.set '{"name":"v30","mtu":1500}' >/dev/null || true
  cli interface.set '{"name":"ether1","mtu":1500}' >/dev/null || true
}

case_lldp() {
  cli ip.neighbor.discovery.set '{"enabled":true,"interfaces":["ether1"],"interval_secs":5}' >/dev/null
  # CoreRouter sees the CHR: RouterOS sends LLDP and MNDP every 30 s; an
  # interface change (the address below) makes it send at once.
  rosx '/ip address add address=10.39.9.1/24 interface=ether1 comment=lldp-kick' >/dev/null || true
  local ms
  ms=$(wait_for 70 cr_sees lldp) && result lldp OK "CoreRouter ip.neighbor sees the CHR by LLDP after ${ms} ms: $(cli ip.neighbor.list '{"protocol":"lldp"}' | jq -c '[.[] | {interface, identity, mac, platform, version, remote_interface, address}][0]')" \
    || result lldp FAIL "CoreRouter: no LLDP neighbor ($(cli ip.neighbor.list | jq -c .))"
  ms=$(wait_for 70 cr_sees mndp) && result lldp OK "CoreRouter sees the CHR by MNDP (read only): $(cli ip.neighbor.list '{"protocol":"mndp"}' | jq -c '[.[] | {identity, version, board, address, remote_interface}][0]')" \
    || result lldp FAIL "CoreRouter: no MNDP neighbor"
  ms=$(wait_for 70 ros_sees) && result lldp OK "CHR /ip neighbor sees the CoreRouter after ${ms} ms: $(ros ip/neighbor | jq -c '[.[] | select(.identity == "cr-a") | {interface, identity, "mac-address", address, platform, version, discovered-by: .["discovered-by"], "interface-name", "system-caps-enabled"}][0]')" \
    || result lldp FAIL "CHR: CoreRouter not in /ip neighbor ($(ros ip/neighbor | jq -c '[.[] | {identity, "discovered-by"}]'))"
  # The LLDPDU we send, decoded by tcpdump (802.1AB TLVs).
  timeout 12 ip netns exec crcore tcpdump -c 1 -vnei ether1 'ether proto 0x88cc and ether src '"$(ip -n crcore -o link show ether1 | grep -o 'link/ether [^ ]*' | cut -d' ' -f2)" 2>/dev/null > "$W/lldp.txt" || true
  result lldp INFO "our LLDPDU: $(grep -oE '(Chassis ID|Port ID|Time to Live|System Name|System Capabilities|Management Address)[^\n]*' "$W/lldp.txt" | tr -s ' \t' ' ' | head -8 | paste -sd ';' | cut -c1-400)"
  rosx '/ip address remove [find comment=lldp-kick]' >/dev/null || true
}
cr_sees() { [ "$(cli ip.neighbor.list "{\"protocol\":\"$1\"}" | jq '[.[] | select(.identity == "chr-g39h")] | length')" -ge 1 ]; }
ros_sees() { [ "$(ros ip/neighbor | jq '[.[] | select(.identity == "cr-a")] | length')" -ge 1 ]; }

case_arp() {
  cr_ping_ok 10.39.1.1 >/dev/null || true
  local e; e=$(cli ip.arp.list '{"search":"10.39.1.1"}' | jq -c '[.rows[]? // .[]? | {address, mac_address, interface, state}][0] // {}')
  [[ $e == *52:54:00:39:01:01* || $e == *52:54:00:39:01:01* ]] && result arp OK "CoreRouter learned the CHR: $e" || result arp FAIL "ARP entry for 10.39.1.1: $e"
  local m; m=$(ros ip/arp | jq -c '[.[] | select(.address == "10.39.1.2")][0] // {}')
  [ "$(jq -r '.["mac-address"] // "" | ascii_upcase' <<< "$m")" = "$(ip -n crcore -o link show ether1 | grep -o 'link/ether [^ ]*' | cut -d' ' -f2 | tr a-f A-F)" ] \
    && result arp OK "CHR learned the CoreRouter: $(jq -c '{address, "mac-address", status}' <<< "$m")" || result arp FAIL "CHR ARP for 10.39.1.2: $m"
  # Proxy ARP, one host (published). Linux (and so the CoreRouter) answers
  # for a published address only when its route leaves by another interface
  # (net/ipv4/arp.c: rt->dst.dev != dev): the host behind the router. The
  # address inside ether1's own subnet is the INFO case below.
  local mac; mac=$(ip -n crcore -o link show ether1 | grep -o 'link/ether [^ ]*' | cut -d' ' -f2)
  cli ip.route.add '{"dst_address":"10.39.1.3/32","gateway":"ether8"}' >/dev/null || result arp FAIL "ip.route.add 10.39.1.3/32 via ether8"
  cli ip.arp.add "{\"address\":\"10.39.1.3\",\"mac_address\":\"$mac\",\"interface\":\"ether1\",\"published\":true}" >/dev/null \
    || result arp FAIL "ip.arp.add published"
  ros_ping 10.39.1.3 >/dev/null || true
  m=$(ros ip/arp | jq -c '[.[] | select(.address == "10.39.1.3")][0] // {}')
  [ "$(jq -r '.["mac-address"] // "" | ascii_downcase' <<< "$m")" = "$mac" ] && result arp OK "proxy ARP (published 10.39.1.3, routed via ether8): the CHR resolves it to the CoreRouter's MAC" \
    || result arp FAIL "proxy ARP 10.39.1.3 (routed via ether8) on the CHR: $m"
  cli ip.arp.add "{\"address\":\"10.39.1.6\",\"mac_address\":\"$mac\",\"interface\":\"ether1\",\"published\":true}" >/dev/null || true
  ros_ping 10.39.1.6 >/dev/null || true
  result arp INFO "CoreRouter published 10.39.1.6 inside ether1's own subnet: CHR sees $(ros ip/arp | jq -c '[.[] | select(.address == "10.39.1.6") | {"mac-address", status}][0] // {}')"
  # ip.arp.ping itself, to an address that answers.
  run_task ip.arp.ping '{"address":"10.39.1.1","count":3}' > "$W/arpping.json" || true
  local r; r=$(jq -c '.summary // {}' "$W/arpping.json" 2>/dev/null)
  [[ $r == *'"received":3'* || $r == *'"received":2'* ]] && result arp OK "ip.arp.ping 10.39.1.1 (the CHR): $(cut -c1-160 <<< "$r")" || result arp FAIL "ip.arp.ping 10.39.1.1: $r"
  # And the other way: the CHR publishes 10.39.1.4 behind a bridge of its own
  # (routed elsewhere) and 10.39.1.5 inside ether1's subnet.
  rosx '/interface bridge add name=lo4
/ip route add dst-address=10.39.1.4/32 gateway=lo4
/ip arp add address=10.39.1.4 mac-address=52:54:00:39:01:01 interface=ether1 published=yes
/ip arp add address=10.39.1.5 mac-address=52:54:00:39:01:01 interface=ether1 published=yes' >/dev/null || true
  local addr
  for addr in 10.39.1.4 10.39.1.5; do
    run_task ip.arp.ping "{\"address\":\"$addr\",\"count\":3}" > "$W/arpping.json" || true
    e=$(cli ip.arp.list "{\"search\":\"$addr\"}" | jq -c '[.rows[]? // .[]? | {address, mac_address, state}][0] // {}')
    if [ $addr = 10.39.1.4 ]; then
      # ip.arp.ping uses its own socket: the answer is in its summary, not the table.
      r=$(jq -c '.summary // {}' "$W/arpping.json" 2>/dev/null)
      [[ $r == *'"received":3'* || $r == *'"received":2'* ]] && result arp OK "CHR published $addr (routed to lo4): ip.arp.ping answered ($(cut -c1-160 <<< "$r"))" || result arp FAIL "CHR-published $addr (routed to lo4): $r"
    else
      result arp INFO "CHR published $addr inside ether1's own subnet: ip.arp.ping $(jq -c '.summary | {sent, received}' "$W/arpping.json" 2>/dev/null)"
    fi
  done
}

case_tools() {
  local p
  p=$(cr_ping 10.255.39.1 '{"count":10,"interval_ms":100}')
  result tools INFO "ping CHR loopback: $(jq -c '.summary_lines // .summary' <<< "$p" | cut -c1-300)"
  cr_ping_ok 10.255.39.1 && result tools OK "tool.ping to the CHR" || result tools FAIL "tool.ping to the CHR"
  p=$(run_task tool.traceroute.start '{"address":"10.255.39.1","use_dns":false,"probes":3}')
  local hops; hops=$(jq -r '[.summary.hops[]? | "\(.host // "*") \(.avg_ms // "-") ms"] | join(" | ")' <<< "$p" | cut -c1-300)
  [[ $hops == *10.255.39.1* ]] && result tools OK "traceroute reaches the CHR: $hops" || result tools FAIL "traceroute: $hops $(jq -c .summary <<< "$p" | head -c 200)"
  for proto in udp tcp; do
    p=$(run_task tool.traceroute.start "{\"address\":\"10.255.39.1\",\"use_dns\":false,\"protocol\":\"$proto\",\"probes\":2}")
    hops=$(jq -r '[.summary.hops[]? | "\(.host // "*") \(.avg_ms // "-") ms"] | join(" | ")' <<< "$p" | cut -c1-200)
    [[ $hops == *10.255.39.1* ]] && result tools OK "traceroute $proto reaches the CHR" || result tools INFO "traceroute $proto: $hops"
  done
  p=$(run_task tool.mtr.start '{"address":"10.255.39.1","count":10,"interval_ms":200,"use_dns":false}')
  result tools INFO "mtr: $(jq -r '.lines // [] | join(" | ")' <<< "$p" | cut -c1-300)"
  [[ $(jq -r '.lines // [] | join(" ")' <<< "$p") == *10.255.39.1* ]] && result tools OK "mtr to the CHR" || result tools FAIL "mtr to the CHR"
  # And the CHR's own traceroute to the CoreRouter through ether1.
  result tools INFO "CHR /tool traceroute 10.39.1.2: $(rosp tool/traceroute '{"address":"10.39.1.2","count":"1"}' | jq -c '[.[] | {address, loss, last}]' | cut -c1-200)"
}

# --- DHCPv4 -------------------------------------------------------------------
# Capture DHCP on <iface> in crcore to <file> in the background.
dhcp_cap() { ip netns exec crcore tcpdump -U -s0 -nni "$1" -w "$2" 'udp port 67 or udp port 68' 2>/dev/null & echo $! > "$W/tcpdump-$1.pid"; sleep 0.5; }
dhcp_cap_stop() { kill "$(cat "$W/tcpdump-$1.pid")" 2>/dev/null || true; rm -f "$W/tcpdump-$1.pid"; sleep 0.3; }

case_dhcp() {
  # CoreRouter A serves VLAN 10; the CHR's client takes options 3/6/15/42/121.
  cr_vlan 10 192.168.10.1/24; ros_vlan 10
  cli ip.pool.add '{"name":"p10","ranges":"192.168.10.50-192.168.10.60"}' >/dev/null
  cli ip.dhcp-server.add '{"name":"d10","interface":"v10","address_pool":"p10","lease_time":"1m"}' >/dev/null
  cli ip.dhcp-server.network.add '{"address":"192.168.10.0/24","gateway":"192.168.10.1","dns_server":"192.168.10.1","domain":"lab.example","ntp_server":"192.168.10.1"}' >/dev/null
  # Option 121: 10.99.0.0/16 via the router, plus the default route (RFC 3442, "DHCP Client Behavior": a
  # client that takes 121 ignores option 3, so 0/0 must be in it too).
  local err
  if err=$(cli ip.dhcp-server.option.add '{"name":"cls","code":121,"value":"0x100a63c0a80a0100c0a80a01"}' 2>&1); then
    cli ip.dhcp-server.network.set '{"id":"192.168.10.0/24","dhcp_option":"cls"}' >/dev/null || result dhcp FAIL "network.set dhcp_option"
  else
    result dhcp FAIL "option 121: $(head -c 200 <<< "$err")"
  fi
  # Conflict detection is the dhcp-conflict case: the CHR answers ARP for any
  # of its addresses from the asking port's MAC (Linux arp_ignore=0), so a
  # squatter on it looks like the client itself (RFC 5227: offered again).
  dhcp_cap v10 "$W/dhcp10.pcap"
  rosx '/ip dhcp-client add interface=v10 add-default-route=yes use-peer-dns=yes use-peer-ntp=yes comment=g39h' >/dev/null
  local ms
  ms=$(wait_for 30 ros_bound v10) && result dhcp OK "CHR client bound in ${ms} ms: $(ros ip/dhcp-client | jq -c '.[] | select(.interface == "v10") | {address, gateway, "dhcp-server", "primary-dns", "primary-ntp", "expires-after"}')" \
    || { result dhcp FAIL "CHR client on v10: $(ros ip/dhcp-client | jq -c '.[] | select(.interface == "v10") | {status}')"; dhcp_cap_stop v10; return; }
  # What the CHR did with the options.
  local r; r=$(ros ip/route | jq -c '[.[] | select((.["dst-address"] == "10.99.0.0/16" or .["dst-address"] == "0.0.0.0/0") and (.gateway // "" | startswith("192.168.10.1")))] | map({"dst-address", gateway, dhcp: (.dhcp // null)})')
  [[ $r == *10.99.0.0/16* ]] && result dhcp OK "option 121: the CHR installed $r" || result dhcp FAIL "option 121 not installed on the CHR: $r"
  [[ $(rosput '[/ip dns get dynamic-servers]') == *192.168.10.1* ]] && result dhcp OK "option 6: CHR dynamic DNS server 192.168.10.1" || result dhcp FAIL "option 6 on the CHR: $(rosput '[/ip dns get dynamic-servers]')"
  result dhcp INFO "CHR NTP client after the lease: $(ros system/ntp/client | jq -c '{servers: (.servers // null), "dynamic-servers": (.["dynamic-servers"] // null), mode}')"
  # Renewal at T1 = 0.5 × lease (RFC 2131 §4.4.5): lease 60 s, so a unicast
  # REQUEST about 30 s after the ACK.
  sleep 40
  dhcp_cap_stop v10
  tcpdump -r "$W/dhcp10.pcap" -tt -nv 2>/dev/null > "$W/dhcp10.txt" || true
  local opts; opts=$(grep -A40 'DHCP-Message (53), length 1: ACK' "$W/dhcp10.txt" | grep -oE '^\s+[A-Za-z-]+ (Option )?\(?[0-9]+\)?' | awk '{print $1}' | sort -u | paste -sd, )
  result dhcp INFO "ACK options (tcpdump): $opts"
  for o in Subnet-Mask Default-Gateway Domain-Name-Server Domain-Name NTP Classless-Static-Route Lease-Time Server-ID; do
    grep -A40 'DHCP-Message (53), length 1: ACK' "$W/dhcp10.txt" | grep -q "$o" || result dhcp FAIL "ACK without $o"
  done
  local acks; acks=$(ack_times "$W/dhcp10.txt")
  local first second; first=$(head -1 <<< "$acks"); second=$(sed -n 2p <<< "$acks")
  if [ -n "$second" ]; then
    local d; d=$(awk -v a="$first" -v b="$second" 'BEGIN {printf "%.1f", b - a}')
    awk -v d="$d" 'BEGIN {exit !(d >= 27 && d <= 34)}' && result dhcp OK "renewal ACK ${d} s after the first (T1 = 0.5 × 60 s, RFC 2131 §4.4.5)" \
      || result dhcp FAIL "renewal at ${d} s, expected ~30 s"
  else
    result dhcp FAIL "no renewal ACK in 40 s"
  fi
  # Release: the lease leaves the server at once (RFC 2131 §4.4.6).
  rosx '/ip dhcp-client release [find interface=v10]' >/dev/null || true
  sleep 2
  local st; st=$(cli ip.dhcp-server.lease.print '{"server":"d10"}' | jq -c '[.[] | {address, status, mac_address}]')
  # RouterOS's `release` frees the binding and starts the client again, so the
  # lease comes back at once: the release shows in A's log.
  wait_for 5 a_logged 'released by the client' >/dev/null && result dhcp OK "release reached the server: 'released by the client' ($st)" || result dhcp FAIL "release: no 'released by the client' in A's log ($st)"
  ms=$(wait_for 30 ros_bound v10) && result dhcp OK "CHR bound again ${ms} ms after its release" || result dhcp INFO "CHR not bound again after release"
  result dhcp INFO "server statistics: $(cli ip.dhcp-server.statistics.print | jq -c '{received, sent, latency_us}')"
}
# ack_times <tcpdump -tt -v text>: the time of each ACK (the header line that
# starts the packet; a unicast ACK has more lines before option 53).
ack_times() { awk '/^[0-9]+\.[0-9]+ IP / {t = $1} /DHCP-Message \(53\), length 1: ACK/ {print t}' "$1"; }
ros_bound() { [ "$(ros ip/dhcp-client | jq -r --arg i "$1" '.[] | select(.interface == $i) | .status')" = bound ]; }

case_dhcp-client() {
  # The CHR serves VLAN 11; the CoreRouter is the client.
  ros_vlan 11 192.168.11.1/24
  rosx '/ip pool add name=p11 ranges=192.168.11.100-192.168.11.150
/ip dhcp-server option add name=cls code=121 value=0x100a62c0a80b0100c0a80b01
/ip dhcp-server add name=d11 interface=v11 address-pool=p11 lease-time=1m
/ip dhcp-server network add address=192.168.11.0/24 gateway=192.168.11.1 dns-server=192.168.11.1 domain=chr.example ntp-server=192.168.11.1 dhcp-option=cls' >/dev/null
  cr_vlan 11
  dhcp_cap v11 "$W/dhcp11.pcap"
  local id; id=$(cli ip.dhcp-client.add '{"interface":"v11","use_peer_dns":true,"use_peer_ntp":true}' | jq -r .id)
  local ms
  ms=$(wait_for 30 cr_bound v11) && result dhcp-client OK "CoreRouter client bound in ${ms} ms: $(cli ip.dhcp-client.list '{"interface":"v11"}' | jq -c '.[0] | {address, gateway, dhcp_server, primary_dns, primary_ntp, domain, lease_time, routes}')" \
    || { result dhcp-client FAIL "CoreRouter client: $(cli ip.dhcp-client.list '{"interface":"v11"}' | jq -c '.[0] | {status, error, notes}')"; dhcp_cap_stop v11; return; }
  local c; c=$(cli ip.dhcp-client.list '{"interface":"v11"}' | jq -c '.[0]')
  [ "$(jq -r .domain <<< "$c")" = chr.example ] && result dhcp-client OK "option 15: domain chr.example" || result dhcp-client FAIL "option 15: $(jq -c .domain <<< "$c")"
  [[ $(jq -c .primary_ntp <<< "$c") == *192.168.11.1* ]] && result dhcp-client OK "option 42: NTP 192.168.11.1" || result dhcp-client FAIL "option 42: $(jq -c .primary_ntp <<< "$c")"
  # RFC 3442 ("DHCP Client Behavior"): with 121 present the client ignores option 3; the
  # classless default route (0/0 in 121) is what goes into the table.
  local rt; rt=$(ip -n crcore route show | grep -E '10\.98\.0\.0/16|default' | tr '\n' ';')
  [[ $rt == *10.98.0.0/16*192.168.11.1* ]] && result dhcp-client OK "option 121 in the kernel: $rt" || result dhcp-client FAIL "option 121 routes: $rt / $(jq -c '.route_states' <<< "$c")"
  result dhcp-client INFO "received options: $(cli ip.dhcp-client.options "{\"id\":\"$id\"}" | jq -c '[.options[] | "\(.code)=\(.value)"]' | cut -c1-300)"
  # The CHR's lease for us: host name and client id as RouterOS reads them.
  result dhcp-client INFO "CHR lease: $(ros ip/dhcp-server/lease | jq -c '.[] | select(.server == "d11") | {address, "mac-address", "client-id", "host-name", status}')"
  sleep 40
  dhcp_cap_stop v11
  tcpdump -r "$W/dhcp11.pcap" -tt -nv 2>/dev/null > "$W/dhcp11.txt" || true
  local req; req=$(grep -cE 'DHCP-Message \(53\), length 1: Request' "$W/dhcp11.txt" || true)
  local t; t=$(ack_times "$W/dhcp11.txt" | head -2 | paste -sd' ')
  local d; d=$(awk -v t="$t" 'BEGIN {split(t, a, " "); if (a[2]) printf "%.1f", a[2] - a[1]; else print "-"}')
  awk -v d="$d" 'BEGIN {exit !(d != "-" && d >= 27 && d <= 34)}' && result dhcp-client OK "renewed ${d} s after binding (T1 = 30 s of 60, RFC 2131 §4.4.5)" \
    || result dhcp-client FAIL "renewal at ${d} s (requests seen: $req)"
  # The renewal is unicast to the server (RFC 2131 §4.4.5, RENEWING).
  grep -q '192.168.11.[0-9]*.68 > 192.168.11.1.67' "$W/dhcp11.txt" && result dhcp-client OK "RENEWING request unicast to 192.168.11.1" \
    || result dhcp-client INFO "renewal requests: $(grep -E '^[0-9.]+ IP' "$W/dhcp11.txt" | tail -3 | cut -c1-120 | paste -sd'|')"
  # Release: the CHR drops the lease.
  cli ip.dhcp-client.release "{\"id\":\"$id\"}" >/dev/null || result dhcp-client FAIL "ip.dhcp-client.release"
  sleep 2
  local l; l=$(ros ip/dhcp-server/lease | jq -c '[.[] | select(.server == "d11") | .status]')
  # The CoreRouter's release, like RouterOS's, frees the lease and starts
  # again: the CHR logs the deassign, and the client binds once more.
  ros log | jq -r '.[].message' | grep -q 'd11 deassigned' && result dhcp-client OK "release: the CHR deassigned the lease (now $l)" || result dhcp-client FAIL "release: no 'deassigned' in the CHR log (lease $l)"
  cli ip.dhcp-client.renew "{\"id\":\"$id\"}" >/dev/null || true
  ms=$(wait_for 30 cr_bound v11) && result dhcp-client OK "renew after release: bound in ${ms} ms" || result dhcp-client FAIL "renew after release"
}
cr_bound() { [ "$(cli ip.dhcp-client.list "{\"interface\":\"$1\"}" | jq -r '.[0].status')" = bound ]; }

case_dhcp-relay() {
  # The CHR's client on VLAN 20 → relay on CoreRouter A → server on CoreRouter B.
  cr_vlan 20 192.168.20.1/24; ros_vlan 20
  clib ip.route.add '{"dst_address":"192.168.20.0/24","gateway":"10.39.5.1"}' >/dev/null
  clib ip.pool.add '{"name":"p20","ranges":"192.168.20.100-192.168.20.110"}' >/dev/null
  clib ip.dhcp-server.add '{"name":"d20","interface":"ether1","address_pool":"p20","relay":"192.168.20.1","lease_time":"10m"}' >/dev/null
  clib ip.dhcp-server.network.add '{"address":"192.168.20.0/24","gateway":"192.168.20.1","dns_server":"192.168.20.1"}' >/dev/null
  cli ip.dhcp-relay.add '{"name":"r20","interface":"v20","dhcp_server":"10.39.5.2","add_relay_info":true}' >/dev/null || result dhcp-relay FAIL "ip.dhcp-relay.add"
  rosx '/ip dhcp-client add interface=v20 add-default-route=no use-peer-dns=no' >/dev/null
  local ms
  ms=$(wait_for 30 ros_bound v20) && result dhcp-relay OK "CHR bound through the relay in ${ms} ms: $(ros ip/dhcp-client | jq -c '.[] | select(.interface == "v20") | {address, gateway, "dhcp-server"}')" \
    || result dhcp-relay FAIL "CHR via relay: $(ros ip/dhcp-client | jq -c '.[] | select(.interface == "v20") | {status}'); relay: $(cli ip.dhcp-relay.print | jq -c '.[0] | {requests, replies, dropped, error}')"
  local l; l=$(clib ip.dhcp-server.lease.print '{"server":"d20"}' | jq -c '.[0] // {}')
  result dhcp-relay INFO "B's lease (option 82 from the relay, RFC 3046): $(jq -c '{address, status, mac_address, circuit_id: (.circuit_id // null), remote_id: (.remote_id // null), agent: (.agent_circuit_id // .relay // null)}' <<< "$l")"
  result dhcp-relay INFO "relay counters: $(cli ip.dhcp-relay.print | jq -c '.[0] | {requests, replies, dropped}')"
  # Relay to the CHR's server instead: the CoreRouter B client → A relay → CHR.
  # (RouterOS: a server with relay= serves only that giaddr.)
}

# --- DHCPv6 / RA ----------------------------------------------------------------
case_dhcp6() {
  # A serves VLAN 12: an address (IA_NA) and a /56 (IA_PD) to the CHR.
  cr_vlan 12 2001:db8:12::1/64
  ros_vlan 12
  cli ipv6.pool.add '{"name":"na12","prefix":"2001:db8:12::/64","prefix_length":128}' >/dev/null
  cli ipv6.pool.add '{"name":"pd12","prefix":"2001:db8:1200::/40","prefix_length":56}' >/dev/null
  cli ipv6.dhcp-server.add '{"name":"d6","interface":"v12","address_pool":"na12","prefix_pool":"pd12","lease_time":"10m","dns_server":"2001:db8:12::1"}' >/dev/null || result dhcp6 FAIL "ipv6.dhcp-server.add"
  rosx '/ipv6 dhcp-client add interface=v12 request=address,prefix pool-name=frcr pool-prefix-length=64 add-default-route=no use-peer-dns=yes' >/dev/null
  local ms
  ms=$(wait_for 40 ros6_bound v12) && result dhcp6 OK "CHR DHCPv6 client bound in ${ms} ms: $(ros ipv6/dhcp-client | jq -c '.[] | select(.interface == "v12") | {address, prefix, "dhcp-server-v6": (.["dhcp-server-v6"] // null), status}')" \
    || result dhcp6 FAIL "CHR DHCPv6 client: $(ros ipv6/dhcp-client | jq -c '.[] | select(.interface == "v12") | {status, address, prefix}')"
  result dhcp6 INFO "A's bindings: $(cli ipv6.dhcp-server.binding.print | jq -c '[.[] | {type, address, status, duid}]' | cut -c1-300)"
  local pd; pd=$(cli ipv6.dhcp-server.binding.print | jq -r '[.[] | select(.type == "prefix")][0].address // empty')
  [ -n "$pd" ] && ip -n crcore -6 route show "$pd" | grep -q via && result dhcp6 OK "route to the delegated $pd: $(ip -n crcore -6 route show "$pd" | head -1)" \
    || result dhcp6 FAIL "no route to the delegated prefix '$pd' ($(ip -n crcore -6 route | grep 2001:db8:12 | head -3 | tr '\n' ';'))"
  [[ $(rosput '[/ip dns get dynamic-servers]') == *2001:db8:12::1* ]] && result dhcp6 OK "DNS option (23): the CHR uses 2001:db8:12::1" || result dhcp6 INFO "CHR dynamic DNS: $(rosput '[/ip dns get dynamic-servers]')"
}
ros6_bound() { [ "$(ros ipv6/dhcp-client | jq -r --arg i "$1" '.[] | select(.interface == $i) | .status')" = bound ]; }

case_dhcp6-client() {
  # The CHR serves VLAN 13 (a /56 from its pool); CoreRouter A asks for address + prefix.
  ros_vlan 13
  rosx '/ipv6 address add address=2001:db8:13::1/64 interface=v13 advertise=no
/ipv6 pool add name=chrpd prefix=2001:db8:1300::/40 prefix-length=56
/ipv6 pool add name=chrna prefix=2001:db8:13::/64 prefix-length=128
/ipv6 dhcp-server add name=d13 interface=v13 prefix-pool=chrpd address-pool=chrna lease-time=10m' >/dev/null 2>"$W/ros6.err" \
    || rosx '/ipv6 dhcp-server add name=d13 interface=v13 address-pool=chrpd lease-time=10m' >/dev/null || result dhcp6-client FAIL "CHR DHCPv6 server: $(cat "$W/ros6.err")"
  cr_vlan 13
  local id; id=$(cli ipv6.dhcp-client.add '{"interface":"v13","request":"address,prefix","pool_name":"fromchr","prefix_hint":"::/56"}' | jq -r .id)
  local ms
  ms=$(wait_for 40 cr6_bound v13) && result dhcp6-client OK "CoreRouter DHCPv6 client bound in ${ms} ms: $(cli ipv6.dhcp-client.list '{"interface":"v13"}' | jq -c '.[0] | {address, prefix, dhcp_server, status}')" \
    || result dhcp6-client FAIL "CoreRouter DHCPv6 client: $(cli ipv6.dhcp-client.list '{"interface":"v13"}' | jq -c '.[0] | {status, address, prefix}'); history: $(cli ipv6.dhcp-client.history '{}' | jq -c '[.events[-4:][] | .message]' | cut -c1-300)"
  result dhcp6-client INFO "pool: $(cli ipv6.pool.list | jq -c '[.[] | select(.name == "fromchr") | {prefix, status, valid_lifetime}]'), CHR bindings: $(ros ipv6/dhcp-server/binding | jq -c '[.[] | {address, status, duid: (.duid // null)}]' | cut -c1-200)"
  # From the delegated prefix to a LAN address (ip.address.add from_pool).
  cli ip.address.add '{"address":"::1/64","interface":"ether8","from_pool":"fromchr"}' >/dev/null \
    && result dhcp6-client OK "address from the delegated pool on ether8: $(ip -n crcore -6 -o addr show dev ether8 scope global | awk '{print $4}' | head -1)" \
    || result dhcp6-client FAIL "ip.address.add from_pool"
}
cr6_bound() { [ "$(cli ipv6.dhcp-client.list "{\"interface\":\"$1\"}" | jq -r '.[0].status')" = bound ]; }

case_ra() {
  # CHR → CoreRouter: the CHR advertises 2001:db8:14::/64 on VLAN 14; A takes RAs there.
  ros_vlan 14
  rosx '/ipv6 address add address=2001:db8:14::1/64 interface=v14 advertise=yes
/ipv6 nd add interface=v14 ra-interval=3s-5s' >/dev/null 2>&1 || rosx '/ipv6 address add address=2001:db8:14::1/64 interface=v14 advertise=yes' >/dev/null
  cr_vlan 14
  cli ipv6.settings.set '{"accept_router_advertisements":"yes","accept_router_advertisements_on":"all"}' >/dev/null || result ra FAIL "ipv6.settings.set"
  result ra INFO "A ipv6.settings: $(cli ipv6.settings.get | jq -c '[.interfaces[] | select(.interface == "v14")][0]')"
  local ms
  ms=$(wait_for 20 slaac v14) && result ra OK "SLAAC on A from the CHR's RA in ${ms} ms (RFC 4862 §5.5.3): $(ip -n crcore -6 -o addr show dev v14 scope global | awk '{print $4}' | head -1), default $(ip -n crcore -6 route show default | head -1)" \
    || result ra FAIL "no SLAAC address on v14 ($(ip -n crcore -6 addr show dev v14 | grep inet6 | tr -s ' ' | paste -sd';'); sysctl accept_ra=$(ip netns exec crcore sysctl -n net.ipv6.conf.v14.accept_ra), autoconf=$(ip netns exec crcore sysctl -n net.ipv6.conf.v14.autoconf))"
  result ra INFO "A ip.address.list on v14: $(cli ip.address.list | jq -c '[.[]? // .rows[]? | select(.interface == "v14") | {address, dynamic: (.dynamic // null)}]' 2>/dev/null)"
  # CoreRouter → CHR (G3.9ha): A advertises 2001:db8:15::/64 on VLAN 15
  # (`ipv6.nd.add`, RFC 4861 §6.2); the CHR autoconfigures from it.
  cr_vlan 15 2001:db8:15::1/64; ros_vlan 15
  rosx '/ipv6 settings set accept-router-advertisements=yes' >/dev/null || true
  local nd; nd=$(cli ipv6.nd.add '{"interface":"v15","ra_interval":"3s-4s","hop_limit":64,"other_configuration":true}') \
    || result ra FAIL "ipv6.nd.add: $nd"
  ms=$(wait_for 30 ros_slaac v15) && result ra OK "CHR autoconfigured from A's RA in ${ms} ms (RFC 4862 §5.5.3): $(ros ipv6/address | jq -c '[.[] | select(.interface == "v15" and ((.address // "") | startswith("2001:db8:15"))) | .address]')" \
    || result ra FAIL "CHR has no 2001:db8:15:: address from A's RA (A: $(cli ipv6.nd.list | jq -c '.interfaces'))"
  ms=$(wait_for 20 ros_ra_default v15) && result ra OK "CHR default route via A's link-local: $(ros ipv6/route | jq -c '[.[] | select(."dst-address" == "::/0") | {gateway, dynamic: (.dynamic // null)}]')" \
    || result ra FAIL "CHR has no default route from A's RA: $(ros ipv6/route | jq -c '[.[] | select(."dst-address" == "::/0")]')"
  result ra INFO "A ipv6.nd.list: $(cli ipv6.nd.list | jq -c '[.interfaces[] | select(.interface == "v15") | {state, prefixes, ra_sent, rs_received, conflict}]')"
  # Disabled: the final RA (Router Lifetime 0, RFC 4861 §6.2.5) takes the
  # CHR's default route away at once.
  cli ipv6.nd.disable '{"id":"v15"}' >/dev/null
  ms=$(wait_for 15 ros_no_ra_default v15) && result ra OK "final RA: the CHR dropped the default route in ${ms} ms" \
    || result ra FAIL "the CHR kept the default route after ipv6.nd.disable: $(ros ipv6/route | jq -c '[.[] | select(."dst-address" == "::/0")]')"
}
ros_slaac() { [ "$(ros ipv6/address | jq -c --arg i "$1" '[.[] | select(.interface == $i and ((.address // "") | startswith("2001:db8:15")))]')" != "[]" ]; }
ros_ra_default() { ros ipv6/route | jq -e --arg i "$1" '[.[] | select(."dst-address" == "::/0" and ((.gateway // "") | contains($i)))] | length > 0' >/dev/null; }
ros_no_ra_default() { ! ros_ra_default "$1"; }
slaac() { ip -n crcore -6 -o addr show dev "$1" scope global | grep -q 2001:db8:14:; }

# --- NTP / DNS --------------------------------------------------------------------
case_ntp() {
  rosx '/system ntp server set enabled=yes use-local-clock=yes local-clock-stratum=5' >/dev/null || rosx '/system ntp server set enabled=yes' >/dev/null || true
  cli system.ntp.client.set '{"enabled":true,"servers":["10.39.1.1"],"min_poll":6}' >/dev/null
  local ms
  ms=$(wait_for 90 ntp_sync) && result ntp OK "CoreRouter client synchronized to the CHR in ${ms} ms: $(cli system.ntp.client.get | jq -c '{status, synced_address, synced_stratum, system_offset_ms, round_trip_ms, poll_secs}')" \
    || result ntp FAIL "CoreRouter NTP client: $(cli system.ntp.client.get | jq -c '{status, last_error, synced_stratum}')"
  # CHR → CoreRouter: there is no NTP server on the CoreRouter yet (G4.6c).
  rosx '/system ntp client set enabled=yes mode=unicast servers=10.39.1.2' >/dev/null || true
  sleep 15
  local s; s=$(ros system/ntp/client | jq -c '{status: (.status // null), "synced-server": (.["synced-server"] // null)}')
  [[ $s == *synchronized* ]] && result ntp OK "CHR synchronized to the CoreRouter: $s" \
    || result ntp INFO "CHR as client of the CoreRouter: $s (no NTP server in the CoreRouter: gap G4.6c)"
  rosx '/system ntp client set enabled=no' >/dev/null || true
}
ntp_sync() { [ "$(cli system.ntp.client.get | jq -r .status)" = synchronized ]; }

case_dns() {
  # B is the upstream (a static name of its own); A resolves for the CHR.
  clib ip.dns.set '{"allow_remote_requests":true,"allowed_from":["10.39.0.0/16"]}' >/dev/null
  clib ip.dns.static.add '{"name":"up.lab","address":"10.39.5.2"}' >/dev/null
  cli ip.dns.set '{"servers":["10.39.5.2"],"allow_remote_requests":true,"allowed_from":["10.39.0.0/16","192.168.0.0/16","10.40.0.0/16"]}' >/dev/null
  cli ip.dns.static.add '{"name":"cr.lab","address":"10.39.1.2"}' >/dev/null
  cli ip.dns.static.add '{"name":"alias.lab","type":"CNAME","cname":"cr.lab"}' >/dev/null || true
  rosx '/ip dns set servers=10.39.1.2' >/dev/null
  local a
  a=$(rosput '[:resolve cr.lab]'); [ "$a" = 10.39.1.2 ] && result dns OK "CHR resolves the static cr.lab through the CoreRouter" || result dns FAIL "CHR :resolve cr.lab = $a"
  a=$(rosput '[:resolve alias.lab]'); [ "$a" = 10.39.1.2 ] && result dns OK "static CNAME alias.lab → cr.lab" || result dns INFO "CNAME alias.lab = $a"
  a=$(rosput '[:resolve up.lab]'); [ "$a" = 10.39.5.2 ] && result dns OK "CHR resolves up.lab (A forwards to B)" || result dns FAIL "CHR :resolve up.lab = $a"
  rosx '/ip dns cache flush' >/dev/null || true
  rosput '[:resolve up.lab]' >/dev/null
  local c; c=$(cli ip.dns.cache.print '{"name":"up.lab"}' | jq -c '[.[] | {name, type, ttl, hits, server}]')
  [[ $c == *up.lab* ]] && result dns OK "A cache holds up.lab: $c" || result dns FAIL "A cache: $c"
  result dns INFO "A statistics: $(cli ip.dns.statistics.print | jq -c . | cut -c1-300)"
  # NXDOMAIN passes through (RFC 1035 §4.1.1 rcode 3), and refusal off-list.
  a=$(rosput '[:resolve nope.lab]' 2>&1 | head -c 120); result dns INFO "CHR :resolve nope.lab: $a"
  a=$(ip netns exec crcl timeout 3 python3 -I - <<'PY' 2>&1
import socket, struct
q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x02cr\x03lab\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(q, ("10.40.0.1", 53)); r = s.recv(512)
print("rcode", r[3] & 15, "answers", struct.unpack(">H", r[6:8])[0])
PY
)
  result dns INFO "query from 10.40.255.254 (allowed): $a"
}

# --- firewall / NAT / CGNAT --------------------------------------------------------
nat_setup() { # the CHR behind A on VLAN 10 (a DHCP lease from case dhcp, or static)
  if ! ros_bound v10 2>/dev/null; then
    cr_vlan 10 192.168.10.1/24 2>/dev/null || true
    ros_vlan 10 2>/dev/null || true
    rosx '/ip address add address=192.168.10.55/24 interface=v10 comment=nat
/ip route add dst-address=0.0.0.0/0 gateway=192.168.10.1 comment=nat' >/dev/null 2>&1 || true
  fi
  [ -f "$W/http.pid" ] || { ip netns exec crpeer python3 -I -m http.server 8080 --bind 0.0.0.0 --directory "$W" >/dev/null 2>&1 & echo $! > "$W/http.pid"; sleep 1; }
}
case_nat() {
  nat_setup
  # Without NAT B has no route back: nothing passes.
  [ "$(ros_ping 10.39.5.2)" = 0 ] && result nat OK "without NAT the CHR's 192.168.10.x does not reach B (no route back)" || result nat INFO "CHR reaches B without NAT"
  cli ip.firewall.nat.add '{"chain":"srcnat","action":"masquerade","out_interface":"ether5","comment":"g39h"}' >/dev/null || result nat FAIL "nat.add masquerade"
  [ "$(ros_ping 10.39.5.2)" -ge 4 ] && result nat OK "masquerade: CHR → B ping" || result nat FAIL "masquerade: CHR → B ping"
  local f; f=$(rosp tool/fetch '{"url":"http://10.39.5.2:8080/results.txt","output":"none"}')
  [[ $f == *finished* ]] && result nat OK "masquerade: CHR HTTP fetch from B (TCP)" || result nat FAIL "HTTP fetch: $(head -c 200 <<< "$f")"
  local ct; ct=$(cli ip.firewall.connection.list '{"dst":"10.39.5.2"}' | jq -c '[(.rows // .)[] | {protocol, src: (.src_address // .src // null), dst: (.dst_address // .dst // null), reply_dst: (.reply_dst_address // .reply_dst // null), state: (.tcp_state // .state // null), nat: (.nat // null)}]' 2>/dev/null)
  [[ $ct == *192.168.10.* ]] && result nat OK "connection tracking shows the CHR's flows: $(head -c 300 <<< "$ct")" || result nat FAIL "connection.list: $(head -c 300 <<< "$ct")"
  # A filter drop on forward stops the ping and counts it.
  local id; id=$(cli ip.firewall.filter.add '{"chain":"forward","action":"drop","protocol":"icmp","src_address":"192.168.10.0/24","comment":"g39h"}' | jq -r .id)
  [ "$(ros_ping 10.39.5.2)" = 0 ] && result nat OK "filter forward drop icmp: blocked ($(cli ip.firewall.filter.list | jq -c --arg id "$id" '[(.rows // .)[] | select(.id == $id) | {packets, bytes}][0]'))" || result nat FAIL "filter drop did not block"
  cli ip.firewall.filter.remove "{\"id\":\"$id\"}" >/dev/null || true
  local nid; nid=$(cli ip.firewall.nat.list | jq -r '[(.rows // .)[] | select(.comment == "g39h")][0].id')
  cli ip.firewall.nat.remove "{\"id\":\"$nid\"}" >/dev/null || true
}
case_cgnat() {
  nat_setup
  # Its own destination on B: the CHR reuses its ICMP id and TCP source port,
  # and conntrack keeps the NAT of an entry it already has (the masquerade of
  # case nat), as RouterOS does. The CoreRouter has no
  # `ip.firewall.connection.remove` to clear them (gap G3.9hd).
  clib ip.address.add '{"address":"10.39.6.2/24","interface":"ether1"}' >/dev/null || true
  cli ip.route.add '{"dst_address":"10.39.6.0/24","gateway":"10.39.5.2"}' >/dev/null || true
  clib ip.route.add '{"dst_address":"198.51.100.0/30","gateway":"10.39.5.1"}' >/dev/null
  cli ip.firewall.cgnat.pool.add '{"name":"cg","inside":"192.168.10.0/24","outside":"198.51.100.0/30","ports_per_subscriber":1000,"out_interface":"ether5"}' >/dev/null || { result cgnat FAIL "cgnat.pool.add"; return; }
  [ "$(ros_ping 10.39.6.2)" -ge 4 ] && result cgnat OK "deterministic CGNAT: CHR → B ping" || result cgnat FAIL "CGNAT: CHR → B ping"
  local f; f=$(rosp tool/fetch '{"url":"http://10.39.6.2:8080/results.txt","output":"none"}')
  [[ $f == *finished* ]] && result cgnat OK "CGNAT: CHR HTTP fetch from B" || result cgnat FAIL "CGNAT fetch: $(head -c 200 <<< "$f")"
  local sub; sub=$(ros ip/address | jq -r '[.[] | select(.interface == "v10")][0].address' | cut -d/ -f1)
  local lk; lk=$(cli ip.firewall.cgnat.lookup "{\"subscriber\":\"$sub\"}" | jq -c .)
  result cgnat INFO "lookup $sub: $lk"
  local ct; ct=$(cli ip.firewall.connection.list "{\"subscriber\":\"$sub\",\"dst\":\"10.39.6.2\"}" | jq -c '[(.rows // .)[] | {protocol, nat: (.nat // null), reply_dst: (.reply_dst_address // .reply_dst // null)}]' 2>/dev/null | head -c 300)
  local pub; pub=$(jq -r .public <<< "$lk")
  [[ $ct == *$pub* ]] && result cgnat OK "connections of $sub leave as $pub in the subscriber's port block: $ct" || result cgnat FAIL "connection.list subscriber: $ct"
  local port; port=$(jq -r .first_port <<< "$lk")
  result cgnat INFO "who-was $pub:$port: $(cli ip.firewall.cgnat.who-was "{\"public\":\"$pub\",\"port\":$port}" | jq -c '{subscriber, via, dhcp}' | head -c 300)"
  cli ip.firewall.cgnat.pool.remove '{"id":"cg"}' >/dev/null || true
}

# --- bonding --------------------------------------------------------------------
# bond_loss <cut command> <restore command>: a 10 ms ping A → CHR across the
# bond while one member is cut; prints the lost time in ms.
bond_loss() {
  local out
  ip netns exec crcore ping -q -i 0.01 -W 1 -w 14 10.39.60.1 > "$W/bondping.txt" 2>&1 &
  local p=$!
  sleep 3; eval "$1"; sleep 9; eval "$2"
  wait $p || true
  local tx rx; tx=$(grep -oE '^[0-9]+ packets transmitted' "$W/bondping.txt" | cut -d' ' -f1); rx=$(grep -oE '[0-9]+ received' "$W/bondping.txt" | cut -d' ' -f1)
  echo $(( (${tx:-0} - ${rx:-0}) * 10 ))
}
# The member carrying A's traffic to the CHR (by tx counter).
busy_member() { local a b; a=$(ip netns exec crcore cat /sys/class/net/ether2/statistics/tx_packets); b=$(ip netns exec crcore cat /sys/class/net/ether3/statistics/tx_packets)
  ip netns exec crcore ping -q -c 50 -i 0.01 10.39.60.1 >/dev/null 2>&1 || true
  local a2 b2; a2=$(ip netns exec crcore cat /sys/class/net/ether2/statistics/tx_packets); b2=$(ip netns exec crcore cat /sys/class/net/ether3/statistics/tx_packets)
  [ $((a2 - a)) -ge $((b2 - b)) ] && echo 2 || echo 3; }
case_bond() {
  local err
  rosx '/interface bonding add name=bond1 slaves=ether2,ether3 mode=802.3ad lacp-rate=1sec transmit-hash-policy=layer-2-and-3
/ip address add address=10.39.60.1/24 interface=bond1' >/dev/null
  err=$(cli interface.bonding.add '{"name":"bond1","slaves":"ether2,ether3","mode":"802.3ad","lacp_rate":"1sec","transmit_hash_policy":"layer-2-and-3","mii_interval":100}' 2>&1) || { result bond FAIL "bonding.add: $err"; return; }
  cli ip.address.add '{"address":"10.39.60.2/24","interface":"bond1"}' >/dev/null
  local ms
  ms=$(wait_for 30 lacp_up) && result bond OK "802.3ad with the CHR: both members in the aggregate after ${ms} ms (CHR monitor: $(ros_bond_mon | jq -c '{"active-ports", "inactive-ports", "lacp-system-id", "lacp-partner-system-id"}'))" \
    || { result bond FAIL "802.3ad: CHR monitor $(ros_bond_mon | jq -c .), A: $(lacp_state)"; lacp_dump; }
  result bond INFO "A side: $(lacp_state)"
  result bond INFO "CoreRouter interface.bonding.list: $(cli interface.bonding.list | jq -c '.[0]')"
  [ "$(ros_ping 10.39.60.2)" -ge 4 ] && result bond OK "802.3ad: CHR → A ping over the bond" || result bond FAIL "ping over the LACP bond"
  local m; m=$(busy_member)
  # (a) A's member goes down (carrier): A moves at once; the CHR only by LACP (3 × 1 s).
  local lost; lost=$(bond_loss "ip -n crcore link set ether$m down" "ip -n crcore link set ether$m up")
  result bond INFO "802.3ad, A's ether$m admin down (the CHR keeps carrier): ${lost} ms lost (A → CHR at 10 ms)"
  wait_for 20 lacp_up >/dev/null || true
  # (b) silent cut on the CHR side: QEMU link off on the member that carries traffic.
  m=$(busy_member)
  lost=$(bond_loss "mon 'set_link e$m off'" "mon 'set_link e$m on'")
  awk -v l="$lost" 'BEGIN {exit !(l <= 4000)}' && result bond OK "802.3ad, CHR ether$m link off (no carrier at A: LACP fast timeout, 3 s, 802.1AX §6.4): ${lost} ms lost" \
    || result bond FAIL "802.3ad silent cut: ${lost} ms lost (expected ≤ 3–4 s with lacp-rate 1sec)"
  wait_for 20 lacp_up >/dev/null || true
  # Mismatched rate: the CHR at 30 s still aggregates; failover then takes up to 90 s.
  # active-backup, then balance-xor (same hash both sides).
  for mode in active-backup balance-xor; do
    rosx "/interface bonding set bond1 mode=$mode" >/dev/null
    local x='{"name":"bond1","mode":"'$mode'"}'
    [ $mode = balance-xor ] && x='{"name":"bond1","mode":"balance-xor","transmit_hash_policy":"layer-2-and-3"}'
    err=$(cli interface.bonding.set "$x" 2>&1) || { result bond FAIL "$mode: $err"; continue; }
    sleep 2
    [ "$(ros_ping 10.39.60.2)" -ge 4 ] && result bond OK "$mode: ping over the bond" || result bond FAIL "$mode: ping"
    m=$(busy_member)
    lost=$(bond_loss "mon 'set_link e$m off'; ip -n crcore link set ether$m down" "mon 'set_link e$m on'; ip -n crcore link set ether$m up")
    result bond INFO "$mode: member ether$m cut on both sides (carrier): ${lost} ms lost (mii 100 ms)"
    sleep 2
  done
  rosx '/ip address remove [find interface=bond1]
/interface bonding remove bond1' >/dev/null || true
}
ros_bond_mon() { rosp interface/bonding/monitor '{"numbers":"bond1","once":""}' | jq -c '.[0] // {}'; }
# Where the LACPDUs (slow protocols, 0x8809) stop: each hop of the wire.
lacp_dump() {
  local d
  for d in "crt2 root" "crv2 root" "ether2 crcore" "crt3 root" "ether3 crcore"; do
    set -- $d
    local x=""; [ "$2" = root ] || x="ip netns exec $2"
    result bond INFO "LACPDUs on $1 ($2), 4 s: $(timeout 4 $x tcpdump -l -nei "$1" 'ether proto 0x8809' 2>/dev/null | awk '{print $2}' | sort | uniq -c | tr -s ' ' | paste -sd';')"
  done
  result bond INFO "tc on crt2/crv2: $(tc -s filter show dev crt2 ingress | grep -oE 'Sent [0-9]+ bytes [0-9]+ pkt' | head -1) / $(tc -s filter show dev crv2 ingress | grep -oE 'Sent [0-9]+ bytes [0-9]+ pkt' | head -1)"
}
lacp_state() { ip netns exec crcore cat /proc/net/bonding/bond1 2>/dev/null | grep -E 'Aggregator ID|Partner Mac|Slave Interface|MII Status|Number of ports' | tr -s ' ' | paste -sd';' | cut -c1-400; }
lacp_up() { [[ $(ros_bond_mon | jq -r '.["active-ports"] // "" | tostring') == *ether2*ether3* ]] && [ "$(ip netns exec crcore grep -c 'Aggregator ID' /proc/net/bonding/bond1 2>/dev/null)" -ge 3 ] && \
  [ "$(ip netns exec crcore awk '/Aggregator ID/ {print $3}' /proc/net/bonding/bond1 | sort -u | wc -l)" = 1 ]; }

# --- CoreRouter × CoreRouter ---------------------------------------------------------
case_cr-dhcp() {
  # VLAN 50 between A ether5 and B ether1; A serves, B is the client.
  cli interface.vlan.add '{"name":"v50","parent":"ether5","vlan_id":50}' >/dev/null
  cli ip.address.add '{"address":"192.168.50.1/24","interface":"v50"}' >/dev/null
  clib interface.vlan.add '{"name":"v50","parent":"ether1","vlan_id":50}' >/dev/null
  cli ip.pool.add '{"name":"p50","ranges":"192.168.50.10-192.168.50.20"}' >/dev/null
  cli ip.dhcp-server.add '{"name":"d50","interface":"v50","address_pool":"p50","lease_time":"1m"}' >/dev/null
  cli ip.dhcp-server.network.add '{"address":"192.168.50.0/24","gateway":"192.168.50.1","dns_server":"192.168.50.1","domain":"cr.example"}' >/dev/null
  local id; id=$(clib ip.dhcp-client.add '{"interface":"v50","add_default_route":"no"}' | jq -r .id)
  local ms
  ms=$(wait_for 30 crb_bound v50) && result cr-dhcp OK "B bound from A over VLAN 50 in ${ms} ms: $(clib ip.dhcp-client.list '{"interface":"v50"}' | jq -c '.[0] | {address, gateway, primary_dns, domain}')" \
    || result cr-dhcp FAIL "B client: $(clib ip.dhcp-client.list '{"interface":"v50"}' | jq -c '.[0] | {status, error}')"
  # RouterOS `/ip dhcp-client release`: "release current binding and
  # restart DHCP client", so B binds again right after the RELEASE.
  clib ip.dhcp-client.release "{\"id\":\"$id\"}" >/dev/null || true
  local rel; rel=$(wait_for 5 a_logged 'released by the client') || true
  local again; again=$(wait_for 15 crb_bound v50) || true
  [ "${rel:--1}" != -1 ] && [ "${again:--1}" != -1 ] && result cr-dhcp OK "B's release reaches A (lease freed) and B binds again, as RouterOS does" \
    || result cr-dhcp FAIL "release between CoreRouters: A saw the release: $([ "${rel:--1}" != -1 ] && echo yes || echo no), B bound again: $([ "${again:--1}" != -1 ] && echo yes || echo no)"
}
a_logged() { cli log.print '{"limit":50}' | grep -q "$1"; }
crb_bound() { [ "$(clib ip.dhcp-client.list "{\"interface\":\"$1\"}" | jq -r '.[0].status')" = bound ]; }

case_cr-bond() {
  # LACP between the two kernels (A ether6+7, B ether2+3), then throughput
  # from the clients' namespace through A to B over the bond.
  cli interface.bonding.add '{"name":"bond2","slaves":"ether6,ether7","mode":"802.3ad","lacp_rate":"1sec","transmit_hash_policy":"layer-3-and-4"}' >/dev/null || { result cr-bond FAIL "A bonding.add"; return; }
  clib interface.bonding.add '{"name":"bond2","slaves":"ether2,ether3","mode":"802.3ad","lacp_rate":"1sec","transmit_hash_policy":"layer-3-and-4"}' >/dev/null || { result cr-bond FAIL "B bonding.add"; return; }
  cli ip.address.add '{"address":"10.39.70.1/24","interface":"bond2"}' >/dev/null
  clib ip.address.add '{"address":"10.39.70.2/24","interface":"bond2"}' >/dev/null
  clib ip.route.add '{"dst_address":"10.40.0.0/16","gateway":"10.39.70.1"}' >/dev/null
  ip -n crcl route add default via 10.40.0.1 2>/dev/null || true
  local ms
  ms=$(wait_for 30 crlacp) && result cr-bond OK "802.3ad A × B: one aggregator with both members in ${ms} ms" || result cr-bond FAIL "A × B LACP: $(ip netns exec crcore grep -E 'Aggregator ID|Partner Mac' /proc/net/bonding/bond2 | tr -s ' ' | paste -sd';')"
  ip netns exec crpeer iperf3 -s -D -B 10.39.70.2 -p 5201 --pidfile "$W/iperf.pid" >/dev/null
  sleep 1
  local g1 g4
  g1=$(ip netns exec crcl iperf3 -c 10.39.70.2 -t 5 -J 2>/dev/null | jq -r '.end.sum_received.bits_per_second / 1e9 | . * 100 | round / 100')
  g4=$(ip netns exec crcl iperf3 -c 10.39.70.2 -t 5 -P 4 -J 2>/dev/null | jq -r '.end.sum_received.bits_per_second / 1e9 | . * 100 | round / 100')
  result cr-bond INFO "throughput clients → A (routing) → bond → B: 1 flow ${g1} Gbit/s, 4 flows ${g4} Gbit/s (veth, one VM: CPU bound)"
  local a b; a=$(ip netns exec crcore cat /sys/class/net/ether6/statistics/tx_bytes); b=$(ip netns exec crcore cat /sys/class/net/ether7/statistics/tx_bytes)
  result cr-bond INFO "tx bytes per member (layer-3-and-4 spreads the 4 flows): ether6 $a, ether7 $b"
  local lost
  ip netns exec crcore ping -q -i 0.01 -W 1 -w 10 10.39.70.2 > "$W/crbond.txt" 2>&1 &
  local p=$!; sleep 3; ip -n crpeer link set ether2 down; ip -n crpeer link set ether3 down; ip -n crpeer link set ether3 up; sleep 6; ip -n crpeer link set ether2 up; wait $p || true
  local tx rx; tx=$(grep -oE '^[0-9]+ packets transmitted' "$W/crbond.txt" | cut -d' ' -f1); rx=$(grep -oE '[0-9]+ received' "$W/crbond.txt" | cut -d' ' -f1)
  result cr-bond INFO "member cut on B (veth carrier goes down on A too): $(( (${tx:-0} - ${rx:-0}) * 10 )) ms lost"
  # Silent cut: B's ether2 drops every frame but keeps its carrier, so only
  # the LACP timeout tells (802.1AX: 3 × the 1 s fast period).
  ms=$(wait_for 30 crlacp) || true
  # Cut the member A sends the ping on (A ether6 = B ether2, ether7 = ether3).
  ip netns exec crcore ping -q -i 0.01 -W 1 -w 12 10.39.70.2 > "$W/crbond2.txt" 2>&1 &
  p=$!
  local t6 t7 cut
  t6=$(ip netns exec crcore cat /sys/class/net/ether6/statistics/tx_packets); t7=$(ip netns exec crcore cat /sys/class/net/ether7/statistics/tx_packets)
  sleep 2
  t6=$(( $(ip netns exec crcore cat /sys/class/net/ether6/statistics/tx_packets) - t6 )); t7=$(( $(ip netns exec crcore cat /sys/class/net/ether7/statistics/tx_packets) - t7 ))
  if [ "$t6" -ge "$t7" ]; then cut=ether2; else cut=ether3; fi
  ip netns exec crpeer tc qdisc add dev $cut clsact
  ip netns exec crpeer tc filter add dev $cut ingress matchall action drop
  ip netns exec crpeer tc filter add dev $cut egress matchall action drop
  wait $p || true
  tx=$(grep -oE '^[0-9]+ packets transmitted' "$W/crbond2.txt" | cut -d' ' -f1); rx=$(grep -oE '[0-9]+ received' "$W/crbond2.txt" | cut -d' ' -f1)
  local left; left=$(ip netns exec crcore awk '/Slave Interface/ {i=$3} /Aggregator ID/ && i {a[i]=$3} END {for (k in a) printf "%s=%s ", k, a[k]}' /proc/net/bonding/bond2)
  result cr-bond INFO "silent cut of the busy member (B $cut; carrier up, frames dropped): $(( (${tx:-0} - ${rx:-0}) * 10 )) ms lost to the LACP timeout; aggregators after: $left"
  ip netns exec crpeer tc qdisc del dev $cut clsact 2>/dev/null || true
}
crlacp() { [ "$(ip netns exec crcore awk '/Aggregator ID/ {print $3}' /proc/net/bonding/bond2 2>/dev/null | sort -u | wc -l)" = 1 ] &&
  ! ip netns exec crcore grep -q 'Partner Mac Address: 00:00:00:00:00:00' /proc/net/bonding/bond2; }

# --- performance ------------------------------------------------------------------
case_storm() {
  # N clients with their own MACs (BNG Blaster IPoE, DHCPv4 only) against
  # A's server on ether8: leases per second and CPU per daemon thread.
  local n=${STORM_N:-20000} rate=${STORM_RATE:-10000}
  cli ip.pool.add '{"name":"p40","ranges":"10.40.1.0-10.40.254.255"}' >/dev/null
  cli ip.dhcp-server.add '{"name":"d40","interface":"ether8","address_pool":"p40","lease_time":"30m","conflict_detection":false,"client_rate_limit":0}' >/dev/null || { result storm FAIL "server on ether8"; return; }
  cli ip.dhcp-server.network.add '{"address":"10.40.0.0/16","gateway":"10.40.0.1","dns_server":"10.40.0.1"}' >/dev/null
  cli ip.dhcp-server.statistics.reset >/dev/null || true
  ip -n crcl addr flush dev cl0
  cat > "$W/storm.json" <<EOF
{"interfaces": {"tx-interval": 1.0, "rx-interval": 1.0, "access": [{"interface": "cl0", "type": "ipoe", "vlan-mode": "N:1", "ipv4": true, "ipv6": false}]},
 "sessions": {"count": $n, "start-rate": $rate, "max-outstanding": 2000},
 "ipoe": {"ipv4": true, "ipv6": false},
 "dhcp": {"enable": true, "timeout": 5, "retry": 10},
 "dhcpv6": {"enable": false}}
EOF
  if ! command -v bngblaster >/dev/null; then storm_py "$n" "$rate"; return; fi
  snapshot "$W/cpu0"
  local t0; t0=$(now_ms)
  ip netns exec crcl timeout 120 bngblaster -C "$W/storm.json" -J "$W/storm-report.json" -S "$W/storm.sock" -l dhcp > "$W/storm.log" 2>&1 &
  local bp=$!
  local bound=0
  while [ $(( $(now_ms) - t0 )) -lt 90000 ]; do
    bound=$(cli ip.dhcp-server.statistics.print | jq -r '.leases.bound')
    [ "$bound" -ge "$n" ] && break
    sleep 1
  done
  local dt=$(( $(now_ms) - t0 ))
  snapshot "$W/cpu1"
  local st; st=$(cli ip.dhcp-server.statistics.print | jq -c '{leases, received, sent, peak_acks, latency_us}')
  kill -INT $bp 2>/dev/null || true; wait $bp 2>/dev/null || true
  [ "$bound" -ge "$n" ] && result storm OK "$n clients bound in $dt ms ($(( n * 1000 / dt )) leases/s average, BNG Blaster start rate $rate/s)" \
    || result storm FAIL "$bound of $n bound in $dt ms"
  result storm INFO "server: $st"
  result storm INFO "CPU per daemon thread over the storm: $(cpu_report "$W/cpu0" "$W/cpu1" "$(awk -v d=$dt 'BEGIN {print d / 1000}')")"
  result storm INFO "bngblaster: $(grep -E 'Sessions|Setup|Rate|established' "$W/storm.log" | tail -5 | tr -s ' ' | paste -sd';' | cut -c1-300)"
  ip -n crcl addr add 10.40.255.254/16 dev cl0 2>/dev/null || true
}

case_dhcp-conflict() {
  # RFC 2131 §4.4.1 (SHOULD probe before offering) and RouterOS's
  # conflict-detection: a host with .50 that the server does not know (in
  # crcl, its own MAC) makes the server mark .50 conflict and offer .51.
  cli ip.address.add '{"address":"10.41.0.1/24","interface":"ether8"}' >/dev/null || true
  cli ip.pool.add '{"name":"p41","ranges":"10.41.0.50-10.41.0.52"}' >/dev/null
  cli ip.dhcp-server.add '{"name":"d41","interface":"ether8","address_pool":"p41","lease_time":"10m","conflict_detection":true}' >/dev/null || { result dhcp-conflict FAIL "server on ether8"; return; }
  cli ip.dhcp-server.network.add '{"address":"10.41.0.0/24","gateway":"10.41.0.1"}' >/dev/null
  ip -n crcl addr add 10.41.0.50/24 dev cl0
  storm_py 1 1 dhcp-conflict
  local l; l=$(cli ip.dhcp-server.lease.print '{"server":"d41"}' | jq -c '[.[] | {address, status, mac_address}]')
  [[ $(jq -r '[.[] | select(.address == "10.41.0.50") | .status][0] // ""' <<< "$l") == conflict ]] \
    && [[ $(jq -r '[.[] | select(.status == "bound") | .address][0] // ""' <<< "$l") != 10.41.0.50 ]] \
    && result dhcp-conflict OK "the ARP probe found .50 in use: $l" || result dhcp-conflict FAIL "leases: $l"
  ip -n crcl addr del 10.41.0.50/24 dev cl0 2>/dev/null || true
  # One server per interface: free ether8 for the storm.
  cli ip.dhcp-server.remove '{"id":"d41"}' >/dev/null || true
}

# storm_py <n> <rate> [case]: without BNG Blaster, n DHCP clients from one raw
# socket on cl0 (own MAC each, broadcast flag so the replies reach the
# socket): DISCOVER at <rate>/s, REQUEST on each OFFER, ACKs counted.
storm_py() {
  cat > "$W/storm.py" <<'PY2'
import os, random, socket, struct, sys, time
n, rate = int(sys.argv[1]), int(sys.argv[2])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
s.bind(("cl0", 0)); s.setblocking(False)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 24)
def csum(b):
    if len(b) % 2: b += b"\0"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b)); t = (t >> 16) + (t & 0xffff); t += t >> 16
    return ~t & 0xffff
def frame(mac, xid, opts):
    bootp = struct.pack("!BBBBIHHIIII", 1, 1, 6, 0, xid, 0, 0x8000, 0, 0, 0, 0) + mac + b"\0" * 10 + b"\0" * 192
    bootp += b"\x63\x82\x53\x63" + opts + b"\xff"
    udp = struct.pack("!HHHH", 68, 67, 8 + len(bootp), 0) + bootp
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, b"\0" * 4, b"\xff" * 4)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return b"\xff" * 6 + mac + b"\x08\x00" + ip + udp
macs = [b"\x02\x39" + struct.pack("!I", i + 1) for i in range(n)]
by_xid = {}
acked = set(); offers = naks = 0
t0 = time.time(); sent = 0; last_retry = t0; t99 = 0
def recv():
    global offers, naks
    while True:
        try: f = s.recv(2048)
        except BlockingIOError: return
        if len(f) < 282 or f[23] != 17 or f[36:38] != b"\x00\x44": continue
        b = f[42:]
        if b[0] != 2: continue
        xid = struct.unpack("!I", b[4:8])[0]; i = by_xid.get(xid)
        if i is None: continue
        yi = b[16:20]; o = b[240:]; mt = sid = None; k = 0
        while k < len(o) and o[k] != 255:
            if o[k] == 0: k += 1; continue
            c, l = o[k], o[k + 1]; v = o[k + 2:k + 2 + l]; k += 2 + l
            if c == 53: mt = v[0]
            elif c == 54: sid = v
        if mt == 2 and sid:
            offers += 1
            s.send(frame(macs[i], xid, b"\x35\x01\x03\x32\x04" + yi + b"\x36\x04" + sid))
        elif mt == 5: acked.add(i)
        elif mt == 6: naks += 1
while len(acked) < n and time.time() - t0 < 90:
    due = min(n, int((time.time() - t0) * rate) + 1)
    while sent < due:
        xid = random.getrandbits(32); by_xid[xid] = sent
        s.send(frame(macs[sent], xid, b"\x35\x01\x01")); sent += 1
    recv()
    if not t99 and len(acked) * 100 >= n * 99: t99 = time.time() - t0
    if sent == n and time.time() - last_retry > 1:
        last_retry = time.time()
        for i in range(n):
            if i not in acked:
                xid = random.getrandbits(32); by_xid[xid] = i
                s.send(frame(macs[i], xid, b"\x35\x01\x01"))
    time.sleep(0.0005)
dt = time.time() - t0
print(len(acked), n, int(dt * 1000), offers, naks, int(t99 * 1000), int(n / rate * 1000))
PY2
  ip link set dev lo up 2>/dev/null || true
  snapshot "$W/cpu0"
  local out; out=$(ip netns exec crcl python3 -I "$W/storm.py" "$1" "$2" 2>&1 | tail -1)
  snapshot "$W/cpu1"
  local acked n ms offers naks t99 tsend; read -r acked n ms offers naks t99 tsend <<< "$out"
  if [ "${acked:-0}" = "$1" ] && [ "${ms:-0}" -gt 0 ] && [ "${t99:-0}" -gt 0 ]; then
    result "${3:-storm}" OK "$1 clients: 99% bound in $t99 ms ($(( $1 * 990 / t99 )) leases/s), all in $ms ms; DISCOVERs sent over $tsend ms (Python generator, $2/s); $offers offers, $naks NAKs"
  else
    result "${3:-storm}" FAIL "storm: ${out:0:200}"
  fi
  result "${3:-storm}" INFO "server: $(cli ip.dhcp-server.statistics.print | jq -c '{leases, received, sent, peak_acks, latency_us}' | cut -c1-300)"
  result "${3:-storm}" INFO "CPU per daemon thread over the storm: $(cpu_report "$W/cpu0" "$W/cpu1" "$(awk -v d="${ms:-1000}" 'BEGIN {print d / 1000}')")"
  ip -n crcl addr add 10.40.255.254/16 dev cl0 2>/dev/null || true
}

case_dns-qps() {
  # A loop of queries from the clients' namespace: answered per second by
  # A's resolver for a static name and for a cached forwarded one.
  local err
  err=$(cli ip.dns.set '{"allow_remote_requests":true,"allowed_from":["10.39.0.0/16","192.168.0.0/16","10.40.0.0/16"],"max_queries_per_client":0,"servers":["10.39.5.2"]}' 2>&1) || { result dns-qps FAIL "ip.dns.set: ${err:0:200}"; return; }
  wait_for 15 grep -q 'answering the LAN' "$W/daemon-a.log" >/dev/null || { result dns-qps FAIL "A's LAN forwarder did not open: $(grep -i 'dns' "$W/daemon-a.log" | tail -3 | paste -sd';' | cut -c1-300)"; return; }
  cli ip.dns.static.add '{"name":"qps.lab","address":"10.40.0.1"}' >/dev/null 2>&1 || true
  clib ip.dns.set '{"allow_remote_requests":true,"allowed_from":["10.39.0.0/16"]}' >/dev/null
  clib ip.dns.static.add '{"name":"fwd.lab","address":"10.39.5.2"}' >/dev/null 2>&1 || true
  cat > "$W/qps.py" <<'PY'
import socket, struct, sys, time, os, select
server, name, secs, window = sys.argv[1], sys.argv[2], float(sys.argv[3]), int(sys.argv[4])
qn = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setblocking(False)
s.connect((server, 53))
sent = got = 0; qid = 0; out = 0; err = 0
end = time.time() + secs
while time.time() < end:
    while out < window:
        qid = (qid + 1) & 0xffff
        try:
            s.send(struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qn + struct.pack(">HH", 1, 1)); sent += 1; out += 1
        except OSError as e:  # ICMP unreachable from an earlier query
            err = e.errno; break
    r, _, _ = select.select([s], [], [], 0.05)
    if not r:
        out = 0  # lost: refill the window
        continue
    try:
        while True:
            s.recv(512); got += 1; out -= 1
    except BlockingIOError:
        pass
    except OSError as e:
        err = e.errno; out = 0
print(sent, got, err)
PY
  local name procs
  for name in qps.lab fwd.lab; do
    ip netns exec crcl python3 -I "$W/qps.py" 10.40.0.1 "$name" 1 8 >/dev/null 2>&1 || true
    for procs in 1 4 8; do
      snapshot "$W/q0"
      local i tot=0
      local qp=()
      for i in $(seq $procs); do ip netns exec crcl python3 -I "$W/qps.py" 10.40.0.1 "$name" 5 32 > "$W/qps.$i" 2>&1 & qp+=($!); done
      wait "${qp[@]}" || true
      snapshot "$W/q1"
      local errs=""
      for i in $(seq $procs); do
        tot=$(( tot + $(awk 'NR == 1 {n = $2} END {print (n ~ /^[0-9]+$/ ? n : 0)}' "$W/qps.$i") ))
        errs+=$(awk 'NR == 1 && $3 != 0 {printf " errno %s", $3}' "$W/qps.$i")
      done
      result dns-qps INFO "$name, $procs client(s) × 32 in flight: $(( tot / 5 )) answers/s${errs:+ (socket errors:$errs)}; CPU: $(cpu_report "$W/q0" "$W/q1" 5)"
    done
  done
  result dns-qps INFO "A statistics: $(cli ip.dns.statistics.print | jq -c . | cut -c1-300)"
}

# G3.9hl: the `print`/`export` of the /interface sub-menus as RouterOS 7
# writes them (terminal text, the columns a test of crates/shell copies) and
# as the CoreRouter's terminal writes them for the same config. Not a pass
# or fail case: two text blocks to compare by eye and by test.
prints_menus=("interface vlan" "interface bridge" "interface bridge port" "interface bonding" "interface pppoe-client" "interface ethernet")
case_prints() {
  rosx '/interface vlan add name=v30 vlan-id=30 interface=ether1 comment=prints
/interface vlan add name=v31 vlan-id=31 interface=ether1 disabled=yes
/interface bridge add name=br1
/interface bridge port add bridge=br1 interface=v30
/interface bonding add name=bond1 slaves=ether2,ether3 mode=802.3ad
/interface pppoe-client add name=pc1 interface=ether1 user=u1 password=p1 disabled=yes' >/dev/null
  cr_vlan 30 10.39.30.2/24
  cli interface.vlan.add '{"name":"v31","parent":"ether1","vlan_id":31,"disabled":true}' >/dev/null
  cli interface.set '{"name":"v30","comment":"prints"}' >/dev/null
  cli interface.bridge.add '{"name":"br1"}' >/dev/null
  cli interface.bridge.port.add '{"bridge":"br1","interface":"v30"}' >/dev/null
  cli interface.bonding.add '{"name":"bond1","slaves":"ether2,ether3","mode":"802.3ad"}' >/dev/null
  cli interface.pppoe-client.add '{"name":"pc1","interface":"ether1","user":"u1","password":"p1","disabled":true}' >/dev/null || true
  local m v
  for m in "${prints_menus[@]}"; do
    for v in print "print detail" "print terse" "print as-value" "print where name~\"1\"" export; do
      echo "--- RouterOS: /$m $v"
      rosx "/$m $v" | jq -r '.ret // .'
      echo "--- CoreRouter: /$m $v"
      printf '/%s %s\n' "$m" "$v" | ip netns exec crcore "$bin/corerouter-cli" --connect 127.0.0.1:7990 shell 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
    done
  done | tee "$W/prints.txt"
  result prints INFO "$(grep -c '^--- ' "$W/prints.txt") outputs in $W/prints.txt"
}

for c in "${CASES[@]}"; do
  echo "=== $c ==="
  "case_$c" || result "$c" FAIL "the case stopped: exit $?"
done
echo
echo "=== results (RouterOS $ROS_VERSION CHR × CoreRouter $(git rev-parse --short HEAD 2>/dev/null || echo ?)) ==="
cat "$W/results.txt"
if [ $FAILED != 0 ]; then
  echo "--- A daemon log (tail) ---"; tail -30 "$W/daemon-a.log"
  echo "--- A log.print ---"; cli log.print '{"limit":30}' | jq -r '.[] | "\(.time) \(.topics | join(",")) \(.message)"' | cut -c1-200 || true
  echo "--- CHR log (tail) ---"; ros log | jq -r '.[-20:][] | "\(.time) \(.topics) \(.message)"' || true
fi
exit $FAILED
