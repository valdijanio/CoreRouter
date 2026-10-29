#!/usr/bin/env bash
# G3.9f: BGP of the CoreRouter (linux backend + its FRR) against a real
# MikroTik RouterOS v7 CHR, against FRR and against another CoreRouter.
# Runs as root inside the lab VM only:
#   cargo xtask vm-lab run --lock-timeout 2h -- scripts/routeros-interop-bgp.sh [case…]
# Cases (default: all, in this order):
#   ebgp4 ebgp6 mpbgp multihop md5 communities filters ibgp nexthop-self
#   rr rr-chr maxprefix restart bfd convergence scale crcr
# A round of everything takes ~25 min (the CHR boot ~1 min, scale ~5 min);
# pass a few cases to keep a round short. HOLD=<s> keeps the lab up that
# long at the end. Results: a table at the end and /tmp/crg39f/results.txt
# in the VM; exit 1 if any case failed.
#
# Topology (all inside the VM; each CoreRouter lives in its own netns with
# its own FRR, so the linux backend sees only its own ports):
#
#   R3 (ns cfr3, FRR AS 65003) eth0 ──cfb2── ether2 ┐
#                                                   CHR (QEMU/KVM, AS 65001)
#   CR1 (ns cf1, AS 65000) ether1 ──cfb1── ether1 ──┤
#   CR1 ether5 ─────────────────cfb3── ether3 ──────┘ (a second path)
#   CR1 ether2 ── eth0 R4 (ns cfr4, FRR AS 65000)
#   CR1 ether3 ── ether1 CR2 (ns cf2, AS 65000; 65002 in crcr)
#   CR1 ether4 ── cl0 R4 (CR1's clients, 100.64.39.0/24)
#   CHR ether4 ──cfbm── 192.168.238.1 (REST from the VM's root namespace)
#
# Links 10.39.<n>.0/30 and fd39:<n>::/64 (the CHR side or CR1 is .1/::1):
# 1 CHR—CR1, 2 CHR—R3, 3 CHR—CR1 (second), 4 CR1—R4, 5 CR1—CR2.
# Loopbacks 10.255.39.<n>/32: CHR 1, CR1 2, R3 3, R4 4, CR2 5.
set -euo pipefail
# vm-lab run holds its lock on fd 9: a daemon started from here would
# inherit it and keep the VM locked after the round.
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }

ROS_VERSION=${ROS_VERSION:-7.25}
CASES=("$@")
[ ${#CASES[@]} -gt 0 ] || CASES=(ebgp4 ebgp6 mpbgp multihop md5 communities filters ibgp nexthop-self rr rr-chr maxprefix restart bfd convergence scale crcr)
W=/tmp/crg39f
CHR_DIR=/srv/lab/chr
PW=g39f-lab-only
ROS=192.168.238.2
FAILED=0
mkdir -p "$W"
: > "$W/results.txt"

result() { # result <case> <OK|FAIL|INFO> <text>
  printf '%-13s %-4s %s\n' "$1" "$2" "$3" | tee -a "$W/results.txt"
  [ "$2" != FAIL ] || FAILED=1
}

img=$CHR_DIR/chr-$ROS_VERSION.img
[ -f "$img" ] || { echo "no $img: run scripts/routeros-interop.sh once (it fetches and checks the image)"; exit 1; }
[ -e /dev/kvm ] || { echo "no /dev/kvm in the VM: nested virtualization is off"; exit 1; }
command -v qemu-system-x86_64 >/dev/null || { echo "no qemu: run scripts/routeros-interop.sh once"; exit 1; }

cargo build -q --release -p corerouter-daemon -p corerouter-cli
bin="$(realpath "${CARGO_TARGET_DIR:-target}")/release"

# --- teardown ---------------------------------------------------------------
NSS="cf1 cf2 cfr3 cfr4"
cleanup() {
  [ -f "$W/qemu.pid" ] && kill "$(cat "$W/qemu.pid")" 2>/dev/null || true
  for n in 1 2; do [ -f "$W/daemon$n.pid" ] && kill "$(cat "$W/daemon$n.pid")" 2>/dev/null || true; done
  for ns in $NSS; do pkill -f -- "-N $ns( |$)" 2>/dev/null || true; done
  sleep 0.5
  for ns in $NSS; do pkill -9 -f -- "-N $ns( |$)" 2>/dev/null || true; ip netns del $ns 2>/dev/null || true; done
  for l in cfb1 cfb2 cfb3 cfbm cfv1 cfv2 cfv3 cft1 cft2 cft3 cft4; do ip link del $l 2>/dev/null || true; done
  rm -f "$W/qemu.pid" "$W/daemon1.pid" "$W/daemon2.pid"
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
for ns in $NSS; do
  ip netns add $ns
  ip -n $ns link set lo up
  ip netns exec $ns sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
done
segment() { # segment <bridge> <veth here> <veth there> <netns>
  ip link add "$1" type bridge
  ip link set "$1" up
  ip link add "$2" type veth peer name "$3" netns "$4"
  ip link set "$2" master "$1" up
  ip -n "$4" link set "$3" up
}
pair() { # pair <ns a> <if a> <ns b> <if b>
  ip link add "cfp$$" type veth peer name "$4" netns "$3"
  ip link set "cfp$$" netns "$1"
  ip -n "$1" link set "cfp$$" name "$2"
  ip -n "$1" link set "$2" up
  ip -n "$3" link set "$4" up
}
segment cfb1 cfv1 ether1 cf1
segment cfb2 cfv2 eth0 cfr3
segment cfb3 cfv3 ether5 cf1
pair cf1 ether2 cfr4 eth0
pair cf1 ether3 cf2 ether1
pair cf1 ether4 cfr4 cl0
pair cf2 ether2 cfr4 cl1
ip link add cfbm type bridge
ip addr add 192.168.238.1/24 dev cfbm
ip link set cfbm up
ip -n cfr3 addr add 10.39.2.2/30 dev eth0
ip -n cfr3 addr add fd39:2::2/64 dev eth0 nodad
ip -n cfr3 addr add 10.255.39.3/32 dev lo
ip -n cfr4 addr add 10.39.4.2/30 dev eth0
ip -n cfr4 addr add fd39:4::2/64 dev eth0 nodad
ip -n cfr4 addr add 10.255.39.4/32 dev lo
ip -n cfr4 addr add 100.64.39.2/24 dev cl0
ip -n cfr4 addr add 100.64.40.2/24 dev cl1
ip -n cfr4 route add 10.39.0.0/16 via 10.39.4.1
ip -n cfr4 route add 10.255.39.0/24 via 10.39.4.1

# --- the CHR ---------------------------------------------------------------
cp "$img" "$W/chr.img"
qemu-system-x86_64 -enable-kvm -cpu host -m 768 -smp 2 -name chr-g39f \
  -drive file="$W/chr.img",format=raw,if=virtio \
  -netdev tap,id=e1,ifname=cft1,script=no,downscript=no -device virtio-net-pci,netdev=e1,mac=52:54:00:39:0f:01 \
  -netdev tap,id=e2,ifname=cft2,script=no,downscript=no -device virtio-net-pci,netdev=e2,mac=52:54:00:39:0f:02 \
  -netdev tap,id=e3,ifname=cft3,script=no,downscript=no -device virtio-net-pci,netdev=e3,mac=52:54:00:39:0f:03 \
  -netdev tap,id=e4,ifname=cft4,script=no,downscript=no -device virtio-net-pci,netdev=e4,mac=52:54:00:39:0f:04 \
  -serial unix:$W/chr.sock,server,nowait -monitor unix:$W/chr.mon,server,nowait \
  -display none -daemonize -pidfile "$W/qemu.pid"
ip link set cft1 master cfb1 up
ip link set cft2 master cfb2 up
ip link set cft3 master cfb3 up
ip link set cft4 master cfbm up

# The console (as in scripts/routeros-interop.sh): log in, take the
# first-login questions, type the bootstrap; the rest goes by REST.
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
python3 -I "$W/console.py" "$W/chr.sock" "$PW" <<ROS
/system identity set name=chr-g39f
/ip address add address=$ROS/24 interface=ether4
/ip service set www disabled=no
ROS
for _ in $(seq 100); do curl -sf -m 2 -u "admin:$PW" "http://$ROS/rest/system/resource" >/dev/null && break; sleep 0.2; done

ros() { curl -sf -m 20 -u "admin:$PW" "http://$ROS/rest/$1"; }
rosx() {
  local out
  out=$(jq -n --arg s "$1" '{script: $s}' |
    curl -s -m 60 -u "admin:$PW" -H 'content-type: application/json' -d @- "http://$ROS/rest/execute")
  if echo "$out" | jq -e 'type == "object" and has("error")' >/dev/null 2>&1; then
    echo "RouterOS refused: $out" >&2
    return 1
  fi
  printf '%s' "$out"
}
echo "RouterOS: $(ros system/resource | jq -r '"\(.version) on \(.["architecture-name"]), \(.["cpu-count"]) CPU"')"

# --- FRR nodes R3 and R4 (zebra, staticd, bgpd, bfdd) -------------------------
frr_plain() { # frr_plain <ns> <bgpd.conf text>
  local ns=$1 d=/etc/frr/$1
  install -d -o frr -g frr "$d" "/var/run/frr/$ns"
  : > "$d/zebra.conf"; : > "$d/vtysh.conf"; : > "$d/staticd.conf"; : > "$d/bfdd.conf"
  printf '%s\n' "$2" > "$d/bgpd.conf"
  chown frr:frr "$d"/*.conf
  # mgmtd and staticd take no -f (FRR 10: mgmtd holds staticd's config).
  ip netns exec "$ns" /usr/lib/frr/mgmtd -N "$ns" -d
  sleep 1
  ip netns exec "$ns" /usr/lib/frr/zebra -N "$ns" -d -f "$d/zebra.conf"
  sleep 1
  ip netns exec "$ns" /usr/lib/frr/staticd -N "$ns" -d
  for p in bgpd bfdd; do ip netns exec "$ns" /usr/lib/frr/$p -N "$ns" -d -f "$d/$p.conf"; done
}
vt() { vtysh -N "$1" -c "$2"; }
frr_plain cfr3 'router bgp 65003
 bgp router-id 10.255.39.3
 no bgp ebgp-requires-policy
 no bgp default ipv4-unicast
 neighbor 10.39.2.1 remote-as 65001
 address-family ipv4 unicast
  redistribute kernel
  neighbor 10.39.2.1 activate
 exit-address-family
exit'
frr_plain cfr4 'router bgp 65000
 bgp router-id 10.255.39.4
 no bgp default ipv4-unicast
 neighbor 10.39.4.1 remote-as 65000
 neighbor 10.39.4.1 shutdown
 address-family ipv4 unicast
  network 192.0.2.0/24
  neighbor 10.39.4.1 activate
 exit-address-family
exit'
ip -n cfr4 route add blackhole 192.0.2.0/24

# --- the two CoreRouters: each its own FRR (bfdd with our engine as its data
# plane) and the daemon with the linux backend ---------------------------------
export COREROUTER_RUNTIME_DIR=$W/run
rm -rf "$COREROUTER_RUNTIME_DIR" "$W/cfg1" "$W/cfg2"
mkdir -p "$COREROUTER_RUNTIME_DIR"
frr_cr() { # frr_cr <ns>
  local ns=$1 d=/etc/frr/$1
  install -d -o frr -g frr "$d" "/var/run/frr/$ns"
  : > "$d/zebra.conf"; : > "$d/vtysh.conf"
  for p in bgpd ospfd ospf6d ldpd bfdd staticd; do : > "$d/$p.conf"; done
  chown frr:frr "$d"/*.conf
  ip netns exec "$ns" /usr/lib/frr/mgmtd -N "$ns" -d
  sleep 0.5
  ip netns exec "$ns" /usr/lib/frr/zebra -N "$ns" -d -f "$d/zebra.conf"
  sleep 1
  ip netns exec "$ns" /usr/lib/frr/staticd -N "$ns" -d
  for p in bgpd ospfd; do ip netns exec "$ns" /usr/lib/frr/$p -N "$ns" -d -f "$d/$p.conf"; done
  ip netns exec "$ns" /usr/lib/frr/bfdd -N "$ns" -d -f "$d/bfdd.conf" \
    --dplaneaddr "unix:/var/run/frr/$ns/bfdd_dplane.sock"
  for _ in $(seq 50); do [ -S "/var/run/frr/$ns/bfdd_dplane.sock" ] && break; sleep 0.2; done
}
start_daemon() { # start_daemon <1|2>
  local n=$1
  ip netns exec "cf$n" "$bin/corerouter-daemon" --backend linux --manage 'ether*' \
    --config-dir "$W/cfg$n" --control "799$n" --frr "/var/run/frr/cf$n" --no-discovery \
    >> "$W/daemon$n.log" 2>&1 &
  echo $! > "$W/daemon$n.pid"
  for _ in $(seq 100); do cr "$n" routing.backend.get >/dev/null 2>&1 && break; sleep 0.2; done
}
cr() { local n=$1; shift; ip netns exec "cf$n" "$bin/corerouter-cli" --connect "127.0.0.1:799$n" run "$@"; }
cr1() { cr 1 "$@"; }
cr2() { cr 2 "$@"; }
frr_cr cf1
frr_cr cf2
: > "$W/daemon1.log"; : > "$W/daemon2.log"
start_daemon 1
start_daemon 2

now_ms() { date +%s%3N; }
wait_for() { # wait_for <timeout s> <command…>: poll every 100 ms; prints the ms waited
  local t=$1; shift
  local t0; t0=$(now_ms)
  while ! "$@" >/dev/null 2>&1; do
    [ $(( $(now_ms) - t0 )) -lt $(( t * 1000 )) ] || { echo -1; return 1; }
    sleep 0.1
  done
  echo $(( $(now_ms) - t0 ))
}

# --- state readers -------------------------------------------------------------
# The CoreRouter's view of a session (by connection name), from session.list.
cr_sess() { cr "$1" routing.bgp.session.list | jq -c --arg c "$2" '[.[] | select(.connection == $c)][0] // {}'; }
cr_up() { [ "$(cr_sess "$1" "$2" | jq -r '.established // false')" = true ]; }
cr_state() { cr_sess "$1" "$2" | jq -r '.state // "none"'; }
# RouterOS: sessions by connection name (the session is named <conn>-1).
ros_sess() { ros routing/bgp/session | jq -c --arg c "$1" '[.[] | select((.name // "") | startswith($c + "-"))][0] // {}'; }
ros_up() { [ "$(ros_sess "$1" | jq -r '.established // "false"')" = true ]; }
# The active route on CHR to a prefix: "<gateway> <json>".
ros_route() { ros "ip/route?dst-address=$1" | jq -c '[.[] | select(.active == "true")][0] // {}'; }
ros_route6() { ros "ipv6/route?dst-address=$1" | jq -c '[.[] | select(.active == "true")][0] // {}'; }
ros_gw() { ros_route "$1" | jq -r '.gateway // "-"'; }
ros_gw6() { ros_route6 "$1" | jq -r '.gateway // "-"'; }
# BGP attributes live in /routing/route (bgp.as-path, bgp.med, bgp.communities…);
# /ip/route only has the forwarding fields.
ros_battr() { ros "routing/route?dst-address=$1" | jq -c '[.[] | select(has("bgp.as-path") or ((.["belongs-to"] // "") | startswith("bgp")))][0] // {} | with_entries(select(.key | startswith("bgp.") or . == "gateway" or . == "belongs-to"))'; }
# CR1's addresses on the CHR link: global or link-local (RFC 2545 §3 sends both;
# a receiver on the same link may use the link-local one).
ros_via6_cr1() { local g; g=$(ros_gw6 "$1"); [[ $g == fd39:1::2* || $g == fe80::*%ether1 ]]; }
# The kernel route in a namespace: "via X" or "-".
k_route() { ip -n "$1" route show "$2" 2>/dev/null | grep -o 'via [0-9.]*' | head -1 || true; }
k_route6() { ip -n "$1" -6 route show "$2" 2>/dev/null | grep -o 'via [0-9a-f:]*' | head -1 || true; }
k_has() { [ -n "$(k_route "$1" "$2")" ]; }
k_has6() { [ -n "$(k_route6 "$1" "$2")" ]; }
k_via() { [ "$(k_route "$1" "$2")" = "via $3" ]; }
ros_via() { [[ $(ros_gw "$1") == "$2"* ]]; }
ros_via6() { [[ $(ros_gw6 "$1") == "$2"* ]]; }
# A received route on the CoreRouter, through routing.bgp.route.list (the
# command, not vtysh: what an operator sees).
cr_rx() { # cr_rx <n> <connection> <prefix>
  local out i
  for i in $(seq 30); do
    out=$(cr "$1" routing.bgp.route.list "{\"connection\":\"$2\",\"prefix\":\"$3\",\"match\":\"exact\",\"refresh\":$([ "$i" = 1 ] && echo true || echo false)}" 2>/dev/null) || true
    [ "$(jq -r '.state // ""' <<< "$out")" = loading ] || break
    sleep 0.3
  done
  jq -c '[.rows[]? | select(.filtered | not)][0] // {}' <<< "$out"
}
# The best path in bgpd's table, after the inbound policy (route.list shows
# received routes before it, and without communities: G3.2g).
bgp_path() { # bgp_path <ns> <prefix>
  vt "$1" "show bgp $([[ $2 == *:* ]] && echo ipv6 || echo ipv4) unicast $2 json" |
    jq -c '[.paths[]? | select(.bestpath.overall // false)][0] // {} | {as_path: .aspath.string, med: .metric, local_pref: .locPrf, communities: .community.string, large: .largeCommunity.string, ext: .extendedCommunity.string, originator: .originatorId}' 2>/dev/null || echo '{}'
}
dump() {
  echo "--- CHR sessions"; ros routing/bgp/session | jq -c '.[] | {name, "remote.address", established, "last-stopped", "last-started", "prefix-count"}'
  echo "--- CR1 sessions"; cr1 routing.bgp.session.list | jq -c '.[] | {connection, remote_address, state, reason, last_error, prefix_count, prefix_sent}'
  echo "--- cf1 bgpd"; vt cf1 'show bgp summary' | tail -n +4 | head -20
  vt cf1 'show running-config' | sed -n '/^router bgp/,/^exit/p' | head -60
}

# --- base config -------------------------------------------------------------
rosx '/interface bridge add name=lo0
/ip address add address=10.255.39.1/32 interface=lo0
/ip address add address=10.39.1.1/30 interface=ether1
/ip address add address=10.39.2.1/30 interface=ether2
/ip address add address=10.39.3.1/30 interface=ether3
/ipv6 address add address=fd39:1::1/64 interface=ether1 advertise=no
/ipv6 address add address=fd39:2::1/64 interface=ether2 advertise=no
/ipv6 address add address=fd39:3::1/64 interface=ether3 advertise=no
/routing bgp instance add name=default as=65001 router-id=10.255.39.1
/ip route add dst-address=203.0.113.0/24 blackhole
/ip route add dst-address=198.51.100.0/24 blackhole
/ipv6 route add dst-address=fd39:203::/48 blackhole
/ip firewall address-list add list=bgp-out address=203.0.113.0/24
/ip firewall address-list add list=bgp-out address=198.51.100.0/24
/ipv6 firewall address-list add list=bgp-out6 address=fd39:203::/48' >/dev/null

# addr <n> <address> <interface>
addr() { cr "$1" ip.address.add "{\"address\":\"$2\",\"interface\":\"$3\"}" >/dev/null; }
cr1 interface.loopback.add '{"name":"lo"}' >/dev/null
addr 1 10.39.1.2/30 ether1; addr 1 fd39:1::2/64 ether1
addr 1 10.39.3.2/30 ether5; addr 1 fd39:3::2/64 ether5
addr 1 10.39.4.1/30 ether2; addr 1 fd39:4::1/64 ether2
addr 1 10.39.5.1/30 ether3; addr 1 fd39:5::1/64 ether3
addr 1 100.64.39.1/24 ether4; addr 1 fd39:64::1/64 ether4
addr 1 10.255.39.2/32 lo
cr2 interface.loopback.add '{"name":"lo"}' >/dev/null
addr 2 10.39.5.2/30 ether1; addr 2 fd39:5::2/64 ether1
addr 2 100.64.40.1/24 ether2
addr 2 10.255.39.5/32 lo
cr1 routing.bgp.instance.set '{"asn":65000,"router_id":"10.255.39.2"}' >/dev/null
cr2 routing.bgp.instance.set '{"asn":65000,"router_id":"10.255.39.5"}' >/dev/null
for n in 1 2; do
  cr "$n" routing.filter.rule.add '{"chain":"all","rule":"accept"}' >/dev/null
done
cr1 ip.firewall.address-list.add '{"list":"bgp-out","address":"100.64.39.0/24"}' >/dev/null
cr1 ip.firewall.address-list.add '{"list":"bgp-out","address":"fd39:64::/64"}' >/dev/null
cr2 ip.firewall.address-list.add '{"list":"bgp-out","address":"100.64.40.0/24"}' >/dev/null
# Connection helpers: crc <n> <json> adds; crd <n> <name> removes.
crc() { cr "$1" routing.bgp.connection.add "$2" >/dev/null; }
crd() { cr "$1" routing.bgp.connection.remove "{\"id\":\"$2\"}" >/dev/null 2>&1 || true; }
rosd() { rosx "/routing bgp connection remove [find name=$1]" >/dev/null 2>&1 || true; }
# An eBGP session CR1—CHR on link 1 (IPv4), the base of several cases.
ebgp4_up() { # ebgp4_up [extra CR json] [extra CHR args]
  local x=${1:-} y=${2:-}
  [ -n "$x" ] || x='{}'
  [[ $y == *afi=* ]] || y="afi=ip $y"
  crc 1 "$(jq -c '. + $x' --argjson x "$x" <<< '{"name":"chr4","remote_address":"10.39.1.1","remote_as":65001,"input_filter":"all","output_filter":"all","output_network":"bgp-out"}')"
  rosx "/routing bgp connection add name=cr4 instance=default remote.address=10.39.1.2 remote.as=65000 local.role=ebgp output.network=bgp-out $y" >/dev/null
}
ebgp4_down() { crd 1 chr4; rosd cr4; }

# --- cases -------------------------------------------------------------------
case_ebgp4() {
  local t0 ms r
  t0=$(now_ms)
  ebgp4_up
  ms=$(wait_for 60 cr_up 1 chr4) || { result ebgp4 FAIL "no Established: CR $(cr_state 1 chr4), CHR $(ros_sess cr4 | jq -c '{established, "last-stopped"}')"; dump; ebgp4_down; return; }
  result ebgp4 OK "eBGP IPv4 Established ${ms} ms after both configs"
  result ebgp4 INFO "CR sees $(cr_sess 1 chr4 | jq -c '{state, hold_time, keepalive_time, afi, remote_id}')"
  result ebgp4 INFO "CHR sees $(ros_sess cr4 | jq -c '{"remote.cap", "local.cap", "remote.hold-time", "hold-time", "keepalive-time"}')"
  ms=$(wait_for 30 k_via cf1 203.0.113.0/24 10.39.1.1) && result ebgp4 OK "CHR's 203.0.113.0/24 in CR1's kernel via 10.39.1.1" \
    || result ebgp4 FAIL "203.0.113.0/24 on CR1: '$(k_route cf1 203.0.113.0/24)'"
  r=$(cr_rx 1 chr4 203.0.113.0/24)
  [[ $r == *'"as_path"'* ]] && result ebgp4 OK "route.list: $(jq -c '{prefix, as_path, origin, next_hop}' <<< "$r")" \
    || result ebgp4 FAIL "route.list for 203.0.113.0/24: $r"
  ms=$(wait_for 30 ros_via 100.64.39.0/24 10.39.1.2) && result ebgp4 OK "output_network: 100.64.39.0/24 active on CHR via the CoreRouter" \
    || { result ebgp4 FAIL "100.64.39.0/24 on CHR: $(ros_route 100.64.39.0/24)"; dump; }
  result ebgp4 INFO "CHR route: $(ros_battr 100.64.39.0/24)"
  result ebgp4 INFO "CHR /routing/route keys: $(ros 'routing/route?dst-address=100.64.39.0/24' | jq -c '[.[]? | keys] | add // [] | unique')"
  ip netns exec cf1 ping -c 3 -i 0.2 -W 1 -I 100.64.39.1 10.39.2.1 >/dev/null 2>&1 \
    && result ebgp4 OK "CR1's clients' gateway reaches CHR's ether2 address through the BGP-learnt routes" \
    || result ebgp4 INFO "ping 100.64.39.1 → 10.39.2.1 failed (CHR does not announce 10.39.2.0/30)"
  # The other way: what the CoreRouter's own filter list says it sends.
  result ebgp4 INFO "CR advertised: $(cr1 routing.bgp.route.list '{"connection":"chr4","direction":"advertised","refresh":true}' | jq -c '[.rows[]?.prefix]')"
  ebgp4_down
  ms=$(wait_for 30 bash -c "! ip -n cf1 route show 203.0.113.0/24 | grep -q via") && result ebgp4 OK "removed connection: the route left the kernel in ${ms} ms" \
    || result ebgp4 FAIL "203.0.113.0/24 still in CR1's kernel after the connection was removed"
}

case_ebgp6() {
  crc 1 '{"name":"chr6","remote_address":"fd39:1::1","remote_as":65001,"afi":"ipv6","input_filter":"all","output_filter":"all","output_network":"bgp-out"}'
  rosx '/routing bgp connection add name=cr6 instance=default remote.address=fd39:1::2 remote.as=65000 local.role=ebgp afi=ipv6 output.network=bgp-out6' >/dev/null
  local ms
  ms=$(wait_for 60 cr_up 1 chr6) || { result ebgp6 FAIL "no Established: CR $(cr_state 1 chr6), CHR $(ros_sess cr6 | jq -c .)"; dump; crd 1 chr6; rosd cr6; return; }
  result ebgp6 OK "eBGP IPv6 (transport and NLRI) Established in ${ms} ms"
  ms=$(wait_for 30 k_has6 cf1 fd39:203::/48) && result ebgp6 OK "fd39:203::/48 in CR1's kernel $(k_route6 cf1 fd39:203::/48)" \
    || result ebgp6 FAIL "fd39:203::/48 on CR1: '$(k_route6 cf1 fd39:203::/48)'"
  ms=$(wait_for 30 ros_via6_cr1 fd39:64::/64) && result ebgp6 OK "fd39:64::/64 active on CHR via CR1 ($(ros_gw6 fd39:64::/64))" \
    || result ebgp6 FAIL "fd39:64::/64 on CHR: $(ros_route6 fd39:64::/64)"
  result ebgp6 INFO "CHR route: $(ros_battr fd39:64::/64)"
  crd 1 chr6; rosd cr6
}

# One IPv4 session carrying IPv4 and IPv6 (RFC 4760). The IPv6 next hop
# over an IPv4 session is where implementations differ (RFC 2545 §3 wants a
# global IPv6 address; an IPv4-mapped one is not routable).
case_mpbgp() {
  ebgp4_up '{"afi":"ip,ipv6"}' 'afi=ip,ipv6'
  local ms
  ms=$(wait_for 60 cr_up 1 chr4) || { result mpbgp FAIL "no Established: $(cr_state 1 chr4)"; dump; ebgp4_down; return; }
  result mpbgp OK "one IPv4 session, afi ip+ipv6: Established in ${ms} ms, families $(cr_sess 1 chr4 | jq -c .afi)"
  # output.network names one list; RouterOS takes the IPv4 and the IPv6
  # address-list of that name.
  rosx '/ipv6 firewall address-list add list=bgp-out address=fd39:203::/48' >/dev/null || true
  ms=$(wait_for 30 k_has6 cf1 fd39:203::/48) && result mpbgp OK "IPv6 over the IPv4 session: fd39:203::/48 on CR1 $(k_route6 cf1 fd39:203::/48)" \
    || result mpbgp FAIL "IPv6 over IPv4 on CR1: kernel '$(k_route6 cf1 fd39:203::/48)', bgpd: $(vt cf1 'show bgp ipv6 unicast fd39:203::/48 json' | jq -c '.paths[0] | {valid, nexthops}' 2>/dev/null)"
  ms=$(wait_for 30 ros_via6 fd39:64::/64 '') || true
  local r6; r6=$(ros "ipv6/route?dst-address=fd39:64::/64" | jq -c '[.[] | {gateway, active, "immediate-gw"}]')
  [[ $r6 == *'"active":"true"'* ]] && result mpbgp OK "IPv6 over the IPv4 session: fd39:64::/64 active on CHR $r6" \
    || result mpbgp FAIL "fd39:64::/64 on CHR over the IPv4 session: $r6"
  result mpbgp INFO "CR1 bgpd next hop it sends: $(vt cf1 'show bgp ipv6 unicast neighbors 10.39.1.1 advertised-routes json' | jq -c '[.advertisedRoutes[]? | .nextHop] | unique' 2>/dev/null)"
  result mpbgp INFO "zebra on CR1: $(vt cf1 'show ipv6 route fd39:203::/48 json' | jq -c '[.[]?[]? | {protocol, selected, installed, nh: [.nexthops[]? | {ip, afi, active, unreachable}]}]' 2>/dev/null)"
  result mpbgp INFO "next hop CR1 got: $(vt cf1 'show bgp ipv6 unicast fd39:203::/48 json' | jq -c '[.paths[]?.nexthops[]? | {ip, afi, scope, accessible}]' 2>/dev/null)"
  ebgp4_down
}

case_multihop() {
  cr1 ip.route.add '{"dst_address":"10.255.39.1/32","gateway":"10.39.1.1"}' >/dev/null
  rosx '/ip route add dst-address=10.255.39.2/32 gateway=10.39.1.2' >/dev/null
  crc 1 '{"name":"chrlo","remote_address":"10.255.39.1","remote_as":65001,"multihop":true,"update_source":"10.255.39.2","input_filter":"all","output_filter":"all","output_network":"bgp-out"}'
  rosx '/routing bgp connection add name=crlo instance=default remote.address=10.255.39.2 remote.as=65000 local.role=ebgp local.address=10.255.39.1 multihop=yes output.network=bgp-out' >/dev/null
  local ms
  ms=$(wait_for 60 cr_up 1 chrlo) && result multihop OK "eBGP between loopbacks (multihop, update_source): Established in ${ms} ms" \
    || { result multihop FAIL "no Established: CR $(cr_state 1 chrlo) $(cr_sess 1 chrlo | jq -c '{reason, last_error}'), CHR $(ros_sess crlo | jq -c .)"; dump; }
  ms=$(wait_for 30 k_via cf1 203.0.113.0/24 10.39.1.1) && result multihop OK "203.0.113.0/24 resolved through the static route to the loopback (via 10.39.1.1)" \
    || result multihop FAIL "203.0.113.0/24 on CR1: '$(k_route cf1 203.0.113.0/24)'"
  result multihop INFO "TTL on the wire from CR1: $(timeout 4 ip netns exec cf1 tcpdump -c 1 -nv -i ether1 'tcp port 179 and src host 10.255.39.2' 2>/dev/null | grep -o 'ttl [0-9]*' | head -1)"
  # Without multihop on our side: eBGP with TTL 1 to a loopback never gets there.
  cr1 routing.bgp.connection.set '{"id":"chrlo","multihop":false}' >/dev/null
  cr1 routing.bgp.session.clear '{"connection":"chrlo"}' >/dev/null 2>&1 || true
  sleep 12
  result multihop INFO "multihop=false on the CoreRouter (TTL 1 to a loopback): CR $(cr_state 1 chrlo), CHR established=$(ros_sess crlo | jq -r '.established // false')"
  result multihop INFO "the connection check says: $(cr1 routing.bgp.connection.check '{"id":"chrlo","multihop":false}' | jq -c '[.checks[] | select(.level != "ok") | .message][0:2]')"
  crd 1 chrlo; rosd crlo
  cr1 ip.route.list '{"origin":"static"}' | jq -r '.[] | select(.dst_address == "10.255.39.1/32") | .id' | while read -r id; do cr1 ip.route.remove "{\"id\":\"$id\"}" >/dev/null; done
  rosx '/ip route remove [find dst-address=10.255.39.2/32]' >/dev/null
}

case_md5() {
  ebgp4_up '{"tcp_md5_key":"g39f-md5-key"}' 'tcp-md5-key=g39f-md5-key'
  local ms
  ms=$(wait_for 60 cr_up 1 chr4) && result md5 OK "TCP MD5 (RFC 2385) with the same key: Established in ${ms} ms" \
    || { result md5 FAIL "same key, no session: CR $(cr_state 1 chr4), CHR $(ros_sess cr4 | jq -c .)"; dump; }
  result md5 INFO "connection.list key_set=$(cr1 routing.bgp.connection.list '{"find":"chr4"}' | jq -c '.[0].key_set'), params $(cr1 routing.bgp.connection.list '{"find":"chr4"}' | jq -c '.[0].params.tcp_md5_key')"
  grep -q g39f-md5-key "$W"/cfg1/* 2>/dev/null && result md5 FAIL "the key is in clear text in the config dir" || result md5 OK "the key is not in clear text in the config dir"
  # A wrong key on CHR: the session must go and stay down.
  rosx '/routing bgp connection set [find name=cr4] tcp-md5-key=wrong-key' >/dev/null
  sleep 15
  local st; st=$(cr_state 1 chr4)
  cr_up 1 chr4 && result md5 FAIL "wrong key: still Established" || result md5 OK "wrong key: the session drops and stays down (CR state $st)"
  result md5 INFO "CR reason: $(cr_sess 1 chr4 | jq -c '{reason, last_error}'); kernel: $(dmesg | grep -c 'MD5 Hash' || true) 'MD5 Hash' lines in dmesg"
  rosx '/routing bgp connection set [find name=cr4] tcp-md5-key=g39f-md5-key' >/dev/null
  ms=$(wait_for 90 cr_up 1 chr4) && result md5 OK "key fixed: back up in ${ms} ms" || result md5 FAIL "key fixed: no session"
  # Changing the key on the CoreRouter types it into bgpd (no restart of the others).
  cr1 routing.bgp.connection.set '{"id":"chr4","tcp_md5_key":"g39f-new-key"}' >/dev/null
  rosx '/routing bgp connection set [find name=cr4] tcp-md5-key=g39f-new-key' >/dev/null
  ms=$(wait_for 120 cr_up 1 chr4) && result md5 OK "new key on both: up in ${ms} ms" || result md5 FAIL "new key: no session"
  ebgp4_down
}

case_communities() {
  # CHR tags what it sends: a normal, a large and an extended community.
  rosx '/routing filter rule add chain=cr-out rule="if (dst == 203.0.113.0/24) { set bgp-communities 65001:100,no-export; set bgp-large-communities 65001:1:2; set bgp-ext-communities rt:65001:7; accept } accept"' >/dev/null
  cr1 routing.filter.rule.add '{"chain":"chr-out","rule":"if (dst == 100.64.39.0/24) { append bgp-communities 65000:200; append bgp-large-communities 65000:3:4; accept } reject"}' >/dev/null
  ebgp4_up '{"output_filter":"chr-out"}' 'output.filter-chain=cr-out'
  local ms r
  ms=$(wait_for 60 cr_up 1 chr4) || { result communities FAIL "no session"; ebgp4_down; return; }
  wait_for 30 k_has cf1 203.0.113.0/24 >/dev/null || true
  r=$(bgp_path cf1 203.0.113.0/24)
  [[ $(jq -r .communities <<< "$r") == *65001:100* && $(jq -r .communities <<< "$r") == *no-export* ]] && result communities OK "RFC 1997 from CHR: $(jq -c .communities <<< "$r")" \
    || result communities FAIL "communities on CR1: $r"
  [[ $(jq -r .large <<< "$r") == *65001:1:2* ]] && result communities OK "RFC 8092 large from CHR: $(jq -c .large <<< "$r")" \
    || result communities FAIL "large communities on CR1: $r"
  local ext; ext=$(jq -r .ext <<< "$r")
  [[ $ext == *65001:7* ]] && result communities OK "RFC 4360 extended from CHR reaches bgpd: $ext" || result communities FAIL "extended community in bgpd: $ext"
  result communities INFO "extended communities: route.list has no column for them and routing.filter has no bgp-ext-communities (G3.9fc)"
  # no-export: CR1 must not send it on to an eBGP neighbor (RFC 1997).
  ms=$(wait_for 30 ros_via 100.64.39.0/24 10.39.1.2) || true
  local rr; rr=$(ros_battr 100.64.39.0/24)
  [[ $rr == *65000:200* ]] && result communities OK "CR1's append reaches CHR: $(jq -c '{"bgp.communities", "bgp.large-communities"}' <<< "$rr")" \
    || result communities FAIL "CHR route from CR1: $rr"
  [[ $rr == *65000:3:4* ]] || result communities FAIL "large community from CR1 not on CHR: $rr"
  # A list match on our side: reject what carries 65001:100.
  cr1 routing.filter.community-list.add '{"name":"from-chr","communities":"65001:100"}' >/dev/null
  cr1 routing.filter.rule.add '{"chain":"chr-in","rule":"if (bgp-communities any-list from-chr) { reject } accept"}' >/dev/null
  cr1 routing.bgp.connection.set '{"id":"chr4","input_filter":"chr-in"}' >/dev/null
  ms=$(wait_for 30 bash -c "! ip -n cf1 route show 203.0.113.0/24 | grep -q via") && result communities OK "input chain matching a community list drops 203.0.113.0/24 in ${ms} ms (198.51.100.0/24 stays: $(k_route cf1 198.51.100.0/24))" \
    || result communities FAIL "203.0.113.0/24 still on CR1 after the community match"
  ebgp4_down
  rosx '/routing filter rule remove [find chain=cr-out]' >/dev/null
}

case_filters() {
  # In on CR1: drop one, set local-pref on the rest. Out on CR1: MED and
  # prepend on the clients' subnet, nothing else.
  cr1 routing.filter.rule.add '{"chain":"f-in","rule":"if (dst == 198.51.100.0/24) { reject } set bgp-local-pref 150; accept"}' >/dev/null
  cr1 routing.filter.rule.add '{"chain":"f-out","rule":"if (dst in 100.64.39.0/24) { set bgp-med 77; set bgp-path-prepend 2; accept } reject"}' >/dev/null
  cr1 ip.firewall.address-list.add '{"list":"bgp-out","address":"10.255.39.2/32"}' >/dev/null
  # On CHR: prepend 3 on what it sends, local-pref 222 on what it gets.
  rosx '/routing filter rule add chain=f-out rule="set bgp-path-prepend 3; accept"
/routing filter rule add chain=f-in rule="if (dst == 100.64.39.0/24) { set bgp-local-pref 222; accept } reject"' >/dev/null
  ebgp4_up '{"input_filter":"f-in","output_filter":"f-out"}' 'output.filter-chain=f-out input.filter=f-in'
  local ms r
  ms=$(wait_for 60 cr_up 1 chr4) || { result filters FAIL "no session"; ebgp4_down; return; }
  wait_for 30 k_has cf1 203.0.113.0/24 >/dev/null || true
  r=$(bgp_path cf1 203.0.113.0/24)
  [ "$(jq -r .local_pref <<< "$r")" = 150 ] && result filters OK "in: local-pref 150 set by our chain" || result filters FAIL "in: local-pref $(jq -c '{local_pref}' <<< "$r")"
  # How many times RouterOS puts its AS for "set bgp-path-prepend 3" on eBGP:
  # 3 (the count includes the one eBGP adds) or 4 (3 more).
  local n; n=$(jq -r '.as_path // ""' <<< "$r" | tr ' ' '\n' | grep -c '^65001$')
  [ "$n" -ge 3 ] && result filters OK "CHR's out prepend 3: 65001 appears $n times (as_path $(jq -c .as_path <<< "$r"))" \
    || result filters FAIL "CHR prepend: as_path $(jq -c .as_path <<< "$r")"
  k_has cf1 198.51.100.0/24 && result filters FAIL "in: 198.51.100.0/24 should be rejected" || result filters OK "in: 198.51.100.0/24 rejected"
  local f; f=$(cr1 routing.bgp.route.list '{"connection":"chr4","prefix":"198.51.100.0/24","match":"exact"}' | jq -c '[.rows[]? | {prefix, filtered}]')
  result filters INFO "route.list shows the refused one: $f"
  ms=$(wait_for 30 ros_via 100.64.39.0/24 10.39.1.2) || true
  r=$(ros_battr 100.64.39.0/24)
  result filters INFO "CHR got: $r"
  [ "$(jq -r '."bgp.med" // ""' <<< "$r")" = 77 ] && result filters OK "out: MED 77 on CHR" || result filters FAIL "out: MED on CHR: $(jq -c '."bgp.med"' <<< "$r")"
  n=$(jq -r '."bgp.as-path" // ""' <<< "$r" | tr ', ' '\n\n' | grep -c '^65000$')
  [ "$n" -ge 2 ] && result filters OK "out: our prepend 2: 65000 appears $n times on CHR (as-path $(jq -r '."bgp.as-path"' <<< "$r"))" \
    || result filters FAIL "out: as-path on CHR: $(jq -r '."bgp.as-path"' <<< "$r")"
  [ "$(jq -r '."bgp.local-pref" // ""' <<< "$r")" = 222 ] && result filters OK "CHR's in chain set local-pref 222" || result filters INFO "CHR local-pref: $(jq -c '."bgp.local-pref"' <<< "$r")"
  [ "$(ros_gw 10.255.39.2/32)" = - ] && result filters OK "out: our loopback (in the list, not in the chain) stays out of CHR" \
    || result filters FAIL "out: 10.255.39.2/32 leaked: $(ros_route 10.255.39.2/32)"
  # A new rule applies without a reset (soft reconfiguration).
  local up0; up0=$(cr_sess 1 chr4 | jq -r '.uptime_secs // 0')
  local id; id=$(cr1 routing.filter.rule.list '{"chain":"f-in"}' | jq -r '.[0].id')
  local t0; t0=$(now_ms)
  cr1 routing.filter.rule.set "{\"id\":\"$id\",\"rule\":\"set bgp-local-pref 160; accept\"}" >/dev/null
  ms=$(wait_for 30 k_has cf1 198.51.100.0/24) && result filters OK "changed in chain: 198.51.100.0/24 accepted $(( $(now_ms) - t0 )) ms after the commit, no reset (uptime ${up0} → $(cr_sess 1 chr4 | jq -r .uptime_secs) s)" \
    || result filters FAIL "changed in chain: 198.51.100.0/24 not on CR1"
  ebgp4_down
  rosx '/routing filter rule remove [find chain=f-out]
/routing filter rule remove [find chain=f-in]' >/dev/null
}

# iBGP between loopbacks over static routes (the IGP stand-in).
loop_routes() {
  cr1 ip.route.add '{"dst_address":"10.255.39.1/32","gateway":"10.39.1.1"}' >/dev/null
  rosx '/ip route add dst-address=10.255.39.2/32 gateway=10.39.1.2' >/dev/null
}
loop_routes_off() {
  cr1 ip.route.list '{"origin":"static"}' | jq -r '.[] | select(.dst_address == "10.255.39.1/32") | .id' | while read -r id; do cr1 ip.route.remove "{\"id\":\"$id\"}" >/dev/null; done
  rosx '/ip route remove [find dst-address=10.255.39.2/32]' >/dev/null || true
}
case_ibgp() {
  loop_routes
  crc 1 '{"name":"chri","remote_address":"10.255.39.1","remote_as":65000,"update_source":"10.255.39.2","afi":"ip,ipv6","output_network":"bgp-out"}'
  rosx '/routing bgp connection add name=cri instance=default as=65000 remote.address=10.255.39.2 remote.as=65000 local.role=ibgp local.address=10.255.39.1 afi=ip output.network=bgp-out' >/dev/null
  local ms
  ms=$(wait_for 60 cr_up 1 chri) && result ibgp OK "iBGP between loopbacks (CHR with as=65000 on the connection): Established in ${ms} ms" \
    || { result ibgp FAIL "no Established: CR $(cr_state 1 chri), CHR $(ros_sess cri | jq -c .)"; dump; }
  result ibgp INFO "kind $(cr1 routing.bgp.connection.list '{"find":"chri"}' | jq -r '.[0].kind'); no chain needed on iBGP (RFC 8212 is eBGP only)"
  ms=$(wait_for 30 k_via cf1 203.0.113.0/24 10.255.39.1) && result ibgp OK "203.0.113.0/24 via the CHR loopback (next hop kept on iBGP)" \
    || result ibgp FAIL "203.0.113.0/24 on CR1: '$(k_route cf1 203.0.113.0/24)'"
  local r; r=$(bgp_path cf1 203.0.113.0/24)
  [ "$(jq -r .local_pref <<< "$r")" = 100 ] && result ibgp OK "LOCAL_PREF 100 on iBGP (RFC 4271 §5.1.5)" || result ibgp INFO "local_pref $(jq -c .local_pref <<< "$r")"
  ms=$(wait_for 30 ros_via 100.64.39.0/24 10.255.39.2) && result ibgp OK "100.64.39.0/24 on CHR via our loopback" || result ibgp FAIL "100.64.39.0/24 on CHR: $(ros_route 100.64.39.0/24)"
  crd 1 chri; rosd cri
  loop_routes_off
}

# eBGP route from CHR, sent on over iBGP to CR2 (no IGP between them):
# without next-hop-self CR2 cannot resolve 10.39.1.1.
case_nexthop-self() {
  ebgp4_up
  crc 1 '{"name":"cr2","remote_address":"10.39.5.2","remote_as":65000,"output_network":"bgp-out"}'
  crc 2 '{"name":"cr1","remote_address":"10.39.5.1","remote_as":65000,"output_network":"bgp-out"}'
  local ms
  ms=$(wait_for 60 cr_up 1 cr2) && result nexthop-self OK "iBGP CR1—CR2 Established in ${ms} ms" || { result nexthop-self FAIL "CR1—CR2: $(cr_state 1 cr2)"; dump; }
  wait_for 30 cr_up 1 chr4 >/dev/null || true
  sleep 3
  local r; r=$(vt cf2 'show bgp ipv4 unicast 203.0.113.0/24 json' | jq -c '[.paths[]? | {valid, nh: .nexthops[0].ip, acc: .nexthops[0].accessible}]' 2>/dev/null)
  result nexthop-self INFO "default (RFC 4271 §5.1.3: next hop kept on iBGP): CR2 has $r, kernel '$(k_route cf2 203.0.113.0/24)'"
  k_has cf2 203.0.113.0/24 && result nexthop-self INFO "CR2 installed it without next-hop-self" || result nexthop-self OK "without next-hop-self CR2 does not install a route via 10.39.1.1 (unreachable)"
  cr1 routing.bgp.connection.set '{"id":"cr2","nexthop_choice":"force-self"}' >/dev/null
  ms=$(wait_for 30 k_via cf2 203.0.113.0/24 10.39.5.1) && result nexthop-self OK "nexthop_choice=force-self: CR2 installs it via 10.39.5.1 ${ms} ms after the commit" \
    || result nexthop-self FAIL "force-self: CR2 '$(k_route cf2 203.0.113.0/24)'"
  ip netns exec cf2 ping -c 2 -i 0.2 -W 1 -I 100.64.40.1 10.39.1.1 >/dev/null 2>&1 && result nexthop-self INFO "CR2 → CHR ether1 ping (needs CHR's route back to 100.64.40.0/24)" || true
  # CR2's network reaches CHR through CR1 (eBGP rewrites the next hop anyway).
  ms=$(wait_for 30 ros_via 100.64.40.0/24 10.39.1.2) && result nexthop-self OK "CR2's 100.64.40.0/24 reaches CHR through CR1 (iBGP → eBGP)" \
    || result nexthop-self FAIL "100.64.40.0/24 on CHR: $(ros_route 100.64.40.0/24)"
  crd 1 cr2; crd 2 cr1; ebgp4_down
}

# CoreRouter as route reflector (RFC 4456): clients CHR (iBGP) and R4 (FRR).
case_rr() {
  loop_routes
  crc 1 '{"name":"chri","remote_address":"10.255.39.1","remote_as":65000,"update_source":"10.255.39.2","local_role":"ibgp-rr"}'
  crc 1 '{"name":"r4","remote_address":"10.39.4.2","remote_as":65000,"local_role":"ibgp-rr"}'
  rosx '/routing bgp connection add name=cri instance=default as=65000 remote.address=10.255.39.2 remote.as=65000 local.role=ibgp local.address=10.255.39.1 output.network=bgp-out' >/dev/null
  vt cfr4 'configure terminal
router bgp 65000
 no neighbor 10.39.4.1 shutdown' >/dev/null
  local ms
  ms=$(wait_for 60 cr_up 1 chri) || result rr FAIL "CHR client: $(cr_state 1 chri)"
  ms=$(wait_for 60 cr_up 1 r4) || result rr FAIL "R4 client: $(cr_state 1 r4)"
  local j
  ms=$(wait_for 30 bash -c "vtysh -N cfr4 -c 'show bgp ipv4 unicast 203.0.113.0/24 json' | jq -e '.paths[0]' >/dev/null") || true
  j=$(vt cfr4 'show bgp ipv4 unicast 203.0.113.0/24 json' | jq -c '.paths[0] | {originatorId: .originatorId, clusterList: .clusterList.list, nh: .nexthops[0].ip}' 2>/dev/null)
  [[ $j == *'"originatorId":"10.255.39.1"'* && $j == *10.255.39.2* ]] \
    && result rr OK "CHR → CR1 (RR) → R4: 203.0.113.0/24 with ORIGINATOR_ID and CLUSTER_LIST $j" \
    || result rr FAIL "R4 got $j"
  ms=$(wait_for 30 ros_via 192.0.2.0/24 10.39.4.2) || true
  local r; r=$(ros_route 192.0.2.0/24)
  [[ $r != "{}" ]] && result rr OK "R4 → CR1 (RR) → CHR: 192.0.2.0/24 $(jq -c 'with_entries(select(.key | test("originator|cluster|gateway")))' <<< "$r")" \
    || result rr FAIL "192.0.2.0/24 on CHR: $(ros "ip/route?dst-address=192.0.2.0/24" | jq -c .)"
  result rr INFO "CHR session caps: $(ros_sess cri | jq -c '{"remote.cap", "local.cap"}')"
  # Without the role, a plain iBGP neighbor does not get the other's routes (RFC 4271 §9.2).
  cr1 routing.bgp.connection.set '{"id":"r4","local_role":"ibgp"}' >/dev/null
  ms=$(wait_for 30 bash -c "! vtysh -N cfr4 -c 'show bgp ipv4 unicast 203.0.113.0/24 json' | jq -e '.paths[0]' >/dev/null") \
    && result rr OK "local_role ibgp (no RR): R4 loses CHR's route in ${ms} ms (iBGP split horizon)" || result rr FAIL "R4 still has CHR's route without reflection"
  crd 1 chri; crd 1 r4; rosd cri
  vt cfr4 'configure terminal
router bgp 65000
 neighbor 10.39.4.1 shutdown' >/dev/null
  loop_routes_off
}

# CHR as route reflector: clients CR1 (direct) and R4 (multihop through CR1).
case_rr-chr() {
  rosx '/ip route add dst-address=10.39.4.0/30 gateway=10.39.1.2
/routing bgp connection add name=crc instance=default as=65000 remote.address=10.39.1.2 remote.as=65000 local.role=ibgp-rr
/routing bgp connection add name=r4c instance=default as=65000 remote.address=10.39.4.2 remote.as=65000 local.role=ibgp-rr multihop=yes' >/dev/null
  crc 1 '{"name":"chrrr","remote_address":"10.39.1.1","remote_as":65000,"output_network":"bgp-out"}'
  vt cfr4 'configure terminal
router bgp 65000
 neighbor 10.39.1.1 remote-as 65000
 neighbor 10.39.1.1 update-source 10.39.4.2
 address-family ipv4 unicast
  neighbor 10.39.1.1 activate' >/dev/null
  local ms j
  ms=$(wait_for 60 cr_up 1 chrrr) && result rr-chr OK "CR1 as client of CHR (local.role=ibgp-rr there): Established in ${ms} ms" || result rr-chr FAIL "CR1 client: $(cr_state 1 chrrr)"
  ms=$(wait_for 60 bash -c "vtysh -N cfr4 -c 'show bgp ipv4 unicast 100.64.39.0/24 json' | jq -e '.paths[0]' >/dev/null") || true
  j=$(vt cfr4 'show bgp ipv4 unicast 100.64.39.0/24 json' | jq -c '.paths[0] | {originatorId, clusterList: .clusterList.list, nh: .nexthops[0].ip}' 2>/dev/null)
  [[ $j == *'"originatorId":"10.255.39.2"'* && $j == *10.255.39.1* ]] \
    && result rr-chr OK "CR1 → CHR (RR) → R4: 100.64.39.0/24 $j" || result rr-chr FAIL "R4 got $j"
  ms=$(wait_for 30 bash -c "vtysh -N cf1 -c 'show bgp ipv4 unicast 192.0.2.0/24 json' | jq -e '.paths[0]' >/dev/null") || true
  j=$(vt cf1 'show bgp ipv4 unicast 192.0.2.0/24 json' | jq -c '.paths[0] | {originatorId, clusterList: .clusterList.list, nh: .nexthops[0].ip}' 2>/dev/null)
  [[ $j == *'"originatorId":"10.255.39.4"'* ]] && result rr-chr OK "R4 → CHR (RR) → CR1: 192.0.2.0/24 $j" || result rr-chr FAIL "CR1 got $j"
  local why; why=$(cr1 routing.bgp.route.explain '{"prefix":"192.0.2.0/24"}' 2>/dev/null || true)
  sleep 1; why=$(cr1 routing.bgp.route.explain '{"prefix":"192.0.2.0/24"}' 2>/dev/null || true)
  result rr-chr INFO "route.explain: $(jq -c '{state, paths: [.paths[]? | {originator_id, cluster_list_len, best}]}' <<< "$why")"
  crd 1 chrrr
  rosx '/routing bgp connection remove [find name=crc]
/routing bgp connection remove [find name=r4c]
/ip route remove [find dst-address=10.39.4.0/30]' >/dev/null
  vt cfr4 'configure terminal
router bgp 65000
 no neighbor 10.39.1.1' >/dev/null
}

case_maxprefix() {
  # CHR sends 6 prefixes; we take at most 3.
  local i
  for i in 1 2 3 4; do rosx "/ip route add dst-address=198.18.$i.0/24 blackhole
/ip firewall address-list add list=bgp-out address=198.18.$i.0/24" >/dev/null; done
  ebgp4_up '{"max_prefix_ipv4":3,"max_prefix_action":"shutdown"}'
  local ms
  ms=$(wait_for 60 bash -c "[ \"\$(ip netns exec cf1 $bin/corerouter-cli --connect 127.0.0.1:7991 run routing.bgp.session.list | jq -r '[.[] | select(.connection == \"chr4\")][0].state')\" != Established ]") || true
  sleep 3
  local s; s=$(cr_sess 1 chr4)
  ! cr_up 1 chr4 && result maxprefix OK "6 prefixes over max_prefix_ipv4=3 (shutdown): session down, state $(jq -r .state <<< "$s"), reason $(jq -c '{reason, last_error}' <<< "$s")" \
    || result maxprefix FAIL "6 > 3 and still Established: $s"
  result maxprefix INFO "CHR side: $(ros_sess cr4 | jq -c '{established, "last-stopped", "stopped"}') ; CHR log: $(ros log | jq -r '[.[] | select(.topics | test("bgp")) | .message][-2:] | join(" | ")' 2>/dev/null | cut -c1-240)"
  result maxprefix INFO "history: $(cr1 routing.bgp.session.history '{"connection":"chr4"}' | jq -c '[.[0:2][] | {event, state, reason}]')"
  # warning: the session stays and everything is kept.
  cr1 routing.bgp.connection.set '{"id":"chr4","max_prefix_action":"warning"}' >/dev/null
  cr1 routing.bgp.session.clear '{"connection":"chr4"}' >/dev/null 2>&1 || true
  ms=$(wait_for 60 cr_up 1 chr4) && result maxprefix OK "max_prefix_action=warning: session up in ${ms} ms with $(cr_sess 1 chr4 | jq -r .prefix_count) prefixes" \
    || result maxprefix FAIL "warning: no session ($(cr_state 1 chr4))"
  # The other way: RouterOS input.limit-process-routes-ipv4=10 with 12 from us.
  for i in $(seq 10 21); do cr1 ip.firewall.address-list.add "{\"list\":\"many\",\"address\":\"10.100.$i.0/24\"}" >/dev/null; cr1 ip.route.add "{\"dst_address\":\"10.100.$i.0/24\",\"gateway\":\"10.39.4.2\"}" >/dev/null; done
  cr1 routing.bgp.connection.set '{"id":"chr4","output_network":"many"}' >/dev/null
  rosx '/routing bgp connection set [find name=cr4] input.limit-process-routes-ipv4=10' >/dev/null
  sleep 10
  local n; n=$(ros 'ip/route?bgp=true' | jq '[.[] | select((.["dst-address"] // "") | startswith("10.100."))] | length')
  result maxprefix INFO "RouterOS input.limit-process-routes-ipv4=10 with 12 sent: CHR keeps $n, session established=$(ros_sess cr4 | jq -r '.established // false') (it stops processing; no Cease, unlike RFC 4486 max-prefix)"
  ebgp4_down
  for i in 1 2 3 4; do rosx "/ip route remove [find dst-address=198.18.$i.0/24]
/ip firewall address-list remove [find address=198.18.$i.0/24]" >/dev/null; done
}

# Restarting the CoreRouter daemon must not touch the sessions FRR holds;
# restarting bgpd itself is a real BGP restart (graceful restart, RFC 4724).
case_restart() {
  ebgp4_up
  local ms
  ms=$(wait_for 60 cr_up 1 chr4) || { result restart FAIL "no session"; ebgp4_down; return; }
  wait_for 30 ros_via 100.64.39.0/24 10.39.1.2 >/dev/null || true
  local up0; up0=$(ros_sess cr4 | jq -r '.uptime // ""')
  # Probe from CHR's side: ping the CoreRouter's clients' gateway every 100 ms.
  kill "$(cat "$W/daemon1.pid")"; sleep 1
  local t0; t0=$(now_ms)
  start_daemon 1
  local tr=$(( $(now_ms) - t0 ))
  sleep 5
  local up1; up1=$(ros_sess cr4 | jq -r '.uptime // ""')
  ros_up cr4 && ros_via 100.64.39.0/24 10.39.1.2 \
    && result restart OK "corerouter-daemon restarted (up again in ${tr} ms): CHR session untouched (uptime $up0 → $up1), route kept" \
    || result restart FAIL "daemon restart dropped the session or the route: CHR $(ros_sess cr4 | jq -c '{established, uptime}') route $(ros_gw 100.64.39.0/24)"
  grep -q "differently" "$W/daemon1.log" && result restart INFO "daemon log: $(grep -o 'FRR prints [^;]*' "$W/daemon1.log" | sort | uniq -c | head -3 | tr '\n' ' ')" || true
  # bgpd restart: FRR offers graceful restart as helper only by default.
  result restart INFO "caps: CHR $(ros_sess cr4 | jq -r '."remote.cap" // "-"') (what CR1 sent) / $(ros_sess cr4 | jq -r '."local.cap" // "-"')"
  result restart INFO "CR1 bgpd GR: $(vt cf1 'show bgp neighbors 10.39.1.1 graceful-restart json' | jq -c '."10.39.1.1" | {localGrMode, remoteGrMode}' 2>/dev/null)"
  local t1 lost
  t1=$(now_ms)
  pkill -f -- "bgpd -N cf1( |$)"
  # How long CHR keeps the route and how long until it is back.
  lost=$(wait_for 30 bash -c "[ \"\$(curl -sf -m 5 -u admin:$PW 'http://$ROS/rest/ip/route?dst-address=100.64.39.0/24' | jq '[.[] | select(.active == \"true\")] | length')\" = 0 ]") || true
  result restart INFO "bgpd killed: CHR drops 100.64.39.0/24 after ${lost} ms (no graceful restart: the session is gone)"
  ip netns exec cf1 /usr/lib/frr/bgpd -N cf1 -d -f /etc/frr/cf1/bgpd.conf
  ms=$(wait_for 120 ros_via 100.64.39.0/24 10.39.1.2) && result restart OK "bgpd started again: the CoreRouter types its config back and CHR has the route $(( $(now_ms) - t1 )) ms after the kill" \
    || { result restart FAIL "bgpd restarted empty: the CoreRouter did not type the BGP config back ($(vt cf1 'show running-config' | grep -c neighbor) neighbor lines)"; dump; }
  ebgp4_down
}

# BFD on the session (RFC 5882): CHR's use-bfd and our bfd profile.
case_bfd() {
  cr1 routing.bfd.profile.add '{"name":"g39f","min_tx":300,"min_rx":300,"multiplier":3}' >/dev/null
  rosx '/routing bfd configuration add interfaces=ether1 min-rx=300ms min-tx=300ms multiplier=3' >/dev/null
  ebgp4_up '{"bfd":"g39f"}' 'use-bfd=yes'
  local ms
  ms=$(wait_for 60 cr_up 1 chr4) || { result bfd FAIL "no session"; ebgp4_down; return; }
  ms=$(wait_for 30 bash -c "ip netns exec cf1 $bin/corerouter-cli --connect 127.0.0.1:7991 run routing.bfd.session.list | jq -e '.sessions[] | select(.peer == \"10.39.1.1\" and .state == \"up\")' >/dev/null") \
    && result bfd OK "BFD up with CHR for the BGP session: $(cr1 routing.bfd.session.list | jq -c '[.sessions[] | select(.peer == "10.39.1.1")][0] | {state, users, tx_interval_us, multiplier}')" \
    || result bfd FAIL "BFD: $(cr1 routing.bfd.session.list | jq -c '.sessions')"
  result bfd INFO "CHR: $(ros routing/bfd/session | jq -c '[.[] | {"remote-address", state, "tx-interval", multiplier}]' 2>/dev/null)"
  result bfd INFO "bgpd: $(vt cf1 'show bgp neighbors 10.39.1.1 json' | jq -c '."10.39.1.1".peerBfdInfo | {status, type}' 2>/dev/null)"
  ebgp4_down
  rosx '/routing bfd configuration remove [find interfaces=ether1]' >/dev/null || true
}

# Convergence (measured): two eBGP sessions CR1—CHR, on link 1 and link 3;
# CHR prefers link 1 (lower peer address). Cut link 1 three ways.
case_convergence() {
  cr1 routing.bfd.profile.add '{"name":"g39f","min_tx":300,"min_rx":300,"multiplier":3}' >/dev/null 2>&1 || true
  rosx '/routing bfd configuration add interfaces=ether1,ether3 min-rx=300ms min-tx=300ms multiplier=3' >/dev/null || true
  local common='"remote_as":65001,"input_filter":"all","output_filter":"all","output_network":"bgp-out","hold_time":9'
  local mode
  for mode in hold bfd linkdown; do
    local bfdj='' bfdr=''
    [ $mode = bfd ] && { bfdj=',"bfd":"g39f"'; bfdr='use-bfd=yes'; }
    crc 1 "{\"name\":\"l1\",\"remote_address\":\"10.39.1.1\",$common$bfdj}"
    crc 1 "{\"name\":\"l3\",\"remote_address\":\"10.39.3.1\",$common$bfdj}"
    rosx "/routing bgp connection add name=l1 instance=default remote.address=10.39.1.2 remote.as=65000 local.role=ebgp output.network=bgp-out hold-time=9s $bfdr
/routing bgp connection add name=l3 instance=default remote.address=10.39.3.2 remote.as=65000 local.role=ebgp output.network=bgp-out hold-time=9s $bfdr" >/dev/null
    wait_for 60 cr_up 1 l1 >/dev/null; wait_for 60 cr_up 1 l3 >/dev/null
    local ms
    ms=$(wait_for 30 ros_via 100.64.39.0/24 10.39.1.2) || true
    wait_for 30 k_via cf1 203.0.113.0/24 10.39.1.1 >/dev/null || true
    [ $mode = bfd ] && sleep 3
    if ! ros_via 100.64.39.0/24 10.39.1.2 || ! k_via cf1 203.0.113.0/24 10.39.1.1; then
      result convergence FAIL "$mode: not on link 1 before the cut: CHR $(ros_gw 100.64.39.0/24), CR1 $(k_route cf1 203.0.113.0/24)"
    else
      local t0 a b
      t0=$(now_ms)
      case $mode in
        linkdown) ip -n cf1 link set ether1 down ;;
        *) ip link set cfv1 down ;;  # silent: both ports stay up
      esac
      a=$(wait_for 30 ros_via 100.64.39.0/24 10.39.3.2) || true
      b=$(( $(now_ms) - t0 ))
      wait_for 30 k_via cf1 203.0.113.0/24 10.39.3.1 >/dev/null || true
      local c=$(( $(now_ms) - t0 ))
      if [ "$a" != -1 ] && k_via cf1 203.0.113.0/24 10.39.3.1; then
        result convergence OK "$mode cut of link 1: CHR on link 3 after ${b} ms, CR1's kernel after ≤ ${c} ms"
      else
        result convergence FAIL "$mode cut: CHR $(ros_gw 100.64.39.0/24), CR1 $(k_route cf1 203.0.113.0/24) after 30 s"
      fi
      case $mode in linkdown) ip -n cf1 link set ether1 up ;; *) ip link set cfv1 up ;; esac
    fi
    crd 1 l1; crd 1 l3; rosd l1; rosd l3
    sleep 2
  done
  rosx '/routing bfd configuration remove [find]' >/dev/null || true
}

# 100 000 prefixes: R3 (FRR) → CHR → CR1 (and on to CR2 over iBGP), with
# the time, the RSS and the CPU of each thread of the daemon, bgpd and zebra.
pid_of() { pgrep -f -- "$1 -N $2( |$)" | head -1; }
cpu_threads() { # cpu_threads <pid>: "tid comm ticks" per thread
  local t
  for t in /proc/"$1"/task/*; do
    [ -r "$t/stat" ] || continue
    awk -v tid="${t##*/}" '{ sub(/^[0-9]+ \(/, ""); split($0, a, ") "); split(a[2], f, " "); gsub(/ /, "_", a[1]); print tid, a[1], f[12] + f[13] }' "$t/stat" 2>/dev/null
  done
}
cpu_report() { # cpu_report <label> <before file> <pid> <ms>
  local hz; hz=$(getconf CLK_TCK)
  cpu_threads "$3" > "$W/cpu.after"
  awk -v hz="$hz" -v ms="$4" 'NR == FNR { b[$1] = $3; next } { d = $3 - b[$1]; if (d > 0) printf "%s %.0f%% (%.1fs); ", $2, 100 * d / hz / (ms / 1000), d / hz }' "$2" "$W/cpu.after" | head -c 600
}
rss() { awk '/VmRSS|VmHWM/ {printf "%s %d MiB ", $1, $2/1024}' "/proc/$1/status"; }
case_scale() {
  local N=${SCALE_N:-100000}
  # R3's 100k: blackhole routes in its kernel, redistributed by its bgpd.
  awk -v n="$N" 'BEGIN { for (i = 0; i < n; i++) printf "route add blackhole %d.%d.%d.0/24\n", 20 + int(i / 65536), int(i / 256) % 256, i % 256 }' > "$W/r3.batch"
  rosx '/routing bgp connection add name=r3 instance=default remote.address=10.39.2.2 remote.as=65003 local.role=ebgp' >/dev/null
  wait_for 60 ros_up r3 >/dev/null || result scale FAIL "CHR—R3 session down"
  local t0 ms
  t0=$(now_ms)
  ip -n cfr3 -batch "$W/r3.batch"
  # zebra can miss part of 100k kernel notifications sent at once (netlink
  # buffer; seen on the host lab): restart R3's FRR on the loaded table.
  pkill -f -- "-N cfr3( |$)" || true
  sleep 1
  ip netns exec cfr3 /usr/lib/frr/mgmtd -N cfr3 -d
  sleep 1
  ip netns exec cfr3 /usr/lib/frr/zebra -N cfr3 -d -f /etc/frr/cfr3/zebra.conf
  sleep 2
  ip netns exec cfr3 /usr/lib/frr/bgpd -N cfr3 -d -f /etc/frr/cfr3/bgpd.conf
  wait_for 120 bash -c "[ \"\$(vtysh -N cfr3 -c 'show ip route summary json' | jq '[.routes[]? | select(.type == \"kernel\") | .rib] | add // 0')\" -ge $N ]" >/dev/null || true
  result scale INFO "R3 holds $(vtysh -N cfr3 -c 'show ip route summary json' | jq '[.routes[]? | select(.type == "kernel") | .rib] | add // 0') kernel routes"
  ms=$(wait_for 300 bash -c "[ \"\$(curl -sf -m 10 -u admin:$PW 'http://$ROS/rest/routing/bgp/session' | jq -r '[.[] | select(.name | startswith(\"r3-\"))][0][\"prefix-count\"] // 0')\" -ge $N ]") || true
  result scale INFO "CHR learnt $N prefixes from R3 in ${ms} ms (CHR: $(ros system/resource | jq -r '"\(.["free-memory"] / 1048576 | floor) MiB free"'))"
  local dpid bpid zpid
  dpid=$(cat "$W/daemon1.pid"); bpid=$(pid_of /usr/lib/frr/bgpd cf1); zpid=$(pid_of /usr/lib/frr/zebra cf1)
  result scale INFO "before: daemon $(rss "$dpid"), bgpd $(rss "$bpid"), zebra $(rss "$zpid")"
  cpu_threads "$dpid" > "$W/cpu.d"; cpu_threads "$bpid" > "$W/cpu.b"; cpu_threads "$zpid" > "$W/cpu.z"
  t0=$(now_ms)
  ebgp4_up '{"max_prefix_ipv4":200000}'
  ms=$(wait_for 300 bash -c "[ \$(ip -n cf1 route show proto bgp | wc -l) -ge $N ]") \
    && result scale OK "$N prefixes from CHR in CR1's kernel ${ms} ms after the config (CHR's 1 Mbit/s licence limits the link)" \
    || result scale FAIL "after 300 s CR1's kernel has $(ip -n cf1 route show proto bgp | wc -l) BGP routes"
  local el=$(( $(now_ms) - t0 ))
  result scale INFO "after: daemon $(rss "$dpid"), bgpd $(rss "$bpid"), zebra $(rss "$zpid")"
  result scale INFO "CPU over ${el} ms — daemon: $(cpu_report d "$W/cpu.d" "$dpid" "$el")"
  result scale INFO "CPU — bgpd: $(cpu_report b "$W/cpu.b" "$bpid" "$el")"
  result scale INFO "CPU — zebra: $(cpu_report z "$W/cpu.z" "$zpid" "$el")"
  # Idle with 100k: does the daemon spend CPU per poll on the table?
  cpu_threads "$dpid" > "$W/cpu.d"; cpu_threads "$bpid" > "$W/cpu.b"
  sleep 30
  result scale INFO "idle 30 s with $N routes — daemon: $(cpu_report d "$W/cpu.d" "$dpid" 30000) bgpd: $(cpu_report b "$W/cpu.b" "$bpid" 30000)"
  local tq
  tq=$(now_ms); cr1 routing.bgp.session.list >/dev/null; result scale INFO "routing.bgp.session.list: $(( $(now_ms) - tq )) ms"
  tq=$(now_ms); local st
  for _ in $(seq 120); do st=$(cr1 routing.bgp.route.list '{"connection":"chr4","limit":10}' | jq -r .state); [ "$st" = loading ] || break; sleep 0.5; done
  result scale INFO "routing.bgp.route.list (first page of $N): $(( $(now_ms) - tq )) ms, state $st, daemon $(rss "$dpid")"
  tq=$(now_ms); cr1 routing.bgp.route.list '{"connection":"chr4","prefix":"21.1.2.0/24","match":"exact"}' >/dev/null
  result scale INFO "route.list one prefix (cached table): $(( $(now_ms) - tq )) ms"
  tq=$(now_ms); cr1 ip.route.page '{"limit":10}' >/dev/null 2>&1; result scale INFO "ip.route.page (10 of $N): $(( $(now_ms) - tq )) ms"
  # CR1 → CR2 over iBGP: CoreRouter to CoreRouter, no licence in the way.
  crc 1 '{"name":"cr2","remote_address":"10.39.5.2","remote_as":65000,"nexthop_choice":"force-self"}'
  crc 2 '{"name":"cr1","remote_address":"10.39.5.1","remote_as":65000}'
  local d2; d2=$(cat "$W/daemon2.pid")
  cpu_threads "$d2" > "$W/cpu.d2"
  t0=$(now_ms)
  ms=$(wait_for 300 bash -c "[ \$(ip -n cf2 route show proto bgp | wc -l) -ge $N ]") \
    && result scale OK "CR1 → CR2 (iBGP, veth): $N prefixes in CR2's kernel ${ms} ms after the config" \
    || result scale FAIL "CR2 has $(ip -n cf2 route show proto bgp | wc -l) after 300 s"
  el=$(( $(now_ms) - t0 ))
  result scale INFO "CR2: daemon $(rss "$d2") CPU $(cpu_report d2 "$W/cpu.d2" "$d2" "$el"); bgpd $(rss "$(pid_of /usr/lib/frr/bgpd cf2)")"
  # Clear and resync, measured on CR2's kernel (withdraw then re-add).
  t0=$(now_ms)
  cr1 routing.bgp.session.clear '{"connection":"cr2"}' >/dev/null
  wait_for 60 bash -c "[ \$(ip -n cf2 route show proto bgp | wc -l) -lt $N ]" >/dev/null || true
  ms=$(wait_for 300 bash -c "[ \$(ip -n cf2 route show proto bgp | wc -l) -ge $N ]") \
    && result scale OK "session.clear CR1—CR2: $N back in CR2's kernel $(( $(now_ms) - t0 )) ms after the clear" \
    || result scale FAIL "after clear: CR2 has $(ip -n cf2 route show proto bgp | wc -l)"
  crd 1 cr2; crd 2 cr1
  t0=$(now_ms)
  ebgp4_down
  ms=$(wait_for 300 bash -c "[ \$(ip -n cf1 route show proto bgp | wc -l) -lt 10 ]") && result scale OK "connection removed: $N withdrawn from CR1's kernel in ${ms} ms" \
    || result scale FAIL "withdraw: $(ip -n cf1 route show proto bgp | wc -l) left"
  rosd r3
  sed 's/^route add/route del/' "$W/r3.batch" | ip -n cfr3 -batch - 2>/dev/null || true
}

# CoreRouter × CoreRouter: eBGP (CR2 in AS 65002) IPv4 + IPv6 over one
# session, MD5, a filter each way, communities and BFD.
case_crcr() {
  cr2 routing.bgp.instance.set '{"asn":65002,"router_id":"10.255.39.5"}' >/dev/null
  cr2 ip.firewall.address-list.add '{"list":"bgp-out","address":"fd39:40::/64"}' >/dev/null
  addr 2 fd39:40::1/64 ether2
  for n in 1 2; do cr "$n" routing.bfd.profile.add '{"name":"g39f","min_tx":100,"min_rx":100,"multiplier":3}' >/dev/null 2>&1 || true; done
  cr1 routing.filter.rule.add '{"chain":"cr-out","rule":"if (dst in 100.64.39.0/24) { append bgp-communities 65000:10; append bgp-large-communities 65000:0:10; set bgp-med 5; accept } if (dst in fd39:64::/64) { accept } reject"}' >/dev/null
  cr2 routing.filter.rule.add '{"chain":"cr-in","rule":"if (bgp-communities includes 65000:10) { set bgp-local-pref 300; accept } if (dst in fd39:64::/64) { accept } reject"}' >/dev/null
  crc 1 '{"name":"cr2e","remote_address":"10.39.5.2","remote_as":65002,"afi":"ip,ipv6","tcp_md5_key":"crcr-key","bfd":"g39f","input_filter":"all","output_filter":"cr-out","output_network":"bgp-out"}'
  local t0 ms; t0=$(now_ms)
  crc 2 '{"name":"cr1e","remote_address":"10.39.5.1","remote_as":65000,"afi":"ip,ipv6","tcp_md5_key":"crcr-key","bfd":"g39f","input_filter":"cr-in","output_filter":"all","output_network":"bgp-out"}'
  ms=$(wait_for 60 cr_up 1 cr2e) && result crcr OK "eBGP CR1 (65000) — CR2 (65002), MD5, ip+ipv6: Established in ${ms} ms" \
    || { result crcr FAIL "no session: $(cr_sess 1 cr2e | jq -c '{state, reason, last_error}')"; dump; }
  ms=$(wait_for 30 k_via cf2 100.64.39.0/24 10.39.5.1) && result crcr OK "CR2 has 100.64.39.0/24 via 10.39.5.1" || result crcr FAIL "CR2: '$(k_route cf2 100.64.39.0/24)'"
  local r; r=$(bgp_path cf2 100.64.39.0/24)
  [ "$(jq -r .local_pref <<< "$r")" = 300 ] && [[ $(jq -r .large <<< "$r") == *65000:0:10* ]] && [ "$(jq -r .med <<< "$r")" = 5 ] \
    && result crcr OK "community match → local-pref 300, large community and MED 5 across: $r" \
    || result crcr FAIL "attributes on CR2: $r"
  ms=$(wait_for 30 k_has6 cf2 fd39:64::/64) && result crcr OK "IPv6 over the IPv4 session: CR2 has fd39:64::/64 $(k_route6 cf2 fd39:64::/64)" \
    || result crcr FAIL "CR2 IPv6: kernel '$(k_route6 cf2 fd39:64::/64)', bgpd $(vt cf2 'show bgp ipv6 unicast fd39:64::/64 json' | jq -c '[.paths[]? | {valid, nexthops}]' 2>/dev/null)"
  ms=$(wait_for 30 k_via cf1 100.64.40.0/24 10.39.5.2) && result crcr OK "CR1 has CR2's 100.64.40.0/24" || result crcr FAIL "CR1: '$(k_route cf1 100.64.40.0/24)'"
  ms=$(wait_for 30 bash -c "ip netns exec cf1 $bin/corerouter-cli --connect 127.0.0.1:7991 run routing.bfd.session.list | jq -e '.sessions[] | select(.peer == \"10.39.5.2\" and .state == \"up\")' >/dev/null") \
    && result crcr OK "BFD 100 ms × 3 up between the two CoreRouters" || result crcr FAIL "BFD: $(cr1 routing.bfd.session.list | jq -c '[.sessions[] | {peer, state}]')"
  ip netns exec cf2 ping -c 3 -i 0.2 -W 1 -I 100.64.40.1 100.64.39.1 >/dev/null && result crcr OK "CR2's clients' gateway → CR1's (ping)" || result crcr FAIL "ping 100.64.40.1 → 100.64.39.1"
  # A silent cut: BFD must take the session down in ~300 ms.
  t0=$(now_ms)
  ip netns exec cf2 tc qdisc add dev ether1 root netem loss 100%
  ms=$(wait_for 20 bash -c "! ip -n cf1 route show 100.64.40.0/24 | grep -q via") \
    && result crcr OK "silent loss on the link: CR1 withdraws CR2's route after ${ms} ms (BFD 100 ms × 3; hold time 180 s)" \
    || result crcr FAIL "silent loss: route still on CR1 after 20 s"
  ip netns exec cf2 tc qdisc del dev ether1 root
  ms=$(wait_for 60 cr_up 1 cr2e) && result crcr OK "loss over: session back in ${ms} ms" || result crcr FAIL "session not back"
  result crcr INFO "CR1 history: $(cr1 routing.bgp.session.history '{"connection":"cr2e"}' | jq -c '[.[0:3][] | {event, state, reason}]')"
  # The same on iBGP: CR2 back to AS 65000 (instance change resets everything).
  crd 1 cr2e; crd 2 cr1e
  cr2 routing.bgp.instance.set '{"asn":65000,"router_id":"10.255.39.5"}' >/dev/null
  crc 1 '{"name":"cr2i","remote_address":"10.39.5.2","remote_as":65000,"local_role":"ibgp-rr","output_network":"bgp-out"}'
  crc 2 '{"name":"cr1i","remote_address":"10.39.5.1","remote_as":65000,"output_network":"bgp-out"}'
  ms=$(wait_for 60 cr_up 1 cr2i) && result crcr OK "iBGP CR1 (RR) — CR2 (client): Established in ${ms} ms" || result crcr FAIL "iBGP: $(cr_state 1 cr2i)"
  ms=$(wait_for 30 k_via cf1 100.64.40.0/24 10.39.5.2) && result crcr OK "iBGP: CR1 has 100.64.40.0/24" || result crcr FAIL "iBGP: CR1 '$(k_route cf1 100.64.40.0/24)'"
  crd 1 cr2i; crd 2 cr1i
}

for c in "${CASES[@]}"; do
  echo "=== $c ==="
  "case_$c" || result "$c" FAIL "the case stopped: exit $?"
done
echo
echo "=== results (RouterOS $ROS_VERSION CHR × CoreRouter $(git rev-parse --short HEAD 2>/dev/null || echo ?)) ==="
cat "$W/results.txt"
echo "--- daemon 1 warnings ---"; grep -iE "warn|error|refused" "$W/daemon1.log" | sort | uniq -c | sort -rn | head -15 || true
if [ $FAILED != 0 ]; then
  echo "--- CR1 daemon log (tail) ---"; tail -25 "$W/daemon1.log"
  echo "--- CHR log (tail) ---"; ros log | jq -r '.[-25:][] | "\(.time) \(.topics) \(.message)"' || true
fi
exit $FAILED
