#!/usr/bin/env bash
# G3.9g: the CoreRouter PPPoE BNG (ppp.*, radius.*, proto-pppoe,
# proto-radius) against a real MikroTik RouterOS v7 CHR as the subscriber's
# CPE. Runs as root inside the lab VM only:
#   cargo xtask vm-lab run -- scripts/routeros-interop-pppoe.sh [case…]
# Cases (default: all, in this order): auth mtu ipcp-dns ipv6 keepalive padt
#   service-name mac-limit multi radius coa import client timeline
# HOLD=<s> keeps the lab up that long at the end; XDP=0 leaves the access
# and uplink ports on the slow path (no XDP data plane, no policer).
# MULTI=<n> sets how many CHR clients the `multi` case brings up (default 32).
# Results: a table at the end and /tmp/crg39g/results.txt in the VM; exit 1
# if any case failed.
#
# Topology (all inside the VM; the CoreRouter lives in netns crgcore, the
# uplink host with FreeRADIUS in netns crgup):
#
#   CHR ether1 ──crgb1── ether1 CoreRouter (BNG, pppoe-server) ether2 ── up0 crgup
#   CHR ether2 ──crgbm── 192.168.240.1 (REST from the VM's root namespace)
#
# Subscribers get 100.64.40.0/24 (pool ppp4), the link /64 from
# 2001:db8:40::/48 and a /56 from 2001:db8:4100::/40; crgup is
# 198.51.100.2 and 2001:db8:ff::2 (FreeRADIUS, the traffic source).
set -euo pipefail
# vm-lab run holds its lock on fd 9: a daemon started from here would
# inherit it and keep the VM locked after the round.
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }

ROS_VERSION=${ROS_VERSION:-7.25}
ROS_SHA256=${ROS_SHA256:-6b981288350de2a2c7a3218bd820ab702633b8cd6cd339f2bb34dda1f1a2550e}
CASES=("$@")
[ ${#CASES[@]} -gt 0 ] || CASES=(auth mtu ipcp-dns ipv6 keepalive padt service-name mac-limit multi radius coa import client)
W=/tmp/crg39g
CHR_DIR=/srv/lab/chr
PW=g39g-lab-only
ROS=192.168.240.2
RAD_SECRET=g39g-radius
MULTI=${MULTI:-32}
FAILED=0
mkdir -p "$W"
: > "$W/results.txt"

result() { # result <case> <OK|FAIL|INFO> <text>
  printf '%-13s %-4s %s\n' "$1" "$2" "$3" | tee -a "$W/results.txt"
  [ "$2" != FAIL ] || FAILED=1
}

# --- tools and image -------------------------------------------------------
need=()
command -v qemu-system-x86_64 >/dev/null || need+=(qemu-system-x86 qemu-utils unzip)
command -v freeradius >/dev/null || need+=(freeradius)
command -v radclient >/dev/null || need+=(freeradius-utils)
command -v jq >/dev/null || need+=(jq)
if [ ${#need[@]} -gt 0 ]; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${need[@]}" >/dev/null
fi
# The package starts its own server in the root namespace: ours runs in crgup.
systemctl disable --now freeradius >/dev/null 2>&1 || true
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
  local f
  for f in qemu daemon radius blast; do
    [ -f "$W/$f.pid" ] && kill "$(cat "$W/$f.pid")" 2>/dev/null || true
    rm -f "$W/$f.pid"
  done
  for ns in crgcore crgup; do
    ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
  done
  sleep 0.3
  for ns in crgcore crgup; do ip netns del $ns 2>/dev/null || true; done
  for l in crgb1 crgbm crgv1 crgt1 crgt2; do ip link del $l 2>/dev/null || true; done
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
for ns in crgcore crgup; do
  ip netns add $ns
  ip -n $ns link set lo up
  ip netns exec $ns sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 \
    net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
done
# The access segment carries 1508-byte frames (RFC 4638 needs them for a
# 1500-byte PPP payload); each side's own MTU decides what it sends.
ip link add crgb1 type bridge
ip link add crgv1 type veth peer name ether1 netns crgcore
ip link set crgv1 mtu 1508 master crgb1 up
ip -n crgcore link set ether1 mtu 1508 up
ip link add ether2 netns crgcore type veth peer name up0 netns crgup
ip -n crgcore link set ether2 up
ip -n crgup link set up0 up
ip -n crgup addr add 198.51.100.2/24 dev up0
ip -n crgup addr add 2001:db8:ff::2/64 dev up0 nodad
ip -n crgup route add 100.64.40.0/24 via 198.51.100.1
ip -n crgup route add 2001:db8:40::/48 via 2001:db8:ff::1
ip -n crgup route add 2001:db8:4100::/40 via 2001:db8:ff::1
ip link add crgbm type bridge
ip addr add 192.168.240.1/24 dev crgbm
ip link set crgbm up

# --- the CHR ---------------------------------------------------------------
cp "$img" "$W/chr.img"
qemu-system-x86_64 -enable-kvm -cpu host -m 512 -smp 2 -name chr-g39g \
  -drive file="$W/chr.img",format=raw,if=virtio \
  -netdev tap,id=e1,ifname=crgt1,script=no,downscript=no -device virtio-net-pci,netdev=e1,mac=52:54:00:39:07:01 \
  -netdev tap,id=e2,ifname=crgt2,script=no,downscript=no -device virtio-net-pci,netdev=e2,mac=52:54:00:39:07:02 \
  -serial unix:$W/chr.sock,server,nowait -monitor unix:$W/chr.mon,server,nowait \
  -display none -daemonize -pidfile "$W/qemu.pid"
ip link set crgt1 mtu 1508 master crgb1 up
ip link set crgb1 mtu 1508 up
ip link set crgt2 master crgbm up

# The console: log in, take the first-login questions, then type the
# bootstrap (the same dance as scripts/routeros-interop.sh). Everything
# after that goes through the REST API on ether2.
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
python3 -I "$W/console.py" "$W/chr.sock" "$PW" <<'ROS'
/system identity set name=chr-g39g
/ip address add address=192.168.240.2/24 interface=ether2
/ip service set www disabled=no
ROS
for _ in $(seq 100); do curl -sf -m 2 -u "admin:$PW" "http://$ROS/rest/system/resource" >/dev/null && break; sleep 0.2; done

ros() { curl -sf -m 10 -u "admin:$PW" "http://$ROS/rest/$1"; }
# rospost <path> <json>: POST /rest/<path> (monitor, print with options).
rospost() { curl -s -m 20 -u "admin:$PW" -H 'content-type: application/json' -d "$2" "http://$ROS/rest/$1"; }
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

# --- FreeRADIUS in crgup ------------------------------------------------------
rad_start() {
  rm -rf "$W/raddb"
  cp -a /etc/freeradius/3.0 "$W/raddb"
  # Run as root in the lab, logging to stdout; our NAS is 198.51.100.1.
  sed -i -e 's/^\s*user = .*/#&/' -e 's/^\s*group = .*/#&/' "$W/raddb/radiusd.conf"
  cat > "$W/raddb/clients.conf" <<EOF
client corerouter {
  ipaddr = 198.51.100.1
  secret = $RAD_SECRET
  require_message_authenticator = no
}
EOF
  cat > "$W/raddb/mods-config/files/authorize" <<'EOF'
rad1  Cleartext-Password := "g39g-rad-1"
      Framed-IP-Address = 100.64.40.201,
      Mikrotik-Rate-Limit = "512k/512k",
      Acct-Interim-Interval = 60,
      Class = "g39g-class-1"
rad2  Cleartext-Password := "g39g-rad-2"
      Session-Timeout = 30
radrej Cleartext-Password := "g39g-rad-3", Auth-Type := Reject
      Reply-Message = "g39g: blocked by the provider"
EOF
  : > "$W/radius.log"
  ip netns exec crgup freeradius -d "$W/raddb" -f -X >> "$W/radius.log" 2>&1 &
  echo $! > "$W/radius.pid"
  for _ in $(seq 50); do grep -q "Ready to process requests" "$W/radius.log" && return 0; sleep 0.2; done
  echo "FreeRADIUS did not start:"; tail -20 "$W/radius.log"; return 1
}

# --- CoreRouter ----------------------------------------------------------------
export COREROUTER_RUNTIME_DIR=$W/run
rm -rf "$COREROUTER_RUNTIME_DIR" "$W/cfg"
mkdir -p "$COREROUTER_RUNTIME_DIR"
: > "$W/daemon.log"
ip netns exec crgcore env RUST_LOG=warn "$bin/corerouter-daemon" --backend linux --manage 'ether*' \
  --config-dir "$W/cfg" --control 7991 --no-discovery >> "$W/daemon.log" 2>&1 &
echo $! > "$W/daemon.pid"
cli() { ip netns exec crgcore "$bin/corerouter-cli" --connect 127.0.0.1:7991 run "$@"; }
for _ in $(seq 100); do cli interface.list >/dev/null 2>&1 && break; sleep 0.2; done
cli interface.list >/dev/null || { echo "daemon did not start"; tail -20 "$W/daemon.log"; exit 1; }

now_ms() { date +%s%3N; }
wait_for() { # wait_for <timeout s> <command…>: poll every 100 ms; prints ms waited
  local t=$1; shift
  local t0; t0=$(now_ms)
  while ! "$@" >/dev/null 2>&1; do
    [ $(( $(now_ms) - t0 )) -lt $(( t * 1000 )) ] || { echo -1; return 1; }
    sleep 0.1
  done
  echo $(( $(now_ms) - t0 ))
}

cli ip.address.add '{"address":"198.51.100.1/24","interface":"ether2"}' >/dev/null
cli ip.address.add '{"address":"2001:db8:ff::1/64","interface":"ether2"}' >/dev/null \
  || echo "note: no IPv6 address on ether2 (ip.address.add refused it)"
if [ "${XDP:-1}" = 1 ]; then
  for i in ether1 ether2; do
    cli ip.firewall.xdp.interface.add "{\"interface\":\"$i\",\"mode\":\"generic\"}" >/dev/null \
      || echo "note: XDP on $i refused; the slow path carries the traffic"
  done
fi
cli ip.pool.add '{"name":"ppp4","ranges":"100.64.40.10-100.64.40.199"}' >/dev/null
cli ipv6.pool.add '{"name":"ppp6","prefix":"2001:db8:40::/48","prefix_length":64}' >/dev/null
cli ipv6.pool.add '{"name":"pd6","prefix":"2001:db8:4100::/40","prefix_length":56}' >/dev/null
cli ppp.profile.add '{"name":"g39g","local_address":"100.64.40.1","remote_address":"ppp4","dns_server":["198.51.100.53","198.51.100.54"]}' >/dev/null
cli ppp.secret.add '{"name":"cpe1","password":"g39g-pw-1","service":"pppoe","profile":"g39g"}' >/dev/null
cli ppp.secret.add '{"name":"cpe2","password":"g39g-pw-2","service":"pppoe","profile":"g39g"}' >/dev/null
cli interface.pppoe-server.server.add '{"interface":"ether1","default_profile":"g39g"}' >/dev/null
SRV=pppoe-ether1
# The pppoe service rereads the config once a second: give it two.
srvset() { cli interface.pppoe-server.server.set "$(jq -c --arg id "$SRV" '. + {id: $id, force: true}' <<< "$1")" >/dev/null; sleep 2; }
echo "CoreRouter: $(cli interface.pppoe-server.monitor | jq -c '{running, dataplane, workers}' 2>/dev/null)"

# --- helpers: the CHR's pppoe-client and the CoreRouter's view of it ---------
# pc_add <name> <user> <password> [extra RouterOS args]: a disabled client on
# ether1. The CHR has no other way back to crgup: each client adds a
# default route (distance 1 for the first, the others behind it).
pc_add() {
  rosx "/interface pppoe-client add name=$1 interface=${PC_IF:-ether1} user=$2 password=\"$3\" disabled=yes add-default-route=yes ${4:-}" >/dev/null
}
pc_set() { rosx "/interface pppoe-client set [find name=$1] $2" >/dev/null; }
pc_up() { pc_set "$1" disabled=no; }
pc_down() { pc_set "$1" disabled=yes; }
pc_del() { rosx "/interface pppoe-client remove [find name=$1]" >/dev/null 2>&1 || true; }
pc_running() { [ "$(ros "interface/pppoe-client?name=$1" | jq -r '.[0].running // "false"')" = true ]; }
pc_not_running() { ! pc_running "$1"; }
pc_mon() { rospost interface/pppoe-client/monitor "{\"numbers\":\"$1\",\"once\":\"\"}" | jq -c '.[0] // {}'; }
cr_row() { cli ppp.active.list "{\"find\":\"$1\"}" | jq -c --arg n "$1" '[.rows[] | select(.name == $n)][0] // empty'; }
cr_up() { [ -n "$(cr_row "$1")" ]; }
cr_gone() { [ -z "$(cr_row "$1")" ]; }
cr_count() { cli ppp.active.list '{"limit":100000}' | jq -r '.total'; }
cr_why() { cli ppp.why "{\"name\":\"$1\"}" | jq -c '{last_stage, last: (.last // {} | {event, stage, reason})}'; }
# ping from crgup through the CoreRouter to the subscriber.
up_ping() { ip netns exec crgup ping -c 2 -i 0.2 -W 1 "$@" >/dev/null 2>&1; }
up_ping1() { ip netns exec crgup ping -c 1 -W 1 "$@" >/dev/null 2>&1; }

dump() {
  echo "--- CHR pppoe-clients"; ros interface/pppoe-client | jq -c '.[] | {name, running, disabled, user}' | head -20
  echo "--- CHR log"; ros log | jq -r '.[-15:][] | "\(.time) \(.topics) \(.message)"'
  echo "--- CR active"; cli ppp.active.list | jq -c '.rows[] | {name, address, mtu, encoding, caller_id}' | head -20
  echo "--- CR monitor"; cli interface.pppoe-server.monitor | jq -c . | cut -c1-600
  echo "--- CR log"; cli log.print '{"limit":15}' | jq -r '.[] | "\(.time) \(.topics | join(",")) \(.message)"' | cut -c1-200
}

# --- cases -------------------------------------------------------------------
case_auth() {
  pc_add c1 cpe1 g39g-pw-1
  local m ms row
  for m in mschap2 mschap1 chap pap; do
    srvset "{\"authentication\":\"$m\"}"
    pc_up c1
    if ms=$(wait_for 30 pc_running c1); then
      wait_for 10 cr_up cpe1 >/dev/null || true
      row=$(cr_row cpe1)
      result auth OK "$m (CHR default allow): up in ${ms} ms; CR: $(jq -c '{address, encoding, mtu}' <<< "$row")"
      local addr pms; addr=$(jq -r '.address // empty' <<< "$row")
      # The first reply can lag the session by the route's install.
      if [ -n "$addr" ] && pms=$(wait_for 5 up_ping1 "$addr"); then
        result auth OK "$m: crgup → $addr through the BNG (first reply ${pms} ms after up)"
      else
        result auth FAIL "$m: crgup cannot ping the subscriber '$addr' for 5 s"; dump
      fi
    else
      result auth FAIL "$m: CHR not up in 30 s; CR why $(cr_why cpe1)"; dump
    fi
    pc_down c1; wait_for 15 cr_gone cpe1 >/dev/null || result auth FAIL "$m: session still on CR after the CHR disabled it"
  done
  srvset '{"authentication":"mschap2,mschap1,chap,pap"}'
  pc_up c1
  wait_for 30 pc_running c1 >/dev/null && wait_for 10 cr_up cpe1 >/dev/null \
    && result auth INFO "all four offered: CHR and CR agree on $(cr_row cpe1 | jq -r .encoding) (RouterOS server picks mschap2 first)" \
    || result auth FAIL "all four offered: no session"
  pc_down c1; wait_for 15 cr_gone cpe1 >/dev/null || true
  # A wrong password: no session, and ppp.why tells the operator.
  pc_set c1 password=wrong
  pc_up c1; sleep 8
  pc_running c1 && result auth FAIL "wrong password: CHR is up" \
    || result auth OK "wrong password: refused; CR why $(cr_why cpe1)"
  pc_down c1; pc_set c1 password=g39g-pw-1
  # The CHR restricted to one method that the BNG does not offer.
  srvset '{"authentication":"pap"}'
  pc_set c1 allow=mschap2; pc_up c1; sleep 8
  pc_running c1 && result auth FAIL "CHR allow=mschap2 vs BNG pap: came up" \
    || result auth OK "CHR allow=mschap2 vs BNG pap: no session (LCP Configure-Nak/Reject); CR why $(cr_why cpe1)"
  pc_down c1; pc_set c1 allow=pap,chap,mschap1,mschap2
  srvset '{"authentication":"mschap2,mschap1,chap,pap"}'
  wait_for 15 cr_gone cpe1 >/dev/null || true
}

# mtu_try <client max-mtu/mru> <expected mtu>: bring c1 up and probe the path.
mtu_try() {
  local want=$1 expect=$2 row mon mtu
  pc_set c1 "max-mtu=$want max-mru=$want"
  pc_up c1
  if ! wait_for 30 pc_running c1 >/dev/null || ! wait_for 10 cr_up cpe1 >/dev/null; then
    result mtu FAIL "client $want: no session; CR why $(cr_why cpe1)"; dump; pc_down c1; return
  fi
  sleep 2
  row=$(cr_row cpe1); mon=$(pc_mon c1)
  mtu=$(jq -r '.mtu // 0' <<< "$row")
  local addr; addr=$(jq -r .address <<< "$row")
  local info="CR mtu $mtu, CHR mtu/mru $(jq -r '"\(.mtu // "?")/\(.mru // "?")"' <<< "$mon")"
  [ "$mtu" = "$expect" ] && result mtu OK "client $want: $info (expected $expect)" \
    || result mtu FAIL "client $want: $info (expected $expect)"
  # The path: a DF ping of exactly the MTU passes, one byte more does not.
  local p=$((expect - 28))
  ip netns exec crgup ping -c 2 -i 0.2 -W 1 -M do -s "$p" "$addr" >/dev/null 2>&1 \
    && result mtu OK "client $want: $expect-byte DF ping crgup → CHR passes" \
    || result mtu FAIL "client $want: $expect-byte DF ping crgup → CHR lost"
  local big; big=$(ip netns exec crgup ping -c 1 -W 1 -M do -s $((p + 1)) "$addr" 2>&1 | grep -o 'mtu = [0-9]*\|Frag needed[^)]*\|message too long.*\|100% packet loss' | head -1)
  # (1501 bytes never leave crgup: its own up0 is 1500.)
  result mtu INFO "client $want: $((expect + 1))-byte DF ping: ${big:-passed}"
  pc_down c1; wait_for 15 cr_gone cpe1 >/dev/null || true
}
case_mtu() {
  [ -n "$(ros 'interface/pppoe-client?name=c1' | jq -r '.[0].name // empty')" ] || pc_add c1 cpe1 g39g-pw-1
  # RouterOS defaults on both sides (server max-mtu 1480 here as there).
  pc_up c1
  if wait_for 30 pc_running c1 >/dev/null && wait_for 10 cr_up cpe1 >/dev/null; then
    sleep 2
    result mtu INFO "defaults (CHR client auto, BNG 1480): CR mtu $(cr_row cpe1 | jq -r .mtu), CHR $(pc_mon c1 | jq -c '{mtu, mru}')"
  fi
  pc_down c1; wait_for 15 cr_gone cpe1 >/dev/null || true
  srvset '{"max_mtu":1492,"max_mru":1492}'
  mtu_try 1480 1480
  mtu_try 1492 1492
  # RFC 4638: 1500 needs PPP-Max-Payload on both sides and 1508-byte frames.
  rosx '/interface ethernet set ether1 mtu=1508' >/dev/null || result mtu INFO "CHR ether1 mtu=1508 refused"
  cli interface.set '{"name":"ether1","mtu":1508}' >/dev/null || result mtu INFO "CR ether1 mtu 1508 refused"
  mtu_try 1500 1492
  srvset '{"max_payload":1500}'
  mtu_try 1500 1500
  srvset '{"max_payload":"none","max_mtu":1480,"max_mru":1480}'
  rosx '/interface ethernet set ether1 mtu=1500' >/dev/null || true
  cli interface.set '{"name":"ether1","mtu":1500}' >/dev/null || true
  pc_set c1 "max-mtu=auto max-mru=auto"
}

case_ipcp-dns() {
  pc_add c2 cpe2 g39g-pw-2 "use-peer-dns=yes"
  pc_up c2
  wait_for 30 pc_running c2 >/dev/null || { result ipcp-dns FAIL "no session"; dump; return; }
  sleep 2
  local dns; dns=$(ros ip/dns | jq -r '.["dynamic-servers"] // ""')
  [[ $dns == *198.51.100.53* && $dns == *198.51.100.54* ]] \
    && result ipcp-dns OK "IPCP DNS (RFC 1877): CHR dynamic-servers '$dns'" \
    || result ipcp-dns FAIL "CHR dynamic-servers '$dns', expected the profile's 198.51.100.53,54"
  local mon; mon=$(pc_mon c2)
  result ipcp-dns INFO "CHR monitor: $(jq -c '{status, "local-address", "remote-address", "ac-name", "service-name", "mtu", "mru", encoding}' <<< "$mon")"
  [ "$(jq -r '.["remote-address"]' <<< "$mon")" = 100.64.40.1 ] \
    && result ipcp-dns OK "the BNG's IPCP address is the profile's local_address 100.64.40.1" \
    || result ipcp-dns FAIL "CHR remote-address $(jq -r '.["remote-address"]' <<< "$mon")"
  local r; r=$(ros 'ip/route?dst-address=0.0.0.0/0' | jq -r '[.[] | select(.active == "true")][0].gateway // "-"')
  [[ $r == *c2* || $r == 100.64.40.1* ]] && result ipcp-dns OK "add-default-route: CHR default via $r" \
    || result ipcp-dns INFO "CHR default route gateway '$r'"
  pc_down c2; wait_for 15 cr_gone cpe2 >/dev/null || true
}

case_ipv6() {
  cli ppp.profile.set '{"id":"g39g","use_ipv6":"yes","remote_ipv6_prefix_pool":"ppp6","dhcpv6_pd_pool":"pd6","dns_server_ipv6":["2001:db8:ff::53"]}' >/dev/null \
    || { result ipv6 FAIL "profile with IPv6 refused"; return; }
  rosx '/ipv6 settings set accept-router-advertisements=yes' >/dev/null || true
  [ -n "$(ros 'interface/pppoe-client?name=c1' | jq -r '.[0].name // empty')" ] || pc_add c1 cpe1 g39g-pw-1
  rosx '/ipv6 dhcp-client add interface=c1 request=prefix pool-name=g39pd add-default-route=yes' >/dev/null \
    || result ipv6 INFO "CHR dhcp-client add refused"
  pc_up c1
  wait_for 30 pc_running c1 >/dev/null && wait_for 10 cr_up cpe1 >/dev/null || { result ipv6 FAIL "no session"; dump; return; }
  local ms row
  ms=$(wait_for 30 chr_v6_slaac c1) && result ipv6 OK "IPv6CP + RA: CHR has a global address on c1 ${ms} ms after up ($(chr_v6_slaac c1))" \
    || result ipv6 FAIL "no SLAAC address on CHR c1: $(ros 'ipv6/address' | jq -c '[.[] | {address, interface}]')"
  ms=$(wait_for 30 chr_pd) && result ipv6 OK "DHCPv6-PD: CHR bound $(chr_pd) ${ms} ms after its SLAAC" \
    || result ipv6 FAIL "DHCPv6-PD: $(ros ipv6/dhcp-client | jq -c '.[] | {status, prefix}')"
  row=$(cr_row cpe1)
  result ipv6 INFO "CR: $(jq -c '{ipv6_prefix, delegated_prefix, delegated_bound, link_local}' <<< "$row")"
  local a; a=$(chr_v6_slaac c1); a=${a%/*}
  [ -n "$a" ] && ip netns exec crgup ping -6 -c 2 -i 0.2 -W 1 "$a" >/dev/null 2>&1 \
    && result ipv6 OK "crgup → $a (IPv6 through the BNG)" || result ipv6 FAIL "crgup cannot ping6 '$a'"
  local rd; rd=$(ros ip/dns | jq -r '.["dynamic-servers"] // ""')
  result ipv6 INFO "CHR dynamic DNS servers with IPv6 on: '$rd' (RDNSS 2001:db8:ff::53 expected only if RouterOS takes it)"
  pc_down c1; wait_for 15 cr_gone cpe1 >/dev/null || true
  rosx '/ipv6 dhcp-client remove [find interface=c1]' >/dev/null || true
  cli ppp.profile.set '{"id":"g39g","use_ipv6":"default"}' >/dev/null || true
}
chr_v6_slaac() {
  local a; a=$(ros ipv6/address | jq -r --arg i "$1" '[.[] | select(.interface == $i and (.address | startswith("fe80") | not))][0].address // empty')
  [ -n "$a" ] && echo "$a"
}
chr_pd() {
  local p; p=$(ros ipv6/dhcp-client | jq -r '[.[] | select(.status == "bound")][0].prefix // empty')
  [ -n "$p" ] && echo "$p"
}

# cut / heal the access segment silently (no carrier change on either side).
cut_link() { tc qdisc replace dev crgt1 root netem loss 100%; tc qdisc replace dev crgv1 root netem loss 100%; }
heal_link() { tc qdisc del dev crgt1 root 2>/dev/null || true; tc qdisc del dev crgv1 root 2>/dev/null || true; }
case_keepalive() {
  [ -n "$(ros 'interface/pppoe-client?name=c1' | jq -r '.[0].name // empty')" ] || pc_add c1 cpe1 g39g-pw-1
  local kc
  for kc in "10 10" "10 60" "30 10"; do
    local ks=${kc% *} kcl=${kc#* }
    srvset "{\"keepalive_timeout\":$ks}"
    pc_set c1 "keepalive-timeout=$kcl"
    pc_up c1
    wait_for 30 pc_running c1 >/dev/null && wait_for 10 cr_up cpe1 >/dev/null || { result keepalive FAIL "no session"; return; }
    sleep 3
    local t0 cr_ms=-1 chr_ms=-1
    t0=$(now_ms); cut_link
    while [ $(( $(now_ms) - t0 )) -lt 150000 ]; do
      [ "$cr_ms" = -1 ] && cr_gone cpe1 && cr_ms=$(( $(now_ms) - t0 ))
      [ "$chr_ms" = -1 ] && pc_not_running c1 && chr_ms=$(( $(now_ms) - t0 ))
      [ "$cr_ms" != -1 ] && [ "$chr_ms" != -1 ] && break
      sleep 0.2
    done
    heal_link
    # RouterOS: the server drops after keepalive-timeout; the client after its own.
    local ok=OK
    { [ "$cr_ms" -ge 0 ] && [ "$cr_ms" -le $(( (ks + 3) * 1000 )) ]; } || ok=FAIL
    result keepalive $ok "server $ks s / client $kcl s, link cut silently: CR dropped it in ${cr_ms} ms, CHR in ${chr_ms} ms; CR why $(cr_why cpe1)"
    pc_down c1; sleep 1
  done
  srvset '{"keepalive_timeout":10}'; pc_set c1 keepalive-timeout=10
  wait_for 15 cr_gone cpe1 >/dev/null || true
}

case_padt() {
  [ -n "$(ros 'interface/pppoe-client?name=c1' | jq -r '.[0].name // empty')" ] || pc_add c1 cpe1 g39g-pw-1
  pc_set c1 keepalive-timeout=60
  pc_up c1
  wait_for 30 pc_running c1 >/dev/null && wait_for 10 cr_up cpe1 >/dev/null || { result padt FAIL "no session"; return; }
  # BNG → CPE: ppp.active.remove sends PADT (and LCP Terminate-Request).
  local id ms; id=$(cr_row cpe1 | jq -r .id)
  cli ppp.active.remove "{\"id\":\"$id\"}" >/dev/null || cli ppp.active.remove "{\"name\":\"cpe1\"}" >/dev/null || true
  ms=$(wait_for 20 pc_not_running c1) \
    && result padt OK "BNG removes the session: CHR saw it down in ${ms} ms (keepalive 60 s, so by Terminate/PADT)" \
    || result padt FAIL "BNG removed the session, CHR still up after 20 s"
  # RouterOS redials on its own; wait for it, then CPE → BNG.
  wait_for 40 pc_running c1 >/dev/null && wait_for 10 cr_up cpe1 >/dev/null || { result padt INFO "CHR did not redial in 40 s"; pc_up c1; wait_for 30 cr_up cpe1 >/dev/null; }
  local t0; t0=$(now_ms)
  pc_down c1
  ms=$(wait_for 20 cr_gone cpe1) && result padt OK "CHR disables its client: CR dropped the session in ${ms} ms; why $(cr_why cpe1)" \
    || result padt FAIL "CHR disabled, session still on CR after 20 s"
  pc_set c1 keepalive-timeout=10
}

case_service-name() {
  [ -n "$(ros 'interface/pppoe-client?name=c1' | jq -r '.[0].name // empty')" ] || pc_add c1 cpe1 g39g-pw-1
  srvset '{"service_name":"isp-g39"}'
  local sn
  for sn in isp-g39 "" wrong-name; do
    pc_set c1 "service-name=\"$sn\""
    pc_up c1
    if wait_for 15 pc_running c1 >/dev/null; then
      [ "$sn" = wrong-name ] && result service-name FAIL "client service-name '$sn' got a session" \
        || result service-name OK "client service-name '${sn:-<empty>}': up; CHR sees $(pc_mon c1 | jq -c '{"service-name", "ac-name"}')"
    else
      [ "$sn" = wrong-name ] && result service-name OK "client service-name '$sn': no PADO, no session (RFC 2516 §5.2)" \
        || { result service-name FAIL "client service-name '${sn:-<empty>}': no session; CR why $(cr_why cpe1)"; }
    fi
    pc_down c1; wait_for 15 cr_gone cpe1 >/dev/null || true
  done
  pc_set c1 'service-name=""'
  srvset '{"service_name":""}'
  # ac-name: the CHR only takes a PADO with this AC-Name; the BNG sends
  # its /system identity, as RouterOS does.
  cli system.identity.set '{"name":"bng-g39g"}' >/dev/null; sleep 2
  local ac; pc_up c1
  wait_for 15 pc_running c1 >/dev/null || true
  ac=$(pc_mon c1 | jq -r '.["ac-name"] // ""')
  pc_down c1; wait_for 15 cr_gone cpe1 >/dev/null || true
  [ "$ac" = bng-g39g ] && result service-name OK "AC-Name is the /system identity '$ac', as RouterOS sends it" \
    || result service-name FAIL "AC-Name '$ac', expected the identity bng-g39g"
  for a in "$ac" not-our-ac; do
    pc_set c1 "ac-name=\"$a\""
    pc_up c1
    if wait_for 15 pc_running c1 >/dev/null; then
      [ "$a" = not-our-ac ] && result service-name FAIL "ac-name '$a' got a session" || result service-name OK "ac-name '$a': up"
    else
      [ "$a" = not-our-ac ] && result service-name OK "ac-name '$a': no session" || result service-name FAIL "ac-name '$a': no session"
    fi
    pc_down c1; wait_for 15 cr_gone cpe1 >/dev/null || true
  done
  pc_set c1 'ac-name=""'
}

case_mac-limit() {
  # Two clients on the same port = the same MAC (one CPE dialling twice).
  [ -n "$(ros 'interface/pppoe-client?name=c1' | jq -r '.[0].name // empty')" ] || pc_add c1 cpe1 g39g-pw-1
  [ -n "$(ros 'interface/pppoe-client?name=c2' | jq -r '.[0].name // empty')" ] || pc_add c2 cpe2 g39g-pw-2
  pc_set c2 "use-peer-dns=no"
  local ops
  for ops in true false; do
    srvset "{\"one_session_per_host\":$ops}"
    pc_up c1; wait_for 30 cr_up cpe1 >/dev/null || true
    pc_up c2; sleep 15
    local a b; a=$(pc_running c1 && echo up || echo down); b=$(pc_running c2 && echo up || echo down)
    local cr; cr=$(cli ppp.active.list | jq -c '[.rows[] | .name]')
    result mac-limit INFO "one_session_per_host=$ops, two clients from one MAC, after 15 s: CHR c1 $a, c2 $b; CR active $cr"
    if [ "$ops" = true ]; then
      [ "$(jq length <<< "$cr")" -le 1 ] && result mac-limit OK "one_session_per_host=yes: at most one session from the MAC" \
        || result mac-limit FAIL "one_session_per_host=yes: $cr"
    else
      [ "$(jq length <<< "$cr")" = 2 ] && result mac-limit OK "one_session_per_host=no: both sessions up" \
        || result mac-limit FAIL "one_session_per_host=no: $cr"
    fi
    pc_down c1; pc_down c2
    wait_for 15 cr_gone cpe1 >/dev/null || true; wait_for 15 cr_gone cpe2 >/dev/null || true
  done
  srvset '{"one_session_per_host":true}'
}

case_multi() {
  local n=$MULTI i
  # Each client on its own macvlan: a MAC per CPE (mac_padi_limit is per MAC).
  local script=""
  for i in $(seq 1 "$n"); do
    cli ppp.secret.add "{\"name\":\"m$i\",\"password\":\"g39g-m$i\",\"service\":\"pppoe\",\"profile\":\"g39g\"}" >/dev/null
    script+="/interface macvlan add name=mv$i interface=ether1 mac-address=02:39:07:00:$(printf %02x $((i / 256))):$(printf %02x $((i % 256)))
/interface pppoe-client add name=m$i interface=mv$i user=m$i password=g39g-m$i disabled=yes keepalive-timeout=10
"
  done
  rosx "$script" >/dev/null || { result multi FAIL "CHR refused the macvlans/clients (macvlan in this RouterOS?)"; return; }
  local base t0 ms; base=$(cr_count)
  t0=$(now_ms)
  rosx "/interface pppoe-client enable [find name~\"^m[0-9]+\$\"]" >/dev/null
  ms=$(wait_for 120 multi_all "$((base + n))") && result multi OK "$n CHR clients (one MAC each): all up on the BNG in ${ms} ms" \
    || result multi FAIL "$n clients: $(( $(cr_count) - base )) up on the BNG after 120 s; CHR running $(ros interface/pppoe-client | jq '[.[] | select(.running == "true")] | length')"
  local addrs; addrs=$(cli ppp.active.list '{"find":"m","limit":100000}' | jq -r '[.rows[] | select(.name | test("^m[0-9]+$")) | .address] | unique | length')
  [ "$addrs" = "$n" ] && result multi OK "$n distinct addresses from the pool" || result multi FAIL "$addrs distinct addresses for $n sessions"
  local lost=0 r a
  for a in $(cli ppp.active.list '{"find":"m","limit":100000}' | jq -r '.rows[] | select(.name | test("^m[0-9]+$")) | .address'); do
    ip netns exec crgup ping -c 1 -W 1 "$a" >/dev/null 2>&1 || lost=$((lost + 1))
  done
  [ $lost = 0 ] && result multi OK "every subscriber answers a ping from crgup" || result multi FAIL "$lost of $n subscribers do not answer"
  # All down at once from the CPE side: every PADT seen.
  t0=$(now_ms)
  rosx "/interface pppoe-client disable [find name~\"^m[0-9]+\$\"]" >/dev/null
  ms=$(wait_for 60 multi_all "$base") && result multi OK "$n clients disabled on the CHR: the BNG back to $base sessions in ${ms} ms" \
    || result multi FAIL "after disabling: $(cr_count) sessions (base $base)"
  rosx "/interface pppoe-client remove [find name~\"^m[0-9]+\$\"]
/interface macvlan remove [find name~\"^mv[0-9]+\$\"]" >/dev/null || true
}
multi_all() { [ "$(cr_count)" = "$1" ]; }

case_radius() {
  rad_start || { result radius FAIL "FreeRADIUS did not start"; return; }
  cli radius.add "{\"address\":\"198.51.100.2\",\"service\":\"ppp\",\"secret\":\"$RAD_SECRET\",\"src_address\":\"198.51.100.1\",\"require_message_auth\":\"no\"}" >/dev/null
  cli ppp.aaa.set '{"use_radius":true,"accounting":true,"interim_update":0}' >/dev/null
  cli radius.incoming.set '{"accept":true}' >/dev/null
  pc_add r1 rad1 g39g-rad-1 "keepalive-timeout=10"
  pc_up r1
  local ms row
  ms=$(wait_for 30 pc_running r1) || { result radius FAIL "rad1: no session; CR why $(cr_why rad1)"; tail -40 "$W/radius.log"; return; }
  wait_for 10 cr_up rad1 >/dev/null || true
  row=$(cr_row rad1)
  result radius OK "rad1 via FreeRADIUS: up in ${ms} ms; CR $(jq -c '{address, rate_limit, radius, encoding}' <<< "$row")"
  [ "$(jq -r .address <<< "$row")" = 100.64.40.201 ] && result radius OK "Framed-IP-Address 100.64.40.201 given to the CPE" \
    || result radius FAIL "Framed-IP-Address: CR gave $(jq -r .address <<< "$row")"
  [[ $(jq -r '.rate_limit // ""' <<< "$row") == 512k/512k* ]] && result radius OK "Mikrotik-Rate-Limit 512k/512k on the session" \
    || result radius FAIL "rate_limit '$(jq -r '.rate_limit // ""' <<< "$row")'"
  grep -q 'Acct-Status-Type = Start' "$W/radius.log" && result radius OK "Accounting-Start received" || result radius FAIL "no Accounting-Start"
  grep -A40 'Acct-Status-Type = Start' "$W/radius.log" | grep -q 'Class = 0x' \
    && result radius OK "Class echoed in Accounting (RFC 2865 §5.25)" || result radius INFO "Class not seen in the Start dump"
  # Interim every 60 s from Acct-Interim-Interval.
  ms=$(wait_for 75 grep -q 'Acct-Status-Type = Interim-Update' "$W/radius.log") \
    && result radius OK "Interim-Update ${ms} ms after the check began (Acct-Interim-Interval 60)" \
    || result radius FAIL "no Interim-Update in 75 s"
  # Session-Timeout 30 s.
  pc_add r2 rad2 g39g-rad-2
  pc_up r2
  if wait_for 30 cr_up rad2 >/dev/null; then
    local t0; t0=$(now_ms)
    ms=$(wait_for 45 cr_gone rad2) && result radius OK "Session-Timeout 30: the BNG ended it $(( $(now_ms) - t0 )) ms after it came up; why $(cr_why rad2)" \
      || result radius FAIL "Session-Timeout 30: still up after 45 s"
    grep -q 'Acct-Terminate-Cause = Session-Timeout' "$W/radius.log" && result radius OK "Acct-Terminate-Cause Session-Timeout" \
      || result radius INFO "Stop causes seen: $(grep -o 'Acct-Terminate-Cause = [A-Za-z-]*' "$W/radius.log" | sort | uniq -c | tr '\n' ' ')"
  else
    result radius FAIL "rad2: no session; CR why $(cr_why rad2)"
  fi
  pc_down r2
  # Access-Reject with Reply-Message.
  pc_add r3 radrej g39g-rad-3
  pc_up r3; sleep 8
  pc_running r3 && result radius FAIL "radrej: up after Access-Reject" \
    || result radius OK "Access-Reject: no session; CR why $(cr_why radrej)"
  result radius INFO "CHR log on the reject: $(ros log | jq -r '[.[] | select(.message | test("r3|radrej|authentication"))][-2:][] | .message' | tr '\n' ' ')"
  pc_down r3
}

# rate_down <address> <seconds>: download kbit/s the CHR receives on r1
# while crgup sends 2 Mbit/s of UDP to it.
rate_down() {
  local addr=$1 secs=$2
  ip netns exec crgup python3 -I - "$addr" "$secs" <<'PY' &
import socket, sys, time
dst, secs = sys.argv[1], float(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
pkt = b"x" * 1000
gap = 1000 * 8 / 2_000_000.0
end = time.time() + secs; nxt = time.time()
while time.time() < end:
    s.sendto(pkt, (dst, 9)); nxt += gap
    d = nxt - time.time()
    if d > 0: time.sleep(d)
PY
  local p=$!
  sleep 2
  local sum=0 k=0 v
  for _ in 1 2 3 4; do
    v=$(rospost interface/monitor-traffic '{"interface":"r1","once":""}' | jq -r '.[0]["rx-bits-per-second"] // 0')
    sum=$((sum + v)); k=$((k + 1)); sleep 0.5
  done
  wait $p 2>/dev/null || true
  echo $(( sum / k / 1000 ))
}
case_coa() {
  [ -f "$W/radius.pid" ] && pc_running r1 || { result coa FAIL "needs the radius case first (r1 up)"; return; }
  local row addr sid kb
  row=$(cr_row rad1); addr=$(jq -r .address <<< "$row")
  kb=$(rate_down "$addr" 5)
  result coa INFO "before CoA (512k/512k): the CHR receives ${kb} kbit/s of a 2 Mbit/s stream"
  [ "$kb" -ge 380 ] && [ "$kb" -le 640 ] && result coa OK "the 512k limit holds on the wire (${kb} kbit/s)" \
    || result coa FAIL "512k limit: ${kb} kbit/s measured"
  sid=$(grep -o 'Acct-Session-Id = "[^"]*"' "$W/radius.log" | head -1 | cut -d'"' -f2)
  local out
  out=$(printf 'User-Name = "rad1"\nAcct-Session-Id = "%s"\nMikrotik-Rate-Limit = "256k/256k"\n' "$sid" |
    ip netns exec crgup radclient -r 2 -t 3 198.51.100.1:3799 coa "$RAD_SECRET" 2>&1 | tail -3)
  [[ $out == *CoA-ACK* ]] && result coa OK "CoA (RFC 5176) answered CoA-ACK" || result coa FAIL "CoA: $out"
  sleep 1
  result coa INFO "CR rate_limit after CoA: $(cr_row rad1 | jq -r '.rate_limit // ""')"
  kb=$(rate_down "$addr" 5)
  [ "$kb" -ge 180 ] && [ "$kb" -le 330 ] && result coa OK "after CoA 256k: ${kb} kbit/s on the wire" \
    || result coa FAIL "after CoA 256k: ${kb} kbit/s measured"
  # Disconnect-Request: the session goes, the CHR sees it.
  out=$(printf 'User-Name = "rad1"\nAcct-Session-Id = "%s"\n' "$sid" |
    ip netns exec crgup radclient -r 2 -t 3 198.51.100.1:3799 disconnect "$RAD_SECRET" 2>&1 | tail -3)
  [[ $out == *Disconnect-ACK* ]] && result coa OK "Disconnect-Request answered Disconnect-ACK" || result coa FAIL "Disconnect: $out"
  local ms; ms=$(wait_for 15 pc_not_running r1) && result coa OK "CHR saw the disconnect in ${ms} ms" \
    || result coa FAIL "CHR still up 15 s after Disconnect-ACK"
  # An unknown session gets a NAK with Error-Cause (RFC 5176 §3.5: 503).
  out=$(printf 'User-Name = "nobody"\nAcct-Session-Id = "deadbeef"\n' |
    ip netns exec crgup radclient -r 1 -t 3 198.51.100.1:3799 disconnect "$RAD_SECRET" 2>&1 | grep -E 'NAK|Error-Cause' | tr '\n' ' ')
  [[ $out == *Disconnect-NAK* ]] && result coa OK "unknown session: $out" || result coa FAIL "unknown session: '$out'"
  pc_down r1
}

case_import() {
  rosx '/ppp profile add name=imp-10m rate-limit=10M/20M local-address=10.9.9.1 only-one=yes
/ppp secret add name=imp1 password=Imp1-pw service=pppoe profile=imp-10m remote-address=100.64.41.5 comment="first subscriber"
/ppp secret add name=imp2 password="p w;\"q" service=pppoe profile=imp-10m caller-id=AA:BB:CC:00:00:02
/ppp secret add name=imp3 password=Imp3 service=any profile=default disabled=yes
/ppp secret add name=imp4 password=Imp4 service=pppoe profile=default-encryption routes="10.77.0.0/24 0.0.0.0 1"
/ppp secret add name=cpe1 password=other service=pppoe' >/dev/null || { result import FAIL "CHR refused the secrets"; return; }
  rosx '/ppp secret export show-sensitive file=g39g-secrets' >/dev/null
  sleep 1
  local text; text=$(ros 'file?name=g39g-secrets.rsc' | jq -r '.[0].contents // empty')
  [ -n "$text" ] || { result import FAIL "could not read the export back from the CHR"; return; }
  printf '%s\n' "$text" > "$W/secrets.rsc"
  local rep
  rep=$(cli ppp.secret.import "$(jq -n --arg t "$text" '{text: $t, dry_run: true}')") \
    || { result import FAIL "dry run refused: $rep"; return; }
  result import INFO "dry run: $(jq -c '{total, with_password, conflicts, missing_profiles, profiles_in_file}' <<< "$rep" | cut -c1-400)"
  rep=$(cli ppp.secret.import "$(jq -n --arg t "$text" '{text: $t, on_conflict: "skip"}')") \
    || { result import FAIL "import refused: $rep"; return; }
  result import INFO "import: $(jq -c '{added, skipped, profiles_created, errors, warnings}' <<< "$rep" | cut -c1-400)"
  [ "$(jq -r .added <<< "$rep")" = 4 ] && result import OK "4 secrets added, the existing cpe1 skipped" \
    || result import FAIL "added $(jq -r .added <<< "$rep") (expected 4)"
  local l; l=$(cli ppp.secret.list '{}' 2>/dev/null || cli ppp.secret.list)
  local s2; s2=$(jq -c '[(.rows // .)[] | select(.name == "imp2")][0] // {}' <<< "$l")
  [ "$(jq -r .caller_id <<< "$s2" | tr a-f A-F)" = AA:BB:CC:00:00:02 ] && result import OK "caller-id kept" || result import FAIL "imp2: $s2"
  # A password with a space, ';' and '"' survives: the CHR logs in with it.
  pc_add i2 imp2 'p w;\\\"q'
  srvset '{"authentication":"chap"}'
  cli ppp.secret.set '{"id":"imp2","caller_id":"","profile":"g39g"}' >/dev/null
  pc_up i2
  wait_for 30 pc_running i2 >/dev/null && result import OK "imported password with space, ';' and '\"' works over CHAP" \
    || result import FAIL "imp2 cannot log in with the imported password; why $(cr_why imp2)"
  pc_down i2; srvset '{"authentication":"mschap2,mschap1,chap,pap"}'
  local p1; p1=$(cli ppp.profile.list | jq -c '[.[] | select(.name == "imp-10m")][0] // {}')
  [[ $(jq -r '.rate_limit // ""' <<< "$p1") == 10M/20M* ]] && result import OK "profile imp-10m created with rate-limit 10M/20M" \
    || result import INFO "profile imp-10m: $p1"
  local s4; s4=$(jq -c '[(.rows // .)[] | select(.name == "imp4")][0] // {}' <<< "$l")
  result import INFO "imp4 (profile default-encryption, routes): $(jq -c '{profile, routes}' <<< "$s4")"
}

# One connect on the wire: where the ~3 s from enable to running go.
case_timeline() {
  [ -n "$(ros 'interface/pppoe-client?name=c1' | jq -r '.[0].name // empty')" ] || pc_add c1 cpe1 g39g-pw-1
  local k
  for k in 1 2 3; do
    tcpdump -i crgv1 -nn -e -ttt -l 'pppoed or pppoes' > "$W/timeline$k.txt" 2>/dev/null &
    local tp=$!
    sleep 1
    local t0 ms; t0=$(now_ms)
    pc_up c1
    ms=$(wait_for 30 cr_up cpe1) || ms=-1
    sleep 1
    kill $tp 2>/dev/null; wait $tp 2>/dev/null || true
    result timeline INFO "connect $k: session up on the BNG ${ms} ms after enable; frames:"
    # -ttt: time since the previous frame; one line per frame, the PPP part.
    sed -E 's/ethertype PPPoE (D|S) \(0x886[34]\), length [0-9]+: //' "$W/timeline$k.txt" \
      | cut -c1-190 | sed 's/^/    /' | tee -a "$W/results.txt"
    pc_down c1; wait_for 15 cr_gone cpe1 >/dev/null || true
    sleep 2
  done
}

case_client() {
  # The reverse direction: the CoreRouter as a PPPoE client of a RouterOS
  # pppoe-server. There is no interface.pppoe-client yet.
  if ip netns exec crgcore "$bin/corerouter-cli" --connect 127.0.0.1:7991 list interface.pppoe-client 2>/dev/null | grep -q pppoe-client; then
    result client INFO "interface.pppoe-client exists: write this case"
  else
    result client INFO "no PPPoE client in the CoreRouter (interface.pppoe-client); gap G3.9ga"
  fi
}

for c in "${CASES[@]}"; do
  echo "=== $c ==="
  "case_$c" || result "$c" FAIL "the case stopped: exit $?"
done
echo
echo "=== results (RouterOS $ROS_VERSION CHR × CoreRouter $(git rev-parse --short HEAD 2>/dev/null || echo ?)) ==="
cat "$W/results.txt"
if [ $FAILED != 0 ]; then
  dump || true
  echo "--- CR daemon log (tail) ---"; tail -20 "$W/daemon.log"
fi
exit $FAILED
