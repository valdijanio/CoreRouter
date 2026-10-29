#!/usr/bin/env bash
# G3.4l: how often does ospfd abort with TI-LFA on (FRR assert in
# get_reverse_distance)? Only OSPF and TI-LFA, no LDP, no BFD, no CoreRouter:
# every router is a zebra + ospfd of its own (-N) in a namespace, and each
# iteration builds the topology, starts them in sequence, lets OSPF converge,
# flaps one link and checks that every ospfd is still alive. Root inside the
# lab VM only:
#   cargo xtask vm-lab put frr-dbg.tar.gz
#   cargo xtask vm-lab run -- scripts/frr-tilfa-repro.sh \
#     --frr /srv/lab/inbox/frr-dbg.tar.gz --topo square --sr on --runs 50
# --frr: a tarball of an FRR built with --prefix=/opt/frr-dbg (extracted
#   there), or "system" for the VM's /usr/lib/frr.
# --topo: pair (R1–R2), line (R1–R2–R3), triangle, square (the one of
#   frr-sr-live.sh: R1–R2–R3–R4–R1, R3–R4 cost 20).
# --sr on|off: segment-routing in ospfd (TI-LFA runs its SPFs either way).
# --protection link|node.
# --churn flap|rid: after convergence, flap R1's first link (default), or
#   also change R1's router-id (its old router-LSA is flushed and leaves
#   the LSDB while the neighbors' LSAs still name it), or remove R1's
#   "router ospf" (the same flush, as hal-frr does between frr-sr-live
#   tests); R1 is then left out of the checks.
# Each abort leaves its ospfd log and core in $out (default
# /srv/lab/tilfa-repro/<label>), with a line in $out/summary.txt.
set -euo pipefail
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
frr=system topo=square sr=on runs=50 protection=link settle=8 churn=flap label="" out=""
while [ $# -gt 0 ]; do
  case $1 in
    --frr) frr=$2; shift 2 ;;
    --topo) topo=$2; shift 2 ;;
    --sr) sr=$2; shift 2 ;;
    --runs) runs=$2; shift 2 ;;
    --protection) protection=$2; shift 2 ;;
    --settle) settle=$2; shift 2 ;;
    --churn) churn=$2; shift 2 ;;
    --label) label=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
done
if [ "$frr" = system ]; then
  bin=/usr/lib/frr vtysh=vtysh
else
  rm -rf /opt/frr-dbg
  tar -C / -xzf "$frr"
  bin=/opt/frr-dbg/lib/frr vtysh=/opt/frr-dbg/bin/vtysh
fi
label=${label:-$(basename "$frr" .tar.gz)-$topo-sr$sr-$protection-$churn}
out=${out:-/srv/lab/tilfa-repro/$label}
mkdir -p "$out"
: > "$out/summary.txt"
modprobe mpls_router
modprobe mpls_iptunnel
# Cores of the daemons (they run as frr after dropping root).
old_pattern=$(cat /proc/sys/kernel/core_pattern)
old_dumpable=$(cat /proc/sys/fs/suid_dumpable)
mkdir -p "$out/cores"
sysctl -qw "kernel.core_pattern=$out/cores/core.%e.%p.%t" fs.suid_dumpable=2
ulimit -c unlimited
case $topo in
  pair) nodes=(1 2); links=("1 2 10") ;;
  line) nodes=(1 2 3); links=("1 2 10" "2 3 10") ;;
  triangle) nodes=(1 2 3); links=("1 2 10" "2 3 10" "1 3 10") ;;
  square) nodes=(1 2 3 4); links=("1 2 10" "2 3 10" "3 4 20" "1 4 10") ;;
  *) echo "unknown topology $topo"; exit 2 ;;
esac
cleanup() {
  pkill -f -- "-N crtl" 2>/dev/null || true
  for _ in $(seq 30); do pgrep -f -- "-N crtl" >/dev/null || break; sleep 0.1; done
  pkill -9 -f -- "-N crtl" 2>/dev/null || true
  for n in 1 2 3 4; do ip netns del crtl$n 2>/dev/null || true; rm -rf "/etc/frr/crtl$n" "/var/run/frr/crtl$n"; done
}
finish() {
  cleanup
  sysctl -qw "kernel.core_pattern=$old_pattern" "fs.suid_dumpable=$old_dumpable"
}
trap finish EXIT
# interface names: tA-B is A's side of the A–B link
build() {
  for n in "${nodes[@]}"; do
    ip netns add crtl$n
    ip -n crtl$n link set lo up
    ip -n crtl$n addr add 10.255.0.$n/32 dev lo
    ip netns exec crtl$n sysctl -qw net.mpls.platform_labels=1048575 net.ipv4.ip_forward=1
  done
  for l in "${links[@]}"; do
    read -r a b c <<<"$l"
    ip -n crtl$a link add t$a-$b type veth peer name t$b-$a netns crtl$b
    ip -n crtl$a addr add 10.0.$a$b.1/30 dev t$a-$b
    ip -n crtl$b addr add 10.0.$a$b.2/30 dev t$b-$a
    ip -n crtl$a link set t$a-$b up
    ip -n crtl$b link set t$b-$a up
    ip netns exec crtl$a sysctl -qw "net.mpls.conf.t$a-$b.input=1"
    ip netns exec crtl$b sysctl -qw "net.mpls.conf.t$b-$a.input=1"
  done
}
start() {
  local n=$1 d=/etc/frr/crtl$1
  install -d -o frr -g frr "$d" "/var/run/frr/crtl$n"
  : > "$d/vtysh.conf"
  : > "$d/zebra.conf"
  {
    printf 'debug ospf ti-lfa\ndebug ospf spf\ndebug ospf lsa install\n'
    for l in "${links[@]}"; do
      read -r a b c <<<"$l"
      local i=""
      [ "$a" = "$n" ] && i=t$a-$b
      [ "$b" = "$n" ] && i=t$b-$a
      [ -n "$i" ] || continue
      printf 'interface %s\n ip ospf network point-to-point\n ip ospf hello-interval 1\n' "$i"
      printf ' ip ospf dead-interval 4\n ip ospf cost %s\n ip ospf area 0.0.0.0\nexit\n' "$c"
    done
    printf 'interface lo\n ip ospf area 0.0.0.0\n ip ospf passive\nexit\n'
    printf 'router ospf\n ospf router-id 10.255.0.%s\n' "$n"
    if [ "$sr" = on ]; then
      printf ' capability opaque\n router-info area\n segment-routing on\n'
      printf ' segment-routing prefix 10.255.0.%s/32 index %s\n' "$n" "$n"
    fi
    if [ "$protection" = node ]; then printf ' fast-reroute ti-lfa node-protection\nexit\n'; else printf ' fast-reroute ti-lfa\nexit\n'; fi
  } > "$d/ospfd.conf"
  chown -R frr:frr "$d"
  ip netns exec crtl$n "$bin/zebra" -N crtl$n -d -f "$d/zebra.conf" --log "file:$d/zebra.log" </dev/null >/dev/null 2>&1
  for _ in $(seq 50); do [ -S "/var/run/frr/crtl$n/zserv.api" ] && break; sleep 0.1; done
  ip netns exec crtl$n "$bin/ospfd" -N crtl$n -d -f "$d/ospfd.conf" --log "file:$d/ospfd.log" </dev/null >/dev/null 2>&1
}
alive() { pgrep -f -- "ospfd -N crtl$1( |$)" >/dev/null; }
aborts=0 bad_routes=0 started=$(date +%s)
echo "G3.4l repro: $label, FRR $("$bin/ospfd" --version 2>/dev/null | head -n 1), $runs runs" | tee -a "$out/summary.txt"
for run in $(seq "$runs"); do
  cleanup
  build
  for n in "${nodes[@]}"; do start "$n"; done
  sleep "$settle"
  if [ "$churn" = rid ]; then
    "$vtysh" -N crtl1 -c "configure terminal" -c "router ospf" -c "ospf router-id 10.255.1.1" \
      -c "end" -c "clear ip ospf process" >/dev/null 2>&1 || true
    sleep 8
  elif [ "$churn" = remove ]; then
    "$vtysh" -N crtl1 -c "configure terminal" -c "no router ospf" -c "end" >/dev/null 2>&1 || true
    sleep 8
  fi
  # A flap on R1's first link: new router-LSAs, new SPF + TI-LFA runs.
  read -r a b _ <<<"${links[0]}"
  ip -n crtl$a link set t$a-$b down
  sleep 2
  ip -n crtl$a link set t$a-$b up
  sleep 6
  dead=()
  for n in "${nodes[@]}"; do alive "$n" || dead+=("$n"); done
  check=("${nodes[@]}")
  [ "$churn" = remove ] && check=("${nodes[@]:1}")
  if [ ${#dead[@]} -gt 0 ]; then
    aborts=$((aborts + 1))
    for n in "${dead[@]}"; do
      cp "/etc/frr/crtl$n/ospfd.log" "$out/run$run-R$n-ospfd.log"
      why=$(grep -m1 -E "assert|signal|Received signal" "/etc/frr/crtl$n/ospfd.log" | cut -c1-200 || true)
      last=$(grep "G34L reverse-spf" "/etc/frr/crtl$n/ospfd.log" | tail -n 1 | cut -c1-300 || true)
      echo "run $run: R$n ospfd died: $why | last reverse-spf: $last" | tee -a "$out/summary.txt"
    done
  else
    # Every router must reach every loopback (the SPF is still right).
    for n in "${check[@]}"; do
      for m in "${check[@]}"; do
        [ "$n" = "$m" ] && continue
        ip -n crtl$n route show 10.255.0.$m | grep -q . || { bad_routes=$((bad_routes + 1)); echo "run $run: R$n has no route to 10.255.0.$m" | tee -a "$out/summary.txt"; }
      done
    done
    if [ "$run" = 1 ]; then
      "$vtysh" -N crtl1 -c "show ip route ospf" > "$out/run1-R1-routes.txt" 2>&1 || true
      ip -n crtl1 route show > "$out/run1-R1-kernel.txt" 2>&1 || true
      ip -n crtl1 -f mpls route show >> "$out/run1-R1-kernel.txt" 2>&1 || true
    fi
  fi
  absent=$(cat /etc/frr/crtl*/ospfd.log 2>/dev/null | grep -c "G34L reverse-spf.*ABSENT" || true)
  [ "$absent" -gt 0 ] && echo "run $run: $absent reverse-SPF links to an ABSENT router-LSA" | tee -a "$out/summary.txt"
  [ "$run" = 1 ] && cp /etc/frr/crtl1/ospfd.log "$out/run1-R1-ospfd.log"
done
echo "result: $aborts of $runs runs with an ospfd abort, $bad_routes missing routes, $(( $(date +%s) - started )) s" | tee -a "$out/summary.txt"
ls "$out/cores" | sed 's/^/core: /' | tee -a "$out/summary.txt"
