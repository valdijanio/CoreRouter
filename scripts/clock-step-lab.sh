#!/bin/bash
# G0.13: a real daemon's deadlines across steps of the wall clock.
#
# Root, in the lab VM only: it stops NTP, steps CLOCK_REALTIME a year ahead
# and two years back, and puts it back (and NTP) at the end. The router runs
# with the Linux backend inside its own network namespace (it sees only one
# end of a veth pair, never the VM's cards); a busybox `udhcpc` in a second
# namespace takes a lease from it.
#
#   cargo xtask vm-lab run -- scripts/clock-step-lab.sh
#
# After each step it prints, from the router: the lease's time left and
# state, the dynamic address-list entries' time left, a ping task's state,
# and the router log's line about the step. Each must keep counting down
# from where it was, not end (step ahead) or freeze (step back).
set -u
if [ "$(id -u)" != 0 ]; then
    echo "root only, in the lab VM: cargo xtask vm-lab run -- scripts/clock-step-lab.sh" >&2
    exit 2
fi
cargo build -q -p corerouter-daemon -p corerouter-cli || exit 1
T=${CARGO_TARGET_DIR:-target}/debug
W=$(mktemp -d /tmp/crg13.XXXX)
export COREROUTER_RUNTIME_DIR=$W/run
R=crg13r
C=crg13c
ip netns del $R 2>/dev/null
ip netns del $C 2>/dev/null
ip netns add $R
ip netns add $C
ip link add vr type veth peer name vc
ip link set vr netns $R
ip link set vc netns $C
ip -n $R link set lo up
ip -n $C link set lo up
ip -n $C link set vc up
ip -n $R link set vr up

ntp=$(systemctl is-active systemd-timesyncd 2>/dev/null)
systemctl stop systemd-timesyncd 2>/dev/null
t0=$(date +%s)
u0=$(awk '{print int($1)}' /proc/uptime)
D=
cleanup() {
    date -s "@$((t0 + $(awk '{print int($1)}' /proc/uptime) - u0))" >/dev/null
    [ "$ntp" = active ] && systemctl start systemd-timesyncd
    [ -n "$D" ] && kill "$D" 2>/dev/null
    wait 2>/dev/null
    ip netns del $R 2>/dev/null
    ip netns del $C 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT

ip netns exec $R "$T/corerouter-daemon" --backend linux --manage vr --config-dir "$W/cfg" \
    --control 17979 --no-discovery >"$W/d.log" 2>&1 &
D=$!
cli() { ip netns exec $R "$T/corerouter-cli" --connect 127.0.0.1:17979 run "$@" 2>&1 | grep -v WARN; }
for _ in $(seq 1 150); do
    cli interface.list | grep -q '"name"' && break
    sleep 0.2
done

for step in \
    'ip.address.add {"address":"10.13.0.1/24","interface":"vr"}' \
    'ip.pool.add {"name":"subs","ranges":"10.13.0.10-10.13.0.99"}' \
    'ip.dhcp-server.add {"interface":"vr","address_pool":"subs","lease_time":"10m","conflict_detection":false,"address_lists":"subscribers"}' \
    'ip.dhcp-server.network.add {"address":"10.13.0.0/24","gateway":"10.13.0.1"}' \
    'ip.firewall.address-list.add {"list":"blocked","address":"192.0.2.7","timeout":600}'; do
    out=$(cli ${step%% *} "${step#* }")
    case "$out" in *rror*|*refused*|*unknown*) echo "setup: ${step%% *}: $out" ;; esac
done
sleep 2
if ! ip netns exec $C busybox udhcpc -i vc -n -q -t 10 -T 1 -s /bin/true >/dev/null 2>&1; then
    echo "udhcpc got no lease; the router side:"
    ip -n $R -br addr
    cli interface.list '{}' | tr -d ' \n' | cut -c1-400
    echo
    cli ip.address.list '{}' | tr -d ' \n' | cut -c1-300
    echo
    grep -iE "warn|error" "$W/d.log" | head -5
    cli ip.dhcp-server.print '{}' | tr -d ' \n' | cut -c1-600
    echo
    cli system.service.print '{}' | tr -d ' \n' | grep -o '"name":"dhcp-server"[^}]*' | cut -c1-300
fi
cli tool.ping.start '{"address":"10.13.0.1","count":0,"interval_ms":1000}' >/dev/null

show() {
    echo "--- $1 (wall: $(date -u +%FT%TZ))"
    cli ip.dhcp-server.lease.print '{}' | grep -E '"(address|status|expires_after_secs)"' | tr -d ' \n'
    echo
    cli ip.firewall.address-list.list '{}' | grep -E '"(list|timeout)"' | tr -d ' \n'
    echo
    cli tool.task.list '{}' | grep -E '"(state|age_secs|reason)"' | tr -d ' \n'
    echo
}

sleep 2
show "before"
date -s "+1 year" >/dev/null
sleep 3
show "a year ahead"
date -s "-2 years" >/dev/null
sleep 3
show "a year back"
echo "--- router log"
cli log.print '{}' | grep -o 'O relógio de parede deu um passo de [^"]*' | cut -c1-80
grep -iE "panic|error|dhcp" "$W/d.log" | head -8
