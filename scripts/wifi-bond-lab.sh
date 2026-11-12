#!/usr/bin/env bash
# G1.30m part 2: bonding over Wi-Fi backhaul links, end to end, with traffic.
# Two CoreRouters (the image's daemon, hostapd and wpa_supplicant, run from
# the image's root in a chroot), each in its own network namespace with two
# simulated radios (mac80211_hwsim), joined by two station-bridge links on
# different channels and a bond over them. Runs as root inside the lab VM
# only; the host side puts the image there first:
#
#   cargo xtask vm-lab put <images>/rootfs.squashfs <images>/test-tools/iw
#   cargo xtask vm-lab run -- scripts/wifi-bond-lab.sh
#
# (`scripts/wifi-bond-lab.sh --host <images>` on the host does both.)
#
# Topology:
#
#   ns crwa (router A, access points)        ns crwb (router B, station-bridges)
#   wifi1 AP ch 36  ── peer1 ─ ─ ─ ─ ─ ─ ─ ─ wifi1 station-bridge ┐
#   wifi2 AP ch 149 ── peer2 ─ ─ ─ ─ ─ ─ ─ ─ wifi2 station-bridge ┘
#   bond1 = peer1 + peer2 in bridge1          bond1 = wifi1 + wifi2 in bridge1
#   bridge1 10.30.0.1/24                      bridge1 10.30.0.2/24
#
# Checks, per bond mode: the peers up on A; LACP (802.3ad) with the other
# end as partner on both sides; a ping across the bridges; iperf3 across;
# in active-backup, one link down (B's wifi1 off) and the pings that went
# missing. Results: a table at the end and /tmp/crwlab/results.txt in the VM;
# exit 1 if a check failed.
set -euo pipefail

if [ "${1:-}" = "--host" ]; then
	IMAGES=${2:?usage: $0 --host <images dir>}
	# A round first: an unhealthy VM goes back to its snapshot there, which
	# would drop what `put` copied.
	cargo xtask vm-lab run -- true
	cargo xtask vm-lab put "$IMAGES/rootfs.squashfs" "$IMAGES/test-tools/iw"
	exec cargo xtask vm-lab run -- scripts/wifi-bond-lab.sh
fi

# vm-lab run holds its lock on fd 9: the daemons started here must not.
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }

INBOX=/srv/lab/inbox
W=/tmp/crwlab
R=$W/root
SSID1=CR-Backhaul-36
SSID2=CR-Backhaul-149
PASS=lab-backhaul-only
MODES=(${MODES:-802.3ad active-backup balance-rr})
RESULTS=$W/results.txt
FAILED=0

say() { printf '%s\n' "$*" | tee -a "$RESULTS"; }
fail() { say "FAIL $*"; FAILED=1; }

cleanup() {
	set +e
	for ns in crwa crwb; do
		ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
	done
	sleep 1
	for ns in crwa crwb; do
		ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null
		ip netns del "$ns" 2>/dev/null
	done
	modprobe -r mac80211_hwsim 2>/dev/null
	umount -l "$R" 2>/dev/null
	umount -l "$W/lower" 2>/dev/null
	umount -l "$W/rw" 2>/dev/null
}
trap cleanup EXIT

cleanup
rm -rf "$W"
mkdir -p "$W"/{lower,rw,root,a,b}
: > "$RESULTS"

# The image's root, writable on top.
for f in rootfs.squashfs iw; do
	[ -s "$INBOX/$f" ] || { echo "$INBOX/$f missing: run with --host <images> from the host"; exit 1; }
done
modprobe loop 2>/dev/null || true
mount -t squashfs -o loop,ro "$INBOX/rootfs.squashfs" "$W/lower" || { echo "cannot mount the image's root"; exit 1; }
mount -t tmpfs tmpfs "$W/rw"
mkdir -p "$W/rw/upper" "$W/rw/work"
install -m 0755 "$INBOX/iw" "$W/iw"
mount -t overlay overlay -o "lowerdir=$W/lower,upperdir=$W/rw/upper,workdir=$W/rw/work" "$R" ||
	{ echo "cannot mount the overlay"; exit 1; }

# In namespace $1, with $1's own /run and /tmp, the image's root: `$2…`.
in_ns() {
	local ns=$1 side=${1#crw}
	shift
	ip netns exec "$ns" unshare --mount sh -c '
		R=$1; S=$2; shift 2
		mount -t proc proc "$R/proc"
		mount -t sysfs sys "$R/sys"
		mount --rbind /dev "$R/dev"
		mount --bind "$S/run" "$R/run"
		mount --bind "$S/tmp" "$R/tmp"
		exec chroot "$R" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/tmp \
			COREROUTER_RUNTIME_DIR=/run/corerouter "$@"' sh "$R" "$W/$side" "$@"
}

# A command of router $1 (crwa, crwb), its JSON reply on stdout.
cr() {
	local ns=$1
	shift
	in_ns "$ns" /usr/sbin/corerouter-init run "$@"
}

# The reply's `ok` must be true.
ok() {
	local out
	out=$(cr "$@") || true
	if ! printf '%s' "$out" | grep -q '"ok": *true'; then
		echo "command failed on $1: ${*:2} → $out" >&2
		return 1
	fi
	printf '%s\n' "$out"
}

# Wait up to $2 s for `$3…` (a shell condition) to hold.
until_s() {
	local what=$1 secs=$2
	shift 2
	local end=$((SECONDS + secs))
	while ! eval "$@" >/dev/null 2>&1; do
		if [ $SECONDS -ge $end ]; then
			fail "$what (after ${secs}s)"
			return 1
		fi
		sleep 1
	done
}

# --- Radios: four, two per namespace, named wifi1 and wifi2 in each.
modprobe mac80211_hwsim radios=4
sleep 1
ip netns add crwa
ip netns add crwb
mapfile -t WLANS < <(for d in /sys/class/net/*/phy80211; do basename "$(dirname "$d")"; done | sort)
[ ${#WLANS[@]} -ge 4 ] || { echo "hwsim gave ${#WLANS[@]} radios"; exit 1; }
# iw moves a wiphy into the namespace of a process: one that waits in
# each.
declare -A HOLDER
for ns in crwa crwb; do
	ip netns exec "$ns" sleep 100000 &
	HOLDER[$ns]=$!
done
sleep 0.3
i=0
for wl in "${WLANS[@]:0:4}"; do
	phy=$(basename "$(readlink "/sys/class/net/$wl/phy80211")")
	if [ $i -lt 2 ]; then ns=crwa; else ns=crwb; fi
	# iw reads the phy's index from /sys: run it outside the chroot (its
	# libraries, libnl, are the VM's too).
	"$W/iw" phy "$phy" set netns "${HOLDER[$ns]}" 2>/dev/null
	i=$((i + 1))
done
for ns in crwa crwb; do
	n=1
	for wl in $(ip -n "$ns" -o link | awk -F': ' '/wlan/ {print $2}' | sort); do
		ip -n "$ns" link set "$wl" name "wifi$n"
		n=$((n + 1))
	done
	ip -n "$ns" link set lo up
done
ip -n crwa -o link | grep -q wifi2 && ip -n crwb -o link | grep -q wifi2 ||
	{ echo "radios not in the namespaces"; ip -n crwa link; ip -n crwb link; exit 1; }

# --- Two routers.
for side in a b; do
	mkdir -p "$W/$side/run/corerouter" "$W/$side/tmp/cfg"
	in_ns "crw$side" /usr/bin/corerouter-daemon --backend linux --config-dir /tmp/cfg \
		--control 7979 >"$W/$side/daemon.log" 2>&1 &
done
for ns in crwa crwb; do
	until_s "$ns daemon up" 60 "cr $ns interface.wifi.list '{}' | grep -q wifi2" ||
		{ tail -n 30 "$W/${ns#crw}/daemon.log"; exit 1; }
done
say "radios: wifi1 and wifi2 in each namespace, adopted by its router"

for ns in crwa crwb; do
	ok "$ns" interface.wifi.country.set '{"country":"BR"}' >/dev/null
	ok "$ns" interface.bridge.add '{"name":"bridge1"}' >/dev/null
done

# B: two station-bridges in a bond, the bond in the bridge.
for r in wifi1 wifi2; do
	ssid=$SSID1
	[ $r = wifi2 ] && ssid=$SSID2
	ok crwb interface.wifi.set "{\"name\":\"$r\",\"mode\":\"station-bridge\",\"ssid\":\"$ssid\",\"passphrase\":\"$PASS\",\"disabled\":false}" >/dev/null
done

# A: two access points that take only their peers.
ok crwa interface.wifi.set "{\"name\":\"wifi1\",\"mode\":\"ap\",\"ssid\":\"$SSID1\",\"passphrase\":\"$PASS\",\"station_bridge\":\"only\",\"frequency\":\"36\",\"width\":\"20\",\"disabled\":false}" >/dev/null
ok crwa interface.wifi.set "{\"name\":\"wifi2\",\"mode\":\"ap\",\"ssid\":\"$SSID2\",\"passphrase\":\"$PASS\",\"station_bridge\":\"only\",\"frequency\":\"149\",\"width\":\"20\",\"disabled\":false}" >/dev/null

setup_bonds() {
	local mode=$1
	for ns in crwa crwb; do
		cr "$ns" interface.bridge.port.remove '{"bridge":"bridge1","interface":"bond1"}' >/dev/null || true
		cr "$ns" interface.remove '{"name":"bond1"}' >/dev/null || true
	done
	local lacp=""
	[ "$mode" = 802.3ad ] && lacp=',"lacp_rate":"1sec"'
	ok crwb interface.bonding.add "{\"name\":\"bond1\",\"slaves\":[\"wifi1\",\"wifi2\"],\"mode\":\"$mode\"$lacp}" >/dev/null
	ok crwb interface.bridge.port.add '{"bridge":"bridge1","interface":"bond1"}' >/dev/null
	# The peers' MAC: B's bond's (it gave its slaves its own).
	local mac
	until_s "B bond1 MAC" 20 "ip -n crwb link show bond1 | grep -q ether"
	mac=$(ip -n crwb -o link show bond1 | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')
	for p in peer1 peer2; do
		cr crwa interface.wifi.peer.remove "{\"name\":\"$p\"}" >/dev/null || true
	done
	ok crwa interface.wifi.peer.add "{\"radio\":\"wifi1\",\"name\":\"peer1\",\"mac_address\":\"$mac\"}" >/dev/null
	ok crwa interface.wifi.peer.add "{\"radio\":\"wifi2\",\"name\":\"peer2\",\"mac_address\":\"$mac\"}" >/dev/null
	ok crwa interface.bonding.add "{\"name\":\"bond1\",\"slaves\":[\"peer1\",\"peer2\"],\"mode\":\"$mode\"$lacp}" >/dev/null
	ok crwa interface.bridge.port.add '{"bridge":"bridge1","interface":"bond1"}' >/dev/null
}

ok crwa ip.address.add '{"address":"10.30.0.1/24","interface":"bridge1"}' >/dev/null
ok crwb ip.address.add '{"address":"10.30.0.2/24","interface":"bridge1"}' >/dev/null

for mode in "${MODES[@]}"; do
	say "== $mode"
	t0=$SECONDS
	setup_bonds "$mode"
	if ! until_s "$mode: both peers up on A" 90 \
		"[ \$(cr crwa interface.wifi.peer.print '{}' | grep -c '\"state\": *\"up\"') -ge 2 ]"; then
		cr crwa interface.wifi.history '{}' | tail -n 40
		cr crwb interface.wifi.history '{}' | tail -n 40
		continue
	fi
	say "$mode: both links up in $((SECONDS - t0)) s"
	if [ "$mode" = 802.3ad ]; then
		until_s "802.3ad: LACP partner on both sides" 60 \
			"ip netns exec crwa grep -q 'Partner Mac Address: [0-9a-f:]*[1-9a-f]' /proc/net/bonding/bond1 && ip netns exec crwb grep -c 'Partner Mac Address: [0-9a-f:]*[1-9a-f]' /proc/net/bonding/bond1 | grep -q 2" &&
			say "802.3ad: LACP up, $(ip netns exec crwb grep -c 'Partner Mac Address' /proc/net/bonding/bond1) ports with a partner on B"
	fi
	if until_s "$mode: ping across the bridges" 30 "ip netns exec crwb ping -c 1 -W 1 10.30.0.1"; then
		say "$mode: ping $(ip netns exec crwb ping -c 20 -i 0.05 -q 10.30.0.1 | tail -n 2 | tr '\n' ' ')"
	fi
	ip netns exec crwa iperf3 -s -1 -D -I "$W/iperf.pid" >/dev/null 2>&1
	sleep 0.5
	bps=$(ip netns exec crwb iperf3 -c 10.30.0.1 -t 5 -P 4 -J 2>/dev/null |
		sed -n 's/.*"bits_per_second": *\([0-9.e+]*\).*/\1/p' | tail -n 1)
	if [ -n "$bps" ]; then
		say "$mode: iperf3 B→A, 4 streams, 5 s: $(awk -v b="$bps" 'BEGIN{printf "%.1f Mbit/s", b/1e6}')"
	else
		fail "$mode: iperf3 gave no number"
	fi
	if [ "$mode" = active-backup ]; then
		ip netns exec crwb ping -i 0.1 -c 150 10.30.0.1 >"$W/failover.txt" 2>&1 &
		ping_pid=$!
		sleep 3
		active=$(ip netns exec crwb sed -n 's/^Currently Active Slave: //p' /proc/net/bonding/bond1)
		ok crwb interface.wifi.disable "{\"name\":\"$active\"}" >/dev/null
		wait $ping_pid || true
		lost=$(sed -n 's/.* \([0-9]*\) received.*/\1/p' "$W/failover.txt")
		now=$(ip netns exec crwb sed -n 's/^Currently Active Slave: //p' /proc/net/bonding/bond1)
		if [ -n "$now" ] && [ "$now" != "$active" ] && [ "${lost:-0}" -gt 0 ]; then
			say "active-backup: $active off, traffic on $now; $((150 - lost)) of 150 pings lost (100 ms apart: ~$(((150 - lost) * 100)) ms)"
		else
			fail "active-backup: no failover from $active ($(tail -n 2 "$W/failover.txt" | tr '\n' ' '))"
		fi
		ok crwb interface.wifi.enable "{\"name\":\"$active\"}" >/dev/null
	fi
	say "$mode: peers on A: $(cr crwa interface.wifi.peer.print '{}' | tr -d ' \n' | grep -o '"name":"peer[12]"[^}]*"airtime_percent":[^,}]*' | sed 's/"tx_rate.*"uptime_secs"/ … "uptime_secs"/' | tr '\n' ' ')"
done

say ""
say "results:"
cat "$RESULTS"
exit $FAILED
