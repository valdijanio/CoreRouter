#!/bin/bash
# G3.4q: FRR's zebra + ospfd with thousands of OSPF interfaces, without root
# (a user + network + mount namespace) and without the rest of CoreRouter.
#
#   scripts/frr-ospf-many-ifaces.sh --frr <install root> [--prefix /opt/frr-q] \
#       [--n 4000] [--out <dir>] [--kdel one|group] [--perf]
#
# <install root> is a "make install DESTDIR=<root>" of FRR configured with
# --prefix=<prefix> --sbindir=<prefix>/lib/frr --localstatedir=/run/frr-q
# --sysconfdir=/etc/frr-q (docs/frr-many-interfaces.md has the configure line);
# the prefix is mounted over <prefix> inside the namespace only.
#
# Phases (one line each in <out>/phases.txt: wall s, ospfd and zebra CPU s):
#   kernel-add  N 802.1Q VLANs with a /30 each (ip -batch)
#   ospf-add    "interface X / ip ospf network point-to-point / ip ospf area 0"
#               for all of them in one `vtysh -f` (a configuration batch:
#               XFRR_start/end_configuration, as hal-frr types it too)
#   spf         5 times: one interface's cost changed, the last SPF's duration
#   ospf-del    the same stanzas with "no ip ospf …"
#   kernel-del  the VLANs out, one RTM_DELLINK each (--kdel one, what
#               hal-linux does) or all in one by group (--kdel group)
# Each phase ends when ospfd and zebra are idle (< 30 ms of CPU in 1.5 s).
set -euo pipefail

FRR="" PREFIX=/opt/frr-q N=4000 OUT="" KDEL=one PERF=""
while [ $# -gt 0 ]; do
	case $1 in
	--frr) FRR=$2; shift 2 ;;
	--prefix) PREFIX=$2; shift 2 ;;
	--n) N=$2; shift 2 ;;
	--out) OUT=$2; shift 2 ;;
	--kdel) KDEL=$2; shift 2 ;;
	--perf) PERF=1; shift ;;
	--inside) INSIDE=1; shift ;;
	*) echo "unknown option $1" >&2; exit 2 ;;
	esac
done
[ -n "$FRR" ] && [ -d "$FRR$PREFIX/lib/frr" ] || { echo "--frr <install root> with $PREFIX/lib/frr in it" >&2; exit 2; }
case $N in '' | *[!0-9]*) echo "--n must be a number" >&2; exit 2 ;; esac
[ "$N" -le 16000 ] || { echo "--n: at most 16000 (4 dummies of 4000 VLANs)" >&2; exit 2; }
OUT=${OUT:-$(mktemp -d /tmp/frr-many-ifaces.XXXXXX)}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

if [ -z "${INSIDE:-}" ]; then
	exec unshare --user --map-root-user --net --mount --fork "$0" --inside \
		--frr "$(cd "$FRR" && pwd)" --prefix "$PREFIX" --n "$N" --out "$OUT" \
		--kdel "$KDEL" ${PERF:+--perf}
fi

# --- inside the namespaces ---------------------------------------------------
mount -t tmpfs tmpfs /run
S=/run/frr-q/run/frr
mkdir -p "$S" /run/frr-q/lib/frr
# a tmpfs over the prefix's first directory (/opt), then the build on the prefix
top=${PREFIX#/}
top=${top%%/*}
mount -t tmpfs tmpfs "/$top"
mkdir -p "$PREFIX"
mount --bind "$FRR$PREFIX" "$PREFIX"
export LD_LIBRARY_PATH=$PREFIX/lib
ip link set lo up
ulimit -n 65536

: >"$OUT/empty.conf"
"$PREFIX/lib/frr/mgmtd" -d -u root -g root -i "$S/mgmtd.pid" --log file:"$OUT/mgmtd.log"
sleep 0.5
"$PREFIX/lib/frr/zebra" -d -u root -g root -f "$OUT/empty.conf" -i "$S/zebra.pid" \
	--log file:"$OUT/zebra.log" --limit-fds 65536
sleep 1
printf 'router ospf\n ospf router-id 10.255.0.1\nexit\n' >"$OUT/ospf.conf"
"$PREFIX/lib/frr/ospfd" -d -u root -g root -f "$OUT/ospf.conf" -i "$S/ospfd.pid" \
	--log file:"$OUT/ospfd.log" --limit-fds 65536
sleep 1
OPID=$(cat "$S/ospfd.pid") ZPID=$(cat "$S/zebra.pid") MPID=$(cat "$S/mgmtd.pid")
trap 'kill $OPID $ZPID $MPID 2>/dev/null || true' EXIT

vtysh() { "$PREFIX/bin/vtysh" --vty_socket "$S" "$@"; }
ospf_json() { vtysh -d ospfd -c "$1"; }
cpu() { awk '{print $14 + $15}' "/proc/$1/stat"; }
TCK=$(getconf CLK_TCK)
now() { date +%s.%N; }
settle() {
	local a b c d
	while :; do
		a=$(cpu "$OPID") b=$(cpu "$ZPID")
		sleep 1.5
		c=$(cpu "$OPID") d=$(cpu "$ZPID")
		[ $((c - a)) -lt 3 ] && [ $((d - b)) -lt 3 ] && return
	done
}
json() { python3 -I -c "import json, sys; d = json.load(sys.stdin); print($1)"; }
ifs_in_ospf() { ospf_json 'show ip ospf json' | json 'sum(a.get("areaIfTotalCounter", 0) for a in d.get("areas", {}).values())'; }
perf_start() {
	[ -n "$PERF" ] || return 0
	perf record -F 999 -g -p "$OPID,$ZPID" -o "$OUT/perf-$1.data" >/dev/null 2>&1 &
	PERFPID=$!
	sleep 0.3
}
perf_stop() {
	[ -n "$PERF" ] || return 0
	kill -INT "$PERFPID"
	wait "$PERFPID" || true
	perf report -i "$OUT/perf-$1.data" --stdio --no-children --sort comm,symbol -g none \
		--percent-limit 0.8 2>/dev/null | grep -v '^#' | grep -v '^$' | head -n 30 >"$OUT/perf-$1.txt" || true
}
phase() { # <name> <command…>
	local name=$1 t0 o0 z0 t1 o1 z1
	shift
	perf_start "$name"
	o0=$(cpu "$OPID") z0=$(cpu "$ZPID") t0=$(now)
	"$@"
	settle
	t1=$(now) o1=$(cpu "$OPID") z1=$(cpu "$ZPID")
	perf_stop "$name"
	awk -v n="$name" -v N="$N" -v t0="$t0" -v t1="$t1" -v o=$((o1 - o0)) -v z=$((z1 - z0)) -v k="$TCK" \
		'BEGIN {printf "%s n=%d wall=%.1f ospfd_cpu=%.1f zebra_cpu=%.1f\n", n, N, t1 - t0 - 1.5, o / k, z / k}' |
		tee -a "$OUT/phases.txt"
}

# VLAN i (1-based) on dummy d<(i-1)/4000>, VLAN id (i-1)%4000+1, 10.x.y.z/30.
: >"$OUT/links-add"
: >"$OUT/links-del"
: >"$OUT/ospf-add.conf"
: >"$OUT/ospf-del.conf"
for k in $(seq 0 $(((N - 1) / 4000))); do
	ip link add "d$k" type dummy
	ip link set "d$k" up
done
for i in $(seq "$N"); do
	a=$((100 + (i - 1) / 16384)) b=$((((i - 1) / 64) % 256)) c=$((((i - 1) % 64) * 4))
	printf 'link add link d%d name crs%d type vlan id %d\nlink set crs%d up\naddress add 10.%d.%d.%d/30 dev crs%d\n' \
		$(((i - 1) / 4000)) "$i" $(((i - 1) % 4000 + 1)) "$i" "$a" "$b" $((c + 1)) "$i" >>"$OUT/links-add"
	echo "link del crs$i" >>"$OUT/links-del"
	printf 'interface crs%d\n ip ospf network point-to-point\n ip ospf area 0.0.0.0\nexit\n' "$i" >>"$OUT/ospf-add.conf"
	printf 'interface crs%d\n no ip ospf area 0.0.0.0\n no ip ospf network point-to-point\nexit\n' "$i" >>"$OUT/ospf-del.conf"
done

type_conf() { vtysh -f "$1" >>"$OUT/vtysh.log" 2>&1; } # one configuration batch
kernel_add() { ip -batch "$OUT/links-add"; }
ospf_add() {
	type_conf "$OUT/ospf-add.conf"
	while [ "$(ifs_in_ospf)" -lt "$N" ]; do sleep 0.5; done
}
ospf_del() {
	type_conf "$OUT/ospf-del.conf"
	while [ "$(ifs_in_ospf)" -gt 0 ]; do sleep 0.5; done
}
kernel_del() {
	if [ "$KDEL" = group ]; then
		sed 's/^link del \(.*\)$/link set \1 group 99/' "$OUT/links-del" | ip -batch -
		ip link del group 99
	else
		ip -batch "$OUT/links-del"
	fi
}
spf() {
	local k
	for k in 1 2 3 4 5; do
		printf 'interface crs1\n ip ospf cost %d\nexit\n' $((10 + k)) >"$OUT/cost.conf"
		type_conf "$OUT/cost.conf"
		sleep 6
		ospf_json 'show ip ospf json' | json 'd.get("spfLastDurationMsecs")'
	done | tr '\n' ' ' | sed "s/^/spf n=$N ms: /; s/ *\$/\n/" | tee -a "$OUT/phases.txt"
}

phase kernel-add kernel_add
phase ospf-add ospf_add
lsa=$(ospf_json 'show ip ospf database router self-originate json' |
	json '"%s links, seq %s" % (lambda l: (l["numOfLinks"], l["lsaSeqNumber"]))(list(d["routerLinkStates"]["areas"].values())[0][0])')
echo "router-LSA after add: $lsa" | tee -a "$OUT/phases.txt"
echo "ospfd log: $(grep -c 'Out of space in LSA stream' "$OUT/ospfd.log" || true) 'Out of space' lines, $(grep -c 'router-LSA is full' "$OUT/ospfd.log" || true) 'is full' lines, $(stat -c %s "$OUT/ospfd.log") bytes" |
	tee -a "$OUT/phases.txt"
spf
# Without the fix, 10 000 interfaces log gigabytes ("Out of space"): counted above.
[ "$(stat -c %s "$OUT/ospfd.log")" -lt $((64 << 20)) ] || truncate -s 0 "$OUT/ospfd.log"
phase ospf-del ospf_del
phase kernel-del kernel_del
echo "results: $OUT/phases.txt"
