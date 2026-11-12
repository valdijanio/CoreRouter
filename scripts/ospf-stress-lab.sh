#!/usr/bin/env bash
# G3.4m: OSPF under load. Puts CoreRouter's OSPF (FRR's ospfd/zebra driven
# by corerouter-daemon) under a big LSDB, LSA churn, many neighbors and
# operations with load, and measures stability and cost. Runs as root inside
# the lab VM only. The load is BNG Blaster's OSPF emulation (one router, "gen",
# with the LSDB that lspgen generates behind it); see docs/ospf-stress.md.
#
#   scripts/ospf-stress-lab.sh --host <images> [options]     (on the host:
#       puts the image's root in the VM and runs the lab there)
#   cargo xtask vm-lab run -- scripts/ospf-stress-lab.sh [options]
#
# Router under test (DUT):
#   --dut local    (default) the image's daemon and FRR (with our patches),
#                  from its root in a chroot, in network namespace crdut;
#                  the generator in namespace crgen, joined by a veth
#                  (crdut: ether1, crgen: gen1).
#   --dut remote --iface <if> --target <addr[:port]> [--mgmt <cidr>]
#                  a router elsewhere (the notebook of phase C): the
#                  generator speaks OSPF on <if> (moved into crgen for the
#                  run, back at the end) and commands go by
#                  `corerouter-cli --connect tls://<addr>` as --user (admin;
#                  password in $COREROUTER_PASSWORD, empty by default).
#                  --mgmt adds that address to <if> to reach <addr>.
#                  --dut-iface: the router's port on the cable (ether1).
#   --selftest-remote  a local DUT that is driven as a remote one: TLS on
#                  10.99.0.1, the veth end crlink0 as <if>.
#
# Tests (--tests, comma-separated; default all but convergence):
#   lsdb        LSDB size steps (--steps 1000,10000,50000,100000,200000)
#   churn       LSAs changing 1..100 per second (--churn-rates, --churn-secs)
#   neighbors   50/100/250 adjacencies over 802.1Q (--neighbors, --stable-secs)
#   ops         commit, Safe Mode rollback, FRR and daemon restarts, on the
#               biggest step that passed
#   latency     p50/p99 of the state commands, inspect and MCP, with load
#   convergence traffic across the DUT and a cut link: without BFD, with BFD,
#               with BFD and TI-LFA (local only)
#
# Results: $OUT/results.md (a table per test) and $OUT/*.csv (samples);
# exit 1 if a check failed.
set -euo pipefail

usage() { sed -n '2,40p' "$0"; exit 2; }

if [ "${1:-}" = "--host" ]; then
	IMAGES=${2:?usage: $0 --host <images dir> [options]}
	shift 2
	# A round first: an unhealthy VM goes back to its snapshot there, which
	# would drop what `put` copies.
	cargo xtask vm-lab run -- true
	tmp=$(mktemp -d)
	ln -s "$(realpath "$IMAGES/rootfs.squashfs")" "$tmp/ospf-stress-rootfs.squashfs"
	cargo xtask vm-lab put "$tmp/ospf-stress-rootfs.squashfs"
	rm -rf "$tmp"
	exec cargo xtask vm-lab run -- scripts/ospf-stress-lab.sh "$@"
fi

DUT=local IFACE="" TARGET="" RUSER=${RUSER:-admin} MGMT="" DUT_IFACE=ether1
TESTS=lsdb,churn,neighbors,ops,latency
STEPS=1000,10000,50000,100000,200000
CHURN_RATES=1,10,100 CHURN_SECS=120 CHURN_BASE=10000
NEIGHBORS=50,100,250 STABLE_SECS=600
LAT_N=50
DAEMON=image
SELFTEST=0
OUT=""
while [ $# -gt 0 ]; do
	case $1 in
	--dut) DUT=$2; shift 2 ;;
	--iface) IFACE=$2; shift 2 ;;
	--target) TARGET=$2; shift 2 ;;
	--user) RUSER=$2; shift 2 ;;
	--mgmt) MGMT=$2; shift 2 ;;
	--dut-iface) DUT_IFACE=$2; shift 2 ;;
	--tests) TESTS=$2; shift 2 ;;
	--steps) STEPS=$2; shift 2 ;;
	--churn-rates) CHURN_RATES=$2; shift 2 ;;
	--churn-secs) CHURN_SECS=$2; shift 2 ;;
	--churn-base) CHURN_BASE=$2; shift 2 ;;
	--neighbors) NEIGHBORS=$2; shift 2 ;;
	--stable-secs) STABLE_SECS=$2; shift 2 ;;
	--latency-n) LAT_N=$2; shift 2 ;;
	--daemon) DAEMON=$2; shift 2 ;;
	--selftest-remote) SELFTEST=1; shift ;;
	--out) OUT=$2; shift 2 ;;
	-h | --help) usage ;;
	*) echo "unknown option $1"; usage ;;
	esac
done

# vm-lab run holds its lock on fd 9: the daemons started here must not.
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
for t in bngblaster bngblaster-cli lspgen jq vtysh; do
	command -v "$t" >/dev/null || { echo "$t missing in the VM: cargo xtask vm-lab tools --check"; exit 1; }
done

INBOX=/srv/lab/inbox
W=/tmp/crospfstress
R=$W/root
OUT=${OUT:-/srv/lab/ospf-stress/$(date +%Y%m%d-%H%M%S)}
RESULTS=$OUT/results.md
SRC=$(pwd)
FAILED=0
GEN_RID=10.0.0.11 DUT_RID=10.255.0.1
LINK_DUT=10.0.1.1 LINK_GEN=10.0.1.2
BIG_ROOT=192.168.0.0 CHURN_ROOT=10.200.0.0
INSTANCE=stress
TLS_PORT=8729

if [ $SELFTEST = 1 ]; then
	DUT=remote IFACE=crlink0 TARGET=10.99.0.1 MGMT=10.99.0.2/24
fi
case $DUT in
local) ;;
remote)
	[ -n "$IFACE" ] && [ -n "$TARGET" ] || { echo "--dut remote needs --iface and --target"; exit 2; }
	case $TARGET in *:*) ;; *) TARGET=$TARGET:$TLS_PORT ;; esac
	;;
*) echo "--dut local|remote"; exit 2 ;;
esac
GEN_IF=gen1
[ $DUT = remote ] && GEN_IF=$IFACE

mkdir -p "$OUT"
: >"$RESULTS"
say() { printf '%s\n' "$*" | tee -a "$RESULTS"; }
log() { printf '%s %s\n' "$(date +%T)" "$*" >&2; }
fail() { say "FAIL $*"; FAILED=1; }
now() { printf '%s' "${EPOCHREALTIME/./}" | cut -c1-13; } # ms since the epoch
since() { echo $(($(now) - $1)); }                          # ms since $1

# --- The router under test: the image's root in a chroot (local and the
# self-test), FRR started as the image's init starts it (plan.rs), the
# daemon with --frr.

mount_image() {
	[ -s "$INBOX/ospf-stress-rootfs.squashfs" ] ||
		{ echo "$INBOX/ospf-stress-rootfs.squashfs missing: run with --host <images> from the host"; exit 1; }
	mkdir -p "$W"/{lower,rw,root}
	modprobe loop 2>/dev/null || true
	mount -t squashfs -o loop,ro "$INBOX/ospf-stress-rootfs.squashfs" "$W/lower"
	mount -t tmpfs tmpfs "$W/rw"
	mkdir -p "$W/rw/upper" "$W/rw/work"
	mount -t overlay overlay -o "lowerdir=$W/lower,upperdir=$W/rw/upper,workdir=$W/rw/work" "$R"
}

# In the DUT's namespace, with its own /run and /tmp, the image's root: `$@`.
in_dut() {
	ip netns exec crdut unshare --mount sh -c '
		R=$1; S=$2; shift 2
		mount -t proc proc "$R/proc"
		mount -t sysfs sys "$R/sys"
		mount --rbind /dev "$R/dev"
		mount --bind "$S/run" "$R/run"
		mount --bind "$S/tmp" "$R/tmp"
		exec chroot "$R" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/tmp \
			COREROUTER_RUNTIME_DIR=/run/corerouter "$@"' sh "$R" "$W/dut" "$@"
}

FRR_DAEMONS="mgmtd zebra staticd ospfd bfdd"
frr_start() {
	local d args
	for d in $FRR_DAEMONS; do
		args=(-P 0 --log stdout --log-level notifications)
		[ $d = zebra ] && args+=(-s 90000000)
		[ $d = bfdd ] && args+=(--dplaneaddr unix:/var/run/frr/bfdd_dplane.sock)
		in_dut "/usr/sbin/$d" "${args[@]}" >>"$W/dut/frr-$d.log" 2>&1 &
		echo $! >"$W/dut/frr-$d.wrapper"
		# zebra's socket before the protocols (the init waits the same way).
		local end=$((SECONDS + 20))
		until [ -S "$W/dut/run/frr/$d.vty" ]; do
			[ $SECONDS -lt $end ] || { echo "FRR $d did not start"; tail -n 20 "$W/dut/frr-$d.log"; return 1; }
			sleep 0.1
		done
	done
}
frr_stop() { # [-9]
	local sig=${1:-TERM} d p
	for d in $FRR_DAEMONS; do
		p=$(dut_pid "$d") && kill -s "$sig" "$p" 2>/dev/null
	done
	for _ in $(seq 50); do
		local any=0
		for d in $FRR_DAEMONS; do dut_pid "$d" >/dev/null && any=1; done
		[ $any = 0 ] && break
		sleep 0.1
	done
	rm -f "$W/dut/run/frr/"*.vty
}

daemon_start() {
	local extra=()
	[ $SELFTEST = 1 ] && extra=(--listen "0.0.0.0:$TLS_PORT")
	if [ "$DAEMON" = build ]; then
		ip netns exec crdut env COREROUTER_RUNTIME_DIR="$W/dut/run/corerouter" \
			"$CARGO_TARGET_DIR/release/corerouter-daemon" --backend linux --config-dir "$W/dut/tmp/cfg" \
			--control 7979 --frr "$W/dut/run/frr" --frr-daemons "$W/dut/run/corerouter/frr-daemons" \
			"${extra[@]}" >>"$W/dut/daemon.log" 2>&1 &
	else
		in_dut /usr/bin/corerouter-daemon --backend linux --config-dir /tmp/cfg --control 7979 \
			--frr /var/run/frr --frr-daemons /run/corerouter/frr-daemons \
			"${extra[@]}" >>"$W/dut/daemon.log" 2>&1 &
	fi
	local end=$((SECONDS + 60))
	until cr_local system.resource.print >/dev/null 2>&1; do
		[ $SECONDS -lt $end ] || { echo "the DUT's daemon did not answer"; tail -n 30 "$W/dut/daemon.log"; return 1; }
		sleep 0.3
	done
}
daemon_stop() {
	local p
	p=$(dut_pid corerouter-daemon) || return 0
	kill "$p" 2>/dev/null
	for _ in $(seq 100); do kill -0 "$p" 2>/dev/null || return 0; sleep 0.1; done
	kill -9 "$p" 2>/dev/null || true
}

# The pid of the DUT's process named $1 (its comm), local DUT only.
dut_pid() {
	local p
	for p in $(ip netns pids crdut 2>/dev/null); do
		if [ "$(cat "/proc/$p/comm" 2>/dev/null)" = "${1:0:15}" ]; then
			echo "$p"
			return 0
		fi
	done
	return 1
}

dut_up() {
	ip netns add crdut
	ip -n crdut link set lo up
	mkdir -p "$W/dut/run/frr" "$W/dut/run/corerouter" "$W/dut/tmp/cfg"
	# FRR drops to the image's frr user: its state directory is that user's.
	local ids
	ids=$(awk -F: '$1 == "frr" {print $3 ":" $4}' "$R/etc/passwd")
	[ -n "$ids" ] || { echo "no frr user in the image"; exit 1; }
	chown "$ids" "$W/dut/run/frr"
	frr_start
	daemon_start
}

# --- Commands to the DUT. Local: the local token, from inside crdut.
# Remote: TLS from inside crgen (where the cable is).
CLI=""
NOPARAMS='{}'
cr_local() {
	ip netns exec crdut env COREROUTER_RUNTIME_DIR="$W/dut/run/corerouter" \
		"$CLI" --connect 127.0.0.1:7979 run "$1" "${2:-$NOPARAMS}"
}
cli_remote() { # <cli args>
	ip netns exec crgen env COREROUTER_PASSWORD="${COREROUTER_PASSWORD:-}" \
		COREROUTER_KNOWN_HOSTS="$W/known_hosts" "$CLI" --connect "tls://$TARGET" --user "$RUSER" \
		--accept-new-cert "$@"
}
cr() { # <id> [params]: the reply's JSON on stdout
	if [ $DUT = local ]; then
		cr_local "$@"
	else
		cli_remote run "$1" "${2:-$NOPARAMS}"
	fi
}
ok() { # like cr, but a refusal fails the step
	local out
	if ! out=$(cr "$@" 2>&1); then
		log "command failed: $* → $(printf '%s' "$out" | head -c 400)"
		return 1
	fi
	printf '%s\n' "$out"
}
# The CLI's mcp server, connected to the DUT (one connection: Safe Mode).
cli_mcp() {
	if [ $DUT = local ]; then
		ip netns exec crdut env COREROUTER_RUNTIME_DIR="$W/dut/run/corerouter" \
			"$CLI" --connect 127.0.0.1:7979 mcp
	else
		cli_remote mcp
	fi
}

# --- FRR's own view (vtysh on the DUT's vty sockets), local DUT only.
vty() { vtysh --vty_socket "$W/dut/run/frr" -c "$1" 2>/dev/null; }

# --- The generator: BNG Blaster in crgen.
gen_ns_up() {
	ip netns add crgen
	ip -n crgen link set lo up
	if [ $DUT = local ]; then
		ip link add ether1 netns crdut type veth peer name gen1 netns crgen
		ip -n crdut link set ether1 up
	else
		ip link set "$IFACE" netns crgen
		if [ -n "$MGMT" ]; then ip -n crgen addr add "$MGMT" dev "$IFACE"; fi
	fi
	ip -n crgen link set "$GEN_IF" up
	# BNG Blaster sends from user space: no offloads that would leave
	# checksums to a NIC that is not there (veth).
	ip netns exec crgen ethtool -K "$GEN_IF" tx off rx off >/dev/null 2>&1 || true
}

BBL_SOCK=$W/gen/run.sock
bbl() { ip netns exec crgen bngblaster-cli "$BBL_SOCK" "$@" 2>/dev/null; }

# gen_start <config.json>: BNG Blaster with it, up to the OSPF Full
# adjacency (the DUT's view when local).
gen_start() {
	mkdir -p "$W/gen"
	rm -f "$BBL_SOCK"
	ip netns exec crgen bngblaster -C "$1" -S "$BBL_SOCK" -L "$W/gen/bbl.log" -l ospf -l error \
		>"$W/gen/bbl.out" 2>&1 &
	echo $! >"$W/gen/bbl.pid"
	local end=$((SECONDS + 30))
	until [ -S "$BBL_SOCK" ]; do
		[ $SECONDS -lt $end ] || { echo "BNG Blaster did not start"; tail -n 20 "$W/gen/bbl.out"; return 1; }
		sleep 0.2
	done
}
gen_stop() {
	local p
	p=$(cat "$W/gen/bbl.pid" 2>/dev/null) || return 0
	kill -INT "$p" 2>/dev/null || return 0
	# Teardown: the external LSAs go out with MaxAge (purge) first.
	for _ in $(seq 150); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done
	kill -9 "$p" 2>/dev/null || true
	rm -f "$W/gen/bbl.pid"
}
# The number of the generator's instances in state Full.
gen_full() {
	local i n=0
	for i in $(seq "${1:-1}"); do
		bbl ospf-neighbors instance "$i" | grep -q '"state": *"Full"' && n=$((n + 1))
	done
	echo $n
}

# BNG Blaster config: one router (instance 1) on the link, its external
# LSDB connected to it (the lspgen roots of the size and churn topologies).
gen_config() { # <file>
	cat >"$1" <<EOF
{
  "interfaces": {
    "network": [{"interface": "$GEN_IF", "address": "$LINK_GEN/30", "gateway": "$LINK_DUT",
      "ospfv2-instance-id": 1, "ospfv2-type": "p2p"}]
  },
  "ospf": [{"instance-id": 1, "version": 2, "router-id": "$GEN_RID", "hostname": "gen",
    "hello-interval": 1, "dead-interval": 4,
    "external": {"purge": true, "connections": [
      {"router-id": "$BIG_ROOT", "local-ipv4-address": "$LINK_GEN", "metric": 10},
      {"router-id": "$CHURN_ROOT", "local-ipv4-address": "$LINK_GEN", "metric": 10}]}}]
}
EOF
}

# --- Base config on the DUT: the link, an instance, the backbone, one
# template (point-to-point, hello 1 s, dead 4 s).
TEMPLATE_ID=""
dut_config() {
	cr routing.ospf.instance.remove "{\"id\":\"$INSTANCE\"}" >/dev/null 2>&1 || true
	cr ip.address.remove "{\"address\":\"$LINK_DUT/30\"}" >/dev/null 2>&1 || true
	ok ip.address.add "{\"address\":\"$LINK_DUT/30\",\"interface\":\"$DUT_IFACE\"}" >/dev/null
	ok routing.ospf.instance.add "{\"name\":\"$INSTANCE\",\"router_id\":\"$DUT_RID\"}" >/dev/null
	ok routing.ospf.area.add "{\"name\":\"stress-bb\",\"instance\":\"$INSTANCE\",\"area_id\":\"0.0.0.0\"}" >/dev/null
	TEMPLATE_ID=$(ok routing.ospf.interface-template.add \
		"{\"area\":\"stress-bb\",\"networks\":[\"10.0.1.0/30\"],\"type\":\"ptp\",\"hello_interval\":1,\"dead_interval\":4,\"comment\":\"ospf-stress\"}" |
		jq -r '.id // empty')
}
dut_unconfig() {
	cr routing.ospf.instance.remove "{\"id\":\"$INSTANCE\"}" >/dev/null 2>&1 || true
	cr ip.address.remove "{\"address\":\"$LINK_DUT/30\"}" >/dev/null 2>&1 || true
}

# --- What the DUT holds now.
# LSAs in the LSDB: FRR's count (local) or CoreRouter's lsa.list (remote).
dut_lsas() {
	if [ $DUT = local ]; then
		vty 'show ip ospf json' | jq '([.areas[]?.lsaNumber] | add // 0) + (.lsaExternalCounter // 0)'
	else
		cr routing.ospf.lsa.list "{\"instance\":\"$INSTANCE\",\"limit\":1}" | jq '.total // 0'
	fi
}
# Routes in the kernel's main table (local) or OSPF's routes (remote).
dut_routes() {
	if [ $DUT = local ]; then
		ip netns exec crdut sh -c 'ip -4 route show proto ospf | wc -l'
	else
		cr routing.ospf.route.list "{\"instance\":\"$INSTANCE\"}" | jq '.rows | length'
	fi
}
dut_neighbors_full() {
	if [ $DUT = local ]; then
		vty 'show ip ospf neighbor json' | jq '[.neighbors[][]? | select(.nbrState // .converged | tostring | test("Full"))] | length'
	else
		cr routing.ospf.neighbor.list "{\"instance\":\"$INSTANCE\"}" | jq '[.rows[] | select(.state == "Full")] | length'
	fi
}
# SPF runs and the last one's duration (FRR's `show ip ospf json`).
dut_spf() {
	[ $DUT = local ] || { echo "- -"; return; }
	vty 'show ip ospf json' | jq -r '"\(.spfCount // .spfRuns // "-") \(.spfLastDurationMsecs // .spfLastDurationMicroSecs // "-")"'
}

# --- Process cost: RSS (MiB) and CPU (% of one core since the previous
# sample) of ospfd, zebra and corerouter-daemon, plus the memory in use.
PROCS="ospfd zebra corerouter-daemon"
declare -A PREV_TICKS
CLK=$(getconf CLK_TCK)
proc_sample() { # → "ospfd_rss ospfd_cpu zebra_rss zebra_cpu daemon_rss daemon_cpu mem_used_mib"
	local line="" p name t rss
	if [ $DUT = local ]; then
		local t_now
		t_now=$(now)
		for name in $PROCS; do
			if p=$(dut_pid "$name"); then
				rss=$(awk '/^VmRSS/ {printf "%d", $2 / 1024}' "/proc/$p/status" 2>/dev/null)
				t=$(awk '{print $14 + $15}' "/proc/$p/stat" 2>/dev/null)
				local prev=${PREV_TICKS[$name]:-}
				local cpu=0
				if [ -n "$prev" ]; then
					local pt=${prev% *} pms=${prev#* }
					local dt=$((t_now - pms))
					[ $dt -gt 0 ] && cpu=$(((t - pt) * 100000 / CLK / dt))
				fi
				PREV_TICKS[$name]="$t $t_now"
				line+="${rss:-0} $cpu "
			else
				line+="0 0 "
			fi
		done
		line+=$(awk '/^MemTotal/ {t = $2} /^MemAvailable/ {a = $2} END {printf "%d", (t - a) / 1024}' /proc/meminfo)
	else
		local procs res
		procs=$(cr system.resource.process.print '{"sort":"memory","limit":100}' 2>/dev/null || echo '[]')
		for name in $PROCS; do
			line+=$(printf '%s' "$procs" | jq -r --arg n "${name:0:15}" \
				'[.[] | select(.name == $n)][0] // {} | "\((.memory // 0) / 1048576 | floor) \(.cpu // 0 | floor) "')
		done
		res=$(cr system.resource.print 2>/dev/null || echo '{}')
		line+=$(printf '%s' "$res" | jq -r '((.total_memory // 0) - (.memory.available // .free_memory // 0)) / 1048576 | floor')
	fi
	echo "$line"
}
# Peak RSS (MiB) of each process since the last reset (local: VmHWM).
proc_peak_reset() {
	[ $DUT = local ] || return 0
	local name p
	for name in $PROCS; do
		p=$(dut_pid "$name") && echo 5 >"/proc/$p/clear_refs" 2>/dev/null || true
	done
}
proc_peak() { # → "ospfd zebra daemon" in MiB
	local name p out=""
	for name in $PROCS; do
		if [ $DUT = local ] && p=$(dut_pid "$name"); then
			out+="$(awk '/^VmHWM/ {printf "%d", $2 / 1024}' "/proc/$p/status") "
		else
			out+="- "
		fi
	done
	echo "$out"
}

# sampler_start <csv>: one line a second (t_ms lsas routes procs…) until
# sampler_stop.
SAMPLER=""
sampler_start() {
	local csv=$1 t0
	t0=$(now)
	echo "t_ms lsas routes ospfd_rss ospfd_cpu zebra_rss zebra_cpu daemon_rss daemon_cpu mem_used_mib" >"$csv"
	(
		while :; do
			echo "$(since "$t0") $(dut_lsas 2>/dev/null || echo -) $(dut_routes 2>/dev/null || echo -) $(proc_sample)" >>"$csv"
			sleep 1
		done
	) &
	SAMPLER=$!
}
sampler_stop() {
	[ -n "$SAMPLER" ] && kill "$SAMPLER" 2>/dev/null && wait "$SAMPLER" 2>/dev/null || true
	SAMPLER=""
}
# Column $2's maximum in csv $1 (by header name).
csv_max() {
	awk -v c="$2" 'NR == 1 {for (i = 1; i <= NF; i++) if ($i == c) k = i; next}
		$k != "-" && $k + 0 > m {m = $k + 0} END {print m + 0}' "$1"
}
csv_avg() {
	awk -v c="$2" 'NR == 1 {for (i = 1; i <= NF; i++) if ($i == c) k = i; next}
		$k != "-" {s += $k; n++} END {printf "%d", n ? s / n : 0}' "$1"
}

# wait_for <what> <secs> <cmd…>: until the command succeeds; the ms it took.
wait_for() {
	local what=$1 secs=$2 t0
	shift 2
	t0=$(now)
	local end=$((SECONDS + secs))
	until "$@" >/dev/null 2>&1; do
		if [ $SECONDS -ge $end ]; then
			log "timeout: $what (${secs}s)"
			return 1
		fi
		sleep 0.2
	done
	since "$t0"
}
ge() { [ "$("$2")" -ge "$1" ] 2>/dev/null; } # ge <n> <fn>: fn's number ≥ n
le() { [ "$("$2")" -le "$1" ] 2>/dev/null; }
# stable <fn> <secs>: wait until fn's number has not changed for <secs>;
# prints it.
stable() {
	local fn=$1 secs=$2 last="" same=0 v
	while [ $same -lt "$secs" ]; do
		v=$("$fn" 2>/dev/null || echo -)
		if [ "$v" = "$last" ]; then same=$((same + 1)); else same=0 last=$v; fi
		sleep 1
	done
	echo "$last"
}

oom_seen() { dmesg | grep -q -i 'out of memory\|oom-kill'; }

# --- Setup and teardown.
cleanup() {
	set +e
	sampler_stop
	exec 3>&- 4<&- 2>/dev/null
	gen_stop
	jobs -p | xargs -r kill 2>/dev/null
	if [ $DUT = remote ] && [ $SELFTEST = 0 ]; then
		dut_unconfig
		ip -n crgen link set "$IFACE" netns 1 2>/dev/null
	fi
	for ns in crgen crdut; do ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null; done
	sleep 1
	for ns in crgen crdut crconv1 crconv2 crconv3; do
		ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null
		ip netns del "$ns" 2>/dev/null
	done
	ip link del crlink0 2>/dev/null
	umount -l "$R" "$W/lower" "$W/rw" 2>/dev/null
}
trap cleanup EXIT
cleanup
trap cleanup EXIT
rm -rf "$W"
mkdir -p "$W/gen" "$W/lsp"
dmesg -C 2>/dev/null || true

# The CLI of this worktree, release (its parse of big replies is part of
# what the latency test measures).
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$SRC/target-lab}
pkgs=(-p corerouter-cli)
[ "$DAEMON" = build ] && pkgs+=(-p corerouter-daemon)
log "building ${pkgs[*]} (release)"
cargo build --release --quiet "${pkgs[@]}"
CLI=$CARGO_TARGET_DIR/release/corerouter-cli

if [ $DUT = local ] || [ $SELFTEST = 1 ]; then
	mount_image
	dut_up
fi
if [ $SELFTEST = 1 ]; then
	# The DUT's port on the "cable": ether1 in crdut, crlink0 here; the
	# management address that the remote mode reaches it by.
	ip link add ether1 netns crdut type veth peer name crlink0
	ip -n crdut link set ether1 up
	cr_local ip.address.add '{"address":"10.99.0.1/24","interface":"ether1"}' >/dev/null
fi
gen_ns_up
if [ $DUT = remote ]; then
	end=$((SECONDS + 30))
	until cli_remote run system.resource.print >/dev/null 2>"$W/remote.err"; do
		[ $SECONDS -lt $end ] || { echo "the router at $TARGET does not answer: $(cat "$W/remote.err")"; exit 1; }
		sleep 1
	done
fi
dut_config
say "# OSPF stress ($(date -u +%FT%TZ), DUT $DUT${TARGET:+ $TARGET}, daemon $DAEMON)"
say ""
say "$(cr system.resource.print | jq -r '"DUT: \(.board_name // "?"), \(.cpu_model // "?"), \(.cpu_count) CPU, \(.total_memory / 1048576 | floor) MiB, CoreRouter \(.version)"')"
[ $DUT = local ] && say "FRR: $(vty 'show version' | head -n 1)"
say ""

has_test() { case ",$TESTS," in *",$1,"*) return 0 ;; esac; return 1; }

# The LSDB of a step: lspgen's topology of `nodes` routers and `ext`
# external prefixes behind gen (cached per size).
lsdb_nodes() { local n=$(($1 / 20)); [ $n -lt 10 ] && n=10; [ $n -gt 2000 ] && n=2000; echo $n; }
lsdb_mrt() { # <lsas> → path of the MRT file
	local n=$1 nodes ext d=$W/lsp/$1
	nodes=$(lsdb_nodes "$n")
	ext=$((n - nodes))
	if [ ! -s "$d/lsdb.mrt" ]; then
		mkdir -p "$d"
		(cd "$d" && lspgen -P ospf2 -y -c "$nodes" -e "$ext" -n "$BIG_ROOT/32" -x 100.64.0.0/28 \
			-C "$GEN_RID:$LINK_GEN" -m lsdb.mrt >lspgen.log 2>&1)
	fi
	echo "$d/lsdb.mrt"
}

BIGGEST=0
# --- 1. LSDB size steps.
test_lsdb() {
	say "## 1. LSDB size"
	say ""
	say "| LSAs (target) | in LSDB | LSDB full (s) | kernel routes | install (routes/s) | SPF runs / last (ms) | ospfd RSS peak (MiB) | zebra peak | daemon peak | ospfd CPU avg/max (%) | zebra CPU | daemon CPU | RAM used peak (MiB) | purge (s) | result |"
	say "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
	local n
	for n in ${STEPS//,/ }; do
		local mrt csv=$OUT/lsdb-$n.csv t_lsdb t_routes lsas routes base_lsas base_routes
		mrt=$(lsdb_mrt "$n")
		gen_config "$W/gen/conf.json"
		gen_start "$W/gen/conf.json"
		if ! wait_for "gen Full" 60 ge 1 dut_neighbors_full >/dev/null; then
			fail "lsdb $n: no adjacency"; gen_stop; break
		fi
		base_lsas=$(stable dut_lsas 3)
		base_routes=$(dut_routes)
		proc_peak_reset
		sampler_start "$csv"
		local t0 spf0
		spf0=$(dut_spf)
		t0=$(now)
		bbl ospf-load-mrt file "$mrt" instance 1 >/dev/null
		# Full when the count reaches the target and stays 5 s.
		local want=$((base_lsas + n - 5))
		if t_lsdb=$(wait_for "lsdb $n" 1200 ge "$want" dut_lsas); then
			lsas=$(stable dut_lsas 5)
			routes=$(stable dut_routes 5)
			t_routes=$(since "$t0")
		else
			lsas=$(dut_lsas) routes=$(dut_routes) t_routes=-
		fi
		sampler_stop
		local spf peak mem rate
		spf=$(dut_spf)
		peak=$(proc_peak)
		mem=$(csv_max "$csv" mem_used_mib)
		# Install rate: routes over the time from the first to the last
		# change in the samples.
		rate=$(awk 'NR > 1 && $3 != "-" {if (!s && $3 > b) s = $1; if ($3 != l) {e = $1; l = $3}} NR == 2 {b = $3}
			END {if (e > s && s) printf "%d", (l - b) * 1000 / (e - s); else print "-"}' "$csv")
		# Withdraw: the generator leaves (its LSAs purged); back to the base.
		local t1 t_purge
		t1=$(now)
		gen_stop
		if wait_for "purge $n" 600 le "$((base_lsas + 2))" dut_lsas >/dev/null; then
			t_purge=$(awk -v ms="$(since "$t1")" 'BEGIN {printf "%.1f", ms / 1000}')
		else
			t_purge=timeout
		fi
		local verdict=ok
		if [ "$t_routes" = - ]; then verdict="FAIL (LSDB incomplete: $lsas)"; fi
		if oom_seen; then verdict="FAIL (OOM)"; fi
		for p in $PROCS; do [ $DUT = local ] && ! dut_pid "$p" >/dev/null && verdict="FAIL ($p died)"; done
		say "| $n | $lsas | $(awk -v a="${t_lsdb:-0}" 'BEGIN {printf "%.1f", a / 1000}') | $((routes - base_routes)) | $rate | $spf0 → $spf | ${peak// / | }$(csv_avg "$csv" ospfd_cpu)/$(csv_max "$csv" ospfd_cpu) | $(csv_avg "$csv" zebra_cpu)/$(csv_max "$csv" zebra_cpu) | $(csv_avg "$csv" daemon_cpu)/$(csv_max "$csv" daemon_cpu) | $mem | $t_purge | $verdict |"
		if [ "$verdict" != ok ]; then
			FAILED=1
			break
		fi
		BIGGEST=$n
	done
	say ""
}

has_test lsdb && test_lsdb
if [ "${TESTS}" = none ]; then
	say "up: $(dut_neighbors_full) full, LSAs $(dut_lsas), routes $(dut_routes), spf $(dut_spf), procs $(proc_sample)"
	vty 'show ip ospf json' | head -c 3000
fi
say ""
say "results: $RESULTS"
exit $FAILED
