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
	# Under the name this lab reads (vm-lab put copies regular files only:
	# a symbolic link is skipped).
	tmp=$(mktemp -d)
	cp --reflink=auto "$IMAGES/rootfs.squashfs" "$tmp/ospf-stress-rootfs.squashfs"
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
	# What the image's init does at boot (pid1.rs): /var is a tmpfs with
	# log, lib and tmp, and /var/run a link to /run (FRR's state directory
	# is /var/run/frr).
	rm -rf "$R/var/run"
	ln -s /run "$R/var/run"
	mkdir -p "$R/var/log" "$R/var/lib" "$R/var/tmp"
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
			--manage 'ether*' "${extra[@]}" >>"$W/dut/daemon.log" 2>&1 &
	else
		in_dut /usr/bin/corerouter-daemon --backend linux --config-dir /tmp/cfg --control 7979 \
			--frr /var/run/frr --frr-daemons /run/corerouter/frr-daemons \
			--manage 'ether*' "${extra[@]}" >>"$W/dut/daemon.log" 2>&1 &
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

# The DUT's veth ends are its ports: --manage adopts them (a veth whose
# peer is in another namespace is a container's otherwise, owner.rs).
dut_up() {
	mkdir -p "$W/dut/run/frr" "$W/dut/run/corerouter" "$W/dut/tmp/cfg"
	# FRR drops to the image's frr user: its state directory is that user's.
	local ids
	ids=$(awk -F: '$1 == "frr" {print $3 ":" $4}' "$R/etc/passwd")
	[ -n "$ids" ] || { echo "no frr user in the image"; exit 1; }
	chown "$ids" "$W/dut/run/frr"
	frr_start
	daemon_start
}

# The CLI warns on stderr that admin has no password, on every call.
export RUST_LOG=error

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
	if ! out=$(cr "$@" 2>"$W/cr.err"); then
		log "command failed: $* → $(head -c 400 "$W/cr.err")"
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
# OSPF routes in the kernel: zebra's FIB count, the routes the kernel
# acknowledged (local; a counter, cheap at 200 000 routes), or OSPF's
# routes as CoreRouter lists them (remote).
dut_routes() {
	if [ $DUT = local ]; then
		vty 'show ip route summary json' | jq '[.routes[]? | select(.type == "ospf") | .fib] | add // 0'
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
	vty 'show ip ospf json' | jq -r '"\([.areas[]?.spfExecutedCounter] | add // 0) \(.spfLastDurationMsecs // "-")"'
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
			printf '%s %s %s ' "$(since "$t0")" "$(dut_lsas 2>/dev/null || echo -)" "$(dut_routes 2>/dev/null || echo -)" >>"$csv"
			# Not in $( ): the CPU % needs the previous sample's ticks.
			proc_sample >>"$csv"
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
# The DUT's processes that are gone (local DUT), on stdout; false if none.
procs_dead() {
	[ $DUT = local ] || return 1
	local p out=""
	for p in $PROCS; do
		if ! dut_pid "$p" >/dev/null; then out+="$p "; fi
	done
	[ -n "$out" ] && echo "$out"
}

# --- Setup and teardown.
cleanup() {
	set +e
	sampler_stop
	exec 3>&- 4<&-
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
	conv_routers_stop 2>/dev/null
	umount -l "$R" "$W/lower" "$W/rw" 2>/dev/null
}
trap cleanup EXIT
cleanup
set -e
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

for ns in crdut crgen; do
	ip netns add $ns
	ip -n $ns link set lo up
done
if [ $SELFTEST = 1 ]; then
	# The DUT's port on the "cable": ether1 in crdut, crlink0 here.
	ip link add ether1 netns crdut type veth peer name crlink0
	ip -n crdut link set ether1 up
fi
gen_ns_up
if [ $DUT = local ] || [ $SELFTEST = 1 ]; then
	mount_image
	dut_up
fi
if [ $SELFTEST = 1 ]; then
	# The management address that the remote mode reaches it by.
	cr_local ip.address.add '{"address":"10.99.0.1/24","interface":"ether1"}' >/dev/null
fi
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
# load_watch <csv> <want_lsas> <base_routes>: every 200 ms the LSAs and
# the routes, until the LSAs reach <want> and the routes have not moved
# for 5 s (or 20 min); then prints "t_lsdb t_first_route t_routes routes".
load_watch() {
	local csv=$1 want=$2 base=$3 t0 l r last=-1 same=0
	t0=$(now)
	echo "t_ms lsas routes" >"$csv"
	while [ $(($(now) - t0)) -lt 1200000 ]; do
		l=$(dut_lsas 2>/dev/null || echo 0)
		r=$(dut_routes 2>/dev/null || echo 0)
		echo "$(since "$t0") $l $r" >>"$csv"
		if [ "$l" -ge "$want" ] && [ "$r" = "$last" ] && [ "$r" -gt "$base" ]; then
			same=$((same + 1))
			[ $same -ge 25 ] && break
		else
			same=0
		fi
		last=$r
		sleep 0.2
	done
	awk -v want="$want" -v base="$base" 'NR == 1 {next} {t[NR] = $1; l[NR] = $2; r[NR] = $3; n = NR}
		END {
			fin = r[n]; tl = "-"; tf = "-"; tr = "-"
			for (i = 2; i <= n; i++) {
				if (tl == "-" && l[i] >= want) tl = t[i]
				if (tf == "-" && r[i] > base) tf = t[i]
				if (tr == "-" && r[i] == fin) tr = t[i]
			}
			if (l[n] < want) tl = "-"
			print tl, tf, tr, fin
		}' "$csv"
}
ms2s() { awk -v a="$1" 'BEGIN {if (a == "" || a == "-") print "-"; else printf "%.1f", a / 1000}'; }

# --- 1. LSDB size steps.
test_lsdb() {
	say "## 1. LSDB size"
	say ""
	say "Times from the LSDB's load in the generator (BNG Blaster \`ospf-load-mrt\`, one neighbor). Routes: zebra's FIB count of OSPF routes (what the kernel acknowledged). Peaks: VmHWM of each process during the step; RAM: the VM's used memory."
	say ""
	say "| LSAs (target) | in LSDB | LSDB full (s) | first route (s) | all routes (s) | routes | install (routes/s) | SPF runs / last (ms) | ospfd RSS peak (MiB) | zebra peak | daemon peak | ospfd CPU avg/max (%) | zebra CPU | daemon CPU | RAM used peak (MiB) | routes out (s) | LSAs flushed (s) | result |"
	say "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
	local n
	for n in ${STEPS//,/ }; do
		local mrt csv=$OUT/lsdb-$n.csv fast=$OUT/lsdb-$n-load.csv base_lsas base_routes
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
		local spf0 res
		spf0=$(dut_spf)
		bbl ospf-load-mrt file "$mrt" instance 1 >/dev/null
		res=$(load_watch "$fast" "$((base_lsas + n - 5))" "$base_routes")
		local t_lsdb t_first t_routes routes lsas
		read -r t_lsdb t_first t_routes routes <<<"$res"
		lsas=$(dut_lsas)
		sampler_stop
		local spf peak mem rate
		spf=$(dut_spf)
		peak=$(proc_peak)
		mem=$(csv_max "$csv" mem_used_mib)
		rate=$(awk -v a="$t_first" -v b="$t_routes" -v n="$((routes - base_routes))" \
			'BEGIN {if (a == "-" || b == "-" || b <= a) print "-"; else printf "%d", n * 1000 / (b - a)}')
		# Withdraw: the generator leaves (teardown: its LSAs purged with
		# MaxAge); the routes go, then the LSAs leave the LSDB (FRR keeps
		# a MaxAge LSA up to 60 s, maxage-delay, before removing it).
		local t1 t_out t_flush
		t1=$(now)
		gen_stop
		if wait_for "routes out $n" 600 le "$base_routes" dut_routes >/dev/null; then t_out=$(since "$t1"); else t_out=-; fi
		if wait_for "flush $n" 600 le "$((base_lsas + 2))" dut_lsas >/dev/null; then t_flush=$(since "$t1"); else t_flush=-; fi
		local verdict=ok dead
		if [ "$t_lsdb" = - ]; then verdict="FAIL (LSDB incomplete: $lsas)"; fi
		if [ "$t_out" = - ]; then verdict="FAIL (routes not withdrawn)"; fi
		if oom_seen; then verdict="FAIL (OOM)"; fi
		if dead=$(procs_dead); then verdict="FAIL ($dead died)"; fi
		say "| $n | $lsas | $(ms2s "$t_lsdb") | $(ms2s "$t_first") | $(ms2s "$t_routes") | $((routes - base_routes)) | $rate | $spf0 → $spf | ${peak// / | }$(csv_avg "$csv" ospfd_cpu)/$(csv_max "$csv" ospfd_cpu) | $(csv_avg "$csv" zebra_cpu)/$(csv_max "$csv" zebra_cpu) | $(csv_avg "$csv" daemon_cpu)/$(csv_max "$csv" daemon_cpu) | $mem | $(ms2s "$t_out") | $(ms2s "$t_flush") | $verdict |"
		if [ "$verdict" != ok ]; then
			FAILED=1
			break
		fi
		BIGGEST=$n
	done
	say ""
}

# --- The CLI's MCP server as a coprocess: one connection for many
# commands (Safe Mode, batches, the latency of a warm connection).
MCP_PID="" MCP_ID=0
mcp_open() {
	coproc MCP { cli_mcp 2>>"$W/mcp.err"; }
	MCP_PID=$MCP_PID
	exec 3>&"${MCP[1]}" 4<&"${MCP[0]}"
	mcp_send '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"ospf-stress","version":"1"}}}'
	mcp_recv >/dev/null || { log "MCP: no answer: $(tail -n 5 "$W/mcp.err")"; return 1; }
	mcp_send '{"jsonrpc":"2.0","method":"notifications/initialized"}'
}
mcp_send() { printf '%s\n' "$1" >&3; }
# One reply line (head, not read: read takes a byte per syscall and a
# reply of 20 MB would take seconds in the shell).
mcp_recv() { timeout 900 head -n 1 <&4; }
mcp_close() {
	exec 3>&- 4<&-
	[ -n "$MCP_PID" ] && kill "$MCP_PID" 2>/dev/null
	wait "$MCP_PID" 2>/dev/null || true
	MCP_PID=""
}
# mcp_tool <tool> <arguments json> → the tool's text on stdout; false if
# it says isError.
mcp_tool() {
	MCP_ID=$((MCP_ID + 1))
	local reply
	mcp_send "$(jq -cn --arg t "$1" --argjson a "$2" --argjson id $MCP_ID \
		'{jsonrpc: "2.0", id: $id, method: "tools/call", params: {name: $t, arguments: $a}}')"
	reply=$(mcp_recv) || return 1
	printf '%s' "$reply" | jq -r '.result.content[0].text // .error.message // "no reply"'
	[ "$(printf '%s' "$reply" | jq -r '.result.isError // (.error != null)')" = false ]
}
mcp_run() { # <command> [params]
	mcp_tool run_command "$(jq -cn --arg c "$1" --argjson p "${2:-$NOPARAMS}" '{command: $c, params: $p}')"
}

# --- Percentiles of the numbers in a file (nearest rank).
pct() { sort -n "$1" | awk -v p="$2" '{a[NR] = $1} END {i = int((NR * p + 99) / 100); if (i < 1) i = 1; print a[i] + 0}'; }

# --- Loading the LSDB of a step and waiting until it is all in.
# lsdb_load <lsas>: gen up and Full, the MRT loaded, LSDB and routes
# stable. Sets LOADED_LSAS and LOADED_ROUTES.
LOADED_LSAS=0 LOADED_ROUTES=0
lsdb_load() {
	local n=$1 mrt base
	mrt=$(lsdb_mrt "$n")
	gen_config "$W/gen/conf.json"
	gen_start "$W/gen/conf.json"
	wait_for "gen Full" 60 ge 1 dut_neighbors_full >/dev/null || return 1
	base=$(stable dut_lsas 3)
	bbl ospf-load-mrt file "$mrt" instance 1 >/dev/null
	wait_for "lsdb $n" 1200 ge "$((base + n - 5))" dut_lsas >/dev/null || return 1
	LOADED_LSAS=$(stable dut_lsas 5)
	LOADED_ROUTES=$(stable dut_routes 5)
}

# --- 2. Churn: an extra node behind gen whose LSAs change every tick.
# external: k AS-external LSAs whose metric flips 100 ↔ 200 (the routes
# change, ospfd recomputes the externals only); router: k router-LSAs
# whose link metrics flip (each tick is a full SPF). One tick every
# 1.2 s: an LSA changed again in less than MinLSArrival (1 s, RFC 2328
# §13 (5a)) would be dropped by the receiver, so k = rate × 1.2.
CHURN_PERIOD_MS=1200
churn_prepare() { # <kind> <k> → dir
	local kind=$1 k=$2 d=$W/churn/$1-$2
	rm -rf "$d"
	mkdir -p "$d"
	if [ "$kind" = external ]; then
		(cd "$d" && lspgen -P ospf2 -y -c 1 -e "$k" -n "$CHURN_ROOT/32" -x 198.18.0.0/28 \
			-l 172.30.0.0/31 -C "$GEN_RID:$LINK_GEN" -w churn.json >lspgen.log 2>&1)
	else
		(cd "$d" && lspgen -P ospf2 -y -c "$((k + 1))" -e 0 -n "$CHURN_ROOT/32" \
			-l 172.30.0.0/31 -C "$GEN_RID:$LINK_GEN" -w churn.json >lspgen.log 2>&1)
	fi
	echo "$d"
}
# The probe: the prefix whose cost each tick changes, and its cost now
# in CoreRouter (routing.ospf.route.list) and in zebra (local).
churn_probe_prefix() { if [ "$1" = external ]; then echo 198.18.0.0/28; else echo 10.200.0.1/32; fi; }
cost_cr() {
	cr routing.ospf.route.list "{\"instance\":\"$INSTANCE\",\"find\":\"$PROBE\"}" |
		jq -r --arg p "$PROBE" '[.rows[] | select(.prefix == $p)][0] | "\(.cost // "-")/\(.type2_cost // "-")"'
}
cost_zebra() { vty "show ip route $PROBE json" | jq -r --arg p "$PROBE" '.[$p][0].metric // "-"'; }
# churn_tick <dir> <kind> <metric>: the topology with every changing
# metric set, sent to gen (which floods it to the DUT).
churn_tick() {
	local d=$1 kind=$2 m=$3
	if [ "$kind" = external ]; then
		jq --argjson m "$m" '(.["area0.0.0.0"][].ipv4_prefix_list[]? | select(.external_flag == true) | .metric) = $m' \
			"$d/churn.json" >"$d/tick.json"
	else
		jq --argjson m "$m" '(.["area0.0.0.0"][] | select(.is_root != true) | .neighbor_list[]?.metric) = $m' \
			"$d/churn.json" >"$d/tick.json"
	fi
	(cd "$d" && lspgen -r tick.json -S "$BBL_SOCK" -I 1 -Q >>lspgen-ticks.log 2>&1)
}
# churn_run <dir> <kind> <secs> <lagfile>: ticks for <secs>; every 5th
# tick, the time until CoreRouter (and zebra, local) show the new cost.
churn_run() {
	local d=$1 kind=$2 secs=$3 lags=$4 i=0 t_end t_tick m before zb
	t_end=$(($(now) + secs * 1000))
	while [ "$(now)" -lt "$t_end" ]; do
		t_tick=$(now)
		m=$((i % 2 ? 200 : 100))
		if [ $((i % 5)) = 4 ]; then
			before=$(cost_cr)
			[ $DUT = local ] && zb=$(cost_zebra)
		fi
		churn_tick "$d" "$kind" "$m"
		if [ $((i % 5)) = 4 ]; then
			local lag_cr=- lag_z=- c
			while [ $(($(now) - t_tick)) -lt 10000 ]; do
				if [ "$lag_z" = - ] && [ $DUT = local ] && [ "$(cost_zebra)" != "$zb" ]; then lag_z=$(since "$t_tick"); fi
				c=$(cost_cr)
				if [ "$lag_cr" = - ] && [ "$c" != "$before" ]; then lag_cr=$(since "$t_tick"); fi
				[ "$lag_cr" != - ] && { [ $DUT = remote ] || [ "$lag_z" != - ]; } && break
				sleep 0.1
			done
			echo "$i $m $lag_z $lag_cr" >>"$lags"
		fi
		i=$((i + 1))
		local rest=$((CHURN_PERIOD_MS - $(since "$t_tick")))
		[ $rest -gt 0 ] && sleep "$(awk -v r=$rest 'BEGIN {printf "%.3f", r / 1000}')"
	done
	echo "$i" >"$d/ticks"
}

test_churn() {
	say "## 2. Churn (base LSDB $CHURN_BASE LSAs, ${CHURN_SECS} s per rate, one tick every ${CHURN_PERIOD_MS} ms)"
	say ""
	say "| kind | LSAs/s | ticks | ospfd CPU avg/max (%) | zebra CPU | daemon CPU | SPF runs | lag zebra p50/max (ms) | lag CoreRouter p50/max (ms) | stale probes (> 10 s) | Full kept | result |"
	say "|---|---|---|---|---|---|---|---|---|---|---|---|"
	if ! lsdb_load "$CHURN_BASE"; then
		fail "churn: the base LSDB did not load"
		gen_stop
		return
	fi
	local kind rate
	for kind in external router; do
		for rate in ${CHURN_RATES//,/ }; do
			local k=$(((rate * CHURN_PERIOD_MS + 999) / 1000)) d csv=$OUT/churn-$kind-$rate.csv lags=$OUT/churn-$kind-$rate-lag.txt
			[ "$kind" = router ] && [ "$k" -gt 50 ] && k=50
			d=$(churn_prepare "$kind" "$k")
			PROBE=$(churn_probe_prefix "$kind")
			: >"$lags"
			# The first tick brings the extra node in; the routes settle first.
			churn_tick "$d" "$kind" 200
			sleep 5
			local spf0
			spf0=$(dut_spf)
			sampler_start "$csv"
			churn_run "$d" "$kind" "$CHURN_SECS" "$lags"
			sampler_stop
			local full ticks spf stale lz lc verdict=ok
			full=$(dut_neighbors_full)
			ticks=$(cat "$d/ticks")
			spf=$(dut_spf)
			awk '{print $3}' "$lags" | grep -v -- - >"$lags.z" || true
			awk '{print $4}' "$lags" | grep -v -- - >"$lags.c" || true
			stale=$(awk '$4 == "-"' "$lags" | wc -l)
			lz="-"
			[ -s "$lags.z" ] && lz="$(pct "$lags.z" 50)/$(pct "$lags.z" 100)"
			lc="-"
			[ -s "$lags.c" ] && lc="$(pct "$lags.c" 50)/$(pct "$lags.c" 100)"
			[ "$stale" -gt 0 ] && verdict="FAIL ($stale probes stale)"
			[ "$full" -lt 1 ] && verdict="FAIL (adjacency lost)"
			local dead
			if dead=$(procs_dead); then verdict="FAIL ($dead died)"; fi
			[ "$verdict" = ok ] || FAILED=1
			say "| $kind | $(awk -v k=$k -v p=$CHURN_PERIOD_MS 'BEGIN {printf "%.1f", k * 1000 / p}') | $ticks | $(csv_avg "$csv" ospfd_cpu)/$(csv_max "$csv" ospfd_cpu) | $(csv_avg "$csv" zebra_cpu)/$(csv_max "$csv" zebra_cpu) | $(csv_avg "$csv" daemon_cpu)/$(csv_max "$csv" daemon_cpu) | ${spf0%% *} → ${spf%% *} | $lz | $lc | $stale | $full | $verdict |"
		done
	done
	gen_stop
	wait_for "churn purge" 600 le 3 dut_lsas >/dev/null || true
	say ""
}

# --- 3. Many neighbors: n 802.1Q sub-interfaces of the DUT's port, one
# adjacency each (gen instances 2..n+1); gen instance 1 on the untagged
# link carries a base LSDB ($NEIGH_LSDB LSAs) that the DUT floods to all.
NEIGH_LSDB=${NEIGH_LSDB:-10000}
vlan_net() { # <i> (1-based) → "a.b.c" and the last octet base
	echo "10.100.$((($1 - 1) / 64)) $(((($1 - 1) % 64) * 4))"
}
neighbors_gen_config() { # <file> <n>
	local f=$1 n=$2 i
	{
		printf '{\n  "interfaces": {\n    "network": [\n'
		printf '      {"interface": "%s", "address": "%s/30", "gateway": "%s", "ospfv2-instance-id": 1, "ospfv2-type": "p2p"}' \
			"$GEN_IF" "$LINK_GEN" "$LINK_DUT"
		for i in $(seq "$n"); do
			read -r net b <<<"$(vlan_net "$i")"
			printf ',\n      {"interface": "%s", "vlan": %d, "address": "%s.%d/30", "gateway": "%s.%d", "ospfv2-instance-id": %d, "ospfv2-type": "p2p"}' \
				"$GEN_IF" $((100 + i)) "$net" $((b + 2)) "$net" $((b + 1)) $((i + 1))
		done
		printf '\n    ]\n  },\n  "ospf": [\n'
		printf '    {"instance-id": 1, "version": 2, "router-id": "%s", "hello-interval": 1, "dead-interval": 4,\n' "$GEN_RID"
		printf '      "external": {"purge": true, "connections": [{"router-id": "%s", "local-ipv4-address": "%s", "metric": 10}]}}' "$BIG_ROOT" "$LINK_GEN"
		for i in $(seq "$n"); do
			printf ',\n    {"instance-id": %d, "version": 2, "router-id": "10.1.%d.%d", "hello-interval": 1, "dead-interval": 4}' \
				$((i + 1)) $((i / 256)) $((i % 256))
		done
		printf '\n  ]\n}\n'
	} >"$f"
}
# The steps that add (or remove) the n VLANs, their addresses and one
# template for them, as one atomic batch.
neighbors_steps() { # add|remove <n>
	local op=$1 n=$2 i
	{
		for i in $(seq "$n"); do
			read -r net b <<<"$(vlan_net "$i")"
			if [ "$op" = add ]; then
				printf '{"command":"interface.vlan.add","params":{"name":"crs%d","parent":"%s","vlan_id":%d}}\n' $((100 + i)) "$DUT_IFACE" $((100 + i))
				printf '{"command":"ip.address.add","params":{"address":"%s.%d/30","interface":"crs%d"}}\n' "$net" $((b + 1)) $((100 + i))
			else
				printf '{"command":"ip.address.remove","params":{"address":"%s.%d/30"}}\n' "$net" $((b + 1))
				printf '{"command":"interface.remove","params":{"name":"crs%d"}}\n' $((100 + i))
			fi
		done
		if [ "$op" = add ]; then
			printf '{"command":"routing.ospf.interface-template.add","params":{"area":"stress-bb","networks":["10.100.0.0/16"],"type":"ptp","hello_interval":1,"dead_interval":4,"comment":"ospf-stress vlans"}}\n'
		fi
	} | jq -cs '{steps: ., atomic: true}'
}
neighbors_template_remove() {
	local id
	id=$(cr routing.ospf.interface-template.list | jq -r '[.[] | select(.comment == "ospf-stress vlans")][0].id // empty')
	[ -n "$id" ] && cr routing.ospf.interface-template.remove "{\"id\":\"$id\"}" >/dev/null
	return 0
}

test_neighbors() {
	say "## 3. Many neighbors (802.1Q on $DUT_IFACE, hello 1 s / dead 4 s, base LSDB $NEIGH_LSDB LSAs flooded to all)"
	say ""
	say "| neighbors | commit of the VLANs (s) | all Full (s) | min Full in ${STABLE_SECS} s | samples below | ospfd RSS (MiB) | ospfd CPU avg/max (%) | zebra CPU | daemon CPU | removal (s) | result |"
	say "|---|---|---|---|---|---|---|---|---|---|---|"
	local n
	for n in ${NEIGHBORS//,/ }; do
		local csv=$OUT/neighbors-$n.csv t0 t_commit t_full verdict=ok
		mcp_open || { fail "neighbors: MCP"; return; }
		t0=$(now)
		if ! mcp_tool command_batch "$(neighbors_steps add "$n")" >"$W/batch.out"; then
			fail "neighbors $n: the batch was refused: $(head -c 400 "$W/batch.out")"
			mcp_close
			break
		fi
		t_commit=$(since "$t0")
		mcp_close
		neighbors_gen_config "$W/gen/neigh.json" "$n"
		t0=$(now)
		gen_start "$W/gen/neigh.json"
		if [ "$NEIGH_LSDB" -gt 0 ]; then
			wait_for "gen Full" 60 ge 1 dut_neighbors_full >/dev/null || true
			bbl ospf-load-mrt file "$(lsdb_mrt "$NEIGH_LSDB")" instance 1 >/dev/null
		fi
		sampler_start "$csv"
		if t_full=$(wait_for "$n neighbors Full" 600 ge "$((n + 1))" dut_neighbors_full); then
			t_full=$(since "$t0")
		else
			t_full=- verdict="FAIL (only $(dut_neighbors_full) of $((n + 1)) Full)"
		fi
		local min=999999 below=0 end=$((SECONDS + STABLE_SECS)) f
		if [ "$t_full" != - ]; then
			while [ $SECONDS -lt $end ]; do
				f=$(dut_neighbors_full || echo 0)
				[ "$f" -lt "$min" ] && min=$f
				[ "$f" -lt $((n + 1)) ] && below=$((below + 1))
				sleep 5
			done
			[ "$below" -gt 0 ] && verdict="FAIL (adjacencies dropped: $below samples below $((n + 1)))"
		fi
		sampler_stop
		local dead
		if dead=$(procs_dead); then verdict="FAIL ($dead died)"; fi
		gen_stop
		neighbors_template_remove
		mcp_open || true
		t0=$(now)
		mcp_tool command_batch "$(neighbors_steps remove "$n")" >"$W/batch.out" ||
			log "neighbors $n: removal: $(head -c 400 "$W/batch.out")"
		local t_rm
		t_rm=$(since "$t0")
		mcp_close
		wait_for "neighbors purge" 600 le 3 dut_lsas >/dev/null || true
		[ "$verdict" = ok ] || FAILED=1
		say "| $n | $(awk -v a="$t_commit" 'BEGIN {printf "%.1f", a / 1000}') | $(awk -v a="$t_full" 'BEGIN {if (a == "-") print "-"; else printf "%.1f", a / 1000}') | $([ "$min" = 999999 ] && echo - || echo "$min") | $below | $(csv_max "$csv" ospfd_rss) | $(csv_avg "$csv" ospfd_cpu)/$(csv_max "$csv" ospfd_cpu) | $(csv_avg "$csv" zebra_cpu)/$(csv_max "$csv" zebra_cpu) | $(csv_avg "$csv" daemon_cpu)/$(csv_max "$csv" daemon_cpu) | $(awk -v a="$t_rm" 'BEGIN {printf "%.1f", a / 1000}') | $verdict |"
		[ "$verdict" = ok ] || break
	done
	say ""
}

# --- 4. Operations with the biggest LSDB that passed loaded.
# recovered <secs>: Full, the LSDB and the routes back to what was
# loaded; prints the ms it took.
recovered_now() {
	[ "$(dut_neighbors_full)" -ge 1 ] && [ "$(dut_lsas)" -ge "$LOADED_LSAS" ] &&
		[ "$(dut_routes)" -ge "$LOADED_ROUTES" ]
}
recovered() { wait_for "recovery" "$1" recovered_now; }
secs() { awk -v a="$1" 'BEGIN {if (a == "" || a == "-") print "-"; else printf "%.1f", a / 1000}'; }
# The minimum of a column while the sampler ran (did anything drop?).
csv_min() {
	awk -v c="$2" 'NR == 1 {for (i = 1; i <= NF; i++) if ($i == c) k = i; next}
		$k != "-" && (m == "" || $k + 0 < m) {m = $k + 0} END {print m + 0}' "$1"
}
template_json() { cr routing.ospf.interface-template.list | jq -cS '[.[] | del(.matched, .interfaces_now, .state)]'; }

test_ops() {
	say "## 4. Operations with load ($LOADED_LSAS LSAs, $LOADED_ROUTES routes)"
	say ""
	say "| operation | command (ms) | back to normal (s) | min LSAs / routes during | nothing lost | result |"
	say "|---|---|---|---|---|---|"
	local before t0 t_cmd t_back csv verdict
	before=$(template_json)

	# a) An OSPF commit: the template's cost (no adjacency reset).
	csv=$OUT/ops-commit.csv
	sampler_start "$csv"
	t0=$(now)
	ok routing.ospf.interface-template.set "{\"id\":\"$TEMPLATE_ID\",\"cost\":20}" >/dev/null
	t_cmd=$(since "$t0")
	local applied
	if [ $DUT = local ]; then
		applied=$(wait_for "cost 20" 60 sh -c "vtysh --vty_socket '$W/dut/run/frr' -c 'show ip ospf interface $DUT_IFACE json' | grep -q '\"cost\":20'") || applied=-
	else
		applied=$(wait_for "cost 20" 60 sh -c "true") || applied=-
	fi
	sleep 3
	sampler_stop
	verdict=ok
	[ "$applied" = - ] && verdict="FAIL (cost not applied)"
	recovered_now || verdict="FAIL (not recovered)"
	say "| commit (template cost 10 → 20) | $t_cmd | $(secs "$applied") | $(csv_min "$csv" lsas) / $(csv_min "$csv" routes) | $(recovered_now && echo yes || echo NO) | $verdict |"
	[ "$verdict" = ok ] || FAILED=1
	ok routing.ospf.interface-template.set "{\"id\":\"$TEMPLATE_ID\",\"cost\":null}" >/dev/null
	sleep 3

	# b) Safe Mode, undone by hand: the template disabled (the adjacency
	# and all the routes go), then config.safe-mode.cancel.
	# c) Safe Mode, undone by the connection's loss (RouterOS: the session
	# ends, the changes go back).
	local how
	for how in cancel drop; do
		csv=$OUT/ops-safe-$how.csv
		verdict=ok
		mcp_open || { fail "ops: MCP"; return; }
		mcp_run config.safe-mode.enter >/dev/null || verdict="FAIL (enter)"
		mcp_run routing.ospf.interface-template.set "{\"id\":\"$TEMPLATE_ID\",\"disabled\":true}" >/dev/null || verdict="FAIL (set)"
		wait_for "adjacency down" 60 le 0 dut_neighbors_full >/dev/null || verdict="FAIL (did not go down)"
		sampler_start "$csv"
		t0=$(now)
		if [ $how = cancel ]; then
			mcp_run config.safe-mode.cancel >/dev/null || verdict="FAIL (cancel)"
			t_cmd=$(since "$t0")
			mcp_close
		else
			mcp_close
			t_cmd=-
		fi
		if t_back=$(recovered 900); then t_back=$(since "$t0"); else t_back=- verdict="FAIL (not back)"; fi
		sampler_stop
		local same=yes
		[ "$(template_json)" = "$before" ] || { same=NO; verdict="FAIL (config differs)"; }
		say "| Safe Mode, $([ $how = cancel ] && echo cancel || echo connection lost) (template disabled) | $t_cmd | $(secs "$t_back") | $(csv_min "$csv" lsas) / $(csv_min "$csv" routes) | $same | $verdict |"
		[ "$verdict" = ok ] || FAILED=1
	done

	if [ $DUT = remote ]; then
		say "| FRR restart | - | - | - | - | not run (remote: needs the router's console) |"
		say "| daemon restart | - | - | - | - | not run (remote: needs the router's console) |"
		say ""
		return
	fi
	# d) FRR killed (a crash: SIGKILL) and started again, as the init does;
	# the daemon sees it come back and installs the config (routing_resync).
	csv=$OUT/ops-frr-restart.csv
	verdict=ok
	sampler_start "$csv"
	t0=$(now)
	frr_stop KILL
	sleep 1
	frr_start
	if t_back=$(recovered 1200); then t_back=$(since "$t0"); else t_back=- verdict="FAIL (not back)"; fi
	sampler_stop
	local resync
	resync=$(grep -c -i 'resync\|installed again\|attached to FRR' "$W/dut/daemon.log" || true)
	say "| FRR killed and started (routing_resync; daemon log lines: $resync) | - | $(secs "$t_back") | $(csv_min "$csv" lsas) / $(csv_min "$csv" routes) | $(recovered_now && echo yes || echo NO) | $verdict |"
	[ "$verdict" = ok ] || FAILED=1

	# e) The daemon restarted (SIGTERM, start): FRR and the kernel keep
	# forwarding; the time until the daemon answers and reads OSPF again.
	csv=$OUT/ops-daemon-restart.csv
	verdict=ok
	sampler_start "$csv"
	t0=$(now)
	daemon_stop
	daemon_start
	local t_answer t_state
	t_answer=$(since "$t0")
	if t_state=$(wait_for "daemon reads OSPF" 300 sh -c "$(declare -f cr cr_local); DUT=$DUT W=$W CLI=$CLI NOPARAMS='{}'; cr routing.ospf.neighbor.list '{\"instance\":\"$INSTANCE\"}' | grep -q '\"state\":\"Full\"'"); then
		t_state=$(since "$t0")
	else
		t_state=- verdict="FAIL (no OSPF state after the restart)"
	fi
	sleep 3
	sampler_stop
	local minr
	minr=$(csv_min "$csv" routes)
	[ "$minr" -lt "$LOADED_ROUTES" ] && verdict="FAIL (routes dropped to $minr during the restart)"
	recovered_now || verdict="FAIL (not recovered)"
	say "| daemon restarted (answers after $(secs "$t_answer") s) | - | $(secs "$t_state") | $(csv_min "$csv" lsas) / $minr | $(recovered_now && echo yes || echo NO) | $verdict |"
	[ "$verdict" = ok ] || FAILED=1
	say ""
}

# --- 5. Latency of the commands with load: one CLI process per call
# (connection and all, what a script pays) and a warm MCP connection.
LAT_CMDS=(
	"routing.ospf.neighbor.list|{\"instance\":\"$INSTANCE\"}"
	"routing.ospf.interface.list|{\"instance\":\"$INSTANCE\"}"
	"routing.ospf.instance.list|{}"
	"routing.ospf.lsa.list|{\"instance\":\"$INSTANCE\",\"limit\":200}"
	"routing.ospf.route.list|{\"instance\":\"$INSTANCE\"}"
	"ip.route.list|{}"
	"ip.route.page|{\"limit\":500}"
	"system.resource.print|{}"
)
test_latency() {
	say "## 5. Command latency with load ($LOADED_LSAS LSAs, $LOADED_ROUTES routes; $LAT_N calls each)"
	say ""
	say "| command | reply (KiB) | CLI p50 (ms) | CLI p99 | MCP p50 (ms) | MCP p99 |"
	say "|---|---|---|---|---|---|"
	local e id params f t0 size
	for e in "${LAT_CMDS[@]}" "inspect|"; do
		id=${e%%|*} params=${e#*|}
		f=$W/lat-$id
		: >"$f.cli"
		: >"$f.mcp"
		local i
		for i in $(seq "$LAT_N"); do
			t0=$(now)
			if [ "$id" = inspect ]; then
				if [ $DUT = local ]; then
					ip netns exec crdut env COREROUTER_RUNTIME_DIR="$W/dut/run/corerouter" "$CLI" --connect 127.0.0.1:7979 inspect >"$f.out" 2>&1 || true
				else
					cli_remote inspect >"$f.out" 2>&1 || true
				fi
			else
				cr "$id" "$params" >"$f.out" 2>&1 || true
			fi
			since "$t0" >>"$f.cli"
		done
		size=$(($(stat -c %s "$f.out") / 1024))
		mcp_open || { fail "latency: MCP"; return; }
		for i in $(seq "$LAT_N"); do
			MCP_ID=$((MCP_ID + 1))
			local req
			if [ "$id" = inspect ]; then
				req=$(jq -cn --argjson id $MCP_ID '{jsonrpc: "2.0", id: $id, method: "tools/call", params: {name: "inspect_state", arguments: {}}}')
			else
				req=$(jq -cn --arg c "$id" --argjson p "$params" --argjson id $MCP_ID \
					'{jsonrpc: "2.0", id: $id, method: "tools/call", params: {name: "run_command", arguments: {command: $c, params: $p}}}')
			fi
			t0=$(now)
			mcp_send "$req"
			mcp_recv >"$f.mcpout" || true
			since "$t0" >>"$f.mcp"
		done
		mcp_close
		say "| \`$id\` | $size | $(pct "$f.cli" 50) | $(pct "$f.cli" 99) | $(pct "$f.mcp" 50) | $(pct "$f.mcp" 99) |"
	done
	say ""
}

# --- 6. Convergence with traffic (local DUT): BNG Blaster sends 10 000
# pps from gen1 through the DUT to gen2, behind R4; the DUT reaches R4 by
# R2 (cost 10 + 10) or R3 (20 + 10). The DUT–R2 link is cut silently
# (netem in R2's namespace: no carrier change), and the loss is counted.
#
#   gen1 ─ DUT ether2 ─ R2 ─┐
#          DUT ether3 ─ R3 ─ R4 ─ gen2 (10.250.0.2)
CONV_PPS=10000 CONV_RUNS=${CONV_RUNS:-3}
conv_links() {
	local ns
	for ns in crconv1 crconv2 crconv3; do
		ip netns add $ns
		ip -n $ns link set lo up
		ip netns exec $ns sysctl -qw net.ipv4.ip_forward=1 net.mpls.platform_labels=1048575 2>/dev/null || true
	done
	ip link add ether2 netns crdut type veth peer name c1-dut netns crconv1
	ip link add ether3 netns crdut type veth peer name c2-dut netns crconv2
	ip link add c1-r4 netns crconv1 type veth peer name c4-r2 netns crconv3
	ip link add c2-r4 netns crconv2 type veth peer name c4-r3 netns crconv3
	ip link add c4-sink netns crconv3 type veth peer name gen2 netns crgen
	ip -n crdut link set ether2 up
	ip -n crdut link set ether3 up
	ip -n crgen link set gen2 up
	ip netns exec crgen ethtool -K gen2 tx off rx off >/dev/null 2>&1 || true
	local a
	for a in "crconv1 c1-dut 10.0.2.2/30" "crconv1 c1-r4 10.0.24.1/30" "crconv2 c2-dut 10.0.3.2/30" \
		"crconv2 c2-r4 10.0.34.1/30" "crconv3 c4-r2 10.0.24.2/30" "crconv3 c4-r3 10.0.34.2/30" \
		"crconv3 c4-sink 10.250.0.1/24"; do
		set -- $a
		ip -n "$1" addr add "$3" dev "$2"
		ip -n "$1" link set "$2" up
		ip netns exec "$1" sysctl -qw "net.mpls.conf.$2.input=1" 2>/dev/null || true
	done
	set --
}
# conv_router <ns> <n> <if:cost…>: the VM's FRR (zebra, ospfd, bfdd) as R<n>,
# SR on (TI-LFA needs it everywhere), BFD 3 × 10 ms towards the DUT.
conv_router() {
	local ns=$1 n=$2 d=/etc/frr/$1
	shift 2
	install -d -o frr -g frr "$d" "/var/run/frr/$ns"
	: >"$d/vtysh.conf"
	: >"$d/zebra.conf"
	ip -n "$ns" addr add "10.255.0.$n/32" dev lo
	{
		local ic
		for ic in "$@"; do
			printf 'interface %s\n ip ospf network point-to-point\n ip ospf hello-interval 1\n' "${ic%%:*}"
			printf ' ip ospf dead-interval 4\n ip ospf cost %s\n ip ospf area 0.0.0.0\n' "${ic##*:}"
			case ${ic%%:*} in *-dut) printf ' ip ospf bfd\n ip ospf bfd profile crfast\n' ;; esac
			printf 'exit\n'
		done
		[ "$ns" = crconv3 ] && printf 'interface c4-sink\n ip ospf area 0.0.0.0\n ip ospf passive\nexit\n'
		printf 'interface lo\n ip ospf area 0.0.0.0\n ip ospf passive\nexit\n'
		printf 'router ospf\n ospf router-id 10.255.0.%s\n capability opaque\n router-info area\n' "$n"
		printf ' segment-routing on\n segment-routing prefix 10.255.0.%s/32 index %s\nexit\n' "$n" "$n"
	} >"$d/ospfd.conf"
	printf 'bfd\n profile crfast\n  detect-multiplier 3\n  receive-interval 10\n  transmit-interval 10\n exit\nexit\n' >"$d/bfdd.conf"
	chown -R frr:frr "$d"
	ip netns exec "$ns" /usr/lib/frr/zebra -N "$ns" -d -f "$d/zebra.conf" --log "file:$d/zebra.log" </dev/null >/dev/null 2>&1
	for _ in $(seq 50); do [ -S "/var/run/frr/$ns/zserv.api" ] && break; sleep 0.1; done
	ip netns exec "$ns" /usr/lib/frr/ospfd -N "$ns" -d -f "$d/ospfd.conf" --log "file:$d/ospfd.log" </dev/null >/dev/null 2>&1
	ip netns exec "$ns" /usr/lib/frr/bfdd -N "$ns" -d -f "$d/bfdd.conf" --log "file:$d/bfdd.log" </dev/null >/dev/null 2>&1
}
conv_routers_stop() {
	pkill -f -- "-N crconv" 2>/dev/null || true
	for _ in $(seq 30); do pgrep -f -- "-N crconv" >/dev/null || break; sleep 0.1; done
	pkill -9 -f -- "-N crconv" 2>/dev/null || true
	rm -rf /etc/frr/crconv1 /etc/frr/crconv2 /etc/frr/crconv3 /var/run/frr/crconv1 /var/run/frr/crconv2 /var/run/frr/crconv3
}
# The DUT's way to the sink now: the interface of its FIB route.
conv_via() { vty 'show ip route 10.250.0.0/24 json' | jq -r '.["10.250.0.0/24"][]? | select(.selected) | .nexthops[]? | select(.fib) | .interfaceName' | head -n 1; }
conv_backup() { vty 'show ip route 10.250.0.0/24 json' | jq -r '[.["10.250.0.0/24"][]? | select(.selected) | .backupNexthops[]?] | length'; }
conv_cut() { # on|off: the DUT–R2 link, silently (both directions)
	if [ "$1" = on ]; then
		ip netns exec crconv1 tc qdisc add dev c1-dut root netem loss 100%
		ip netns exec crconv1 tc qdisc add dev c1-dut ingress
		ip netns exec crconv1 tc filter add dev c1-dut parent ffff: matchall action drop
	else
		ip netns exec crconv1 tc qdisc del dev c1-dut root 2>/dev/null || true
		ip netns exec crconv1 tc qdisc del dev c1-dut ingress 2>/dev/null || true
	fi
}
conv_counters() { bbl stream-info flow-id 1 | jq -r '.["stream-info"] | "\(.["tx-packets"] // 0) \(.["rx-packets"] // 0)"'; }
via_is() { [ "$(conv_via)" = "$1" ]; }

test_convergence() {
	say "## 6. Convergence with traffic ($CONV_PPS pps, DUT–R2 cut silently, $CONV_RUNS runs each)"
	say ""
	if [ $DUT = remote ]; then
		say "Not run: the remote mode has no R2/R3/R4 behind the router (phase C wires its own)."
		say ""
		return
	fi
	modprobe mpls_router 2>/dev/null || true
	modprobe mpls_iptunnel 2>/dev/null || true
	ip netns exec crdut sysctl -qw net.mpls.platform_labels=1048575 2>/dev/null || true
	conv_links
	ok ip.address.add '{"address":"10.0.2.1/30","interface":"ether2"}' >/dev/null
	ok ip.address.add '{"address":"10.0.3.1/30","interface":"ether3"}' >/dev/null
	local t2 t3
	t2=$(ok routing.ospf.interface-template.add '{"area":"stress-bb","networks":["10.0.2.0/30"],"type":"ptp","cost":10,"hello_interval":1,"dead_interval":4,"comment":"conv R2"}' | jq -r .id)
	t3=$(ok routing.ospf.interface-template.add '{"area":"stress-bb","networks":["10.0.3.0/30"],"type":"ptp","cost":20,"hello_interval":1,"dead_interval":4,"comment":"conv R3"}' | jq -r .id)
	conv_router crconv1 2 c1-dut:10 c1-r4:10
	conv_router crconv2 3 c2-dut:20 c2-r4:10
	conv_router crconv3 4 c4-r2:10 c4-r3:10
	cat >"$W/gen/conv.json" <<EOF
{
  "interfaces": {
    "network": [
      {"interface": "gen1", "address": "$LINK_GEN/30", "gateway": "$LINK_DUT", "ospfv2-instance-id": 1, "ospfv2-type": "p2p"},
      {"interface": "gen2", "address": "10.250.0.2/24", "gateway": "10.250.0.1"}
    ]
  },
  "ospf": [{"instance-id": 1, "version": 2, "router-id": "$GEN_RID", "hello-interval": 1, "dead-interval": 4}],
  "streams": [{"name": "conv", "type": "ipv4", "direction": "downstream", "pps": $CONV_PPS,
    "network-interface": "gen1", "destination-ipv4-address": "10.250.0.2", "length": 128}]
}
EOF
	gen_start "$W/gen/conv.json"
	if ! wait_for "R2, R3 and gen Full" 120 ge 3 dut_neighbors_full >/dev/null ||
		! wait_for "route via R2" 60 via_is ether2 >/dev/null; then
		fail "convergence: the topology did not come up ($(dut_neighbors_full) Full, via $(conv_via))"
		vty 'show ip ospf neighbor'
		gen_stop
		return
	fi
	say "| protection | detection | loss per run (ms) | median (ms) | backup in zebra | result |"
	say "|---|---|---|---|---|---|"
	local mode
	for mode in none bfd ti-lfa; do
		case $mode in
		bfd)
			ok routing.bfd.profile.add '{"name":"crfast","min_tx":10,"min_rx":10,"multiplier":3}' >/dev/null
			ok routing.ospf.interface-template.set "{\"id\":\"$t2\",\"bfd\":\"crfast\"}" >/dev/null
			ok routing.ospf.interface-template.set "{\"id\":\"$t3\",\"bfd\":\"crfast\"}" >/dev/null
			;;
		ti-lfa)
			cr interface.loopback.add '{"name":"lo"}' >/dev/null 2>&1 || true
			ok ip.address.add '{"address":"10.255.0.1/32","interface":"lo"}' >/dev/null
			ok routing.ospf.interface-template.add '{"area":"stress-bb","interfaces":["lo"],"passive":true,"comment":"conv lo"}' >/dev/null
			if ! ok routing.ospf.segment-routing.set "{\"instance\":\"$INSTANCE\",\"ti_lfa\":\"link\",\"force\":true}" >"$W/sr.out"; then
				say "| TI-LFA | - | - | - | - | FAIL (segment-routing.set refused: $(head -c 300 "$W/cr.err")) |"
				FAILED=1
				break
			fi
			wait_for "TI-LFA backup" 120 ge 1 conv_backup >/dev/null || log "no backup next hop in zebra"
			;;
		esac
		sleep 5
		local runs="" r lost verdict=ok
		for r in $(seq "$CONV_RUNS"); do
			wait_for "via R2" 120 via_is ether2 >/dev/null || { verdict="FAIL (not back on R2)"; break; }
			sleep 3
			local a b
			a=$(conv_counters)
			conv_cut on
			wait_for "via R3" 30 via_is ether3 >/dev/null || verdict="FAIL (no switch to R3)"
			sleep 2
			b=$(conv_counters)
			conv_cut off
			lost=$(awk -v a="$a" -v b="$b" -v pps=$CONV_PPS 'BEGIN {split(a, x, " "); split(b, y, " ");
				printf "%.1f", ((y[1] - x[1]) - (y[2] - x[2])) * 1000 / pps}')
			runs+="$lost "
			wait_for "R2 Full again" 60 ge 3 dut_neighbors_full >/dev/null || true
		done
		local med
		med=$(printf '%s\n' $runs | sort -n | awk '{a[NR] = $1} END {print a[int((NR + 1) / 2)]}')
		local det
		case $mode in none) det="dead interval 4 s" ;; bfd) det="BFD 3 × 10 ms" ;; ti-lfa) det="BFD 3 × 10 ms" ;; esac
		[ "$verdict" = ok ] || FAILED=1
		say "| $mode | $det | ${runs% } | $med | $(conv_backup) | $verdict |"
	done
	gen_stop
	conv_routers_stop
	say ""
}

has_test lsdb && test_lsdb
[ "$BIGGEST" = 0 ] && BIGGEST=${LOAD:-10000}
has_test churn && test_churn
has_test neighbors && test_neighbors
if has_test ops || has_test latency; then
	if lsdb_load "$BIGGEST"; then
		has_test ops && test_ops
		has_test latency && test_latency
	else
		fail "ops/latency: the LSDB of $BIGGEST LSAs did not load"
	fi
	gen_stop
fi
has_test convergence && test_convergence
if [ "${TESTS}" = none ]; then
	say "up: $(dut_neighbors_full) full, LSAs $(dut_lsas), routes $(dut_routes), spf $(dut_spf), procs $(proc_sample)"
	vty 'show ip ospf json' | head -c 3000
fi
say ""
say "results: $RESULTS"
exit $FAILED
