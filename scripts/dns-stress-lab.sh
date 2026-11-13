#!/usr/bin/env bash
# G4.1r: CoreRouter's DNS server under load. Puts the forwarder (G4.1b),
# the resolver and its cache (G4.1a), static entries, zones and dynamic
# DNS (G4.1c), the adlist and the encrypted upstreams (G4.1d) under load
# and measures throughput, latency, cost per thread and stability. Runs as
# root inside the lab VM only (or in a user namespace on a host, --userns,
# for development). The load is DNS-OARC's dnsperf; the origin is a Knot DNS
# authoritative server of the lab (never a public resolver), behind
# `tc netem` for delay and loss; Unbound serves it over DoT/DoH and is,
# with dnsmasq, the comparison. See docs/dns-stress.md.
#
#   scripts/dns-stress-lab.sh --host <images> [options]     (on the host:
#       puts the image's root in the VM and runs the lab there)
#   cargo xtask vm-lab run --lock-timeout 4h -- scripts/dns-stress-lab.sh [options]
#   scripts/dns-stress-lab.sh --userns --tools <dir> --daemon build [options]
#       (a host without root: user and network namespaces, the third-party
#       tools unpacked from Ubuntu's .debs in <dir>; no netem there)
#
# Router under test (DUT):
#   --dut local    (default) the image's daemon (--daemon image, its root in
#                  a chroot) or a build (--daemon build: $CARGO_TARGET_DIR,
#                  or a path), in namespace crdut, pinned to --dut-cpus; the
#                  lab (clients, origin) in namespace crgen, pinned to
#                  --gen-cpus, joined by a veth (crdut: ether1, crgen: lab0).
#   --dut remote --iface <if> --target <addr[:port]> [--mgmt <cidr>]
#                  a router elsewhere (the notebook of phase C): clients and
#                  origin answer on <if> (moved into crgen for the run, back
#                  at the end); commands by `corerouter-cli --connect
#                  tls://<addr>` as --user (admin; password in
#                  $COREROUTER_PASSWORD). --mgmt adds that address to <if>
#                  to reach <addr>. --dut-iface: the router's port on the
#                  cable (never the one on the home network). The test
#                  config goes in by transaction and leaves by rollback.
#   --selftest-remote  a local DUT driven as a remote one (TLS on 10.53.0.1).
#
# Tests (--tests, comma-separated; default all but soak):
#   qps       cache hit, static, zone, miss with a 20 ms origin, a mix; each
#             at saturation and at half of it; readers by --dut-cpus-list
#   torture   unique names (water torture), legit clients beside it; equal
#             queries in flight (G4.1o); a flush under load
#   origin    failover, serve-stale (RFC 8767), failure cache (RFC 9520),
#             all origins down under load, loss, a slow origin
#   tcp       TCP clients, idle/slow connections (slowloris), descriptors;
#             DoT and DoH upstream under load
#   cache     cache up to --fill entries: memory per entry, eviction, print
#             and flush under load
#   adlist    a list of --adlist names: load time, memory, cost, reload
#   ddns      a zone of --zone-records records, RFC 2136 UPDATEs and a DHCP
#             storm with names, zone queries beside them (G4.1p, G4.1q)
#   hostile   junk, ANY, big TXT, a client outside allowed_from
#   ops       commands under load (ip.dns.set, statics, flush, statistics,
#             an atomic batch): their p99 and the load's
#   compare   the same runs against Unbound and dnsmasq (local only)
#   soak      moderate load for --soak-secs: RSS, threads, fds, cache, p99
#
# Results: $OUT/results.md (a table per test), $OUT/*.csv and $OUT/raw/;
# exit 1 if a check failed.
set -euo pipefail
# Decimal points, not commas ($EPOCHREALTIME, awk, printf).
export LC_ALL=C

usage() { sed -n '2,52p' "$0"; exit 2; }

if [ "${1:-}" = "--host" ]; then
	IMAGES=${2:?usage: $0 --host <images dir> [options]}
	shift 2
	# A round first: an unhealthy VM goes back to its snapshot there, which
	# would drop what `put` copies.
	cargo xtask vm-lab run --lock-timeout "${LOCK_TIMEOUT:-4h}" -- true
	tmp=$(mktemp -d)
	cp --reflink=auto "$IMAGES/rootfs.squashfs" "$tmp/dns-stress-rootfs.squashfs"
	cargo xtask vm-lab put "$tmp/dns-stress-rootfs.squashfs"
	rm -rf "$tmp"
	exec cargo xtask vm-lab run --lock-timeout "${LOCK_TIMEOUT:-4h}" -- scripts/dns-stress-lab.sh "$@"
fi

if [ "${1:-}" = "--userns" ]; then
	shift
	# Root of a user namespace, with its own mounts (a /run for `ip netns`)
	# and network: nothing reaches the host.
	# A work directory of its own: two rounds on one host (a soak and a
	# profile) must not share the token, the query files or the logs.
	export DNS_LAB_DIR=/tmp/crdnsstress-$$
	exec unshare --user --map-root-user --mount --net --pid --fork --mount-proc \
		bash -c 'mount -t tmpfs tmpfs /run && mkdir -p /run/netns && exec "$0" --in-userns "$@"' "$0" "$@"
fi

DUT=local IFACE="" TARGET="" RUSER=${RUSER:-admin} MGMT="" DUT_IFACE=ether1
TESTS=qps,torture,origin,tcp,cache,adlist,ddns,hostile,ops,compare
DAEMON=image
SELFTEST=0
TOOLS=""
DUR=15
NCPU=$(nproc)
DUT_CPUS=0-$((NCPU / 2 - 1))
GEN_CPUS=$((NCPU / 2))-$((NCPU - 1))
DUT_CPUS_LIST=""
HOT=10000 STATICS=1000 ZONE_N=10000
# The zones hold at most 50 000 records in all (model::dns_zone::
# MAX_RECORDS, the SOA, NS and glue included): test ddns fills them, the
# zone that changes with --zone-records and a second one with the rest
# (G4.1p: every change rebuilds every primary zone).
FILL=1000000 ADLIST_N=1000000 ZONE_RECORDS=40000 DHCP_N=20000
SOAK_SECS=7200
OUT=""
while [ $# -gt 0 ]; do
	case $1 in
	--in-userns) shift ;;
	--dut) DUT=$2; shift 2 ;;
	--iface) IFACE=$2; shift 2 ;;
	--target) TARGET=$2; shift 2 ;;
	--user) RUSER=$2; shift 2 ;;
	--mgmt) MGMT=$2; shift 2 ;;
	--dut-iface) DUT_IFACE=$2; shift 2 ;;
	--tests) TESTS=$2; shift 2 ;;
	--daemon) DAEMON=$2; shift 2 ;;
	--tools) TOOLS=$2; shift 2 ;;
	--duration) DUR=$2; shift 2 ;;
	--dut-cpus) DUT_CPUS=$2; shift 2 ;;
	--gen-cpus) GEN_CPUS=$2; shift 2 ;;
	--dut-cpus-list) DUT_CPUS_LIST=$2; shift 2 ;;
	--hot) HOT=$2; shift 2 ;;
	--fill) FILL=$2; shift 2 ;;
	--adlist) ADLIST_N=$2; shift 2 ;;
	--zone-records) ZONE_RECORDS=$2; shift 2 ;;
	--dhcp-clients) DHCP_N=$2; shift 2 ;;
	--soak-secs) SOAK_SECS=$2; shift 2 ;;
	--selftest-remote) SELFTEST=1; shift ;;
	--out) OUT=$2; shift 2 ;;
	-h | --help) usage ;;
	*) echo "unknown option $1"; usage ;;
	esac
done

# vm-lab run holds its lock on fd 9: the daemons started here must not.
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run) or with --userns"; exit 1; }

# --- Third-party tools: Ubuntu's packages in the VM (installed when
# missing, from the signed archive), or unpacked .debs (--tools).
TENV=()
if [ -n "$TOOLS" ]; then
	# A wrapper per program, with the unpacked libraries (only for them).
	mkdir -p /tmp/crdnsstress-bin
	for b in "$TOOLS"/usr/bin/* "$TOOLS"/usr/sbin/*; do
		printf '#!/bin/sh\nLD_LIBRARY_PATH=%s/usr/lib/x86_64-linux-gnu exec %s "$@"\n' "$TOOLS" "$b" >"/tmp/crdnsstress-bin/${b##*/}"
		chmod +x "/tmp/crdnsstress-bin/${b##*/}"
	done
	export PATH=/tmp/crdnsstress-bin:$PATH
elif ! command -v dnsperf >/dev/null || ! command -v knotd >/dev/null || ! command -v unbound >/dev/null ||
	! command -v kdig >/dev/null || ! command -v dnsmasq >/dev/null; then
	echo "installing dnsperf, knot, knot-dnsutils, unbound and dnsmasq-base (Ubuntu archive)"
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
		dnsperf knot knot-dnsutils unbound dnsmasq-base >/dev/null
	# Packaged services stay off: the lab starts its own.
	systemctl disable --now knot unbound 2>/dev/null || true
fi
for t in dnsperf knotd knotc kdig unbound jq python3 nft tc taskset; do
	command -v "$t" >/dev/null || { echo "$t missing"; exit 1; }
done
tool() { "${TENV[@]}" "$@"; }

INBOX=/srv/lab/inbox
W=${DNS_LAB_DIR:-/tmp/crdnsstress}
R=$W/root
if [ -z "$OUT" ]; then
	if [ -d /srv/lab ]; then OUT=/srv/lab/dns-stress/$(date +%Y%m%d-%H%M%S); else OUT=$W/out; fi
fi
RESULTS=$OUT/results.md
FAILED=0
TLS_PORT=8729

if [ $SELFTEST = 1 ]; then
	DUT=remote IFACE=crlink0 TARGET=10.53.0.1 MGMT=""
fi
case $DUT in
local) ;;
remote)
	[ -n "$IFACE" ] && [ -n "$TARGET" ] || { echo "--dut remote needs --iface and --target"; exit 2; }
	case $TARGET in *:*) ;; *) TARGET=$TARGET:$TLS_PORT ;; esac
	;;
*) echo "--dut local|remote"; exit 2 ;;
esac
LAB_IF=lab0
[ $DUT = remote ] && LAB_IF=$IFACE
[ $SELFTEST = 1 ] && LAB_IF=lab0

# The lab's addresses, one segment: the DUT, clients, origins.
NET=10.53.0
DUT_IP=$NET.1
CLIENTS=($NET.2 $NET.3 $NET.4 $NET.5 $NET.6 $NET.7 $NET.8 $NET.9)
OUTSIDER=$NET.200 # outside allowed_from (10.53.0.0/25)
UP1=$NET.53 UP2=$NET.54 # Knot, two "servers"
SECURE=$NET.55 # Unbound: DoT 853, DoH 443, forwarding to Knot
WEB=$NET.56 # the adlist over HTTP
ORIGINS=$NET.48/28 # what netem delays
DHCP_NET=10.54

mkdir -p "$OUT/raw"
: >"$RESULTS"
say() { printf '%s\n' "$*" | tee -a "$RESULTS"; }
log() { printf '%s %s\n' "$(date +%T)" "$*" >&2; }
fail() { say "FAIL $*"; FAILED=1; }
now() { printf '%s' "${EPOCHREALTIME//[.,]/}" | cut -c1-13; } # ms since the epoch
want() { [[ ",$TESTS," == *",$1,"* ]]; }

# --- Namespaces and the lab segment.
in_gen() { ip netns exec crgen taskset -c "$GEN_CPUS" "$@"; }

net_up() {
	ip netns add crgen
	ip -n crgen link set lo up
	if [ $DUT = local ] || [ $SELFTEST = 1 ]; then
		ip netns add crdut
		ip -n crdut link set lo up
		ip link add ether1 netns crdut type veth peer name lab0 netns crgen
		ip -n crdut link set ether1 up
	else
		ip link set "$IFACE" netns crgen
		[ -n "$MGMT" ] && ip -n crgen addr add "$MGMT" dev "$IFACE"
	fi
	ip -n crgen link set "$LAB_IF" up
	local a
	for a in "${CLIENTS[@]}" $OUTSIDER $UP1 $UP2 $SECURE $WEB; do
		ip -n crgen addr add "$a/24" dev "$LAB_IF"
	done
	ip -n crgen addr add "$DHCP_NET.255.254/16" dev "$LAB_IF"
	# Origin counters and a "dead" set (blackholed origins: no reply, no
	# ICMP, like a server that is gone).
	ip netns exec crgen nft -f - <<EOF
table inet crlab {
	set dead { type ipv4_addr; }
	counter up1 { }
	counter up2 { }
	counter dot_syn { }
	counter doh_syn { }
	chain input {
		type filter hook input priority 0;
		ip daddr $UP1 udp dport 53 counter name up1
		ip daddr $UP2 udp dport 53 counter name up2
		ip daddr $SECURE tcp dport 853 tcp flags & (syn | ack) == syn counter name dot_syn
		ip daddr $SECURE tcp dport 443 tcp flags & (syn | ack) == syn counter name doh_syn
		ip daddr @dead udp dport 53 drop
		ip daddr @dead tcp dport { 53, 443, 853 } drop
	}
}
EOF
	netem_setup
}
net_down() {
	ip netns pids crgen 2>/dev/null | xargs -r kill -9 2>/dev/null || true
	ip netns pids crdut 2>/dev/null | xargs -r kill -9 2>/dev/null || true
	if [ $DUT = remote ] && [ $SELFTEST = 0 ]; then
		ip -n crgen link set "$IFACE" netns 1 2>/dev/null || true
	fi
	ip netns del crgen 2>/dev/null || true
	ip netns del crdut 2>/dev/null || true
}

# netem on the replies of the origins only (a prio qdisc, a filter on
# their source): the clients' traffic is never delayed.
NETEM=0
netem_setup() {
	if ! ip netns exec crgen tc qdisc add dev "$LAB_IF" root handle 1: prio bands 3 \
		priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 2>/dev/null ||
		! ip netns exec crgen tc qdisc add dev "$LAB_IF" parent 1:3 handle 30: netem delay 0ms limit 200000 2>/dev/null; then
		log "no netem here (sch_netem): origin delay and loss are skipped"
		return 0
	fi
	ip netns exec crgen tc filter add dev "$LAB_IF" parent 1: protocol ip prio 1 u32 \
		match ip src "$ORIGINS" flowid 1:3
	NETEM=1
}
origin_delay() { # <ms> [loss %]
	[ $NETEM = 1 ] || return 0
	local loss=()
	[ -n "${2:-}" ] && [ "$2" != 0 ] && loss=(loss "$2%")
	ip netns exec crgen tc qdisc change dev "$LAB_IF" parent 1:3 handle 30: netem delay "${1}ms" limit 200000 "${loss[@]}"
}
origin_dead() { ip netns exec crgen nft add element inet crlab dead "{ $1 }"; }
origin_alive() { ip netns exec crgen nft flush set inet crlab dead; }
origin_count() { # → queries Knot got so far (both addresses)
	ip netns exec crgen nft -j list counters table inet crlab 2>/dev/null |
		jq '[.nftables[] | .counter? | select(.name == "up1" or .name == "up2") | .packets] | add // 0'
}
syn_count() { # <dot_syn|doh_syn>
	ip netns exec crgen nft -j list counter inet crlab "$1" 2>/dev/null | jq '[.nftables[] | .counter?.packets // empty] | add // 0'
}

# --- The origin: Knot, authoritative for up.lab (and nothing else).
# h<i>: the hot names; *.wt: any unique name (water torture, cache
# fill); ttl0: never cached; *.short: TTL 2 (serve-stale); big: TXT of
# ~3.8 KB; many: 60 A records (ANY, amplification).
KNOT=$W/knot
knot_zone() {
	rm -rf "$KNOT"
	mkdir -p "$KNOT"
	{
		echo '$ORIGIN up.lab.'
		echo '$TTL 3600'
		echo '@ SOA ns hostmaster 1 3600 600 86400 300'
		echo '@ NS ns'
		echo "ns A $UP1"
		awk -v n="$HOT" 'BEGIN {for (i = 0; i < n; i++) printf "h%d A 10.1.%d.%d\n", i, int(i / 250) % 250, i % 250 + 1}'
		echo '*.wt A 10.2.0.1'
		echo '*.mix 300 A 10.2.0.2'
		echo 'ttl0 0 A 10.2.0.3'
		echo '*.short 2 A 10.2.0.4'
		local s="" i
		for i in $(seq 15); do s+="\"$(printf '%0250d' "$i")\" "; done
		echo "big TXT $s"
		for i in $(seq 60); do echo "many A 10.3.0.$i"; done
	} >"$KNOT/up.lab.zone"
	cat >"$KNOT/knot.conf" <<EOF
server:
  rundir: $KNOT
  listen: [ $UP1@53, $UP2@53 ]
  udp-workers: 2
  tcp-workers: 2
  background-workers: 1
database:
  storage: $KNOT
template:
  - id: default
    storage: $KNOT
zone:
  - domain: up.lab
    file: up.lab.zone
log:
  - target: $KNOT/knot.log
    any: warning
EOF
}
knot_start() {
	knot_zone
	in_gen "${TENV[@]}" knotd -c "$KNOT/knot.conf" >>"$KNOT/knotd.out" 2>&1 &
	local end=$((SECONDS + 20))
	until in_gen "${TENV[@]}" kdig +short +timeout=1 +retry=0 @"$UP1" h1.up.lab A 2>/dev/null | grep -q .; do
		[ $SECONDS -lt $end ] || { echo "Knot did not answer"; tail -n 20 "$KNOT/knotd.out" "$KNOT/knot.log"; exit 1; }
		sleep 0.2
	done
}

# Unbound's files: where Ubuntu's AppArmor profile for /usr/sbin/unbound
# lets it read (/etc/unbound/**) when we can write there (the VM), else
# in $W (a user namespace on a host: no profile applies to the unpacked
# binary).
ub_dir() { # <name>
	if [ -w /etc/unbound ]; then echo "/etc/unbound/crlab-$1"; else echo "$W/$1"; fi
}
# Unbound in crgen: DoT (853) and DoH (443) in front of Knot, a
# self-signed certificate (the DUT runs verify_doh_cert=no).
SEC=$(ub_dir secure)
secure_start() {
	mkdir -p "$SEC"
	rm -f "$SEC/unbound.log"
	[ -s "$SEC/key.pem" ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-keyout "$SEC/key.pem" -out "$SEC/cert.pem" -days 30 -subj "/CN=lab-origin" \
		-addext "subjectAltName=DNS:lab-origin,IP:$SECURE" 2>/dev/null
	cat >"$SEC/unbound.conf" <<EOF
server:
  username: ""
  chroot: ""
  directory: "$SEC"
  pidfile: ""
  use-syslog: no
  logfile: ""
  verbosity: 0
  do-daemonize: no
  num-threads: 2
  interface: $SECURE@853
  interface: $SECURE@443
  tls-port: 853
  https-port: 443
  tls-service-key: "$SEC/key.pem"
  tls-service-pem: "$SEC/cert.pem"
  incoming-num-tcp: 1000
  access-control: $NET.0/24 allow
  do-not-query-localhost: no
  cache-max-ttl: 0
  msg-cache-size: 4m
  rrset-cache-size: 4m
  domain-insecure: "up.lab"
  module-config: "iterator"
forward-zone:
  name: "."
  forward-addr: $UP1
EOF
	in_gen "${TENV[@]}" unbound -c "$SEC/unbound.conf" >>"$SEC/unbound.out" 2>&1 &
	local end=$((SECONDS + 20))
	until in_gen "${TENV[@]}" kdig +short +tls +timeout=1 +retry=0 @"$SECURE" h1.up.lab A 2>/dev/null | grep -q .; do
		[ $SECONDS -lt $end ] || { log "Unbound (DoT origin) did not answer: $(tail -n 3 "$SEC/unbound.out" | tr '\n' ' ')"; return 1; }
		sleep 0.3
	done
}

# --- The router under test: the image's root in a chroot, or a build.
mount_image() {
	[ -s "$INBOX/dns-stress-rootfs.squashfs" ] ||
		{ echo "$INBOX/dns-stress-rootfs.squashfs missing: run with --host <images> from the host"; exit 1; }
	mkdir -p "$W"/{lower,rw,root}
	modprobe loop 2>/dev/null || true
	mount -t squashfs -o loop,ro "$INBOX/dns-stress-rootfs.squashfs" "$W/lower"
	mount -t tmpfs tmpfs "$W/rw"
	mkdir -p "$W/rw/upper" "$W/rw/work"
	mount -t overlay overlay -o "lowerdir=$W/lower,upperdir=$W/rw/upper,workdir=$W/rw/work" "$R"
	# What the image's init does at boot (pid1.rs).
	rm -rf "$R/var/run"
	ln -s /run "$R/var/run"
	mkdir -p "$R/var/log" "$R/var/lib" "$R/var/tmp"
}
umount_image() {
	umount -l "$R" 2>/dev/null || true
	umount -l "$W/rw" 2>/dev/null || true
	umount -l "$W/lower" 2>/dev/null || true
}

DAEMON_BIN=""
case $DAEMON in
image) ;;
build) DAEMON_BIN=${CARGO_TARGET_DIR:-target}/release/corerouter-daemon ;;
*) DAEMON_BIN=$DAEMON ;;
esac

# The CLI: the build's (the image has none).
CLI=${CLI:-${CARGO_TARGET_DIR:-target}/release/corerouter-cli}
build_tools() {
	local pkgs=(-p corerouter-cli)
	[ "$DAEMON" = build ] && pkgs+=(-p corerouter-daemon)
	if [ ! -x "$CLI" ] || { [ "$DAEMON" = build ] && [ ! -x "$DAEMON_BIN" ]; } || [ -n "${REBUILD:-}" ]; then
		log "building ${pkgs[*]} (release)"
		cargo build --release -q "${pkgs[@]}"
	fi
	CLI=$(readlink -f "$CLI")
	[ -z "$DAEMON_BIN" ] || DAEMON_BIN=$(readlink -f "$DAEMON_BIN")
	# The DUT is found by its name (dut_pid): a daemon kept under another
	# name (an older build, for a before/after) runs through a link named
	# as the build's.
	if [ -n "$DAEMON_BIN" ] && [ "$(basename "$DAEMON_BIN")" != corerouter-daemon ]; then
		mkdir -p "$W/bin"
		ln -sf "$DAEMON_BIN" "$W/bin/corerouter-daemon"
		DAEMON_BIN=$W/bin/corerouter-daemon
	fi
}

daemon_start() { # [cpus]
	local cpus=${1:-$DUT_CPUS} extra=()
	[ $SELFTEST = 1 ] && extra=(--listen "0.0.0.0:$TLS_PORT")
	mkdir -p "$W/dut/run/corerouter" "$W/dut/tmp/cfg"
	if [ -n "$DAEMON_BIN" ]; then
		taskset -c "$cpus" ip netns exec crdut env COREROUTER_RUNTIME_DIR="$W/dut/run/corerouter" RUST_LOG=info \
			"$DAEMON_BIN" --backend linux --config-dir "$W/dut/tmp/cfg" --control 7979 \
			--manage 'ether*' "${extra[@]}" >>"$W/dut/daemon.log" 2>&1 &
	else
		taskset -c "$cpus" ip netns exec crdut unshare --mount sh -c '
			R=$1; S=$2; shift 2
			mount -t proc proc "$R/proc"
			mount -t sysfs sys "$R/sys"
			mount --rbind /dev "$R/dev"
			mount --bind "$S/run" "$R/run"
			mount --bind "$S/tmp" "$R/tmp"
			exec chroot "$R" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/tmp RUST_LOG=info \
				COREROUTER_RUNTIME_DIR=/run/corerouter "$@"' sh "$R" "$W/dut" \
			/usr/bin/corerouter-daemon --backend linux --config-dir /tmp/cfg --control 7979 \
			--manage 'ether*' "${extra[@]}" >>"$W/dut/daemon.log" 2>&1 &
	fi
	local end=$((SECONDS + 60))
	until cr_local system.resource.print >/dev/null 2>&1; do
		[ $SECONDS -lt $end ] || { echo "the DUT's daemon did not answer"; tail -n 30 "$W/dut/daemon.log"; exit 1; }
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
DPID=""
local_dut() { [ $DUT = local ]; }

# The CLI warns on stderr that admin has no password, on every call.
export RUST_LOG=error

# --- Commands to the DUT. Local: the local token, from inside crdut.
# Remote: TLS from inside crgen (where the cable is).
NOPARAMS='{}'
cr_local() {
	ip netns exec crdut env COREROUTER_RUNTIME_DIR="$W/dut/run/corerouter" \
		"$CLI" --connect 127.0.0.1:7979 run "$1" "${2:-$NOPARAMS}"
}
cli_remote() {
	ip netns exec crgen env COREROUTER_PASSWORD="${COREROUTER_PASSWORD:-}" \
		COREROUTER_KNOWN_HOSTS="$W/known_hosts" "$CLI" --connect "tls://$TARGET" --user "$RUSER" \
		--accept-new-cert "$@"
}
cr() { # <id> [params]: the reply's JSON on stdout
	if [ $DUT = local ]; then cr_local "$@"; else cli_remote run "$1" "${2:-$NOPARAMS}"; fi
}
ok() { # like cr, but a refusal fails the step
	local out
	if ! out=$(cr "$@" 2>"$W/cr.err"); then
		log "command failed: ${1} ${2:0:200} → $(head -c 400 "$W/cr.err")"
		return 1
	fi
	printf '%s\n' "$out"
}

# The CLI's MCP server as a coprocess: one warm connection for many
# commands (batches, the latency of a command without the CLI's start).
MCP_ID=0
cli_mcp() {
	if [ $DUT = local ]; then
		exec ip netns exec crdut env COREROUTER_RUNTIME_DIR="$W/dut/run/corerouter" \
			"$CLI" --connect 127.0.0.1:7979 mcp
	else
		exec ip netns exec crgen env COREROUTER_PASSWORD="${COREROUTER_PASSWORD:-}" \
			COREROUTER_KNOWN_HOSTS="$W/known_hosts" "$CLI" --connect "tls://$TARGET" --user "$RUSER" mcp
	fi
}
mcp_open() {
	coproc MCP { cli_mcp 2>>"$W/mcp.err"; }
	exec 3>&"${MCP[1]}" 4<&"${MCP[0]}"
	eval "exec ${MCP[1]}>&- ${MCP[0]}<&-"
	mcp_send '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dns-stress","version":"1"}}}'
	mcp_recv >/dev/null || { log "MCP: no answer: $(tail -n 5 "$W/mcp.err")"; return 1; }
	mcp_send '{"jsonrpc":"2.0","method":"notifications/initialized"}'
}
mcp_send() { printf '%s\n' "$1" >&3; }
mcp_recv() { timeout 900 head -n 1 <&4; }
mcp_close() {
	exec 3>&- 4<&- 2>/dev/null || true
	[ -n "${MCP_PID:-}" ] && { kill "$MCP_PID" 2>/dev/null || true; wait "$MCP_PID" 2>/dev/null || true; }
	MCP_PID=""
}
# mcp_tool <tool> <arguments json file> → the tool's text; false on isError.
mcp_tool() {
	MCP_ID=$((MCP_ID + 1))
	local reply
	mcp_send "$(jq -cn --arg t "$1" --slurpfile a "$2" --argjson id $MCP_ID \
		'{jsonrpc: "2.0", id: $id, method: "tools/call", params: {name: $t, arguments: $a[0]}}')"
	reply=$(mcp_recv) || return 1
	printf '%s' "$reply" | jq -r '.result.content[0].text // .error.message // "no reply"'
	[ "$(printf '%s' "$reply" | jq -r '.result.isError // (.error != null)')" = false ]
}
mcp_run() { # <command> [params]
	jq -cn --arg c "$1" --argjson p "${2:-$NOPARAMS}" '{command: $c, params: $p}' >"$W/mcp-args.json"
	mcp_tool run_command "$W/mcp-args.json"
}
# mcp_batch <file of {command, params} lines>: one atomic batch.
mcp_batch() {
	jq -cs '{steps: ., atomic: true}' "$1" >"$W/mcp-args.json"
	mcp_tool command_batch "$W/mcp-args.json"
}

# --- The DUT's base config: the lab address, the forwarder answering the
# lab's /25, the two Knot addresses as servers, no per-client limit (the
# load comes from a few addresses), a 64 MiB cache (the default 2 MiB does
# not hold the 10 000 hot names; test qps measures it apart).
DNS_BASE='{"servers":["'$UP1'","'$UP2'"],"allow_remote_requests":true,"allowed_from":["10.53.0.0/25"],"max_queries_per_client":0,"max_concurrent_queries":100,"max_concurrent_tcp_sessions":20,"cache_size":65536,"query_server_timeout_ms":2000,"query_total_timeout_ms":10000,"use_doh_server":"","serve_stale_secs":86400,"server_selection":"fastest"}'
dns_set() { ok ip.dns.set "$(jq -cn --argjson b "$DNS_BASE" --argjson o "${1:-$NOPARAMS}" '$b + $o')" >/dev/null; }
REVISION=""
dut_config() {
	if [ $DUT = remote ]; then
		# Phase C: everything below leaves by rollback to this revision.
		REVISION=$(cr config.history | jq -r '[.[].number] | max // empty')
		say "remote DUT: config revision $REVISION before the lab (rolled back at the end)"
	fi
	cr ip.address.list | jq -e --arg a "$DUT_IP/24" 'any(.[]; .address == $a)' >/dev/null ||
		ok ip.address.add "{\"address\":\"$DUT_IP/24\",\"interface\":\"$DUT_IFACE\"}" >/dev/null
	dns_set
	local end=$((SECONDS + 30))
	until q_one h1.up.lab A | grep -q NOERROR; do
		[ $SECONDS -lt $end ] || { fail "the DUT's forwarder does not answer on $DUT_IP:53"; return 1; }
		sleep 0.5
	done
}
dut_unconfig() {
	if [ $DUT = remote ] && [ -n "$REVISION" ]; then
		cr config.rollback "{\"revision\":$REVISION}" >/dev/null 2>&1 &&
			say "remote DUT: rolled back to revision $REVISION" ||
			say "remote DUT: rollback to $REVISION FAILED: undo by hand"
	fi
}

# --- Queries from the lab: one (kdig), and files for dnsperf.
q_one() { # <name> <type> [kdig options…] → "RCODE size answers"
	local name=$1 type=$2
	shift 2
	in_gen "${TENV[@]}" kdig @"$DUT_IP" "$name" "$type" +timeout=3 +retry=0 "$@" 2>/dev/null |
		kdig_summary
}
# kdig's answer → "RCODE[+TC] bytes answers" (";; ->>HEADER<<- …
# status: NOERROR; …", ";; Flags: qr rd ra tc; QUERY: 1; ANSWER: 0; …",
# ";; Received 28 B").
kdig_summary() {
	awk '/status:/ {for (i = 1; i <= NF; i++) if ($i == "status:") {s = $(i + 1); sub(/;/, "", s)}}
		/^;; Received/ {b = $3}
		/Flags:/ {f = $0; sub(/.*Flags: */, "", f); sub(/;.*/, "", f); if (f ~ /(^| )tc( |$)/) tc = "+TC"
			for (i = 1; i <= NF; i++) if ($i == "ANSWER:") {a = $(i + 1); sub(/;/, "", a)}}
		END {printf "%s%s %d %d\n", s, tc, b, a}'
}
QF=$W/q
qfiles() {
	mkdir -p "$QF"
	awk -v n="$HOT" 'BEGIN {for (i = 0; i < n; i++) printf "h%d.up.lab A\n", i}' >"$QF/hot"
	awk -v n="$STATICS" 'BEGIN {for (i = 0; i < n; i++) printf "s%d.st.lab A\n", i}' >"$QF/static"
	awk -v n="$ZONE_N" 'BEGIN {for (i = 0; i < n; i++) printf "z%d.zn.lab A\n", i}' >"$QF/zone"
	echo "ttl0.up.lab A" >"$QF/ttl0"
	# unique: a fresh name each time (a run never repeats one).
	uniq_file "$QF/unique" 2000000 u
	# mix: 85 % hot, 5 % static, 5 % zone, 5 % unique (shuffled, fixed seed).
	{
		awk -v n="$HOT" 'BEGIN {srand(7); for (i = 0; i < 170000; i++) printf "h%d.up.lab A\n", int(n * (rand() ^ 3))}'
		head -n 10000 "$QF/static"; head -n 10000 "$QF/zone"
		awk 'BEGIN {for (i = 0; i < 10000; i++) printf "m%d.mix.up.lab A\n", i}'
	} | shuf --random-source=<(yes) >"$QF/mix"
}
UNIQ_SEQ=0
uniq_file() { # <file> <n> <prefix>: names never asked before in this run
	UNIQ_SEQ=$((UNIQ_SEQ + 1))
	awk -v n="$2" -v p="$3$UNIQ_SEQ" 'BEGIN {for (i = 0; i < n; i++) printf "%s-%d.wt.up.lab A\n", p, i}' >"$1"
}

# --- dnsperf runs and what they say.
# dp <name> <query file> <secs> [dnsperf options…]: one run from crgen,
# its output in $OUT/raw/<name>.txt; sets DP (see dp_parse).
DP=""
dp() {
	local name=$1 file=$2 secs=$3
	shift 3
	in_gen "${TENV[@]}" dnsperf -s "$DUT_IP" -d "$file" -l "$secs" -t 5 -O latency-histogram \
		-O suppress=timeout,unexpected "$@" >"$OUT/raw/$name.txt" 2>&1 || true
	DP=$(dp_parse "$OUT/raw/$name.txt")
}
# → "qps completed lost noerror servfail refused other p50 p99 p999 max"
# (latencies in µs; percentiles from the histogram's upper bounds).
dp_parse() {
	awk '
		/Queries completed:/ {done = $3}
		/Queries lost:/ {lost = $3}
		/Queries per second:/ {qps = $4}
		/Response codes:/ {
			s = $0; sub(/.*Response codes: */, "", s); n = split(s, parts, ",")
			for (i = 1; i <= n; i++) {split(parts[i], f, " "); rc[f[1]] = f[2]}
		}
		/Connection Statistics/ {conn = 1}
		!conn && /Average Latency/ {m = $NF; sub(/\)/, "", m); max = m * 1e6}
		!conn && /^ *[0-9.]+ - [0-9.]+: +[0-9]+/ {k++; hi[k] = $3; sub(/:/, "", hi[k]); c[k] = $4; tot += $4}
		END {
			p50 = p99 = p999 = 0; acc = 0
			for (i = 1; i <= k; i++) {
				acc += c[i]
				if (!p50 && acc >= tot * 0.50) p50 = hi[i] * 1e6
				if (!p99 && acc >= tot * 0.99) p99 = hi[i] * 1e6
				if (!p999 && acc >= tot * 0.999) p999 = hi[i] * 1e6
			}
			other = done - rc["NOERROR"] - rc["SERVFAIL"] - rc["REFUSED"]
			printf "%d %d %d %d %d %d %d %d %d %d %d\n", qps, done, lost, rc["NOERROR"], rc["SERVFAIL"],
				rc["REFUSED"], other, p50, p99, p999, max
		}' "$1"
}
dpf() { echo "$DP" | awk -v i="$1" '{print $i}'; } # field i of DP
pct_of() { awk -v a="$1" -v b="$2" 'BEGIN {if (b > 0) printf "%.1f", a * 100 / b; else print "0"}'; }
us() { awk -v u="$1" 'BEGIN {if (u >= 10000) printf "%.0f ms", u / 1000; else if (u >= 1000) printf "%.1f ms", u / 1000; else printf "%d µs", u}'; }
# A row: qps | lost | NOERROR/SERVFAIL | p50 | p99 | p99.9 | max.
dp_row() {
	local qps ndone lost ok sf ref oth
	read -r qps ndone lost ok sf ref oth _ <<<"$DP"
	printf '%s | %s | %s %% | %s/%s/%s | %s | %s | %s | %s' "$qps" "$ndone" "$(pct_of "$lost" $((ndone + lost)))" \
		"$ok" "$sf" "$((ref + oth))" "$(us "$(dpf 8)")" "$(us "$(dpf 9)")" "$(us "$(dpf 10)")" "$(us "$(dpf 11)")"
}
DP_HEAD='qps | respostas | perdidas | NOERROR/SERVFAIL/outros | p50 | p99 | p99,9 | máx.'
DP_SEP='---|---|---|---|---|---|---|---'

# --- The DUT's cost: CPU per thread group, threads, RSS, descriptors.
# Local: /proc; remote: system.resource.process.print threads=yes.
thr_snap() { # → file of "group ticks" (and "_total ticks")
	local f=$1 t c
	if local_dut; then
		{
			for t in /proc/"$DPID"/task/*; do
				c=$(cat "$t/comm" 2>/dev/null) || continue
				echo "$(thr_group "$c") $(awk '{print $14 + $15}' "$t/stat" 2>/dev/null || echo 0)"
			done
			echo "_total $(awk '{print $14 + $15}' "/proc/$DPID/stat")"
		} >"$f"
	else
		: >"$f"
	fi
}
thr_group() {
	case $1 in
	dns-udp* | dns-query* | dns-tcp | dns-tcp-accept | dns-server | dns-update | dns-effects | dns-zones | dns-adlist | dns) echo "$1" ;;
	dns-*) echo dns-other ;;
	*) echo other ;;
	esac
}
# thr_cpu <before> <after> <secs> → "dns-udp 312 %, …, exited 40 %" (one
# core = 100 %); "exited": threads that ended in between (the dns-query
# workers of the misses, mostly).
CLK=$(getconf CLK_TCK)
thr_cpu() {
	if ! local_dut; then
		# The router's own view, now (not the run's average): the DNS
		# threads by name, the rest together.
		cr system.resource.process.print '{"threads":true,"sort":"cpu","limit":5}' 2>/dev/null |
			jq -r '[.[] | select(.name == "corerouter-daemon") | .tasks[]? |
				.name |= (if startswith("dns-") then . else "other" end)] | group_by(.name) |
				map("\(.[0].name) \(map(.cpu) | add | floor) %") | join(", ")' 2>/dev/null || echo "-"
		return
	fi
	awk -v clk="$CLK" -v secs="$3" '
		FNR == NR {a[$1] += $2; next}
		{b[$1] += $2}
		END {
			live = 0
			for (g in b) if (g != "_total") {d = b[g] - a[g]; if (d < 0) d = b[g]; live += d; if (d > 0) out[g] = d}
			ex = (b["_total"] - a["_total"]) - live
			s = ""
			n = asorti(out, keys)
			for (i = 1; i <= n; i++) s = s sprintf("%s%s %d %%", (s == "" ? "" : ", "), keys[i], out[keys[i]] * 100 / clk / secs)
			if (ex > 0) s = s sprintf(", exited %d %%", ex * 100 / clk / secs)
			print s
		}' "$1" "$2"
}
# A background sampler of the DUT (threads, RSS MiB, fds) every 200 ms;
# samp_stop prints "peak_threads peak_rss_mib peak_fds".
SAMP_PID=""
samp_start() {
	: >"$W/samp"
	if local_dut; then
		(while kill -0 "$DPID" 2>/dev/null; do
			awk '/^Threads/ {t = $2} /^VmRSS/ {r = int($2 / 1024)} END {printf "%d %d ", t, r}' "/proc/$DPID/status"
			ls "/proc/$DPID/fd" 2>/dev/null | wc -l
			sleep 0.2
		done) >"$W/samp" 2>/dev/null &
	else
		(while :; do
			cr system.resource.process.print '{"sort":"memory","limit":100}' 2>/dev/null |
				jq -r '[.[] | select(.name == "corerouter-daemon")][0] // {} | "\(.threads // 0) \((.memory // 0) / 1048576 | floor) \(.fds // 0)"'
			sleep 1
		done) >"$W/samp" 2>/dev/null &
	fi
	SAMP_PID=$!
}
samp_stop() {
	[ -n "$SAMP_PID" ] && { kill "$SAMP_PID" 2>/dev/null || true; wait "$SAMP_PID" 2>/dev/null || true; }
	SAMP_PID=""
	awk 'BEGIN {t = r = f = 0} {if ($1 > t) t = $1; if ($2 > r) r = $2; if ($3 > f) f = $3} END {print t, r, f}' "$W/samp"
}
dut_now() { # → "threads rss_mib fds"
	if local_dut; then
		awk '/^Threads/ {t = $2} /^VmRSS/ {r = int($2 / 1024)} END {printf "%d %d ", t, r}' "/proc/$DPID/status"
		ls "/proc/$DPID/fd" | wc -l
	else
		cr system.resource.process.print '{"sort":"memory","limit":100}' |
			jq -r '[.[] | select(.name == "corerouter-daemon")][0] // {} | "\(.threads // 0) \((.memory // 0) / 1048576 | floor) \(.fds // 0)"'
	fi
}
daemon_cpu() { # CPU seconds of the DUT so far (exited threads included); remote: 0
	if local_dut; then awk -v clk="$CLK" '{printf "%.2f", ($14 + $15) / clk}' "/proc/$DPID/stat"; else echo 0; fi
}
rss_kib() { # exact RSS of the DUT (local) in KiB; remote: process.print
	if local_dut; then awk '/^VmRSS/ {print $2}' "/proc/$DPID/status"; else
		cr system.resource.process.print '{"sort":"memory","limit":100}' |
			jq -r '[.[] | select(.name == "corerouter-daemon")][0].memory // 0 | . / 1024 | floor'
	fi
}
alive_check() { # <what>: the daemon is still the same process and answers
	if local_dut && ! kill -0 "$DPID" 2>/dev/null; then
		fail "$1: the daemon died: $(tail -n 5 "$W/dut/daemon.log" | tr '\n' ' ' | cut -c1-400)"
		return 1
	fi
	if grep -qiE 'panicked|panic' "$W/dut/daemon.log" 2>/dev/null; then
		fail "$1: panic in the daemon's log: $(grep -iE 'panic' "$W/dut/daemon.log" | head -n 2 | cut -c1-300)"
	fi
	q_one h1.up.lab A | grep -q NOERROR || { fail "$1: the forwarder stopped answering"; return 1; }
}
# Under max_concurrent_queries (100): a warm-up that overflowed it would
# leave names out of the cache.
warm() { dp "warm-$1" "$QF/$1" 120 -n 1 -c 4 -q 50; }
flush() { ok ip.dns.cache.flush >/dev/null; }

# PERF=<regex>: a profile of the DUT during the runs whose name matches
# (perf record -g for $DUR s; $OUT/perf-<run>.data), local DUT only.
PERF_PID=""
perf_start() { # <run name>
	PERF_PID=""
	if [ -n "${PERF:-}" ] && local_dut && [[ $1 =~ $PERF ]] && command -v perf >/dev/null; then
		perf record -q -g -p "$DPID" -o "$OUT/perf-$1.data" -- sleep "$DUR" >/dev/null 2>&1 &
		PERF_PID=$!
	fi
}
perf_wait() { [ -z "$PERF_PID" ] || wait "$PERF_PID" 2>/dev/null || true; }

# Saturation: as much as the DUT takes with 500 queries in flight from 8
# client sockets; then the latency at half that rate (no queueing).
SAT_OPTS=(-c 8 -T 2 -q 500)
sat_and_half() { # <label> <query file> [setup command before each run]
	local label=$1 file=$2 half tag
	tag=$(printf '%s' "$label" | tr -c 'a-zA-Z0-9-' _)
	[ -n "${3:-}" ] && eval "$3"
	thr_snap "$W/t0"
	perf_start "$tag"
	dp "$tag-sat" "$file" "$DUR" "${SAT_OPTS[@]}"
	perf_wait
	thr_snap "$W/t1"
	local sat=$DP cpu
	cpu=$(thr_cpu "$W/t0" "$W/t1" "$DUR")
	say "| $label | saturação | $(dp_row) | $cpu |"
	half=$(($(echo "$sat" | awk '{print $1}') / 2))
	[ "$half" -ge 100 ] || half=100
	[ -n "${3:-}" ] && eval "$3"
	dp "$tag-half" "$file" "$DUR" -c 8 -T 2 -q 2000 -Q "$half"
	say "| $label | $half/s (metade) | $(dp_row) | |"
}

###########################################################################
# 1. Queries per second.
###########################################################################
statics_load() {
	cr ip.dns.static.print '{"name":"s0.st.lab"}' | jq -e 'length > 0' >/dev/null && return 0
	awk -v n="$STATICS" 'BEGIN {for (i = 0; i < n; i++) printf "{\"command\":\"ip.dns.static.add\",\"params\":{\"name\":\"s%d.st.lab\",\"address\":\"10.4.%d.%d\",\"ttl_secs\":3600}}\n", i, int(i / 250), i % 250 + 1}' >"$W/statics.jsonl"
	mcp_batch "$W/statics.jsonl" >/dev/null || fail "statics: the batch was refused"
}
zone_load() { # <zone> <records> <prefix>
	local z=$1 n=$2 p=$3 t0
	cr ip.dns.zone.remove "{\"id\":\"$z\"}" >/dev/null 2>&1 || true
	ok ip.dns.zone.add "{\"name\":\"$z\",\"allow_update\":[\"10.53.0.0/24\",\"$DHCP_NET.0.0/16\"],\"minimum_secs\":60}" >/dev/null
	{
		echo "\$ORIGIN $z."
		echo '$TTL 3600'
		echo "@ SOA ns1 hostmaster 1 3600 600 86400 60"
		echo "@ NS ns1"
		echo "ns1 A $DUT_IP"
		awk -v n="$n" -v p="$p" 'BEGIN {for (i = 0; i < n; i++) printf "%s%d A 10.5.%d.%d\n", p, i, int(i / 250) % 250, i % 250 + 1}'
	} >"$W/$z.zone"
	jq -cn --arg z "$z" --rawfile t "$W/$z.zone" '{command: "ip.dns.zone.file.load", params: {zone: $z, text: $t}}' >"$W/zone-args.json"
	t0=$(now)
	mcp_tool run_command "$W/zone-args.json" >"$W/zone-load.out" || { fail "zone $z: file.load refused: $(head -c 300 "$W/zone-load.out")"; return 1; }
	ZONE_LOAD_MS=$(($(now) - t0))
}

test_qps() {
	say ""
	say "## 1. Consultas por segundo"
	say ""
	say "Saturação: dnsperf com 8 clientes, 500 em voo, $DUR s. Metade: a mesma carga limitada à metade da"
	say "saturação, para ver a latência sem fila. CPU: % de um núcleo por grupo de threads do daemon."
	say "Origem a 0 ms, exceto em miss-20ms (netem nas respostas do Knot)."
	local list=${DUT_CPUS_LIST:-$DUT_CPUS} cpus
	local_dut || list=remote
	for cpus in ${list//;/ }; do
		if local_dut; then
			daemon_stop
			daemon_start "$cpus"
			DPID=$(dut_pid corerouter-daemon)
			dut_config
		fi
		mcp_open
		statics_load
		zone_load zn.lab "$ZONE_N" z
		mcp_close
		local readers
		if local_dut; then
			readers=$(ls /proc/"$DPID"/task | while read -r t; do cat "/proc/$DPID/task/$t/comm"; done | grep -c '^dns-udp' || true)
		else
			readers=$(cr system.resource.process.print '{"threads":true,"limit":100}' |
				jq '[.[] | select(.name == "corerouter-daemon") | .tasks[]? | select(.name == "dns-udp")] | length')
		fi
		say ""
		say "### DUT em CPUs $cpus: $readers threads dns-udp"
		say ""
		say "| cenário | carga | $DP_HEAD | CPU por thread |"
		say "|---|---|$DP_SEP|---|"
		origin_delay 0
		dns_set '{"cache_size":2048}'
		flush
		warm hot
		sat_and_half "cache-hit, cache padrão (2 MiB)" "$QF/hot"
		say "| (o cache de 2 MiB guarda $(cr ip.dns.cache.print '{"limit":100000}' | jq length) entradas) | | | | | | | | | | |"
		dns_set
		warm hot
		sat_and_half "cache-hit (64 MiB)" "$QF/hot"
		sat_and_half static "$QF/static"
		sat_and_half zone "$QF/zone"
		uniq_file "$W/u-miss0" 3000000 miss0
		sat_and_half miss-0ms "$W/u-miss0"
		origin_delay 20
		uniq_file "$W/u-miss" 3000000 miss
		sat_and_half miss-20ms "$W/u-miss"
		flush
		warm hot
		sat_and_half mix "$QF/mix" flush
		origin_delay 0
		alive_check "qps $cpus"
	done
}

###########################################################################
# 2. Water torture, equal queries in flight (G4.1o), a flush under load.
###########################################################################
# legit_bg <name> <rate>: a client on the hot names beside the attack,
# from another source address; legit_wait prints its row.
LEGIT_PID=""
legit_bg() {
	ip netns exec crgen taskset -c "$GEN_CPUS" dnsperf -s "$DUT_IP" -a "${CLIENTS[7]}" -d "$QF/hot" -l "$DUR" -t 5 -c 2 -q 500 -Q "$2" \
		-O latency-histogram -O suppress=timeout,unexpected >"$OUT/raw/$1.txt" 2>&1 &
	LEGIT_PID=$!
}
legit_wait() { # <name> → sets DP to the legit client's numbers
	wait "$LEGIT_PID" 2>/dev/null || true
	DP=$(dp_parse "$OUT/raw/$1.txt")
}
test_torture() {
	say ""
	say "## 2. Tempestade de nomes únicos (water torture)"
	say ""
	dns_set
	origin_delay 20
	flush
	warm hot
	say "Nomes únicos *.wt.up.lab (o Knot responde todos), origem a 20 ms. Ao lado, um cliente legítimo"
	say "pede os nomes quentes (cache) a 2000/s de outro endereço. Origem/s: consultas que o Knot recebeu."
	say ""
	say "| max_concurrent_queries | ataque (-Q) | $DP_HEAD | origem/s | threads (pico) | RSS pico MiB | legítimo p99 | legítimo máx. | legítimo SERVFAIL |"
	say "|---|---|$DP_SEP|---|---|---|---|---|---|"
	local mcq rate o0 o1 peak row
	for mcq in 100 1000; do
		dns_set "{\"max_concurrent_queries\":$mcq}"
		for rate in 1000 5000 20000 max; do
			uniq_file "$W/u-wt" 3000000 wt
			local q=()
			[ "$rate" != max ] && q=(-Q "$rate")
			o0=$(origin_count)
			samp_start
			legit_bg "legit-$mcq-$rate" 2000
			dp "torture-$mcq-$rate" "$W/u-wt" "$DUR" -c 8 -T 2 -q 5000 "${q[@]}"
			row=$(dp_row)
			peak=$(samp_stop)
			o1=$(origin_count)
			legit_wait "legit-$mcq-$rate"
			say "| $mcq | $rate | $row | $(((o1 - o0) / DUR)) | $(echo "$peak" | cut -d' ' -f1) | $(echo "$peak" | cut -d' ' -f2) | $(us "$(dpf 9)") | $(us "$(dpf 11)") | $(dpf 5) |"
		done
	done
	dns_set
	alive_check torture

	say ""
	say "### Consultas iguais em andamento (G4.1o)"
	say ""
	say "O mesmo nome com TTL 0 (nunca fica no cache), origem a 20 ms: quantas consultas chegam à origem"
	say "para cada resposta ao cliente. Um resolvedor que junta as iguais (Unbound) manda ~1 a cada 20 ms."
	say ""
	say "| carga (-Q) | $DP_HEAD | consultas à origem | origem por resposta |"
	say "|---|$DP_SEP|---|---|"
	for rate in 500 2000 5000; do
		o0=$(origin_count)
		dp "ttl0-$rate" "$QF/ttl0" "$DUR" -c 8 -T 2 -q 2000 -Q "$rate"
		o1=$(origin_count)
		say "| $rate | $(dp_row) | $((o1 - o0)) | $(awk -v o=$((o1 - o0)) -v a="$(dpf 2)" 'BEGIN {if (a > 0) printf "%.2f", o / a; else print "-"}') |"
		COALESCE_RATIO=$(awk -v o=$((o1 - o0)) -v a="$(dpf 2)" 'BEGIN {if (a > 0) printf "%.3f", o / a; else print "1"}')
	done

	say ""
	say "### Flush do cache com carga"
	say ""
	say "Nomes quentes a 20 000/s, origem a 20 ms; ip.dns.cache.flush aos $((DUR / 2)) s: todos viram miss"
	say "juntos. Origem: consultas que chegaram ao Knot na rodada."
	say ""
	say "| $DP_HEAD | consultas à origem | flush |"
	say "|$DP_SEP|---|---|"
	warm hot
	o0=$(origin_count)
	in_gen "${TENV[@]}" dnsperf -s "$DUT_IP" -d "$QF/hot" -l "$DUR" -t 5 -c 8 -T 2 -q 2000 -Q 20000 \
		-O latency-histogram -O suppress=timeout,unexpected >"$OUT/raw/flush-load.txt" 2>&1 &
	local p=$! t0
	sleep $((DUR / 2))
	t0=$(now)
	flush
	local fl=$(($(now) - t0))
	wait $p || true
	o1=$(origin_count)
	DP=$(dp_parse "$OUT/raw/flush-load.txt")
	say "| $(dp_row) | $((o1 - o0)) | $fl ms |"
	origin_delay 0
	alive_check flush
}

###########################################################################
# 3. A slow, lossy or dead origin.
###########################################################################
# A probe: one unique query every 50 ms for <secs>, each with its own
# socket and a 6 s timeout; "t_ms rtt_ms rcode" lines in <out>.
probe_py() {
	cat >"$W/probe.py" <<'PY'
import random, socket, struct, sys, time, threading
dst, src, secs, out, prefix, every = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4], sys.argv[5], float(sys.argv[6])
names = sys.argv[7] if len(sys.argv) > 7 else ""
fixed = names.split(",") if names else []
lock = threading.Lock()
rows = []
def ask(i, t0):
    qid = random.randrange(65536)
    name = fixed[i % len(fixed)] if fixed else "%s-%d.wt.up.lab" % (prefix, i)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for l in name.split("."):
        q += bytes([len(l)]) + l.encode()
    q += b"\0" + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0)); s.settimeout(6)
    t = time.monotonic()
    s.sendto(q, (dst, 53))
    rc = "timeout"
    try:
        while True:
            r, _ = s.recvfrom(4096)
            if len(r) >= 4 and struct.unpack("!H", r[:2])[0] == qid:
                rc = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"][r[3] & 15] if (r[3] & 15) < 6 else str(r[3] & 15)
                break
    except socket.timeout:
        pass
    rtt = (time.monotonic() - t) * 1000
    with lock:
        rows.append("%d %.1f %s" % ((t - t0) * 1000, rtt, rc))
    s.close()
t0 = time.monotonic(); th = []; i = 0
while time.monotonic() - t0 < secs:
    x = threading.Thread(target=ask, args=(i, t0)); x.start(); th.append(x); i += 1
    time.sleep(every)
for x in th: x.join()
with open(out, "w") as f:
    f.write("\n".join(sorted(rows, key=lambda r: int(r.split()[0]))) + "\n")
PY
}
probe() { # <secs> <out> <prefix> [every_s] [names,…]
	in_gen python3 -I "$W/probe.py" "$DUT_IP" "${CLIENTS[6]}" "$1" "$2" "$3" "${4:-0.05}" "${5:-}"
}
probe_summary() { # <file> [from_ms] [to_ms] → "n ok servfail timeout p50 p99 max" (ms)
	awk -v a="${2:-0}" -v b="${3:-1e18}" '$1 >= a && $1 < b {n++; r[n] = $2; if ($3 == "NOERROR") ok++; else if ($3 == "SERVFAIL") sf++; else if ($3 == "timeout") to++}
		END {asort(r); printf "%d %d %d %d %.0f %.0f %.0f\n", n, ok, sf, to, r[int(n * 0.5) + (n > 0)], r[int(n * 0.99) + (n > 0)], r[n]}' "$1"
}
test_origin() {
	say ""
	say "## 3. Origem lenta, com perda ou fora do ar"
	probe_py
	dns_set
	flush
	origin_delay 5

	say ""
	say "### Troca de servidor"
	say ""
	say "Uma consulta única a cada 50 ms; o primeiro servidor ($UP1) some (descarte, sem ICMP) aos 5 s."
	say "query_server_timeout 2000 ms, total 10000 ms, server_selection fastest. Origem a 5 ms."
	say ""
	(sleep 5; origin_dead "$UP1") &
	probe 20 "$W/failover" fo
	origin_alive
	local s0 s1 s2 rec
	s0=$(probe_summary "$W/failover" 0 5000)
	s1=$(probe_summary "$W/failover" 5000 8000)
	s2=$(probe_summary "$W/failover" 8000)
	rec=$(awk '$1 >= 5000 && $2 > 100 {last = $1} END {print (last ? last - 5000 : 0)}' "$W/failover")
	say "| janela | consultas | NOERROR | SERVFAIL | sem resposta | p50 ms | p99 ms | máx. ms |"
	say "|---|---|---|---|---|---|---|---|"
	say "| antes (0–5 s) | ${s0// / | } |"
	say "| a queda (5–8 s) | ${s1// / | } |"
	say "| depois (8–20 s) | ${s2// / | } |"
	say ""
	say "Última consulta acima de 100 ms: $rec ms depois da queda."
	cp "$W/failover" "$OUT/origin-failover.txt"

	say ""
	say "### Serve-stale (RFC 8767) e cache de falhas (RFC 9520)"
	say ""
	flush
	local names
	names=$(seq -f 'st%g.short.up.lab' 0 19 | paste -sd,)
	probe 1 "$W/stale-fill" st 0.05 "$names" # cached, TTL 2 s
	sleep 4
	origin_dead "$UP1"
	origin_dead "$UP2"
	local o0 o1
	o0=$(origin_count)
	probe 1 "$W/stale-1" st 0.05 "$names"
	probe 1 "$W/stale-2" st 0.05 "$names"
	probe 2 "$W/dead-1" dead 0.1 "gone1.wt.up.lab,gone2.wt.up.lab"
	probe 2 "$W/dead-2" dead 0.1 "gone1.wt.up.lab,gone2.wt.up.lab"
	o1=$(origin_count)
	say "| caso | consultas | NOERROR | SERVFAIL | sem resposta | p50 ms | p99 ms | máx. ms |"
	say "|---|---|---|---|---|---|---|---|"
	say "| expirado, origens fora (1ª vez) | $(probe_summary "$W/stale-1" | tr ' ' '|' | sed 's/|/ | /g') |"
	say "| expirado, origens fora (de novo) | $(probe_summary "$W/stale-2" | tr ' ' '|' | sed 's/|/ | /g') |"
	say "| nunca visto, origens fora (1ª vez) | $(probe_summary "$W/dead-1" | tr ' ' '|' | sed 's/|/ | /g') |"
	say "| nunca visto, de novo (falha guardada) | $(probe_summary "$W/dead-2" | tr ' ' '|' | sed 's/|/ | /g') |"
	say ""
	say "Pacotes que chegaram às origens (descartados) nessas rodadas: $((o1 - o0))."

	say ""
	say "### Origens fora do ar com carga"
	say ""
	say "Nomes únicos sem limite de taxa com as duas origens fora; o cliente legítimo ao lado (cache)."
	say ""
	say "| max_concurrent_queries | $DP_HEAD | threads (pico) | RSS pico MiB | legítimo p99 | legítimo máx. |"
	say "|---|$DP_SEP|---|---|---|---|"
	local mcq peak row
	origin_alive
	warm hot
	origin_dead "$UP1"
	origin_dead "$UP2"
	for mcq in 100 1000; do
		dns_set "{\"max_concurrent_queries\":$mcq}"
		uniq_file "$W/u-dead" 3000000 dead
		samp_start
		legit_bg "dead-legit-$mcq" 2000
		dp "dead-$mcq" "$W/u-dead" "$DUR" -c 8 -T 2 -q 5000
		row=$(dp_row)
		peak=$(samp_stop)
		legit_wait "dead-legit-$mcq"
		say "| $mcq | $row | $(echo "$peak" | cut -d' ' -f1) | $(echo "$peak" | cut -d' ' -f2) | $(us "$(dpf 9)") | $(us "$(dpf 11)") |"
	done
	origin_alive
	dns_set

	say ""
	say "### Perda e origem lenta"
	say ""
	say "| origem | carga | $DP_HEAD | CPU |"
	say "|---|---|$DP_SEP|---|"
	local t0 t1
	origin_delay 20 30
	uniq_file "$W/u-loss" 1000000 loss
	thr_snap "$W/t0"
	dp loss30 "$W/u-loss" "$DUR" -c 8 -T 2 -q 2000 -Q 500
	thr_snap "$W/t1"
	say "| 20 ms, 30 % de perda | 500/s | $(dp_row) | $(thr_cpu "$W/t0" "$W/t1" "$DUR") |"
	origin_delay 200
	uniq_file "$W/u-slow" 1000000 slow
	thr_snap "$W/t0"
	dp slow200 "$W/u-slow" "$DUR" -c 8 -T 2 -q 5000
	thr_snap "$W/t1"
	say "| 200 ms | saturação | $(dp_row) | $(thr_cpu "$W/t0" "$W/t1" "$DUR") |"
	origin_delay 0
	alive_check origin
}

###########################################################################
# 4. TCP: clients, slow connections, encrypted upstreams.
###########################################################################
slowloris_py() {
	cat >"$W/slow.py" <<'PY'
# Connections that send one byte and stall; one the server closes is
# opened again at once (a patient attacker), per source address.
import select, socket, sys, time
dst, secs = sys.argv[1], float(sys.argv[2]); srcs = sys.argv[3].split(","); per = int(sys.argv[4])
def opened(src):
    try:
        c = socket.create_connection((dst, 53), timeout=3, source_address=(src, 0))
        c.send(b"\x00")  # the first byte of a length, then nothing
        c.setblocking(False)
        return c
    except OSError:
        return None
socks = {}
for s in srcs:
    for i in range(per):
        socks[(s, i)] = opened(s)
print("held", sum(1 for c in socks.values() if c), flush=True)
t0 = time.monotonic(); reopened = 0
while time.monotonic() - t0 < secs:
    for k, c in list(socks.items()):
        dead = c is None
        if c is not None:
            r, _, _ = select.select([c], [], [], 0)
            if r:
                try:
                    dead = c.recv(1) == b""
                except OSError:
                    dead = True
        if dead:
            if c is not None:
                c.close()
            socks[k] = opened(k[0]); reopened += 1
    time.sleep(0.1)
print("reopened", reopened, flush=True)
PY
	cat >"$W/tcpprobe.py" <<'PY'
import socket, struct, sys, time
dst, src, secs, out = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4]
q = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) + b"\x02h1\x02up\x03lab\x00" + struct.pack("!HH", 1, 1)
rows = []; t0 = time.monotonic()
while time.monotonic() - t0 < secs:
    t = time.monotonic(); rc = "fail"
    try:
        c = socket.create_connection((dst, 53), timeout=3, source_address=(src, 0))
        c.settimeout(3)
        c.sendall(struct.pack("!H", len(q)) + q)
        n = struct.unpack("!H", c.recv(2))[0]
        r = b""
        while len(r) < n:
            b = c.recv(n - len(r))
            if not b: break
            r += b
        rc = "ok" if len(r) == n else "short"
        c.close()
    except OSError as e:
        rc = "fail"
    rows.append("%d %.1f %s" % ((t - t0) * 1000, (time.monotonic() - t) * 1000, rc))
    time.sleep(0.25)
open(out, "w").write("\n".join(rows) + "\n")
PY
}
test_tcp() {
	say ""
	say "## 4. TCP e DoT/DoH de origem"
	slowloris_py
	dns_set
	flush
	warm hot
	say ""
	say "### Clientes TCP"
	say ""
	say "Nomes quentes por TCP (dnsperf -m tcp), de um endereço só, com max_concurrent_tcp_sessions 20 (o"
	say "RouterOS; antes da G4.1w um endereço ficava com um quarto, 5; depois 10, a metade) e 100 (o padrão"
	say "da G4.1w: 25 por endereço, RFC 9210 §4.5)."
	say ""
	say "| vagas | clientes TCP | $DP_HEAD | fds (pico) |"
	say "|---|---|$DP_SEP|---|"
	local c peak max
	for max in ${TCP_MAX_LIST:-20 100}; do
		dns_set "{\"max_concurrent_tcp_sessions\":$max}"
		for c in 4 16 64; do
			samp_start
			dp "tcp-$max-$c" "$QF/hot" "$DUR" -m tcp -c "$c" -T 2 -q 500
			peak=$(samp_stop)
			say "| $max | $c | $(dp_row) | $(echo "$peak" | cut -d' ' -f3) |"
		done
	done
	say ""
	say "### Conexões paradas (slowloris)"
	say ""
	say "Conexões que mandam um byte e param, de 4 endereços (${CLIENTS[2]}…${CLIENTS[5]}), N por endereço, por"
	say "30 s, reabertas assim que o roteador as fecha; ao lado, um cliente TCP legítimo (${CLIENTS[6]})"
	say "pergunta a cada 250 ms (uma conexão nova por pergunta)."
	say ""
	say "| vagas | por endereço | conexões abertas (reabertas) | consultas legítimas | respondidas | p50 ms | máx. ms | fds (pico) | threads (pico) | CPU do daemon (s) |"
	say "|---|---|---|---|---|---|---|---|---|---|"
	local per n okc cpu0 cpu1
	for max in ${TCP_MAX_LIST:-20 100}; do
	dns_set "{\"max_concurrent_tcp_sessions\":$max}"
	for per in ${SLOW_PER:-10 30}; do
		in_gen python3 -I "$W/slow.py" "$DUT_IP" 30 "${CLIENTS[2]},${CLIENTS[3]},${CLIENTS[4]},${CLIENTS[5]}" "$per" >"$W/slow.out" 2>&1 &
		local sp=$!
		cpu0=$(daemon_cpu)
		samp_start
		sleep 1
		in_gen python3 -I "$W/tcpprobe.py" "$DUT_IP" "${CLIENTS[6]}" 28 "$W/tcpprobe" || true
		peak=$(samp_stop)
		wait $sp 2>/dev/null || true
		cpu1=$(daemon_cpu)
		n=$(wc -l <"$W/tcpprobe")
		okc=$(grep -c ' ok$' "$W/tcpprobe" || true)
		say "| $max | $per | $(awk '/held/ {print $2}' "$W/slow.out") ($(awk '/reopened/ {print $2}' "$W/slow.out")) | $n | $okc | $(awk '$3 == "ok" {print $2}' "$W/tcpprobe" | sort -n | awk '{a[NR] = $1} END {print a[int(NR / 2) + (NR > 0)] + 0}') | $(awk '{print $2}' "$W/tcpprobe" | sort -n | tail -n 1) | $(echo "$peak" | cut -d' ' -f3) | $(echo "$peak" | cut -d' ' -f1) | $(awk -v a="$cpu0" -v b="$cpu1" 'BEGIN {printf "%.1f", b - a}') |"
		cp "$W/tcpprobe" "$OUT/tcp-slowloris-probe-$max-$per.txt"
	done
	done
	dns_set
	alive_check tcp

	say ""
	say "### DoT e DoH de origem com carga"
	say ""
	if ! secure_start; then
		fail "DoT/DoH origin (Unbound) did not start"
		return 0
	fi
	say "Unbound ($SECURE) serve DoT e DoH na frente do Knot; o DUT com use_doh_server e verify_doh_cert=no."
	say "Nomes únicos (sempre miss), origem a 0 ms. Handshakes: SYNs que chegaram ao Unbound."
	say ""
	say "| upstream | carga (-Q) | $DP_HEAD | handshakes/s | CPU |"
	say "|---|---|$DP_SEP|---|---|"
	local url proto rate s0 s1
	for url in "tls://$SECURE#lab-origin" "https://$SECURE/dns-query"; do
		proto=dot_syn
		[[ $url == https* ]] && proto=doh_syn
		dns_set "{\"use_doh_server\":\"$url\",\"verify_doh_cert\":false}"
		sleep 1.5
		for rate in 100 1000 5000; do
			uniq_file "$W/u-sec" 1000000 sec
			s0=$(syn_count $proto)
			thr_snap "$W/t0"
			dp "${proto%_syn}-$rate" "$W/u-sec" "$DUR" -c 8 -T 2 -q 2000 -Q "$rate"
			thr_snap "$W/t1"
			s1=$(syn_count $proto)
			say "| ${url%%:*} | $rate | $(dp_row) | $(((s1 - s0) / DUR)) | $(thr_cpu "$W/t0" "$W/t1" "$DUR") |"
		done
	done
	dns_set
	alive_check secure
}

###########################################################################
# 5. A full cache.
###########################################################################
# bg_hot <name> <rate>: hot names in the background (the "victim" of an
# operation); bg_wait sets DP.
BG_PID=""
bg_hot() {
	ip netns exec crgen taskset -c "$GEN_CPUS" dnsperf -s "$DUT_IP" -a "${CLIENTS[7]}" -d "$QF/hot" -l "$3" -t 5 -c 4 -q 2000 -Q "$2" \
		-O latency-histogram -O suppress=timeout,unexpected >"$OUT/raw/$1.txt" 2>&1 &
	BG_PID=$!
}
bg_wait() { wait "$BG_PID" 2>/dev/null || true; DP=$(dp_parse "$OUT/raw/$1.txt"); }
time_cmd() { # <id> [params] → ms (and the output in $W/time_cmd.out)
	local t0
	t0=$(now)
	cr "$@" >"$W/time_cmd.out" 2>&1 || true
	echo $(($(now) - t0))
}
test_cache() {
	say ""
	say "## 5. Cache cheio"
	say ""
	# A fresh daemon: its RSS before the fill is not inflated by memory
	# that earlier tests freed (malloc keeps it).
	if local_dut; then
		daemon_stop
		daemon_start
		DPID=$(dut_pid corerouter-daemon)
		dut_config
	fi
	dns_set '{"cache_size":1048576,"max_concurrent_queries":1000}'
	origin_delay 0
	flush
	sleep 2
	local r0 r1 t0 fill_ms used
	r0=$(rss_kib)
	uniq_file "$W/u-fill" "$FILL" fill
	t0=$(now)
	# 800 in flight: under max_concurrent_queries (1000), no SERVFAIL.
	dp cache-fill "$W/u-fill" 3600 -n 1 -c 8 -T 2 -q 800
	fill_ms=$(($(now) - t0))
	sleep 2
	r1=$(rss_kib)
	used=$(cr ip.dns.get | jq -r '.cache_used // 0')
	say "Encher: $FILL nomes únicos (origem a 0 ms, max_concurrent_queries 1000) em $fill_ms ms: $(dp_row | cut -d'|' -f1-4)."
	say ""
	say "| entradas pedidas | cache_used (do motor) | RSS antes MiB | RSS depois MiB | RSS por entrada |"
	say "|---|---|---|---|---|"
	say "| $FILL | $used | $((r0 / 1024)) | $((r1 / 1024)) | $(awk -v a="$r0" -v b="$r1" -v n="$FILL" 'BEGIN {printf "%.0f bytes", (b - a) * 1024 / n}') |"
	say ""
	say "Operações com o cache cheio e nomes quentes a 20 000/s ao lado (o p99,9 e o máximo da carga"
	say "mostram quanto tempo a operação segura o lock do cache):"
	say ""
	say "| operação | tempo do comando | carga ao lado: $DP_HEAD |"
	say "|---|---|$DP_SEP|"
	warm hot
	bg_hot cache-base 20000 "$DUR"
	bg_wait cache-base
	say "| (nenhuma) | - | $(dp_row) |"
	local op ms
	for op in 'ip.dns.cache.print {}' 'ip.dns.cache.print {"name":"h1.up.lab"}' 'ip.dns.cache.print {"limit":100000}' 'ip.dns.statistics.print {}'; do
		bg_hot cache-op 20000 "$DUR"
		sleep $((DUR / 3))
		ms=$(time_cmd ${op%% *} "${op#* }")
		bg_wait cache-op
		say "| \`$op\` | $ms ms | $(dp_row) |"
	done
	bg_hot cache-flush 20000 "$DUR"
	sleep $((DUR / 3))
	ms=$(time_cmd ip.dns.cache.flush)
	bg_wait cache-flush
	say "| \`ip.dns.cache.flush\` ($FILL entradas) | $ms ms | $(dp_row) |"
	r1=$(rss_kib)
	say ""
	say "RSS depois do flush: $((r1 / 1024)) MiB."

	say ""
	say "Descarte: cache de 64 MiB já cheio; nomes únicos sem limite de taxa (cada um despeja outro)"
	say "contra o cache vazio."
	say ""
	say "| cache | $DP_HEAD | CPU |"
	say "|---|$DP_SEP|---|"
	dns_set '{"cache_size":65536,"max_concurrent_queries":1000}'
	flush
	uniq_file "$W/u-ev0" 3000000 ev0
	thr_snap "$W/t0"
	dp evict-empty "$W/u-ev0" 5 -c 8 -T 2 -q 2000
	thr_snap "$W/t1"
	say "| vazio | $(dp_row) | $(thr_cpu "$W/t0" "$W/t1" 5) |"
	uniq_file "$W/u-ev1" 600000 ev1
	dp evict-fill "$W/u-ev1" 600 -n 1 -c 8 -T 2 -q 2000
	uniq_file "$W/u-ev2" 3000000 ev2
	thr_snap "$W/t0"
	dp evict-full "$W/u-ev2" "$DUR" -c 8 -T 2 -q 2000
	thr_snap "$W/t1"
	say "| cheio ($(cr ip.dns.get | jq -r '.cache_used // "?"')) | $(dp_row) | $(thr_cpu "$W/t0" "$W/t1" "$DUR") |"
	dns_set
	flush
	alive_check cache
}

###########################################################################
# 6. A big adlist.
###########################################################################
web_start() {
	mkdir -p "$W/web"
	in_gen python3 -I -m http.server 8080 --bind "$WEB" --directory "$W/web" >"$W/web.log" 2>&1 &
	sleep 1
}
test_adlist() {
	say ""
	say "## 6. Adlist de $ADLIST_N domínios"
	say ""
	dns_set
	web_start
	awk -v n="$ADLIST_N" 'BEGIN {print "# lab"; for (i = 0; i < n; i++) printf "0.0.0.0 ad%d.block%d.lab\n", i, i % 997}' >"$W/web/big.txt"
	awk -v n="$ADLIST_N" 'BEGIN {for (i = 0; i < 10000; i++) {j = (i * 97) % n; printf "ad%d.block%d.lab A\n", j, j % 997}}' >"$QF/blocked"
	local r0 r1 t0 id st load_ms
	flush
	warm hot
	dp adlist-before "$QF/hot" "$DUR" "${SAT_OPTS[@]}"
	local before=$DP
	r0=$(rss_kib)
	t0=$(now)
	id=$(ok ip.dns.adlist.add "{\"url\":\"http://$WEB:8080/big.txt\"}" | jq -r .id)
	local end=$((SECONDS + 600))
	while :; do
		st=$(cr ip.dns.adlist.print | jq -r --arg id "$id" '.[] | select(.id == $id) | "\(.state) \(.name_count) \(.error // "")"')
		case $st in loaded*) break ;; failed*) fail "adlist: $st"; return 0 ;; esac
		[ $SECONDS -lt $end ] || { fail "adlist: not loaded in 600 s ($st)"; return 0; }
		sleep 0.2
	done
	load_ms=$(($(now) - t0))
	sleep 2
	r1=$(rss_kib)
	say "| nomes carregados | tempo até loaded | RSS antes MiB | RSS depois MiB | RSS por nome |"
	say "|---|---|---|---|---|"
	say "| $(echo "$st" | cut -d' ' -f2) | $load_ms ms | $((r0 / 1024)) | $((r1 / 1024)) | $(awk -v a="$r0" -v b="$r1" -v n="$ADLIST_N" 'BEGIN {printf "%.0f bytes", (b - a) * 1024 / n}') |"
	say ""
	say "| carga | $DP_HEAD |"
	say "|---|$DP_SEP|"
	DP=$before
	say "| cache quente, sem adlist | $(dp_row) |"
	dp adlist-hot "$QF/hot" "$DUR" "${SAT_OPTS[@]}"
	say "| cache quente, com a adlist | $(dp_row) |"
	dp adlist-blocked "$QF/blocked" "$DUR" "${SAT_OPTS[@]}"
	say "| nomes bloqueados | $(dp_row) |"
	bg_hot adlist-reload 20000 "$DUR"
	sleep $((DUR / 3))
	ok ip.dns.adlist.reload >/dev/null || true
	bg_wait adlist-reload
	say "| cache quente a 20 000/s durante ip.dns.adlist.reload | $(dp_row) |"
	cr ip.dns.adlist.remove "{\"id\":\"$id\"}" >/dev/null || true
	alive_check adlist
}

###########################################################################
# 7. A big zone, UPDATEs and a DHCP storm.
###########################################################################
dhcp_py() {
	cat >"$W/dhcp.py" <<'PY'
# N DHCPv4 clients with their own MACs and host names (option 12), at a
# rate: DISCOVER, then REQUEST for the OFFER; prints bound and seconds.
import os, random, select, socket, struct, sys, time
ifname, n, rate, secs = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
s.bind((ifname, 0)); s.setblocking(False)
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
def opt(c, v): return bytes([c, len(v)]) + v
macs = [b"\x02\x53" + struct.pack("!I", i + 1) for i in range(n)]
state = {}; bound = 0; sent = 0; t0 = time.monotonic(); nxt = t0
while time.monotonic() - t0 < secs and bound < n:
    now = time.monotonic()
    while sent < n and nxt <= now:
        m = macs[sent]; xid = sent + 1
        state[xid] = m
        s.send(frame(m, xid, opt(53, b"\x01") + opt(12, b"h%d" % sent) + opt(55, b"\x01\x03\x06")))
        sent += 1; nxt += 1.0 / rate
    r, _, _ = select.select([s], [], [], 0.001)
    if not r: continue
    while True:
        try: p = s.recv(2048)
        except BlockingIOError: break
        if len(p) < 282 or p[12:14] != b"\x08\x00" or p[23] != 17: continue
        u = 14 + (p[14] & 15) * 4
        if struct.unpack("!H", p[u + 2:u + 4])[0] != 68: continue
        b = p[u + 8:]
        xid = struct.unpack("!I", b[4:8])[0]
        if xid not in state: continue
        yi = b[16:20]; o = b[240:]; mt = None; sid = None; i = 0
        while i < len(o) and o[i] != 255:
            if o[i] == 0: i += 1; continue
            c, l = o[i], o[i + 1]; v = o[i + 2:i + 2 + l]
            if c == 53: mt = v[0]
            if c == 54: sid = v
            i += 2 + l
        if mt == 2 and sid:
            s.send(frame(state[xid], xid, opt(53, b"\x03") + opt(50, yi) + opt(54, sid) + opt(12, b"h%d" % (xid - 1))))
        elif mt == 5:
            bound += 1; del state[xid]
print(bound, "%.2f" % (time.monotonic() - t0))
PY
}
test_ddns() {
	say ""
	local other_n=$((50000 - ZONE_RECORDS - 20))
	say "## 7. Zonas com $((ZONE_RECORDS + other_n)) registros (o teto), UPDATE e tempestade de DHCP"
	say ""
	dns_set
	mcp_open
	# The zones of earlier tests count in the cap.
	cr ip.dns.zone.remove '{"id":"zn.lab"}' >/dev/null 2>&1 || true
	zone_load other.lab "$other_n" o || { mcp_close; return 0; }
	local other_ms=$ZONE_LOAD_MS
	zone_load dyn.lab "$ZONE_RECORDS" d || { mcp_close; return 0; }
	mcp_close
	awk -v n="$ZONE_RECORDS" 'BEGIN {srand(3); for (i = 0; i < 20000; i++) printf "d%d.dyn.lab A\n", int(rand() * n)}' >"$QF/dyn"
	say "Carga de cada zona (ip.dns.zone.file.load por MCP): other.lab ($other_n registros) $other_ms ms,"
	say "dyn.lab ($ZONE_RECORDS) $ZONE_LOAD_MS ms."
	say "Os UPDATEs e as concessões vão para dyn.lab; other.lab só está lá (G4.1p: toda mudança reconstrói"
	say "todas as primárias)."
	sleep 2
	say ""
	say "| carga | $DP_HEAD | UPDATEs/s | escrita em disco por UPDATE | CPU |"
	say "|---|---|$DP_SEP|---|---|---|"
	dp zone-big "$QF/dyn" "$DUR" "${SAT_OPTS[@]}"
	say "| consultas à zona, sem UPDATE | $(dp_row) | - | - | - |"
	local rate w0 w1 u0 ok_u
	for rate in 20 100 500; do
		awk -v n=100000 -v r="$rate" 'BEGIN {for (i = 0; i < n; i++) printf "dyn.lab\nadd u%d-%d.dyn.lab 300 A 10.6.%d.%d\nsend\n", r, i, int(i / 250) % 250, i % 250 + 1}' >"$W/upd"
		local_dut && w0=$(awk '/^write_bytes/ {print $2}' "/proc/$DPID/io")
		thr_snap "$W/t0"
		in_gen "${TENV[@]}" dnsperf -u -s "$DUT_IP" -a "${CLIENTS[5]}" -d "$W/upd" -l "$DUR" -t 5 -c 1 -q 20 -Q "$rate" \
			-O latency-histogram -O suppress=timeout,unexpected >"$OUT/raw/update-$rate.txt" 2>&1 &
		local up=$!
		perf_start "update-$rate"
		dp "zone-under-update-$rate" "$QF/dyn" "$DUR" -c 4 -T 2 -q 500 -Q 5000
		perf_wait
		local zrow
		zrow=$(dp_row)
		wait $up || true
		thr_snap "$W/t1"
		local_dut && w1=$(awk '/^write_bytes/ {print $2}' "/proc/$DPID/io")
		DP=$(dp_parse "$OUT/raw/update-$rate.txt")
		ok_u=$(dpf 4)
		say "| zona a 5000/s com UPDATE a $rate/s | $zrow | $((ok_u / DUR)) ok, p99 $(us "$(dpf 9)") | $(local_dut && awk -v a="$w0" -v b="$w1" -v n="$ok_u" 'BEGIN {if (n > 0) printf "%.0f KiB", (b - a) / 1024 / n; else print "-"}' || echo -) | $(thr_cpu "$W/t0" "$W/t1" "$DUR") |"
	done
	cr ip.dns.zone.dynamic.flush '{"zone":"dyn.lab"}' >/dev/null || true

	say ""
	say "Tempestade de DHCP: $DHCP_N clientes com nome (opção 12) a 1000/s; o servidor DHCP põe A na zona"
	say "dyn.lab a cada concessão. Consultas à zona a 5000/s ao lado."
	say ""
	dhcp_py
	ok ip.address.add "{\"address\":\"$DHCP_NET.0.1/16\",\"interface\":\"$DUT_IFACE\"}" >/dev/null || true
	ok ip.pool.add "{\"name\":\"crdns\",\"ranges\":\"$DHCP_NET.1.0-$DHCP_NET.250.255\"}" >/dev/null || true
	ok ip.dhcp-server.add "{\"name\":\"crdns\",\"interface\":\"$DUT_IFACE\",\"address_pool\":\"crdns\",\"lease_time\":\"1h\",\"conflict_detection\":false,\"client_rate_limit\":0}" >/dev/null || true
	ok ip.dhcp-server.network.add "{\"address\":\"$DHCP_NET.0.0/16\",\"gateway\":\"$DHCP_NET.0.1\",\"dns_zone\":\"dyn.lab\"}" >/dev/null || true
	sleep 2
	local_dut && w0=$(awk '/^write_bytes/ {print $2}' "/proc/$DPID/io")
	thr_snap "$W/t0"
	ip netns exec crgen taskset -c "$GEN_CPUS" dnsperf -s "$DUT_IP" -d "$QF/dyn" -l 60 -t 5 -c 4 -q 500 -Q 5000 \
		-O latency-histogram -O suppress=timeout,unexpected >"$OUT/raw/zone-under-dhcp.txt" 2>&1 &
	local zp=$! res
	local t0
	t0=$(now)
	res=$(ip netns exec crgen python3 -I "$W/dhcp.py" "$LAB_IF" "$DHCP_N" 1000 55 2>&1 | tail -n 1)
	local dt=$(($(now) - t0))
	thr_snap "$W/t1"
	kill -INT $zp 2>/dev/null || true
	wait $zp 2>/dev/null || true
	local_dut && w1=$(awk '/^write_bytes/ {print $2}' "/proc/$DPID/io")
	local dyn bound
	bound=${res%% *}
	dyn=$(cr ip.dns.zone.record.print '{"zone":"dyn.lab"}' | jq '[.[] | select(.dynamic == true)] | length')
	DP=$(dp_parse "$OUT/raw/zone-under-dhcp.txt")
	say "| concessões | em | registros dinâmicos | escrita em disco por concessão | consultas à zona ao lado: $DP_HEAD | CPU |"
	say "|---|---|---|---|$DP_SEP|---|"
	say "| $bound de $DHCP_N | $dt ms | $dyn | $(local_dut && awk -v a="$w0" -v b="$w1" -v n="${bound:-0}" 'BEGIN {if (n > 0) printf "%.0f KiB", (b - a) / 1024 / n; else print "-"}' || echo -) | $(dp_row) | $(thr_cpu "$W/t0" "$W/t1" $((dt / 1000 + 1))) |"
	# A limit measured, not a broken lab: each lease's DNS name costs a
	# rebuild of every zone and a rewrite of the dynamic records (G4.1p,
	# G4.1q).
	[ "${bound:-0}" -ge "$DHCP_N" ] ||
		say "LIMITE: só ${bound:-0} de $DHCP_N concessões em $((dt / 1000)) s com o nome na zona (G4.1p, G4.1q)."
	alive_check ddns
}

###########################################################################
# 8. Hostile input.
###########################################################################
junk_py() {
	cat >"$W/junk.py" <<'PY'
# Malformed DNS at full speed for <secs>: random bytes, a bare header,
# counts that lie, compression loops, a QR=1 "reply", 255 labels.
import os, random, socket, struct, sys, time
dst, src, secs = sys.argv[1], sys.argv[2], float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((src, 0)); s.setblocking(False)
def gen():
    k = random.randrange(7); i = random.randrange(65536)
    if k == 0: return os.urandom(random.randrange(1, 600))
    if k == 1: return struct.pack("!HHHHHH", i, 0x0100, 1, 0, 0, 0)
    if k == 2: return struct.pack("!HHHHHH", i, 0x0100, 60000, 60000, 60000, 60000) + os.urandom(40)
    if k == 3: return struct.pack("!HHHHHH", i, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    if k == 4: return struct.pack("!HHHHHH", i, 0x8180, 1, 1, 0, 0) + b"\x01a\x00" + struct.pack("!HH", 1, 1)
    if k == 5: return struct.pack("!HHHHHH", i, 0x0100, 1, 0, 0, 0) + b"\x01a" * 127 + b"\x00" + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", i, 0x0100, 1, 0, 0, 1) + b"\x01a\x00" + struct.pack("!HH", 1, 1) + b"\x00" + struct.pack("!HHIH", 41, 65535, 0, 9999)
t0 = time.monotonic(); n = 0; pool = [gen() for _ in range(4096)]
while time.monotonic() - t0 < secs:
    try:
        s.sendto(pool[n % 4096], (dst, 53)); n += 1
    except BlockingIOError:
        time.sleep(0.0005)
    try:
        while True: s.recv(4096)
    except BlockingIOError:
        pass
print(n, "%.0f" % (n / secs))
PY
}
test_hostile() {
	say ""
	say "## 8. Entrada hostil"
	say ""
	dns_set
	junk_py
	warm hot
	local res lim
	say "Lixo a toda velocidade de ${CLIENTS[3]} (bytes ao acaso, cabeçalho só, contagens falsas, laço de"
	say "compressão, resposta no lugar de pergunta, 127 rótulos, OPT com versão errada); ao lado, um cliente"
	say "legítimo (cache, 150/s, abaixo do limite por cliente) de outro endereço."
	say ""
	say "| max_queries_per_client | mensagens enviadas | por s | cliente legítimo: $DP_HEAD | CPU |"
	say "|---|---|---|$DP_SEP|---|"
	for lim in 200 0; do
		dns_set "{\"max_queries_per_client\":$lim}"
		thr_snap "$W/t0"
		# Under the default per-client limit (200/s), so only the attacker
		# meets it.
		legit_bg "hostile-legit-$lim" 150
		res=$(in_gen python3 -I "$W/junk.py" "$DUT_IP" "${CLIENTS[3]}" "$DUR")
		legit_wait "hostile-legit-$lim"
		thr_snap "$W/t1"
		say "| $lim$([ "$lim" = 200 ] && echo " (padrão)" || echo " (desligado)") | $(echo "$res" | cut -d' ' -f1) | $(echo "$res" | cut -d' ' -f2) | $(dp_row) | $(thr_cpu "$W/t0" "$W/t1" "$DUR") |"
	done
	dns_set
	say ""
	say "| pergunta | de | EDNS | rcode | bytes da resposta | respostas | fator (resposta/pergunta) |"
	say "|---|---|---|---|---|---|---|"
	local args name type src edns r qb
	for args in "many.up.lab ANY ${CLIENTS[2]} 0" "many.up.lab ANY ${CLIENTS[2]} 4096" "big.up.lab TXT ${CLIENTS[2]} 0" \
		"big.up.lab TXT ${CLIENTS[2]} 4096" "many.up.lab A ${CLIENTS[2]} 4096" "many.up.lab ANY $OUTSIDER 4096" "h1.up.lab A $OUTSIDER 0"; do
		read -r name type src edns <<<"$args"
		local eo=(+noedns)
		[ "$edns" != 0 ] && eo=(+bufsize="$edns")
		r=$(in_gen "${TENV[@]}" kdig @"$DUT_IP" -b "$src" "$name" "$type" +timeout=3 +retry=0 +notcp +ignore "${eo[@]}" 2>/dev/null |
			kdig_summary)
		qb=$((12 + ${#name} + 2 + 4))
		[ "$edns" != 0 ] && qb=$((qb + 11))
		say "| $name $type | $src | ${edns/#0/-} | $(echo "$r" | cut -d' ' -f1) | $(echo "$r" | cut -d' ' -f2) | $(echo "$r" | cut -d' ' -f3) | $(awk -v a="$(echo "$r" | cut -d' ' -f2)" -v b="$qb" 'BEGIN {printf "%.1f", a / b}') |"
	done
	# Outside allowed_from: REFUSED and nothing asked upstream.
	local o0 o1
	o0=$(origin_count)
	in_gen "${TENV[@]}" kdig @"$DUT_IP" -b "$OUTSIDER" "out1-$RANDOM.wt.up.lab" A +timeout=2 +retry=0 >/dev/null 2>&1 || true
	o1=$(origin_count)
	say ""
	[ "$((o1 - o0))" = 0 ] && say "Cliente fora do allowed_from: REFUSED e nenhuma consulta à origem (não é resolvedor aberto)." ||
		fail "a client outside allowed_from made the DUT ask the origin ($((o1 - o0)) queries)"
	local mal
	mal=$(cr ip.dns.statistics.print | jq -c '{queries, rcodes, answered}' 2>/dev/null | cut -c1-400)
	say "ip.dns.statistics.print depois: \`$mal\`"
	alive_check hostile
}

###########################################################################
# 9. Operations under load.
###########################################################################
test_ops() {
	say ""
	say "## 9. Operação com carga"
	say ""
	dns_set
	flush
	warm hot
	local n=50 rate=20000 c t0 id
	say "Nomes quentes a $rate/s durante cada série de $n comandos por uma conexão MCP aberta (sem o"
	say "custo de abrir a CLI). Alvo: p99 do comando < 50 ms (como na G4.2h)."
	say ""
	say "| comando | p50 ms | p99 ms | máx. ms | carga ao lado: $DP_HEAD |"
	say "|---|---|---|---|$DP_SEP|"
	mcp_open
	local cmds=(set static flush statistics batch get)
	for c in "${cmds[@]}"; do
		: >"$W/ops-$c"
		bg_hot "ops-$c" "$rate" 3600
		local i
		for i in $(seq $n); do
			t0=$(now)
			case $c in
			set) mcp_run ip.dns.set "{\"cache_max_ttl_secs\":$((604800 - i % 2))}" >/dev/null ;;
			static)
				id=$(mcp_run ip.dns.static.add "{\"name\":\"op$i.st.lab\",\"address\":\"10.7.0.$i\"}" | jq -r '.id // empty')
				[ -n "$id" ] && mcp_run ip.dns.static.remove "{\"id\":\"$id\"}" >/dev/null
				;;
			flush) mcp_run ip.dns.cache.flush >/dev/null ;;
			statistics) mcp_run ip.dns.statistics.print >/dev/null ;;
			batch)
				printf '{"command":"ip.dns.static.add","params":{"name":"b%d.st.lab","address":"10.7.1.%d"}}\n{"command":"ip.dns.set","params":{"cache_max_ttl_secs":%d}}\n' \
					"$i" "$i" $((604800 - i % 2)) >"$W/ops-batch.jsonl"
				mcp_batch "$W/ops-batch.jsonl" >/dev/null
				;;
			get) mcp_run ip.dns.get >/dev/null ;;
			esac
			echo $(($(now) - t0)) >>"$W/ops-$c"
		done
		kill -INT "$BG_PID" 2>/dev/null || true
		bg_wait "ops-$c"
		local p50 p99 mx
		p50=$(sort -n "$W/ops-$c" | awk '{a[NR] = $1} END {print a[int(NR / 2) + 1]}')
		p99=$(sort -n "$W/ops-$c" | awk '{a[NR] = $1} END {i = int(NR * 0.99 + 0.999); print a[i]}')
		mx=$(sort -n "$W/ops-$c" | tail -n 1)
		local label=$c
		case $c in
		set) label="ip.dns.set" ;; static) label="ip.dns.static.add + remove" ;; flush) label="ip.dns.cache.flush" ;;
		statistics) label="ip.dns.statistics.print" ;; batch) label="lote atômico (static.add + ip.dns.set)" ;; get) label="ip.dns.get" ;;
		esac
		say "| $label | $p50 | $p99 | $mx | $(dp_row) |"
		[ "$p99" -lt 50 ] || OPS_SLOW+="$label p99 $p99 ms; "
	done
	mcp_close
	# The batch's statics stay: removed by name.
	cr ip.dns.static.print | jq -r '.[] | select(.name // "" | test("^b[0-9]+\\.st\\.lab$")) | .id' | while read -r id; do
		cr ip.dns.static.remove "{\"id\":\"$id\"}" >/dev/null || true
	done
	[ -z "${OPS_SLOW:-}" ] || say "Acima do alvo de 50 ms: ${OPS_SLOW}"
	alive_check ops
}

###########################################################################
# 10. Unbound and dnsmasq, same machine, same origin.
###########################################################################
alt_start() { # unbound|dnsmasq
	local d ncpu
	d=$(ub_dir "alt-$1")
	rm -rf "$d"
	mkdir -p "$d"
	ncpu=$(taskset -c "$DUT_CPUS" nproc)
	case $1 in
	unbound)
		cat >"$d/unbound.conf" <<EOF
server:
  username: ""
  chroot: ""
  directory: "$d"
  pidfile: ""
  use-syslog: no
  logfile: ""
  verbosity: 0
  do-daemonize: no
  num-threads: $ncpu
  so-reuseport: yes
  interface: $DUT_IP
  access-control: 10.53.0.0/25 allow
  do-not-query-localhost: no
  msg-cache-size: 512m
  rrset-cache-size: 1g
  domain-insecure: "up.lab"
  module-config: "iterator"
forward-zone:
  name: "."
  forward-addr: $UP1
  forward-addr: $UP2
EOF
		taskset -c "$DUT_CPUS" ip netns exec crdut "${TENV[@]}" unbound -c "$d/unbound.conf" >"$d/out" 2>&1 &
		;;
	dnsmasq)
		taskset -c "$DUT_CPUS" ip netns exec crdut dnsmasq -k -C /dev/null --no-resolv --no-hosts --port=53 \
			--listen-address="$DUT_IP" --bind-interfaces --server="$UP1" --server="$UP2" --all-servers \
			--cache-size=10000 --dns-forward-max=1000 --pid-file= --user=root >"$d/out" 2>&1 &
		;;
	esac
	sleep 1
	local p end=$((SECONDS + 15))
	until q_one h1.up.lab A | grep -q NOERROR; do
		[ $SECONDS -lt $end ] || { log "$1 did not answer: $(tail -n 3 "$d/out")"; return 1; }
		sleep 0.3
	done
	for p in $(ip netns pids crdut); do [ "$(cat "/proc/$p/comm")" = "$1" ] && DPID=$p; done
}
# alt_stop <name>: until it is gone (Unbound's threads take a while to
# let port 53 go, and the next server would find it taken).
alt_stop() {
	local p left i
	for i in $(seq 100); do
		left=0
		for p in $(ip netns pids crdut 2>/dev/null); do
			if [ "$(cat "/proc/$p/comm" 2>/dev/null)" = "$1" ]; then
				left=1
				kill "$([ "$i" -gt 50 ] && echo -9 || echo -TERM)" "$p" 2>/dev/null || true
			fi
		done
		[ $left = 0 ] && return 0
		sleep 0.1
	done
}
compare_one() { # <server label>
	local who=$1 o0 o1 r0 r1
	origin_delay 0
	# Memory first, on a fresh process: after a storm of misses the
	# allocator keeps freed memory and RSS no longer moves. 10 000 names:
	# dnsmasq holds no more (its hard limit).
	sleep 1
	r0=$(awk '/^VmRSS/ {print $2}' "/proc/$DPID/status")
	uniq_file "$W/u-cmpfill" 10000 "cf$who"
	dp "cmp-$who-fill" "$W/u-cmpfill" 600 -n 1 -c 4 -q 50
	sleep 1
	r1=$(awk '/^VmRSS/ {print $2}' "/proc/$DPID/status")
	say "| $who | +10 000 nomes no cache | $(dp_row) | RSS +$(((r1 - r0) / 1024)) MiB ($(awk -v a="$r0" -v b="$r1" 'BEGIN {printf "%.0f", (b - a) * 1024 / 10000}') bytes/entrada) |"
	warm hot
	dp "cmp-$who-hot" "$QF/hot" "$DUR" "${SAT_OPTS[@]}"
	say "| $who | cache quente, saturação | $(dp_row) | |"
	dp "cmp-$who-hot-half" "$QF/hot" "$DUR" -c 8 -T 2 -q 2000 -Q 50000
	say "| $who | cache quente, 50 000/s | $(dp_row) | |"
	origin_delay 20
	uniq_file "$W/u-cmp" 3000000 "cmp$who"
	dp "cmp-$who-miss" "$W/u-cmp" "$DUR" -c 8 -T 2 -q 5000
	say "| $who | miss com origem a 20 ms, saturação | $(dp_row) | |"
	dp "cmp-$who-miss5k" "$W/u-cmp" "$DUR" -c 8 -T 2 -q 5000 -Q 5000
	say "| $who | miss com origem a 20 ms, 5000/s | $(dp_row) | |"
	o0=$(origin_count)
	dp "cmp-$who-ttl0" "$QF/ttl0" "$DUR" -c 8 -T 2 -q 2000 -Q 2000
	o1=$(origin_count)
	say "| $who | o mesmo nome TTL 0 a 2000/s | $(dp_row) | $((o1 - o0)) à origem ($(awk -v o=$((o1 - o0)) -v a="$(dpf 2)" 'BEGIN {if (a > 0) printf "%.2f", o / a}') por resposta) |"
	origin_delay 0
}
test_compare() {
	local_dut || { say ""; say "## 10. Comparação: só com --dut local"; return 0; }
	say ""
	say "## 10. Comparação com Unbound e dnsmasq"
	say ""
	say "Mesmas CPUs ($DUT_CPUS), mesma origem, mesmo gerador. Unbound $(tool unbound -V 2>/dev/null | awk '/Version/ {print $2}')"
	say "com num-threads = CPUs e so-reuseport; dnsmasq $(dnsmasq -v | awk 'NR == 1 {print $3}') (uma thread) com"
	say "cache-size 10000 e dns-forward-max 1000; CoreRouter com max_concurrent_queries 1000 e cache de 1 GiB."
	say ""
	say "| servidor | carga | $DP_HEAD | origem / memória |"
	say "|---|---|$DP_SEP|---|"
	# A fresh daemon: its RSS is not inflated by what earlier tests freed.
	daemon_stop
	daemon_start
	DPID=$(dut_pid corerouter-daemon)
	dut_config
	dns_set '{"max_concurrent_queries":1000,"cache_size":1048576}'
	flush
	compare_one CoreRouter
	dns_set
	daemon_stop
	local alt
	for alt in unbound dnsmasq; do
		if alt_start $alt; then
			compare_one "$alt"
			alt_stop $alt
		else
			say "| $alt | não subiu | - | - | - | - | - | - | - | - | |"
		fi
	done
	daemon_start
	DPID=$(dut_pid corerouter-daemon)
	dut_config
}

###########################################################################
# 11. Soak.
###########################################################################
test_soak() {
	say ""
	say "## 11. Estabilidade com carga moderada ($SOAK_SECS s)"
	say ""
	dns_set
	origin_delay 5
	flush
	warm hot
	# The mix asks statics and a zone (test qps loads them; soak may run
	# alone).
	mcp_open
	statics_load
	cr ip.dns.zone.print '{"name":"zn.lab"}' | jq -e 'length > 0' >/dev/null || zone_load zn.lab "$ZONE_N" z
	mcp_close
	local rate=${SOAK_RATE:-10000} t=0 end=$((SECONDS + SOAK_SECS)) row first="" last=""
	say "A mistura (85 % cache, 5 % estáticos, 5 % zona, 5 % miss) a $rate/s, mais nomes únicos a 50/s;"
	say "uma linha por minuto em soak.csv."
	echo "t_s,qps,lost,servfail,p50_us,p99_us,p999_us,max_us,threads,rss_mib,fds,cache_used" >"$OUT/soak.csv"
	uniq_file "$W/u-soak" 2000000 soak
	in_gen "${TENV[@]}" dnsperf -s "$DUT_IP" -a "${CLIENTS[4]}" -d "$W/u-soak" -l "$SOAK_SECS" -t 5 -c 1 -q 100 -Q 50 \
		-O suppress=timeout,unexpected >"$OUT/raw/soak-unique.txt" 2>&1 &
	local up=$!
	while [ $SECONDS -lt $end ]; do
		dp soak-min "$QF/mix" 60 -c 8 -T 2 -q 2000 -Q "$rate"
		local now_s
		now_s=$(dut_now)
		row="$t,$(echo "$DP" | awk '{print $1 "," $3 "," $5 "," $8 "," $9 "," $10 "," $11}'),$(echo "$now_s" | tr ' ' ','),$(cr ip.dns.get | jq -r '.cache_used // 0')"
		echo "$row" >>"$OUT/soak.csv"
		[ -n "$first" ] || first=$row
		last=$row
		t=$((t + 60))
		alive_check "soak t=$t s" || break
	done
	wait $up 2>/dev/null || true
	say ""
	say "| | t s | qps | perdidas | SERVFAIL | p50 µs | p99 µs | p99,9 µs | máx. µs | threads | RSS MiB | fds | cache_used |"
	say "|---|---|---|---|---|---|---|---|---|---|---|---|---|"
	say "| primeiro minuto | ${first//,/ | } |"
	say "| último minuto | ${last//,/ | } |"
	awk -F, 'NR > 1 {n++; if ($10 > m) m = $10; if ($9 > tm) tm = $9; if ($11 > fm) fm = $11; if ($6 > pm) pm = $6}
		END {printf "\nPicos ao longo da rodada: RSS %d MiB, %d threads, %d fds, p99 %d µs.\n", m, tm, fm, pm}' "$OUT/soak.csv" | tee -a "$RESULTS"
	origin_delay 0
}

###########################################################################
cleanup() {
	set +e
	mcp_close 2>/dev/null
	dut_unconfig 2>/dev/null
	{ [ $DUT = local ] || [ $SELFTEST = 1 ]; } && daemon_stop
	net_down
	[ "$DAEMON" = image ] && umount_image
	[ -d "$W/dut" ] && cp "$W/dut/daemon.log" "$OUT/daemon.log" 2>/dev/null
}

main() {
	cleanup >/dev/null 2>&1 || true
	trap cleanup EXIT
	rm -rf "$W/dut" "$W/q"
	[ "$DAEMON" = image ] && [ $DUT = local ] && mount_image
	build_tools
	mkdir -p "$W"
	net_up
	knot_start
	qfiles
	if [ $DUT = local ] || [ $SELFTEST = 1 ]; then
		daemon_start
		DPID=$(dut_pid corerouter-daemon)
	fi
	if [ $SELFTEST = 1 ]; then
		# The address TLS reaches it on, by the local token (the cable's
		# address is already there on a real remote router).
		cr_local ip.address.add "{\"address\":\"$DUT_IP/24\",\"interface\":\"$DUT_IFACE\"}" >/dev/null
	fi
	dut_config
	{
		echo "# DNS sob carga (G4.1r) — $(date -Is)"
		echo ""
		echo "DUT: $DUT ($([ $DUT = local ] && echo "daemon $DAEMON, CPUs $DUT_CPUS" || echo "$TARGET, porta $DUT_IFACE")); gerador e origem nas CPUs $GEN_CPUS."
		echo "Máquina: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'), $(nproc) CPUs, $(awk '/MemTotal/ {printf "%.1f GiB", $2 / 1048576}' /proc/meminfo); kernel $(uname -r)."
		echo "Ferramentas: dnsperf $(tool dnsperf -h 2>&1 | awk '/^Version/ {print $2}'), Knot $(tool knotd -V | awk '{print $NF}'), netem $([ $NETEM = 1 ] && echo sim || echo NÃO)."
		[ $DUT = local ] && echo "Daemon: $(cr system.resource.print | jq -r '.version // "?"')."
	} | tee -a "$RESULTS"
	local t
	for t in qps torture origin tcp cache adlist ddns hostile ops compare soak; do
		if want "$t"; then
			log "test $t"
			"test_$t" || fail "test $t stopped: see the log"
		fi
	done
	say ""
	say "Resultado: $([ $FAILED = 0 ] && echo OK || echo FALHOU) — $OUT"
	[ $FAILED = 0 ]
}
main
