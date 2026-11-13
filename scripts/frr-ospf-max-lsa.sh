#!/usr/bin/env bash
# G3.4r: FRR's max-lsa (os/patches/frr/0007) under the flood of the gap, on
# the host without root: two FRR sets in user namespaces, the DUT here and
# the generator in a child network namespace, joined by a veth. The
# generator redistributes N kernel routes (a wrong redistribution): N
# type-5 LSAs flood into the DUT, which has max-lsa. Steps: the command and
# its running-config, the flood (time until down, the LSDB's peak, RSS),
# the ignore periods and isolated, the clear, warning-only, no max-lsa, a
# limit set below the count.
#
#   unshare --user --map-root-user --mount --net --pid --fork --mount-proc \
#     env FRR_ROOT=<root> FRR_INSTALL=<DESTDIR>/opt/frr-dbg VTYSH=<vtysh> \
#     bash scripts/frr-ospf-max-lsa.sh
#
# FRR_ROOT: a root to chroot into with FRR's libraries (an export of the
# FRR build container, with root in the frrvty group of its /etc/group);
# FRR_INSTALL: `make install DESTDIR=…` of FRR configured with
# --prefix=/opt/frr-dbg (bind-mounted on the root's /opt/frr-dbg);
# VTYSH: that build's vtysh (with LD_LIBRARY_PATH set for it). N
# (200000), LIMIT (50000), OUT. docs/ospf-stress.md, section 8.
set -u
export LC_ALL=C
N=${N:-200000}
LIMIT=${LIMIT:-50000}
R=${FRR_ROOT:?FRR_ROOT: the root with the FRR libraries}
INST=${FRR_INSTALL:?FRR_INSTALL: the FRR install (opt/frr-dbg)}
VTYSH=${VTYSH:?VTYSH: the vtysh of that build}
H=${WORK:-$(mktemp -d /tmp/frr-max-lsa.XXXXXX)}
OUT=${OUT:-$H/out}
mkdir -p "$OUT"
REP=$OUT/report.md
say() { printf '%s\n' "$*" | tee -a "$REP"; }
nowms() { printf '%s' "${EPOCHREALTIME/./}" | cut -c1-13; }

mount --bind "$INST" "$R/opt/frr-dbg"
mount -t proc proc "$R/proc"
mount --rbind /dev "$R/dev"
ip link set lo up

unshare --net sleep infinity &
GEN=$!
sleep 0.3
gen() { nsenter --net=/proc/$GEN/ns/net "$@"; }
gen ip link set lo up
ip link add ether1 type veth peer name gen1 netns $GEN
ip addr add 10.0.1.1/30 dev ether1; ip link set ether1 up
gen ip addr add 10.0.1.2/30 dev gen1; gen ip link set gen1 up

in_root() { # <side> <cmd…>
	local side=$1; shift
	local ns=()
	[ "$side" = gen ] && ns=(nsenter "--net=/proc/$GEN/ns/net")
	"${ns[@]}" unshare --mount sh -c '
		R=$1; D=$2; shift 2
		mount --bind "$D/run" "$R/run"
		mount --bind "$D/tmp" "$R/tmp"
		exec chroot "$R" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "$@"' sh "$R" "$H/$side" "$@"
}
frr_up() { # <side>
	local side=$1 d
	rm -rf "${H:?}/$side"; mkdir -p "$H/$side/run/frr" "$H/$side/tmp"
	for d in mgmtd zebra ospfd; do
		local a=(-P 0 -u root -g root --log stdout --log-level notifications)
		[ $d = zebra ] && a+=(-s 90000000)
		in_root "$side" /opt/frr-dbg/lib/frr/$d "${a[@]}" >>"$OUT/$side-$d.log" 2>&1 &
		local end=$((SECONDS + 20))
		until [ -S "$H/$side/run/frr/$d.vty" ]; do
			[ $SECONDS -lt $end ] || { say "$side $d did not start"; tail -n 20 "$OUT/$side-$d.log" | tee -a "$REP"; exit 1; }
			sleep 0.1
		done
	done
}
vty() { "$VTYSH" --vty_socket "$H/$1/run/frr" "${@:2}" 2>/dev/null; }
pid_of() { cat "$H/$1/run/frr/$2.pid" 2>/dev/null; }
pj() { python3 -c "import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    print(-1); sys.exit()
$1" 2>/dev/null || echo -1; }
lsas() { vty dut -c 'show ip ospf json' | pj 'print(sum(a.get("lsaNumber",0) for a in d.get("areas",{}).values())+d.get("lsaExternalCounter",0))'; }
others() { vty dut -c 'show ip ospf json' | pj 'print(d.get("lsaOtherRoutersCounter",-1))'; }
mstate() { vty dut -c 'show ip ospf json' | pj 'm=d.get("maxLsa",{}); print(m.get("state","none"), m.get("ignoreEntries","-"), m.get("ignoreRemainingMsecs","-"))'; }
routes() { vty dut -c 'show ip route summary json' | pj 'print(sum(r.get("fib",0) for r in d.get("routes",[]) if r.get("type")=="ospf"))'; }
full() { vty dut -c 'show ip ospf neighbor json' | pj 'print(sum(1 for v in d.get("neighbors",{}).values() for n in v if "Full" in str(n.get("nbrState",""))))'; }
mem() {
	local d p out=""
	for d in ospfd zebra; do
		p=$(pid_of dut $d)
		out+="$d $(awk '/^VmRSS/ {r = $2} /^VmHWM/ {h = $2} END {printf "%d/%d", r / 1024, h / 1024}' /proc/$p/status) MiB "
	done
	echo "$out(rss/peak)"
}

frr_up dut
frr_up gen
say "# G3.4r max-lsa host lab $(date -u +%FT%TZ): $(vty dut -c 'show version' | head -n 1), N=$N, limit $LIMIT"
cfg() { # <side> <rid>
	vty "$1" -c 'configure terminal' -c 'interface '"$( [ "$1" = dut ] && echo ether1 || echo gen1)" \
		-c 'ip ospf area 0' -c 'ip ospf network point-to-point' -c 'ip ospf hello-interval 1' -c 'ip ospf dead-interval 4' \
		-c 'exit' -c 'router ospf' -c "ospf router-id $2" >/dev/null
}
cfg dut 10.255.0.1
cfg gen 10.0.0.11
wait_full() { local end=$((SECONDS + ${1:-60})); until [ "$(full)" -ge 1 ]; do [ $SECONDS -lt $end ] || return 1; sleep 0.2; done; }
wait_full 60 || { say "no adjacency"; exit 1; }
say "adjacency Full; mem before: $(mem)"

# 1. The command and its running-config.
vty dut -c 'configure terminal' -c 'router ospf' -c "max-lsa $LIMIT threshold 80 ignore-time 30 ignore-count 2 reset-time 60" >"$OUT/cmd.txt" 2>&1
say "## 1. running-config"
say '```'; vty dut -c 'show running-config' | sed -n '/^router ospf/,/^exit/p' | tee -a "$REP"; say '```'
say '```'; vty dut -c 'show ip ospf' | grep -A5 'LSAs of other routers' | tee -a "$REP"; say '```'
say "state: $(mstate); others $(others)"
# Range checks: the CLI refuses these.
for bad in "max-lsa 0" "max-lsa 10 threshold 0" "max-lsa 10 ignore-time 10" "max-lsa 10 ignore-count 40" "max-lsa 10 reset-time 30"; do
	r=$(vty dut -c 'configure terminal' -c 'router ospf' -c "$bad" 2>&1 | head -n 1)
	say "refused \`$bad\`: ${r:-(accepted!)}"
done

# The kernel routes the generator redistributes.
python3 - "$N" >"$OUT/routes.batch" <<'PY'
import sys, ipaddress
n = int(sys.argv[1]); base = int(ipaddress.IPv4Address("100.64.0.0"))
for i in range(n):
    print(f"route add blackhole {ipaddress.IPv4Address(base + i)}/32 proto static")
PY
split -l 20000 "$OUT/routes.batch" "$OUT/rb."
for f in "$OUT"/rb.*; do gen ip -batch "$f"; sleep 1; done
K=$(vty gen -c 'show ip route summary json' | pj 'print(sum(r.get("rib",0) for r in d.get("routes",[]) if r.get("type")=="kernel"))')
say "generator: zebra kernel routes $K"

# 2. The flood with max-lsa: the LSDB peak, the first ignore period.
echo 1 >"/proc/$(pid_of dut ospfd)/clear_refs" 2>/dev/null
echo 5 >"/proc/$(pid_of dut ospfd)/clear_refs" 2>/dev/null
echo 5 >"/proc/$(pid_of dut zebra)/clear_refs" 2>/dev/null
say "## 2. flood of $K LSAs, max-lsa $LIMIT (ignore-time 30, ignore-count 2, reset-time 60)"
say "mem before the flood (peak reset): $(mem)"
echo "t_ms lsas state" >"$OUT/flood.csv"
vty gen -c 'configure terminal' -c 'router ospf' -c 'redistribute kernel' >/dev/null
t0=$(nowms); peak=0; tig=""
while [ $(($(nowms) - t0)) -lt 20000 ]; do
	l=$(lsas); st=$(mstate)
	echo "$(($(nowms) - t0)) $l $st" >>"$OUT/flood.csv"
	[ "$l" -gt "$peak" ] && peak=$l
	case $st in ignore*) [ -z "$tig" ] && tig=$(($(nowms) - t0)); [ "$l" -le 1 ] && break ;; esac
	sleep 0.02
done
say "ignore after ${tig:-?} ms; LSDB peak sampled $peak (limit $LIMIT); state $(mstate); LSDB $(lsas); full $(full); routes $(routes)"
grep -h "max-lsa" "$OUT"/dut-ospfd.log | tee -a "$REP"
say "mem: $(mem)"
say '```'; awk 'NR == 1 {next} $2 != last {print; last = $2}' "$OUT/flood.csv" | head -n 30 | tee -a "$REP"; say '```'
sleep 3; say "+3 s: routes $(routes), LSDB $(lsas), mem $(mem)"
say "generator sees: $(vty gen -c 'show ip ospf neighbor' | tail -n +2 | head -n 3 | tr -s ' ')"

# 3. Ignore over: back, the flood again, ignore 2, then isolated.
say "## 3. ignore periods and isolated"
t=$(nowms); last=""
while [ $(($(nowms) - t)) -lt 200000 ]; do
	st=$(mstate); s=${st%% *}
	if [ "$s" != "$last" ]; then say "+$(($(nowms) - t)) ms: state $st, LSDB $(lsas), full $(full), mem $(mem)"; last=$s; fi
	[ "$s" = isolated ] && break
	sleep 0.2
done
grep -h "max-lsa" "$OUT"/dut-ospfd.log | tail -n +2 | tee -a "$REP"
sleep 5; say "isolated +5 s: full $(full), LSDB $(lsas), routes $(routes), mem $(mem)"
say '```'; vty dut -c 'show ip ospf' | grep -A6 'LSAs of other routers' | tee -a "$REP"; say '```'

# 4. Fix the cause (the generator withdraws), then clear.
say "## 4. withdraw at the generator, then clear ip ospf max-lsa"
vty gen -c 'configure terminal' -c 'router ospf' -c 'no redistribute kernel' >/dev/null
sleep 2
t=$(nowms); vty dut -c 'clear ip ospf max-lsa' >/dev/null
wait_full 60; say "clear: Full after $(($(nowms) - t)) ms; state $(mstate)"
end=$(( $(nowms) + 120000 )); until [ "$(lsas)" -le 5 ] || [ "$(nowms)" -gt "$end" ]; do sleep 0.5; done
say "LSDB $(lsas) after $(($(nowms) - t)) ms (the generator's MaxAge flush); state $(mstate); mem $(mem)"

# 5. warning-only: the flood passes, the adjacency stays.
say "## 5. warning-only"
vty dut -c 'configure terminal' -c 'router ospf' -c "max-lsa $LIMIT warning-only" >/dev/null
vty gen -c 'configure terminal' -c 'router ospf' -c 'redistribute kernel' >/dev/null
t=$(nowms); until [ "$(lsas)" -ge "$K" ] || [ $(($(nowms) - t)) -gt 120000 ]; do sleep 0.2; done
say "LSDB $(lsas) after $(($(nowms) - t)) ms; full $(full); state $(mstate); others $(others)"
grep -h "warning-only" "$OUT"/dut-ospfd.log | tee -a "$REP"
say "mem: $(mem)"

# 6. no max-lsa: back to no limit; the JSON keeps only the count.
vty dut -c 'configure terminal' -c 'router ospf' -c 'no max-lsa' >/dev/null
say "## 6. no max-lsa: state $(mstate); running-config: $(vty dut -c 'show running-config' | grep -c max-lsa) max-lsa lines; full $(full)"

# 7. Lower the limit below the count now: ignore at once.
t=$(nowms); vty dut -c 'configure terminal' -c 'router ospf' -c "max-lsa $LIMIT ignore-time 30" >/dev/null
until [ "$(mstate | cut -d' ' -f1)" = ignore ] || [ $(($(nowms) - t)) -gt 10000 ]; do sleep 0.05; done
say "## 7. limit set below the count: state $(mstate) after $(($(nowms) - t)) ms"
vty dut -c 'configure terminal' -c 'router ospf' -c 'no max-lsa' >/dev/null
wait_full 60; say "no max-lsa during ignore: state $(mstate), full $(full)"
say "done: $REP"
kill $GEN
