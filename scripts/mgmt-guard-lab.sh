#!/usr/bin/env bash
# G3.4z: the phase C cut and the management guard against a real FRR.
# Runs as root inside the lab VM only:
#
#   cargo xtask vm-lab run -- scripts/mgmt-guard-lab.sh
#
# Three namespaces joined by veth pairs:
#   crmgop   the operator, 192.168.0.2/24 (ether1's network);
#   crmgdut  corerouter-daemon (--backend linux) driving its own FRR
#            (mgmtd, zebra, ospfd; pathspace crmgdut): ether1 192.168.0.1/24,
#            ether2 10.0.1.1/30;
#   crmggen  the generator, an FRR of its own (pathspace crmggen) that speaks
#            OSPF on 10.0.1.2/30 and announces /32s inside 192.168.0.0/24,
#            the operator's among them, plus 198.18.7.0/24 (not guarded).
#
# Checks, in order: the operator logs in; OSPF brings the /32 and the
# operator is cut (a new login times out); the health check, the summary
# and the log name the covered session; the guard goes in by the local
# console (127.0.0.1, the token); zebra takes the /32s out of the kernel
# and keeps 198.18.7.0/24 (polled every 10 ms through the commit: never
# gone); the operator logs in again; the window's count; the lockout
# refusal when the operator removes the guard of its own network; a second
# commit types nothing into FRR. Results: $OUT/results.md; exit 1 if a
# check failed.
set -u
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
SRC=$(pwd)
OUT=${OUT:-/srv/lab/mgmt-guard/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
RESULTS=$OUT/results.md
: >"$RESULTS"
FAILED=0
say() { printf '%s\n' "$*" | tee -a "$RESULTS"; }
ok() { say "- ok: $*"; }
bad() { say "- FALHOU: $*"; FAILED=1; }
W=/tmp/crmglab
DUT_FRR=/var/run/frr/crmgdut
GEN_FRR=/var/run/frr/crmggen

cleanup() {
	pkill -f -- "-N crmg" 2>/dev/null
	[ -n "${DAEMON:-}" ] && kill "$DAEMON" 2>/dev/null
	[ -n "${SHELLPID:-}" ] && kill "$SHELLPID" 2>/dev/null
	sleep 0.5
	for n in crmgop crmgdut crmggen; do ip netns del $n 2>/dev/null; done
	rm -rf "$W"
}
cleanup
trap cleanup EXIT
mkdir -p "$W"

say "# G3.4z: laboratório da guarda da gerência ($(date -u +%FT%TZ))"
say ""
say "FRR: $(/usr/lib/frr/zebra --version 2>/dev/null | head -1)"
cargo build -q -p corerouter-daemon -p corerouter-cli 2>&1 | tail -5
B=${CARGO_TARGET_DIR:-$SRC/target}/debug
[ -x "$B/corerouter-daemon" ] || { echo "no daemon build in $B"; exit 1; }

for n in crmgop crmgdut crmggen; do ip netns add $n; ip -n $n link set lo up; done
ip link add ether1 netns crmgdut type veth peer name eth0 netns crmgop
ip link add ether2 netns crmgdut type veth peer name eth0 netns crmggen
ip -n crmgop addr add 192.168.0.2/24 dev eth0
ip -n crmgop link set eth0 up
ip -n crmggen addr add 10.0.1.2/30 dev eth0
ip -n crmggen link set eth0 up
ip -n crmggen link add gen0 type dummy
for a in 192.168.0.2/32 192.168.0.77/32 192.168.0.78/32 198.18.7.1/24; do ip -n crmggen addr add $a dev gen0; done
ip -n crmggen link set gen0 up

frr_instance() { # <ns> <pathspace> <ospfd.conf>
	install -d -o frr -g frr "/etc/frr/$2" "/var/run/frr/$2"
	touch "/etc/frr/$2/zebra.conf" "/etc/frr/$2/vtysh.conf"
	printf '%s\n' "$3" >"/etc/frr/$2/ospfd.conf"
	chown frr:frr /etc/frr/"$2"/*.conf
	# mgmtd takes no -f in FRR 10.7.1 (it reads the integrated config).
	ip netns exec "$1" /usr/lib/frr/mgmtd -N "$2" -d
	sleep 0.5
	ip netns exec "$1" /usr/lib/frr/zebra -N "$2" -d -f "/etc/frr/$2/zebra.conf"
	sleep 1
	ip netns exec "$1" /usr/lib/frr/ospfd -N "$2" -d -f "/etc/frr/$2/ospfd.conf"
}
frr_instance crmggen crmggen "router ospf
 ospf router-id 10.0.1.2
 redistribute connected
 network 10.0.1.0/30 area 0
exit"
# The DUT's ospfd starts empty: the daemon types its config.
frr_instance crmgdut crmgdut ""

# The control channel listens on 192.168.0.1 from the start: the address is
# in the kernel before the daemon (and in its config below).
ip -n crmgdut addr add 192.168.0.1/24 dev ether1
ip -n crmgdut addr add 10.0.1.1/30 dev ether2
ip -n crmgdut link set ether1 up
ip -n crmgdut link set ether2 up

export COREROUTER_RUNTIME_DIR=$W/run COREROUTER_KNOWN_HOSTS=$W/known_hosts HOME=$W
mkdir -p "$W/run"
ip netns exec crmgdut "$B/corerouter-daemon" --backend linux --config-dir "$W/cfg" \
	--listen 192.168.0.1:8729 --control 7979 --manage ether1,ether2 --frr "$DUT_FRR" >"$OUT/daemon.log" 2>&1 &
DAEMON=$!
# Listening comes before the local token is written: wait for both.
for _ in $(seq 100); do
	ip netns exec crmgdut ss -ltn | grep -q ':7979' && [ -s "$W/run/control-7979.token" ] && break
	sleep 0.2
done
[ -s "$W/run/control-7979.token" ] || { echo "no local token"; exit 1; }
local_cli() { ip netns exec crmgdut "$B/corerouter-cli" --connect 127.0.0.1:7979 "$@"; }
op_cli() { COREROUTER_PASSWORD= timeout "${T:-6}" ip netns exec crmgop "$B/corerouter-cli" --connect tls://192.168.0.1:8729 --user admin --accept-new-cert "$@"; }
run() { local_cli run "$@" >>"$OUT/commands.log" 2>>"$OUT/cli-stderr.log" || { echo "falhou: $*" >>"$OUT/commands.log"; bad "comando falhou: $*"; return 1; }; }

run ip.address.add '{"address":"192.168.0.1/24","interface":"ether1"}'
run ip.address.add '{"address":"10.0.1.1/30","interface":"ether2"}'
for _ in $(seq 50); do ip netns exec crmgdut ss -ltn | grep -q '192.168.0.1:8729' && break; sleep 0.2; done
if T=10 op_cli run system.identity.get >/dev/null 2>&1; then ok "o operador entra por 192.168.0.1 (TLS)"; else bad "o operador não entrou antes do OSPF"; fi

# The operator's open session: a terminal held by a FIFO.
mkfifo "$W/in"
exec 3<>"$W/in"
COREROUTER_PASSWORD= ip netns exec crmgop "$B/corerouter-cli" --connect tls://192.168.0.1:8729 \
	--user admin --accept-new-cert shell <"$W/in" >"$OUT/operator-shell.out" 2>&1 &
SHELLPID=$!
sleep 2
echo "" >&3
echo "/system identity print" >&3
sleep 1

say ""
say "## OSPF traz o /32 do operador"
run routing.ospf.instance.add '{"name":"lab","router_id":"10.0.1.1"}'
run routing.ospf.area.add '{"name":"backbone","instance":"lab","area_id":"0.0.0.0"}'
run routing.ospf.interface-template.add '{"area":"backbone","networks":"10.0.1.0/30"}'
cut=no
for _ in $(seq 120); do
	if ip -n crmgdut route show 192.168.0.2/32 | grep -q ospf; then cut=yes; break; fi
	sleep 0.5
done
ip -n crmgdut route show proto ospf | sed 's/^/    /' | tee -a "$RESULTS"
say "    route get 192.168.0.2: $(ip -n crmgdut route get 192.168.0.2 from 192.168.0.1 | head -1)"
[ $cut = yes ] && ok "zebra instalou 192.168.0.2/32 (ospf) sobre a 192.168.0.0/24 conectada" || bad "o /32 não chegou"
t0=$(date +%s.%N)
if T=6 op_cli run system.identity.get >/dev/null 2>&1; then bad "o operador ainda entra com o /32 (o corte não reproduziu)"; else ok "corte reproduzido: login novo do operador sem resposta em $(printf '%.1f' "$(echo "$(date +%s.%N) - $t0" | bc)") s"; fi
sleep 3
say ""
say "## O aviso (pelo console local, 127.0.0.1)"
local_cli run system.health.check >"$OUT/health.json" 2>>"$OUT/cli-stderr.log"
python3 - "$OUT/health.json" <<'EOF' | tee -a "$RESULTS"
import json,sys
v=json.load(open(sys.argv[1]))
c=[c for c in v.get("checks",[]) if c["key"]=="management.route"]
print("    management.route:", (c[0]["severity"]+" — "+c[0]["reason"]+" | "+c[0]["action"]) if c else "ausente")
EOF
grep -q '"key": "management.route"' "$OUT/health.json" && grep -A3 '"key": "management.route"' "$OUT/health.json" | grep -q warning \
	&& ok "saúde: management.route em warning" || bad "saúde sem o aviso"
local_cli inspect >"$OUT/inspect.json" 2>>"$OUT/cli-stderr.log"
grep -q '"management_route": \[' "$OUT/inspect.json" && ok "resumo do state.inspect traz management_route (a barra da GUI)" || bad "resumo sem management_route"
local_cli run log.print >"$OUT/log.json" 2>>"$OUT/cli-stderr.log"
grep -q "Gerência: a rota 192.168.0.2/32" "$OUT/log.json" && ok "log: linha 'Gerência: a rota 192.168.0.2/32 …'" || bad "sem linha no log"

say ""
say "## A guarda"
local_cli run routing.management-guard.check '{"network":"192.168.0.0/24"}' >"$OUT/check1.json" 2>>"$OUT/cli-stderr.log"
sleep 2.5
local_cli run routing.management-guard.check '{"network":"192.168.0.0/24"}' >"$OUT/check.json" 2>>"$OUT/cli-stderr.log"
python3 - "$OUT/check.json" <<'EOF' | tee -a "$RESULTS"
import json,sys
v=json.load(open(sys.argv[1]))
for c in v["computed"]: print(f"    prévia: {c['label']}: {c['value']}")
for c in v["checks"]: print(f"    prévia ({c['level']}): {c['message']}")
EOF
grep -q '"Learned routes refused now"' "$OUT/check.json" && ok "a prévia conta as rotas que recusaria (RIB do zebra)" || bad "a prévia não contou"
# 198.18.7.0/24 must never leave the kernel while the guard goes in.
(
	end=$(( $(date +%s) + 8 ))
	gone=0 n=0
	while [ "$(date +%s)" -lt $end ]; do
		ip -n crmgdut route show 198.18.7.0/24 | grep -q ospf || gone=$((gone + 1))
		n=$((n + 1))
		sleep 0.01
	done
	echo "$n $gone" >"$W/poll"
) &
POLL=$!
sleep 0.5
t0=$(date +%s.%N)
run routing.management-guard.add '{"network":"192.168.0.0/24","comment":"lab"}'
for _ in $(seq 500); do ip -n crmgdut route show 192.168.0.2/32 | grep -q ospf || break; sleep 0.01; done
t1=$(date +%s.%N)
wait $POLL
read -r polls gone <"$W/poll"
if ip -n crmgdut route show 192.168.0.2/32 | grep -q .; then bad "o /32 continua no kernel"; else ok "o /32 saiu do kernel $(printf '%.0f' "$(echo "($t1 - $t0) * 1000" | bc)") ms depois do add (**medido**, inclui o CLI)"; fi
[ "$gone" = 0 ] && ok "198.18.7.0/24 (fora da guarda) ficou no kernel o tempo todo ($polls leituras a cada 10 ms)" || bad "198.18.7.0/24 sumiu em $gone de $polls leituras"
say "    route get 192.168.0.2: $(ip -n crmgdut route get 192.168.0.2 from 192.168.0.1 | head -1)"
ip netns exec crmgdut vtysh -N crmgdut -c "show ip route 192.168.0.2/32" 2>/dev/null | sed 's/^/    zebra: /' | head -8 | tee -a "$RESULTS"
ip netns exec crmgdut vtysh -N crmgdut -c "show running-config" 2>/dev/null | grep -E "CR-MG|ip protocol" | sed 's/^/    frr: /' | tee -a "$RESULTS"
if T=10 op_cli run system.identity.get >/dev/null 2>&1; then ok "o operador entra de novo"; else bad "o operador continua sem acesso"; fi
echo "/system identity print" >&3
sleep 4
tail -3 "$OUT/operator-shell.out" | sed 's/^/    shell: /' | tee -a "$RESULTS"
sleep 3
local_cli run routing.management-guard.list >"$OUT/list.json" 2>>"$OUT/cli-stderr.log"
python3 - "$OUT/list.json" <<'EOF' | tee -a "$RESULTS"
import json,sys
v=json.load(open(sys.argv[1]))
for r in v["rows"]: print(f"    lista: {r['network']} {r.get('interface')} sessões={r['sessions']} recusadas={r.get('refused_text', r.get('rib'))} estado={r['state']}")
print(f"    descobertas abertas: {len(v['findings'])}")
EOF
grep -q '"refused_text": "3 (ospf 3)"' "$OUT/list.json" && ok "a lista mostra 3 recusadas (os /32 do gerador: .2, .77, .78)" || bad "a lista não contou 3 recusadas"
local_cli run system.health.check >"$OUT/health2.json" 2>>"$OUT/cli-stderr.log"
grep -A3 '"key": "management.route"' "$OUT/health2.json" | grep -q '"ok"' && ok "saúde voltou a ok" || say "    (saúde: $(grep -A3 '"key": "management.route"' "$OUT/health2.json" | tr -d '\n' | head -c 200))"

say ""
say "## Lockout e idempotência"
id=$(python3 -c "import json;print(json.load(open('$OUT/list.json'))['rows'][0]['id'])")
out=$(T=10 op_cli run routing.management-guard.remove "{\"id\":\"$id\"}" 2>&1)
echo "$out" >"$OUT/lockout.txt"
echo "$out" | grep -q "lockout" && ok "o operador não tira a guarda da própria rede: $(echo "$out" | grep -o 'taking.*session ([0-9.]*)' | head -1)" || bad "remover a guarda da própria sessão passou: $out"
before=$(grep -c "FRR mgmtd" "$OUT/daemon.log")
run system.identity.set '{"name":"lab-dut"}'
run routing.ospf.instance.set '{"id":"lab","comment":"again"}'
sleep 1
after=$(grep -c "FRR mgmtd" "$OUT/daemon.log")
[ "$before" = "$after" ] && ok "commit seguinte não digita nada no mgmtd (a guarda já está como o FRR imprime)" || bad "commit seguinte redigitou no mgmtd ($before → $after): $(grep 'FRR mgmtd' "$OUT/daemon.log" | tail -2)"
grep "FRR mgmtd" "$OUT/daemon.log" | sed 's/^/    daemon: /' | tail -3 | tee -a "$RESULTS"

say ""
[ $FAILED = 0 ] && say "Resultado: tudo ok" || say "Resultado: FALHOU (veja acima)"
exit $FAILED
