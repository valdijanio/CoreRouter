#!/usr/bin/env bash
# G3.4za: the management guard in a VRF (OSPF) and in main against BGP (the
# case G3.4z did not check), against a real FRR. Runs as root inside the lab
# VM only:
#
#   cargo xtask vm-lab run -- scripts/mgmt-guard-vrf-lab.sh
#
# Five namespaces joined by veth pairs:
#   crvop    operator in main, 192.168.0.2/24 (ether1's network);
#   crvop2   operator in the VRF, 10.99.0.2/24 (ether3's network, VRF mgmt);
#   crvdut   corerouter-daemon (--backend linux) driving its own FRR (mgmtd,
#            zebra, bgpd, ospfd; pathspace crvdut): ether1 192.168.0.1/24 and
#            ether2 10.0.1.1/30 in main; ether3 10.99.0.1/24 and ether4
#            10.0.2.1/30 in VRF mgmt. The control channel listens on
#            0.0.0.0:8729 with tcp_l3mdev_accept=1, so the VRF operator's
#            session is a socket of the VRF (its replies use its table);
#   crvbgp   an iBGP neighbor (AS 65000, FRR of its own) on 10.0.1.2/30 that
#            announces /32s inside 192.168.0.0/24, the operator's among them,
#            plus 198.18.7.0/24 (not guarded);
#   crvospf  an OSPF neighbor on 10.0.2.2/30, in the VRF's area, announcing
#            /32s inside 10.99.0.0/24 plus 198.18.9.0/24 (not guarded).
#
# Checks, in order: both operators log in; BGP cuts the main operator and
# OSPF of the VRF cuts the VRF operator; the health check names both, the
# VRF one with its VRF and a fix that carries it; the guard of each goes in
# by the local console; zebra takes each /32 out of its own table and keeps
# the network outside the guard (polled every 10 ms through each commit);
# the running FRR config holds the VRF's `ip protocol` inside `vrf mgmt`;
# both operators log in again; the window's counts; the VRF operator cannot
# take away the guard of its own network (lockout); a second commit types
# nothing into FRR; taking the guards away (force, from the console) brings
# the routes back. Results: $OUT/results.md; exit 1 if a check failed.
set -u
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
SRC=$(pwd)
OUT=${OUT:-/srv/lab/mgmt-guard-vrf/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
RESULTS=$OUT/results.md
: >"$RESULTS"
FAILED=0
say() { printf '%s\n' "$*" | tee -a "$RESULTS"; }
ok() { say "- ok: $*"; }
bad() { say "- FALHOU: $*"; FAILED=1; }
W=/tmp/crvlab
NSS="crvop crvop2 crvdut crvbgp crvospf"

cleanup() {
	pkill -f -- "-N crv" 2>/dev/null
	[ -n "${DAEMON:-}" ] && kill "$DAEMON" 2>/dev/null
	[ -n "${SHELLPID:-}" ] && kill "$SHELLPID" 2>/dev/null
	sleep 0.5
	for n in $NSS; do ip netns del "$n" 2>/dev/null; done
	rm -rf "$W"
}
cleanup
trap cleanup EXIT
mkdir -p "$W"

say "# G3.4za: guarda da gerência em VRF e com BGP ($(date -u +%FT%TZ))"
say ""
say "FRR: $(/usr/lib/frr/zebra --version 2>/dev/null | head -1)"
cargo build -q -p corerouter-daemon -p corerouter-cli 2>&1 | tail -5
B=${CARGO_TARGET_DIR:-$SRC/target}/debug
[ -x "$B/corerouter-daemon" ] || { echo "no daemon build in $B"; exit 1; }

for n in $NSS; do ip netns add "$n"; ip -n "$n" link set lo up; done
link() { # <dut port> <ns> <ns address>
	ip link add "$1" netns crvdut type veth peer name eth0 netns "$2"
	ip -n "$2" addr add "$3" dev eth0
	ip -n "$2" link set eth0 up
}
link ether1 crvop 192.168.0.2/24
link ether2 crvbgp 10.0.1.2/30
link ether3 crvop2 10.99.0.2/24
link ether4 crvospf 10.0.2.2/30
# The ports are up before the daemon, as on a router that boots with links.
for p in ether1 ether2 ether3 ether4; do ip -n crvdut link set "$p" up; done
ip -n crvop route add default via 192.168.0.1
ip -n crvop2 route add default via 10.99.0.1
gen_addrs() { # <ns> <addresses…>
	local ns=$1
	shift
	ip -n "$ns" link add gen0 type dummy
	for a in "$@"; do ip -n "$ns" addr add "$a" dev gen0; done
	ip -n "$ns" link set gen0 up
}
gen_addrs crvbgp 192.168.0.2/32 192.168.0.77/32 198.18.7.1/24
gen_addrs crvospf 10.99.0.2/32 10.99.0.77/32 198.18.9.1/24

frr_instance() { # <ns> <pathspace> <daemon:conf>…
	local ns=$1 ps=$2
	shift 2
	install -d -o frr -g frr "/etc/frr/$ps" "/var/run/frr/$ps"
	touch "/etc/frr/$ps/zebra.conf" "/etc/frr/$ps/vtysh.conf"
	chown frr:frr /etc/frr/"$ps"/*.conf
	# mgmtd takes no -f in FRR 10.7.1 (it reads the integrated config).
	ip netns exec "$ns" /usr/lib/frr/mgmtd -N "$ps" -d
	sleep 0.5
	ip netns exec "$ns" /usr/lib/frr/zebra -N "$ps" -d -f "/etc/frr/$ps/zebra.conf"
	sleep 1
	for dc in "$@"; do
		local d=${dc%%:*} conf=${dc#*:}
		printf '%s\n' "$conf" >"/etc/frr/$ps/$d.conf"
		chown frr:frr "/etc/frr/$ps/$d.conf"
		ip netns exec "$ns" "/usr/lib/frr/$d" -N "$ps" -d -f "/etc/frr/$ps/$d.conf"
	done
}
frr_instance crvbgp crvbgp "bgpd:router bgp 65000
 bgp router-id 10.0.1.2
 neighbor 10.0.1.1 remote-as 65000
 address-family ipv4 unicast
  redistribute connected
 exit-address-family
exit"
frr_instance crvospf crvospf "ospfd:router ospf
 ospf router-id 10.0.2.2
 redistribute connected
 network 10.0.2.0/30 area 0
exit"
# The DUT's daemons start empty: CoreRouter types their config.
frr_instance crvdut crvdut "bgpd:" "ospfd:"

# The control channel on every address, VRF sessions included (the kernel
# docs: an unbound listener takes a VRF's connections with tcp_l3mdev_accept).
ip netns exec crvdut sysctl -qw net.ipv4.tcp_l3mdev_accept=1
export COREROUTER_RUNTIME_DIR=$W/run COREROUTER_KNOWN_HOSTS=$W/known_hosts HOME=$W
mkdir -p "$W/run"
ip netns exec crvdut "$B/corerouter-daemon" --backend linux --config-dir "$W/cfg" \
	--listen 0.0.0.0:8729 --control 7979 --manage ether1,ether2,ether3,ether4 --frr /var/run/frr/crvdut >"$OUT/daemon.log" 2>&1 &
DAEMON=$!
for _ in $(seq 100); do
	ip netns exec crvdut ss -ltn | grep -q ':7979' && [ -s "$W/run/control-7979.token" ] && break
	sleep 0.2
done
[ -s "$W/run/control-7979.token" ] || { echo "no local token"; exit 1; }
local_cli() { ip netns exec crvdut "$B/corerouter-cli" --connect 127.0.0.1:7979 "$@"; }
op_cli() { # <ns> <address> <args…>
	local ns=$1 at=$2
	shift 2
	COREROUTER_PASSWORD= timeout "${T:-6}" ip netns exec "$ns" "$B/corerouter-cli" --connect "tls://$at:8729" --user admin --accept-new-cert "$@"
}
run() { local_cli run "$@" >>"$OUT/commands.log" 2>>"$OUT/cli-stderr.log" || { echo "falhou: $*" >>"$OUT/commands.log"; bad "comando falhou: $*"; return 1; }; }

run ip.vrf.add '{"name":"mgmt","interfaces":"ether3,ether4"}'
run ip.address.add '{"address":"192.168.0.1/24","interface":"ether1"}'
run ip.address.add '{"address":"10.0.1.1/30","interface":"ether2"}'
run ip.address.add '{"address":"10.99.0.1/24","interface":"ether3"}'
run ip.address.add '{"address":"10.0.2.1/30","interface":"ether4"}'
ip -n crvdut -br link show master mgmt | sed 's/^/    vrf mgmt: /' | tee -a "$RESULTS"
sleep 1
for who in "crvop 192.168.0.1 main" "crvop2 10.99.0.1 VRF"; do
	set -- $who
	if T=10 op_cli "$1" "$2" run system.identity.get >/dev/null 2>&1; then ok "o operador ($3) entra por $2 (TLS)"; else bad "o operador ($3) não entrou antes das rotas"; fi
done

say ""
say "## BGP na main e OSPF na VRF trazem os /32 dos operadores"
run routing.bgp.instance.set '{"asn":65000,"router_id":"10.0.1.1"}'
run routing.bgp.connection.add '{"name":"gen","remote_address":"10.0.1.2","local_role":"ibgp"}'
run routing.ospf.instance.add '{"name":"lab","vrf":"mgmt","router_id":"10.0.2.1"}'
run routing.ospf.area.add '{"name":"backbone","instance":"lab","area_id":"0.0.0.0"}'
run routing.ospf.interface-template.add '{"area":"backbone","networks":"10.0.2.0/30"}'
cut=no cutv=no
for _ in $(seq 120); do
	ip -n crvdut route show 192.168.0.2/32 | grep -q bgp && cut=yes
	ip -n crvdut route show vrf mgmt 10.99.0.2/32 | grep -q ospf && cutv=yes
	[ $cut = yes ] && [ $cutv = yes ] && break
	sleep 0.5
done
ip -n crvdut route show proto bgp | sed 's/^/    main: /' | tee -a "$RESULTS"
ip -n crvdut route show vrf mgmt proto ospf | sed 's/^/    vrf mgmt: /' | tee -a "$RESULTS"
[ $cut = yes ] && ok "zebra instalou 192.168.0.2/32 (bgp) sobre a 192.168.0.0/24 conectada (main)" || bad "o /32 do BGP não chegou"
[ $cutv = yes ] && ok "zebra instalou 10.99.0.2/32 (ospf) na tabela da VRF mgmt, sobre a 10.99.0.0/24" || bad "o /32 do OSPF da VRF não chegou"
say "    route get (main): $(ip -n crvdut route get 192.168.0.2 from 192.168.0.1 | head -1)"
say "    route get (vrf): $(ip -n crvdut route get 10.99.0.2 from 10.99.0.1 vrf mgmt | head -1)"
for who in "crvop 192.168.0.1 main" "crvop2 10.99.0.1 VRF"; do
	set -- $who
	if T=6 op_cli "$1" "$2" run system.identity.get >/dev/null 2>&1; then bad "o operador ($3) ainda entra (o corte não reproduziu)"; else ok "corte reproduzido ($3): login novo sem resposta"; fi
done

# The VRF operator's open session: a terminal held by a FIFO (logged in
# before the guard, so it is watched as the one the lockout check knows).
sleep 3
say ""
say "## O aviso (pelo console local, 127.0.0.1)"
local_cli run system.health.check >"$OUT/health.json" 2>>"$OUT/cli-stderr.log"
python3 - "$OUT/health.json" <<'EOF' | tee -a "$RESULTS"
import json,sys
v=json.load(open(sys.argv[1]))
c=[c for c in v.get("checks",[]) if c["key"]=="management.route"]
print("    management.route:", (c[0]["severity"]+" — "+c[0]["reason"][:400]+" | "+c[0]["action"][:300]) if c else "ausente")
EOF
local_cli inspect >"$OUT/inspect.json" 2>>"$OUT/cli-stderr.log"
python3 - "$OUT/inspect.json" >"$W/inspect.txt" <<'EOF'
import json,sys
v=json.load(open(sys.argv[1]))
rows=v.get("management_route") or []
for r in rows: print(r["vrf"], r["protocol"], r["route"], r.get("fix") or "")
EOF
sed 's/^/    resumo: /' "$W/inspect.txt" | tee -a "$RESULTS"
grep -q '^main bgp 192.168.0.2/32 routing.management-guard.add {"network":"192.168.0.0/24"}$' "$W/inspect.txt" && ok "resumo: a sessão da main coberta pelo /32 do BGP, com o comando que resolve" || bad "resumo sem a sessão da main (bgp)"
grep -q '^mgmt ospf 10.99.0.2/32 routing.management-guard.add {"network":"10.99.0.0/24","vrf":"mgmt"}$' "$W/inspect.txt" && ok "resumo: a sessão da VRF coberta pelo /32 do OSPF da VRF, com a VRF no comando" || bad "resumo sem a sessão da VRF"
local_cli run log.print >"$OUT/log.json" 2>>"$OUT/cli-stderr.log"
grep -q "Gerência: a rota 10.99.0.2/32 (ospf.*de ether3 (VRF mgmt)" "$OUT/log.json" && ok "log: linha da VRF com '(VRF mgmt)'" || bad "sem a linha da VRF no log"

# A guard goes in while the network outside it is polled every 10 ms.
guard() { # <label> <params> <guarded /32> <kept net> <ip route show args…>
	local label=$1 params=$2 host=$3 kept=$4
	shift 4
	(
		end=$(( $(date +%s) + 8 ))
		gone=0 n=0
		while [ "$(date +%s)" -lt $end ]; do
			ip -n crvdut route show "$@" "$kept" | grep -q . || gone=$((gone + 1))
			n=$((n + 1))
			sleep 0.01
		done
		echo "$n $gone" >"$W/poll"
	) &
	local poll=$!
	sleep 0.5
	local t0 t1
	t0=$(date +%s.%N)
	run routing.management-guard.add "$params"
	for _ in $(seq 500); do ip -n crvdut route show "$@" "$host" | grep -q . || break; sleep 0.01; done
	t1=$(date +%s.%N)
	wait $poll
	read -r polls gone <"$W/poll"
	if ip -n crvdut route show "$@" "$host" | grep -q .; then bad "$label: o $host continua no kernel"; else ok "$label: o $host saiu da tabela $(printf '%.0f' "$(echo "($t1 - $t0) * 1000" | bc)") ms depois do add (**medido**, inclui o CLI)"; fi
	[ "$gone" = 0 ] && ok "$label: $kept (fora da guarda) ficou na tabela o tempo todo ($polls leituras a cada 10 ms)" || bad "$label: $kept sumiu em $gone de $polls leituras"
}

say ""
say "## A guarda da main (BGP)"
guard "main" '{"network":"192.168.0.0/24","comment":"lab main"}' 192.168.0.2/32 198.18.7.0/24
say ""
say "## A guarda da VRF (OSPF), sem dizer a VRF: o roteador acha a tabela"
local_cli run routing.management-guard.check '{"network":"10.99.0.0/24"}' >"$OUT/check-vrf.json" 2>>"$OUT/cli-stderr.log"
grep -q '"vrf": "mgmt"' "$OUT/check-vrf.json" && ok "a prévia escolhe a VRF mgmt (onde a rede é conectada)" || bad "a prévia não escolheu a VRF: $(head -c 300 "$OUT/check-vrf.json")"
guard "vrf" '{"network":"10.99.0.0/24","comment":"lab vrf"}' 10.99.0.2/32 198.18.9.0/24 vrf mgmt
ip netns exec crvdut vtysh -N crvdut -c "show running-config" 2>/dev/null | grep -E "^vrf|CR-MG|ip protocol" | sed 's/^/    frr: /' | tee -a "$RESULTS"
ip netns exec crvdut vtysh -N crvdut -c "show running-config" 2>/dev/null | grep -A2 '^vrf mgmt' | grep -q 'ip protocol any route-map CR-MG-4-mgmt' \
	&& ok "FRR: 'ip protocol any route-map CR-MG-4-mgmt' dentro de 'vrf mgmt'" || bad "FRR sem o ip protocol dentro da vrf mgmt"
ip netns exec crvdut vtysh -N crvdut -c "show ip route vrf mgmt 10.99.0.2/32" 2>/dev/null | sed 's/^/    zebra (vrf): /' | head -6 | tee -a "$RESULTS"
ip netns exec crvdut vtysh -N crvdut -c "show ip route 192.168.0.2/32" 2>/dev/null | sed 's/^/    zebra (main): /' | head -6 | tee -a "$RESULTS"
sleep 2
for who in "crvop 192.168.0.1 main" "crvop2 10.99.0.1 VRF"; do
	set -- $who
	if T=10 op_cli "$1" "$2" run system.identity.get >/dev/null 2>&1; then ok "o operador ($3) entra de novo"; else bad "o operador ($3) continua sem acesso"; fi
done

say ""
say "## A lista"
local_cli run routing.management-guard.list >"$OUT/list1.json" 2>>"$OUT/cli-stderr.log"
sleep 3
local_cli run routing.management-guard.list >"$OUT/list.json" 2>>"$OUT/cli-stderr.log"
python3 - "$OUT/list.json" <<'EOF' | tee -a "$RESULTS"
import json,sys
v=json.load(open(sys.argv[1]))
for r in v["rows"]: print(f"    lista: {r['network']} vrf={r['vrf']} {r.get('interface')} recusadas={r.get('refused_text', r.get('rib'))} estado={r['state']}")
EOF
grep -q '"refused_text": "2 (bgp 2)"' "$OUT/list.json" && ok "main: 2 recusadas (bgp: .2 e .77)" || bad "main não contou 2 do bgp"
grep -q '"refused_text": "2 (ospf 2)"' "$OUT/list.json" && ok "VRF: 2 recusadas (ospf: .2 e .77, lidas da RIB da VRF)" || bad "VRF não contou 2 do ospf"

say ""
say "## Lockout e idempotência"
id=$(python3 -c "import json;print([r['id'] for r in json.load(open('$OUT/list.json'))['rows'] if r['vrf']=='mgmt'][0])")
out=$(T=10 op_cli crvop2 10.99.0.1 run routing.management-guard.remove "{\"id\":\"$id\"}" 2>&1)
echo "$out" >"$OUT/lockout.txt"
echo "$out" | grep -q "lockout" && ok "o operador da VRF não tira a guarda da própria rede: $(echo "$out" | grep -o 'taking.*session ([0-9.]*)' | head -1)" || bad "remover a guarda da própria sessão (VRF) passou: $out"
before=$(grep -c "FRR mgmtd" "$OUT/daemon.log")
run system.identity.set '{"name":"lab-dut"}'
run routing.ospf.instance.set '{"id":"lab","comment":"again"}'
sleep 1
after=$(grep -c "FRR mgmtd" "$OUT/daemon.log")
[ "$before" = "$after" ] && ok "commit seguinte não digita nada no mgmtd (o render da VRF bate com o que o FRR imprime)" || bad "commit seguinte redigitou no mgmtd ($before → $after): $(grep 'FRR mgmtd' "$OUT/daemon.log" | tail -2)"

say ""
say "## O caminho de volta: tirar as guardas devolve as rotas"
for r in $(python3 -c "import json;print(' '.join(r['id'] for r in json.load(open('$OUT/list.json'))['rows']))"); do
	run routing.management-guard.remove "{\"id\":\"$r\",\"force\":true}"
done
back=no
for _ in $(seq 100); do
	ip -n crvdut route show vrf mgmt 10.99.0.2/32 | grep -q ospf && ip -n crvdut route show 192.168.0.2/32 | grep -q bgp && { back=yes; break; }
	sleep 0.1
done
[ $back = yes ] && ok "sem as guardas, os /32 voltam às duas tabelas (o filtro sai do zebra)" || bad "os /32 não voltaram"
ip netns exec crvdut vtysh -N crvdut -c "show running-config" 2>/dev/null | grep -A3 '^vrf mgmt' | sed 's/^/    frr depois: /' | tee -a "$RESULTS"
ip netns exec crvdut vtysh -N crvdut -c "show running-config" 2>/dev/null | grep -q 'CR-MG' && bad "sobrou CR-MG no FRR" || ok "nada de CR-MG no FRR depois de tirar as guardas"

say ""
[ $FAILED = 0 ] && say "Resultado: tudo ok" || say "Resultado: FALHOU (veja acima)"
exit $FAILED
