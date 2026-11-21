#!/usr/bin/env bash
# G3.4zb: the management services in a VRF of their own. Runs as root inside
# the lab VM only:
#
#   cargo xtask vm-lab run -- scripts/mgmt-vrf-services-lab.sh
#
# Namespaces joined by veth pairs:
#   crsop    operator in main, 192.168.0.2/24 (ether1's network);
#   crsop2   operator in the management VRF, 10.99.0.2/24 (ether3, VRF mgmt);
#   crsgen   a neighbor on ether2 (10.0.1.2/30), main table;
#   crsdut   corerouter-daemon (--backend linux), --listen 0.0.0.0:8729
#            --listen-vrf mgmt, tcp_l3mdev_accept left at the kernel's 0.
#
# Checks, in order: the daemon starts before the VRF exists and its TLS
# control port waits for it (no exit); once the config makes the VRF it
# listens there; www-ssl and metrics move into the VRF; the VRF operator
# reaches the three services and the main operator reaches none; `ss` shows
# them bound to the VRF; a route in main over the VRF operator's address (as
# OSPF or BGP would install) does not touch the VRF session; the way back
# (www-ssl to main by the local console) lets the main operator in again; a
# restart brings the listeners back in the VRF. Results: $OUT/results.md;
# exit 1 if a check failed.
set -u
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
SRC=$(pwd)
OUT=${OUT:-/srv/lab/mgmt-vrf-services/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
RESULTS=$OUT/results.md
: >"$RESULTS"
FAILED=0
say() { printf '%s\n' "$*" | tee -a "$RESULTS"; }
ok() { say "- ok: $*"; }
bad() { say "- FALHOU: $*"; FAILED=1; }
W=/tmp/crslab
NSS="crsop crsop2 crsgen crsdut"

cleanup() {
	[ -n "${DAEMON:-}" ] && kill "$DAEMON" 2>/dev/null
	sleep 0.5
	for n in $NSS; do ip netns del "$n" 2>/dev/null; done
	rm -rf "$W"
}
cleanup
trap cleanup EXIT
mkdir -p "$W"

say "# G3.4zb: serviços de gerência numa VRF ($(date -u +%FT%TZ))"
say ""
cargo build -q -p corerouter-daemon -p corerouter-cli 2>&1 | tail -5
B=${CARGO_TARGET_DIR:-$SRC/target}/debug
[ -x "$B/corerouter-daemon" ] || { echo "no daemon build in $B"; exit 1; }

for n in $NSS; do ip netns add "$n"; ip -n "$n" link set lo up; done
link() { # <dut port> <ns> <ns address>
	ip link add "$1" netns crsdut type veth peer name eth0 netns "$2"
	ip -n "$2" addr add "$3" dev eth0
	ip -n "$2" link set eth0 up
}
link ether1 crsop 192.168.0.2/24
link ether2 crsgen 10.0.1.2/30
link ether3 crsop2 10.99.0.2/24
for p in ether1 ether2 ether3; do ip -n crsdut link set "$p" up; done
ip -n crsop route add default via 192.168.0.1
ip -n crsop2 route add default via 10.99.0.1
say "tcp_l3mdev_accept no roteador: $(ip netns exec crsdut sysctl -n net.ipv4.tcp_l3mdev_accept)"

export COREROUTER_RUNTIME_DIR=$W/run COREROUTER_KNOWN_HOSTS=$W/known_hosts HOME=$W
mkdir -p "$W/run"
start_daemon() {
	ip netns exec crsdut "$B/corerouter-daemon" --backend linux --config-dir "$W/cfg" \
		--listen 0.0.0.0:8729 --listen-vrf mgmt --control 7979 --manage ether1,ether2,ether3 >>"$OUT/daemon.log" 2>&1 &
	DAEMON=$!
	for _ in $(seq 100); do
		ip netns exec crsdut ss -ltn | grep -q '127.0.0.1:7979' && [ -s "$W/run/control-7979.token" ] && break
		sleep 0.2
	done
}
start_daemon
[ -s "$W/run/control-7979.token" ] || { echo "no local token"; tail -20 "$OUT/daemon.log"; exit 1; }
local_cli() { ip netns exec crsdut "$B/corerouter-cli" --connect 127.0.0.1:7979 "$@"; }
op_cli() { # <ns> <address> <args…>
	local ns=$1 at=$2
	shift 2
	COREROUTER_PASSWORD= timeout "${T:-6}" ip netns exec "$ns" "$B/corerouter-cli" --connect "tls://$at:8729" --user admin --accept-new-cert "$@"
}
run() { local_cli run "$@" >>"$OUT/commands.log" 2>>"$OUT/cli-stderr.log" || { echo "falhou: $*" >>"$OUT/commands.log"; bad "comando falhou: $*"; return 1; }; }
reach() { # <ns> <url>: the HTTP code, 000 when nothing answers
	ip netns exec "$1" curl -sk -o /dev/null -m 4 -w '%{http_code}' "$2" 2>/dev/null
}
listening() { ip netns exec crsdut ss -ltn | awk '{print $4}' | grep -E "$1" | tr '\n' ' '; }

say ""
say "## Primeiro boot: a VRF ainda não existe"
sleep 1
kill -0 "$DAEMON" 2>/dev/null && ok "o daemon seguiu de pé sem a VRF" || bad "o daemon saiu porque a VRF não existe"
grep -q -- "--listen 0.0.0.0:8729 in VRF mgmt: .*trying again" "$OUT/daemon.log" && ok "o log diz que o --listen espera a VRF" || bad "sem a linha de espera no log"
say "    log: $(grep -- '--listen 0.0.0.0:8729 in VRF mgmt' "$OUT/daemon.log" | head -1 | cut -c1-200)"

run ip.vrf.add '{"name":"mgmt","interfaces":"ether3"}'
run ip.address.add '{"address":"192.168.0.1/24","interface":"ether1"}'
run ip.address.add '{"address":"10.0.1.1/30","interface":"ether2"}'
run ip.address.add '{"address":"10.99.0.1/24","interface":"ether3"}'
for _ in $(seq 50); do [ -n "$(listening '%mgmt:8729')" ] && break; sleep 0.2; done
[ -n "$(listening '%mgmt:8729')" ] && ok "a porta TLS de controle escuta na VRF quando ela aparece: $(listening ':8729')" || bad "a porta 8729 não abriu na VRF"

say ""
say "## www-ssl e metrics na VRF"
run ip.service.www-ssl.set '{"enabled":true,"vrf":"mgmt"}'
run ip.service.metrics.set '{"enabled":true,"address":"::","vrf":"mgmt"}'
for _ in $(seq 50); do [ -n "$(listening '%mgmt:443')" ] && [ -n "$(listening '%mgmt:9100')" ] && break; sleep 0.2; done
say "    ss: $(listening '%mgmt|:8729|:443|:9100')"
[ -n "$(listening '%mgmt:443')" ] && ok "www-ssl presa à VRF (ss mostra %mgmt:443)" || bad "www-ssl não está na VRF"
[ -n "$(listening '%mgmt:9100')" ] && ok "metrics presa à VRF (ss mostra %mgmt:9100)" || bad "metrics não está na VRF"
local_cli run ip.service.print >"$OUT/services.json" 2>>"$OUT/cli-stderr.log"
python3 - "$OUT/services.json" <<'EOF' | tee -a "$RESULTS"
import json,sys
for r in json.load(open(sys.argv[1])): print(f"    serviço: {r['name']} vrf={r.get('vrf')} status={r.get('status')} listening={r.get('listening')}")
EOF

say ""
say "## Quem chega"
if T=10 op_cli crsop2 10.99.0.1 run system.identity.get >/dev/null 2>&1; then ok "operador da VRF: canal TLS de controle (8729)"; else bad "operador da VRF não entrou no 8729"; fi
c=$(reach crsop2 https://10.99.0.1/); [ "$c" != 000 ] && ok "operador da VRF: www-ssl responde (HTTP $c)" || bad "operador da VRF sem www-ssl"
c=$(reach crsop2 http://10.99.0.1:9100/metrics); [ "$c" = 200 ] && ok "operador da VRF: /metrics (HTTP $c)" || bad "operador da VRF sem /metrics ($c)"
if T=6 op_cli crsop 192.168.0.1 run system.identity.get >/dev/null 2>&1; then bad "operador da main entrou no 8729 (devia estar só na VRF)"; else ok "operador da main: 8729 não responde"; fi
c=$(reach crsop https://192.168.0.1/); [ "$c" = 000 ] && ok "operador da main: www-ssl não responde" || bad "operador da main chegou ao www-ssl ($c)"
c=$(reach crsop http://192.168.0.1:9100/metrics); [ "$c" = 000 ] && ok "operador da main: /metrics não responde" || bad "operador da main chegou ao /metrics ($c)"

say ""
say "## Uma rota na main sobre o operador da VRF (como o OSPF/BGP instalaria)"
ip -n crsdut route add 10.99.0.2/32 via 10.0.1.2 dev ether2 proto ospf
say "    main: $(ip -n crsdut route get 10.99.0.2 | head -1)"
say "    vrf:  $(ip -n crsdut route get 10.99.0.2 vrf mgmt | head -1)"
if T=10 op_cli crsop2 10.99.0.1 run system.identity.get >/dev/null 2>&1; then ok "a sessão da VRF não sente a rota da main"; else bad "a rota da main cortou a VRF"; fi
c=$(reach crsop2 https://10.99.0.1/); [ "$c" != 000 ] && ok "o www-ssl da VRF também não (HTTP $c)" || bad "a rota da main cortou o www-ssl"
ip -n crsdut route del 10.99.0.2/32 via 10.0.1.2 dev ether2 proto ospf

say ""
say "## O caminho de volta: www-ssl para a main pelo console local"
run ip.service.www-ssl.set '{"vrf":"main"}'
for _ in $(seq 50); do [ -z "$(listening '%mgmt:443')" ] && [ -n "$(listening ':443')" ] && break; sleep 0.2; done
c=$(reach crsop https://192.168.0.1/); [ "$c" != 000 ] && ok "o operador da main volta a ter o www-ssl (HTTP $c)" || bad "www-ssl não voltou para a main"
run ip.service.www-ssl.set '{"vrf":"mgmt"}'

say ""
say "## Reinício: os ouvintes voltam na VRF"
kill "$DAEMON"; wait "$DAEMON" 2>/dev/null
start_daemon
for _ in $(seq 75); do [ -n "$(listening '%mgmt:8729')" ] && [ -n "$(listening '%mgmt:443')" ] && break; sleep 0.2; done
say "    ss: $(listening '%mgmt|:8729|:443|:9100')"
[ -n "$(listening '%mgmt:8729')" ] && [ -n "$(listening '%mgmt:443')" ] && [ -n "$(listening '%mgmt:9100')" ] && ok "depois do reinício: 8729, 443 e 9100 na VRF" || bad "depois do reinício faltou ouvinte na VRF"
if T=10 op_cli crsop2 10.99.0.1 run system.identity.get >/dev/null 2>&1; then ok "o operador da VRF entra depois do reinício"; else bad "o operador da VRF não entra depois do reinício"; fi

say ""
[ $FAILED = 0 ] && say "Resultado: tudo ok" || say "Resultado: FALHOU (veja acima)"
exit $FAILED
