# IP › Routes (G1.27)

A janela de rotas responde às perguntas do operador sem ele decorar letras: **qual rota está em uso,
por que esta outra não está, e para onde vai o tráfego para tal IP**. O motor decide tudo
(`crates/engine/src/route_table.rs` e `route_lookup.rs`); a GUI só mostra.

## O que cada rota traz (`ip.route.list`)

| Campo | O que é |
|---|---|
| `state` | `active` (encaminha), `standby` (usável, mas outra de distância menor ganha; assume quando ela cai) ou `inactive` (não usável agora) |
| `origin` | `connected`, `static`, `dhcp`, `ra` (BGP e OSPF entram quando o RIB deles existir) |
| `gateway_address`, `gateway_interface`, `interface` | o gateway separado: endereço, interface configurada e a interface de saída resolvida |
| `gateway_status` | `reachable` / `unreachable` (nulo nas conectadas) |
| `check_gateway` | método, intervalo, falhas seguidas e `up`/`down` (hoje só nas rotas de lease DHCP, G4.7c) |
| `ecmp` | quantos caminhos tem o grupo ECMP da rota (1 = sem ECMP) |
| `reason`, `reason_id`, `reason_args` | por que está `standby`/`inactive`; o id e os argumentos deixam a GUI traduzir |
| `changed_at`, `changed_secs` | quando a rota entrou no estado atual (nulo: já estava assim quando o daemon começou a olhar) |
| `flags` | as letras do RouterOS para o terminal (`X A D C S +`) |

Filtros do comando: `routing_table`, `family` (`ipv4`/`ipv6`), `state`, `origin`.

### Motivos

| `reason_id` | Quando |
|---|---|
| `loses-distance` | outra rota ao mesmo destino tem distância menor ("perde para a distância 1 (rota *1 via …)") |
| `tie` | mesma distância de uma rota que não forma ECMP com ela (conectada e estática não se somam) |
| `connected-wins` | a rede é conectada: a rota conectada (distância 0) ganha |
| `interface-down` | a interface de saída está sem link (o daemon segue o carrier a cada segundo) |
| `interface-disabled`, `address-disabled`, `network-disabled`, `connected-disabled` | algo no caminho foi desativado |
| `check-gateway` | o check-gateway falhou: "check-gateway=arp falhou há 40 s" |
| `unreachable`, `not-on-interface`, `own-address`, `needs-interface`, `other-table`, `bridge-port`, `bond-slave`, `no-interface`, `no-table`, `family-mismatch` | a rota está errada para a config atual (o validador recusa criar assim; aparece se a config mudou embaixo dela) |

A lista completa, com as palavras em inglês e os argumentos, é `route_table::REASONS`; a tradução
para o português fica em `crates/ui/src/i18n/routes_pt.rs` (um teste confere que os argumentos batem).

## ECMP

Rotas estáticas (ou de lease DHCP) ao mesmo destino, na mesma tabela e **com a mesma distância**
formam um grupo ECMP, como no RouterOS v7 (flag `+`). Antes do G1.27 o validador recusava a segunda.
No kernel o grupo vira **uma** rota multipath (`RTA_MULTIPATH`): acrescentar ou tirar um caminho
reescreve a rota com os irmãos (`hal-linux`, `netlink.rs`). Uma rota `proto static` de outro
programa com o mesmo prefixo e métrica nunca é misturada com as nossas: o apply recusa, como antes.
Rotas aprendidas por RA de vários roteadores também formam grupo (o kernel já as junta).

Na GUI o grupo aparece numa linha "+ 2 next-hops" com o selo `ECMP`; um clique abre os caminhos.

## Route lookup (`ip.route.lookup`)

`ip.route.lookup {address, table?, src?}` é o `ip route get` do Linux e o `/ip route check` do
RouterOS. Ordem (RFC 1812 §5.2.4.3, RFC 4632 §5.1):

1. endereço do próprio roteador → `local`;
2. o prefixo mais longo entre as rotas **ativas** da tabela; um grupo ECMP dá todos os caminhos;
3. nada → `unreachable`.

A tabela é a pedida, a da VRF do `src` ou a `main`. Ainda não há regras de política
(`/routing rule`, gap G1.27e): o campo `rule` diz como a tabela foi escolhida. O IP de origem segue a
regra do kernel: o endereço da interface de saída cuja rede contém o gateway, senão o primeiro (no
IPv6 sem link-local, uma versão simples da RFC 6724 §5 regra 2).

Responde pelo modelo do motor, então funciona no lab virtual. Depois pergunta ao plano de dados
(`Hal::route_get`): no Linux é `RTM_GETROUTE` com `RTM_F_LOOKUP_TABLE` (e `RTM_F_FIB_MATCH` para o
prefixo e os caminhos); no lab, o maior prefixo sobre o kernel simulado. Se as respostas diferem,
`kernel.differences` diz onde (prefixo, caminho, origem): uma rota posta à mão, drift, ou uma regra
do kernel. Num grupo ECMP o kernel responde um caminho só (o do hash do fluxo); isso não conta como
diferença.

## Pesquisa

Fontes lidas em 2026-10-23 (resumo completo nas notas da sessão):

- **MikroTik RouterOS v7** — [IP Routing](https://help.mikrotik.com/docs/spaces/ROS/pages/328084/IP+Routing),
  [Routing](https://help.mikrotik.com/docs/spaces/ROS/pages/59965508/Routing),
  [`/ip route` 7.25](https://manual.mikrotik.com/docs/7.25/cli-reference/ip/route/),
  [`/routing route`](http://manual.mikrotik.com/docs/7.25/cli-reference/routing/route/),
  [`/routing nexthop`](http://manual.mikrotik.com/docs/7.25/cli-reference/routing/nexthop/),
  [`/ip route check`](http://manual.mikrotik.com/docs/7.25/cli-reference/ip/route/check/),
  [diferenças v6→v7](https://help.mikrotik.com/docs/spaces/RKB/pages/127369252/ROS+v7+differences+in+IP+Route).
  Flags `D X I A` + origem (`c s r b o i d v m y`) + `H` e `+` (ECMP); `immediate-gw`;
  `check-gateway` = `arp|ping|bfd`, a cada 10 s, inalcançável depois de 2 falhas; no v7, rotas iguais
  formam ECMP; `/routing route` tem `contribution` (`filtered|unreachable|candidate|best-candidate|active`)
  e `belongs-to`; o estado do gateway mora em `/routing nexthop` (`gw-state`, `flap-count`); o v7
  tirou da janela as abas Rules/VRF/Nexthop; `/ip route check {src-ip, dst-ip}` → `status`,
  `interface`, `nexthop`. A WinBox 4 esconde a coluna Routing Table desde a 7.4 (fórum).
- **FRR / VyOS** — [zebra](https://docs.frrouting.org/en/latest/zebra.html),
  [VyOS static](https://docs.vyos.io/en/latest/configuration/protocols/static.html): `show ip route`
  separa `>` (selecionada) de `*` (instalada no FIB), `q` na fila, `r` rejeitada; `show ip route X`
  faz o maior prefixo; `show ip route summary` conta por protocolo.
- **Junos** — [`show route`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route.html),
  [`detail`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route-detail.html),
  [`exact`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route-exact.html),
  [`best`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route-best.html),
  [`forwarding-table`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route-forwarding-table.html):
  `Inactive reason` por rota (preferência, "not best in its group"…), modos de busca
  `exact | longer | orlonger`, `best`, e a tabela de encaminhamento à parte (tipo do próximo salto:
  `ucst`, `ulst` ECMP, `rjct`, `locl`).
- **Cisco** — [`show ip route`](https://www.cisco.com/E-Learning/bulk/public/tac/cim/cib/using_cisco_ios_software/cmdrefs/show_ip_route.htm):
  "Routing entry for", "Known via", distância/métrica e um bloco por caminho ECMP; `longer-prefixes`.
- **Linux** — [ip-route(8)](https://man7.org/linux/man-pages/man8/ip-route.8.html),
  [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html): `ip route get` devolve
  `via`, `dev`, `src`, `table`; `fibmatch` = `RTM_F_FIB_MATCH`; `RTM_F_LOOKUP_TABLE` respeita a tabela
  pedida (VRF).
- **RFCs** — [RFC 1812](https://www.rfc-editor.org/rfc/rfc1812.txt) §5.2.4.3 (Basic Match → Longest
  Match → Weak TOS → Best Metric → Vendor Policy), §5.2.4.4 (preferência administrativa 0–255, 255 =
  nunca usar), §5.2.4.5 (divisão de carga, ECMP); [RFC 4632](https://www.rfc-editor.org/rfc/rfc4632.txt)
  §5.1 (maior prefixo).

**Adotado:** nomes e flags do RouterOS (o terminal continua com `X A D C S +`); ECMP por rotas de
mesma distância como no v7; o "motivo" do Junos, mais fino que o `contribution` do RouterOS; o
"para onde vai" do `ip route get` com o nome de comando que o brief pediu (`ip.route.lookup`) e a
resposta do Linux, comparada com a do kernel (o que o RouterOS não faz).

**Melhorias além dos outros:** o motivo traduzido com argumentos; "há quanto tempo mudou" por rota;
a comparação motor × kernel no próprio lookup; o grupo ECMP numa linha que abre.

**Ficou para depois:** a janela Nexthops (`/routing nexthop`: estado por gateway, flaps); a vista
RIB × FIB do Junos/FRR (selecionada × instalada); regras de política (G1.27e); vizinhos ARP/ND para
o `incomplete` (G1.27d); busca por prefixo contém/contido e escala para a tabela cheia (G1.27c);
avisos ao criar uma rota que esconde outra (RFC 4632) ou com distância 255.
