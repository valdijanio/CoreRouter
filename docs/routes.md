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
| `check_gateway` | método (`ping`, `arp`, `bfd`), intervalo, falhas seguidas, `up`/`down`, `status` (`checking`, `reachable`, `unreachable`, `not-checked`), hold-down e perfil BFD: rotas estáticas (G1.27f/G3.6g) e de lease DHCP (G4.7c) |
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
| `check-gateway` | o check-gateway de uma rota de lease falhou: "check-gateway=arp falhou há 40 s" |
| `check-gateway-down` | o gateway de uma rota estática não responde ao check-gateway (ou a sessão BFD caiu); há quanto tempo está em `changed_secs` |
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

Uma rota de lease (DHCP, DHCPv6) ao lado de uma estática com o mesmo destino e distância nunca
some: até o G1.27h o motor a tirava da lista e do kernel sem dizer nada (achado numa VM: a rota
padrão do DHCP não aparecia, nem inativa, enquanto a estática `*1` existia). Agora as duas formam o
grupo ECMP e `ip.dhcp-client.list` diz com quem a rota divide o tráfego (`route_states`, `notes`);
para usá-la só como reserva, suba o `default_route_distance`.

### Aviso de ECMP (G1.27j)

Um grupo ECMP nunca é silencioso. Cada rota ativa do grupo traz `notice` em `ip.route.list`
(`level`, `text`, `id`, `args`, `fix`), em dois níveis:

- **info** (`ecmp-same`): caminhos de uma origem só para uma rede que não é a padrão (duas
  estáticas por gateways diferentes, RA de dois roteadores). Costuma ser intencional.
- **warning** (`ecmp-mixed`, `ecmp-default`): origens misturadas (estática + DHCP, dois clientes
  DHCP, que são dois uplinks mesmo com a mesma origem) ou a rota padrão. O kernel escolhe o caminho
  por hash do fluxo (`net.ipv4.fib_multipath_hash_policy`: 0 = origem/destino, o padrão; 1 = as
  portas também), então cada conexão sai por um uplink com outro IP público: sites que amarram a
  sessão ao IP quebram e um uplink que cai leva a parte dele das conexões. O `fix` é o comando
  pronto: o cliente DHCP do grupo com `default_route_distance` 254, ou a última estática um passo
  atrás (`ip.route.set {"id":…,"distance":d+1}`).

O aviso aparece na linha do grupo na janela Routes (selo `ECMP` âmbar + `warning`, texto no Motivo,
contagem no rodapé, linha "ECMP" no detalhe com "Copy command"), em `system.health.check`
(`routes.ecmp`, entra no "N warning" da barra), nas `notes` e em `route_states[].notice` de
`ip.dhcp-client.list`/`ipv6.dhcp-client.list`, e em `ip.route.page` (`summary.ecmp_warning`,
`ecmp_info`). A contagem vem do `Summary` guardado com as linhas: a saúde não varre a tabela.

Na GUI o grupo aparece numa linha "+ 2 next-hops" com o selo `ECMP`; um clique abre os caminhos.

## Check-gateway (G1.27f, G3.6g)

`ip.route.add/set` aceitam `check_gateway` = `none | ping | arp | bfd` e `bfd_profile` (só com
`bfd`; vazio = `default`), como o `check-gateway` do RouterOS v7:

- `ping`/`arp`: uma sonda a cada 10 s; 2 sem resposta seguidas e o gateway caiu; a primeira resposta
  o traz de volta. `arp` só para gateway IPv4 (ND é a G1.27g); `ping` serve IPv4 e IPv6.
- `bfd`: uma sessão do **nosso** motor BFD (serviço `bfd`, G3.6) ao gateway, salto único, com o
  perfil da rota; cai no tempo de detecção do perfil. Sessão que não sobe em 5 s conta como caída.
- **Gateway caído:** a rota sai do kernel (`Session::effective` a deixa de fora; `ip.route.list` a
  mostra `inactive` com o motivo `check-gateway-down`) e a concorrente de distância maior assume.
- **Hold-down contra oscilação:** a 1ª queda em 15 min volta na primeira resposta (RouterOS); a 2ª
  espera 10 s respondendo, depois 20 s, 40 s… até 5 min (`hold_down_secs`). Uma falha no meio
  recomeça a contagem.
- **Agrupado por gateway:** rotas com o mesmo método, gateway e tabela dividem uma sonda
  (`ip.route.check.list` mostra os alvos e quantas rotas cada um carrega;
  `ip.route.check.history` as trocas, também no detalhe da rota).
- **Onde roda:** o serviço `route-check` do daemon (uma thread, fora do lock do `Session`): um
  socket ICMP por device e um `AF_PACKET` por interface; o engine (`gateway_check.rs`) guarda a
  máquina de estado, a mesma do cliente DHCP (G4.7c), e retira/devolve as rotas num apply só.
  `--route-check-interval <ms>` muda os 10 s (testes). Uma GUI sem daemon mostra `not-checked`.

Na janela: coluna **Check** (método + selo do estado), campo **Check Gateway** com selos no modal
e **BFD Profile** quando é `bfd`, e o detalhe com falhas, há quanto tempo caiu, hold-down e as
últimas trocas do gateway.

### Pesquisa (G1.27f)

- **MikroTik RouterOS v7** — [`/ip route`](https://manual.mikrotik.com/docs/cli-reference/ip/route)
  e [IP Routing](https://help.mikrotik.com/docs/spaces/ROS/pages/59965493/IP+Routing): `check-gateway`
  = `none|arp|ping|bfd`, a cada 10 s, inalcançável depois de 2 falhas, de volta na primeira resposta;
  o estado fica em `/routing nexthop`. O suporte a `bfd` em rota estática foi por muito tempo "ainda
  não" ([fórum](https://forum.mikrotik.com/t/default-route-check-with-bfd/175874),
  [pedido](https://forum.mikrotik.com/t/feature-request-bfd-for-static-routes/119494)); sem
  hold-down: um gateway oscilando move o tráfego a cada 20 s.
- **Cisco IP SLA + track** — [exemplo](https://networklessons.com/tag/ip-sla/reliable-static-routing-with-ip-sla),
  [delay up/down](https://community.cisco.com/t5/routing/ip-sla-questions/td-p/4283763): `ip sla`
  (icmp-echo) → `track … reachability` com `delay down/up` → `ip route … track N`. Ideia adotada:
  a espera para voltar (aqui crescente com as quedas, em vez de fixa).
- **Juniper Junos** — [BFD em rota estática](https://www.juniper.net/documentation/us/en/software/junos/static-routing/topics/topic-map/bfd-static-routes.html),
  [qualified-next-hop](https://juniper.net/documentation/en_US/junos12.3/topics/example/policy-bfd-qualiified-next-hop.html):
  `bfd-liveness-detection` por next-hop (salto único por padrão, multihop opcional), tempo de
  detecção = intervalo × multiplicador; com o BFD caído o next-hop sai da tabela.
- **VyOS** — [failover](https://docs.vyos.io/en/latest/configuration/protocols/failover.html):
  rota que só fica enquanto um alvo responde (icmp/arp/tcp), alvo pode ser outro host que não o
  next-hop. Ficou de fora (alvo diferente do gateway): vira opção futura.
- **OPNsense/pfSense (dpinger)** — [Gateway Settings](https://doc.pfsense.org/index.php/Gateway_Settings):
  monitoramento contínuo com limites de perda e latência (200/500 ms), alarme e estado amarelo
  "delay". Ficou de fora (latência/perda como gatilho); o dpinger é um processo por gateway, aqui
  uma thread leva 1 000.
- **RFC 5880** §6.8.3 (antes de Up, no máximo 1 pacote/s: daí a carência de 5 s), §6.8.4 (tempo de
  detecção); **RFC 5881** (salto único, TTL 255); **RFC 5882** §3.2 e §4.3 (uso genérico: o cliente
  — aqui a rota estática — age na mudança para Down e não deve reagir a AdminDown como falha do
  caminho; o nosso motor já reporta isso ao cliente) e §3.3 (dampening de oscilação: o do perfil BFD
  mais o hold-down da rota).

**Adotado:** nomes e tempos do RouterOS; BFD como no Junos (perfil por rota, salto único);
espera para voltar como o `delay up` do Cisco, crescente. **Melhorias:** N rotas, 1 sonda;
histórico por gateway; tudo é comando (MCP vê `ip.route.check.list`); retirada de 10 000
gateways num apply. **Ficou para depois:** ND para gateway IPv6 e confirmação passiva pela tabela
de vizinhos (G1.27g); alvo diferente do gateway (VyOS); limites de latência/perda (dpinger).

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

## Detalhe da rota selecionada (`ip.route.detail`, G1.27b)

Com uma rota selecionada (uma linha ECMP vale pelo primeiro caminho), um painel abaixo da tabela
mostra `ip.route.detail {key}`:

- **Origem:** rota estática → a revisão e o comando que a criaram e os que a mudaram por último
  (`config.history`); DHCP → "DHCP client on ether1 (lease from 100.64.0.1)"; RA → a interface e a
  validade; conectada → o endereço que a gera e a revisão dele.
- **Escolha:** por que está em uso ("menor distância (1); a seguinte (10) assume se ela cair",
  "divide o tráfego com mais 1 caminho") ou o motivo de não estar, e as concorrentes ao mesmo
  prefixo como selos (com o motivo de cada uma no tooltip). Traduzida por id (`choice.<id>`,
  `route_detail::CHOICES`), como os motivos.
- **Check gateway:** método, intervalo, falhas seguidas, estado e há quanto tempo caiu. Hoje só nas
  rotas de lease DHCP; em rota estática é a gap G1.27f.
- **Trocas (24 h):** um anel por rota (até 64 trocas, as últimas 24 h) alimentado pelo tick do
  daemon: falha de link, failover, volta. As mesmas trocas vão para o log no tópico `route` (no
  máximo 16 por olhada, e uma linha "N more routes changed state" — uma porta com 10 000 rotas atrás
  não inunda o log). Some com o restart, como o Changed.
- **No kernel:** o que a config põe no plano de dados para esta rota (`expected`), o que o kernel
  tem para o mesmo prefixo (`present`), o que falta e o que está lá sem ser nosso (`extra`).
  Reaproveita o drift da G1.3 (`Hal::snapshot`, `drift::kernel_routes_of`); conectadas e RA dizem
  que é o kernel quem as faz.

O painel pede o detalhe junto com cada atualização da janela (um painel sem janela própria,
`ui/src/route_detail.rs`), só enquanto a janela Routes está aberta e há uma rota selecionada.

## Tabela cheia (`ip.route.page`, G1.27c)

Para uma tabela do tamanho de um BGP full table (~1 milhão de rotas), a janela não recebe mais a lista
inteira: pede `ip.route.page` com os filtros dela e recebe **uma página** (500 linhas), quantas linhas
casam (`total`) e as **contagens da tabela inteira** (`summary`: estados, famílias, por origem, por
tabela). O `ip.route.list` continua igual para quem quer tudo (CLI, MCP, um daemon antigo).

- **Busca por prefixo** (`prefix` + `match`), com os nomes do Junos e o `ip route show
  root|match|exact` do Linux: `exact`; `longer` (só os mais específicos); `orlonger` (ele e os mais
  específicos: "contido", o padrão para um prefixo); `covering` (os que o contêm: "contém", o padrão
  para um endereço — os candidatos de um lookup).
- **Agregação** (`aggregate`): as rotas mais longas que /16 (IPv6 /32) viram uma linha por /16 com
  quantas são e em que estado; um clique nela abre o /16 (busca `contido` daquele prefixo) e o `x`
  da busca volta para a vista agregada.
- **Páginas:** `offset`/`limit` (até 5000); a janela mostra "1–500 de 1 000 000" com `<` e `>`.
- **Sem varrer tudo a cada leitura:** o engine guarda as linhas calculadas (`RouteCache`) e só refaz
  quando muda algo de que elas dependem: a geração do candidato (`ConfigStore::generation`, nova a
  cada escrita), o que os clientes DHCP/DHCPv6 instalaram, o que o kernel aprendeu por RA, os links
  sem carrier e os check-gateway. As contagens vêm junto com as linhas. Uma rota de lease retida
  pelo check-gateway (o motivo diz "há N s") faz refazer sempre.
- **Na GUI:** as linhas da tabela são montadas uma vez por resposta (ou por filtro/grupo aberto), não
  por quadro (a lição da G1.25); os diálogos não releem a lista quando não há nenhum aberto.

Números (**medido**, release, 1 M de rotas): uma página com as linhas guardadas custa 4–12 ms
(primeira, última, com prefixo, só inativas, agregada); refazer as linhas, 0,79 s; o quadro da GUI
com a tabela aberta, 0,8 ms (antes: 4,47 s por quadro, recebendo e desenhando a lista inteira).
Detalhes em `docs/perf.md`.

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

**Parte b (detalhe):** o RouterOS mostra só `belongs-to` (texto da origem) e nenhum histórico por
rota; o Junos `show route X detail` traz `State`, `Inactive reason` e `Age` (há quanto tempo); o FRR
`show ip route X` traz "Known via static, distance 1, metric 0, best" e "Last update … ago"; o
Cisco, "Known via" e um bloco por caminho ECMP. Adotado: a origem com a revisão do journal (que só
o CoreRouter tem: tudo é comando), a escolha comparada com as concorrentes, as trocas das últimas
24 h (o FRR e o Junos só dão a idade da última) e a comparação com o kernel por rota.

**Parte c (escala):** o Junos busca por `exact | longer | orlonger` e conta com `show route
summary`; o FRR conta com `show ip route summary`; o Linux tem `ip route show root|match|exact`; o
WinBox carrega a tabela toda (lento com um full table, relato comum em fórum). Adotado: os modos do
Junos com nomes do operador na GUI (contido, contém, exato), a contagem por origem sempre à mão, a
agregação por /16 que abre sob demanda e a paginação no engine.

**Ficou para depois:** a janela Nexthops (`/routing nexthop`: estado por gateway, flaps); a vista
RIB × FIB do Junos/FRR (selecionada × instalada); regras de política (G1.27e); vizinhos ARP/ND para
o `incomplete` (G1.27d); avisos ao criar uma rota que esconde outra (RFC 4632) ou com distância 255.
