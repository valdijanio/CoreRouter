# Filas (Queues) — controle de banda genérico por alvo (G4.9)

O CoreRouter limita banda por **alvo** (endereço, prefixo ou interface), não só por sessão PPPoE:
a mesma máquina serve PPPoE, IPoE, clientes de DHCP e redes fixas. Decisão do usuário em
2026-10-26: "vai ser possível usar sem ser com PPPoE? como no DHCP server também?" → subsistema
genérico de filas.

| Peça | Onde | Gap |
|---|---|---|
| Modelo `/queue simple` e `/queue type` (nomes do RouterOS v7) | `crates/model/src/queue.rs` | G4.9a |
| Plano: filas fixas + dinâmicas, precedência, avisos | `crates/engine/src/queue.rs` | G4.9a |
| Comandos `queue.simple.*`, `queue.type.*`, `queue.per-ip.*` | `crates/engine/src/cmd/queue_*.rs` | G4.9a |
| `rate_limit` na rede do DHCP; `queue_type`/`download_mode` no perfil PPP | `model/src/dhcp_server.rs`, `model/src/ppp.rs` | G4.9a |
| Shaper de descida (EDT) e policer de subida sem corrida entre CPUs | `dataplane-ebpf(-common)`, `hal-linux` | G4.9b, G4.3cc |
| Entrega pelo kernel ao assinante (`bng0`) | `dataplane-ebpf`, `hal-linux`, daemon | G4.3ca |
| Janela Queues, campos do perfil PPP, colunas em Active Connections | `crates/ui` | G4.9c |
| Janela "Queue <nome>" (Traffic, Statistics, History), `queue.simple.stats`, histórico por fila | `engine/src/queue_live.rs`, `ui/src/queue_view.rs` | G4.9g |

## Como usar

```sh
C="corerouter-cli --connect 127.0.0.1:7979 run"
# Uma fila fixa: upload/download do ponto de vista do alvo.
$C queue.simple.add '{"name":"camera","target":"10.0.1.5","max_limit":"2M/4M"}'
# Rajada como no RouterOS: 8M enquanto a média dos últimos 16 s estiver abaixo de 3M.
$C queue.simple.set '{"id":"camera","burst_limit":"4M/8M","burst_threshold":"1500k/3M","burst_time":"16s"}'
# Cada IP de uma rede com o seu limite (duas filas pcq + uma simple queue).
$C queue.per-ip.add '{"target":"10.0.0.0/16","rate":"10M/20M","max_limit":"1G/2G"}'
# Cada cliente do DHCP de uma rede ganha uma fila dinâmica (não existe no RouterOS).
$C ip.dhcp-server.network.set '{"id":"192.168.88.0/24","rate_limit":"5M/20M"}'
# O perfil PPP escolhe o tipo da fila de descida e se ela é fila (shaper) ou descarte (policer).
$C ppp.profile.set '{"id":"plano-100M","rate_limit":"20M/100M","queue_type":"cake-default","download_mode":"shaper"}'
$C queue.simple.list '{"origin":"dynamic"}'
```

## Regras

- **Pares `upload/download`** do ponto de vista do alvo, como o RouterOS imprime (`max-limit=10M/20M`):
  upload é o tráfego que sai do alvo, download o que chega a ele. O `rate-limit` do PPP, do DHCP e do
  RADIUS (`Mikrotik-Rate-Limit`) é `rx/tx` do ponto de vista do roteador, que é a mesma ordem.
- **Primeira que casa vence** entre as filas fixas, como no RouterOS. Um alvo dentro do alvo de uma
  fila acima nunca casa: não é instalado e a fila ganha um aviso ("mova para cima"). Com essa regra
  a busca por prefixo mais longo do plano de dados dá a mesma resposta da varredura do RouterOS, sem
  o custo O(n) por pacote.
- **Dinâmica vence fixa no próprio endereço:** a fila de uma sessão PPPoE/IPoE, depois a do lease
  estático do DHCP, depois a da rede do DHCP. A fila fixa que perde um endereço e a dinâmica que o
  toma são avisadas (até 8 avisos por fila).
- **Endereço antes de interface:** um alvo de interface pega o que nenhum alvo de endereço pegou.
- **Filas dinâmicas** não se editam (`queue.simple.set` explica de onde vêm): o perfil PPP, o
  RADIUS (inclusive o CoA, que muda a taxa sem zerar a fila), o lease ou a rede do DHCP. Nomes como
  no RouterOS: `<pppoe-usuario>`, `dhcp-ds<host ou MAC>`.
- **`bucket-size`** (RouterOS v7): o balde de cada sentido é `bucket-size × taxa` (0,1 = 100 ms da
  taxa, o padrão). É o "burst ≈ RTT × taxa" do policer de subida.
- **`limit-at` e `priority`** ficam guardados (importação do MikroTik, G4.3n), mas uma fila sem
  filhas é moldada no `max-limit`: a hierarquia (`parent`, CIR, prioridade) é a G4.9e. O comando avisa.
- **Tipos** (`/queue type`): `pfifo`, `bfifo`, `pcq`, `fq-codel`, `cake`. Os do RouterOS existem
  sem entrada (`default`, `default-small`, `ethernet-default`, `pcq-upload-default`,
  `pcq-download-default`) mais `fq-codel-default` e `cake-default`, o padrão das filas dinâmicas
  (o RouterOS usa `default-small`, uma FIFO de 10 pacotes, curta para qualquer taxa acima de poucos
  Mbit/s). `red`, `sfq` e `codel` são recusados com a dica de usar `fq-codel`.
- **Per-IP** (`queue.per-ip.add`) é o PCQ do RouterOS: dois tipos `pcq` (classificados por origem na
  subida e por destino na descida, com `pcq-rate`) e uma simple queue sobre o prefixo. Tipos de mesma
  taxa são reaproveitados. IPv6: um sub-fluxo por /64 por padrão (`ipv6_mask`).

## Plano de dados (G4.9b, G4.3ca, G4.3cc)

Três programas tc no mesmo objeto do XDP (`crates/dataplane-ebpf`), que compartilham os mapas das
sessões:

| Programa | Onde | O que faz |
|---|---|---|
| `shape_egress` | saída de cada porta com alvo atrás (as das redes conectadas que têm alvos; todas, se um alvo só é alcançável por rota) e das portas de acesso PPPoE/IPoE | **Descida**: acha a sessão do destino (moldada) ou a fila (LPM por família, depois a interface), calcula o horário de saída (EDT) e grava `skb->tstamp`; o `fq` segura o pacote |
| `shape_ingress` | entrada das mesmas portas | **Subida** das filas: policer GCRA com burst do RouterOS (as sessões continuam no policer do XDP) |
| `bng_egress` | saída de `bng0` | **G4.3ca**: põe o cabeçalho PPPoE no que o kernel roteou para um assinante e redireciona para a porta de acesso |

- **Relógios sem corrida (G4.3cc).** O estado exato de um alvo é uma palavra de 64 bits — o
  "tempo teórico de chegada" do policer (GCRA, ITU-T I.371) ou o horário da próxima saída do EDT —,
  em ticks de 1/64 ns, movida por `cmpxchg` (BPF ISA v3). As fatias da janela de burst somam com
  adição atômica; o CoDel reivindica cada descarte com `cmpxchg` no horário do próximo. Quatro
  trocas perdidas seguidas descartam o pacote (contadas como `contended`), nunca um laço sem fim.
  Fixar o assinante numa CPU (cpumap) não foi preciso: com o `cmpxchg` o erro já é zero (abaixo).
- **Descarte antes de enfileirar.** O shaper sabe a espera exata que um pacote terá; `pfifo`/`bfifo`
  descartam acima do limite convertido em tempo, `fq-codel`/`cake` aplicam o CoDel (RFC 8289) nessa
  espera e marcam ECN (RFC 3168) só num pacote ECN-capaz (marcar um que não é viraria descarte com o
  relógio já cobrado: 43% da taxa entregue, **medido** e corrigido).
- **`fq` nas portas:** `mq` + um `fq` por fila de transmissão (ou `fq` na raiz), com limite por fluxo
  de 20 000 pacotes (o padrão de 100 cortaria a fila de um alvo rápido). Tirar o plano devolve a
  qdisc padrão da porta.
- **PCQ:** sub-fluxo por endereço mascarado num LRU (`Q_PCQ`); o relógio do sub-fluxo dá o "não
  antes de" do relógio da fila (o `max-limit` de todos juntos).
- **Sessões:** `download_mode=shaper` (padrão) liga `F_SHAPE_DOWN` na sessão: o XDP manda a descida
  ao kernel, que a roteia por `bng0` (PPPoE) ou direto para a porta (IPoE); a fila da sessão fica em
  `SUB_SHAPE`/`SUB_EDT`. O CoA troca a taxa e mantém o relógio.
- **Serviço `queue` do daemon:** a cada segundo, o plano do config e dos leases vai ao HAL quando
  muda, e os contadores voltam para `queue.simple.list` (taxa, fila em ms, descartes).

### Medido (VM do laboratório, 8 vCPUs, kernel 7.0, build de teste, 2026-10-26)

Precisão (`shaper_accuracy`, cada alvo oferecido a ≥ 11× a taxa, contado no receptor):

| alvos | taxa de cada | pior erro |
|---:|---:|---:|
| 1 | 344 Mbit/s | +0,66% |
| 100 | 6,6 Mbit/s | +0,67% |
| 10 000 | 10 kbit/s | +0,69% a +1,33% |

TCP a 50 Mbit/s com 20 ms de RTT (`tcp_shaper_vs_policer`, iperf3, 10 s; ping no mesmo alvo):

| caso | goodput | retransmissões | ping sob carga |
|---|---:|---:|---:|
| sem limite | 1585 Mbit/s | 0 | 20,1 ms |
| shaper fq-codel | 49,7 (sem GSO: 47,9) | 536 (sem GSO: **35**) | 62,0 ms (sem GSO: 35,1) |
| shaper pfifo 10 (`default-small`) | 49,4 | 1783 | 20,1 ms |
| policer, balde 0,1 s (G4.9) | 49,3 | 852 (sem GSO: 1663) | 20,1 ms |
| policer, balde 0,05 s (G4.3c) | 47,5 | 715 | 20,1 ms |

- O shaper com CoDel tem o goodput do policer com uma fração das retransmissões (47× menos sem
  GSO); o balde de 0,1 s devolve ao policer os ~4% que o de 0,05 s perdia.
- Com GSO/GRO ligados (o padrão do kernel) o roteador recebe super-pacotes de até 64 KB (10 ms a
  50 Mbit/s cada): o CoDel decide em pedaços grandes e a espera no alvo fica maior. CAKE separa o
  GSO por isso; aqui é a gap G4.9f.

Policer de um assinante com 1/4/8/16 remetentes, cada um preso a uma CPU (`policer_race_root`,
200 Mbit/s, o mesmo teste na `main` antes):

| remetentes | antes (G4.3c) | depois (GCRA + `cmpxchg`) |
|---:|---:|---:|
| 1 | −0,56% | −0,32% |
| 4 | **+4,87%** | −0,22% |
| 8 | **+14,87%** | −0,42% |
| 16 (em 8 CPUs) | **+14,97%** | −0,35% |

Custo por pacote da subida PPPoE (`pppoe_scale_100k_sessions`, `BPF_PROG_TEST_RUN`): 164–169 ns na
`main`, 172–176 ns agora (dentro da variação da rodada). EDT × HTB: `docs/architecture.md`, "Filas:
EDT × HTB".

## Laboratório em massa (G4.9d)

`cargo xtask bng-lab --root --only shaping --shaping <n>` sobe `n` sessões PPPoE pelo BNG Blaster
com o perfil `default`, manda fluxos a 2× o plano nos dois sentidos e mede a descida segurada
primeiro pelo policer do XDP (`download_mode=policer`) e depois pelo shaper (`shaper`, o padrão).
Acima de 100 sessões o plano encolhe (100/n de `1M/2M`) para o BNG Blaster oferecer os mesmos
~75 mil pacotes/s: um gerador só não manda os 750 mil de 1000 sessões a `1M/2M` (**medido**: saía
~40% do pedido). A etapa falha se a descida moldada sair de ±5% do plano; a do policer só é
medida.

**Medido** (VM, 8 vCPUs, kernel 7.0, BNG Blaster 1.0.1, release, pacotes de 1000 B, janela de
10 s, 2026-10-26):

| sessões | plano | shaper: descida/limite (mín–máx) | fila média (máx) | policer: descida/limite (mín–máx) | CPU shaper / policer |
|---:|---|---|---|---|---|
| 100 | 1M/2M | 1,002 (0,994–1,011) | 50 ms (109) | 1,000 (0,998–1,004) | 3,4% / 2,3% |
| 1 000 | 100k/200k | 1,015 (0,970–1,041) | 120 ms (212) | 0,987 (0,921–1,044) | 6,5% / 3,2% |
| 10 000 | 10k/20k | 1,023 (0,961–1,058) | 808 ms (1117) | 1,077 (0,997–1,145) | 8,3% / 4,6% |

A fila longa a 10k/20k não é defeito: um pacote de 1000 B leva 0,4 s a 20 kbit/s, e o alvo de
5 ms do CoDel não cabe abaixo de um pacote. O policer erra mais nas taxas baixas porque o balde
(0,1 s da taxa) tem dois ou três pacotes.

O laboratório achou a correção de #260: no modo padrão a descida saía sem limite (2× o plano),
porque o bit `ON_SESSIONS` só era escrito com o plano, antes das sessões.

## Uma fila ao vivo e o seu histórico (G4.9g)

Duplo clique numa fila da janela Queues (fixa, PPPoE, IPoE, lease ou rede do DHCP, PCQ) abre
**"Queue <nome>"** com as abas do WinBox:

- **General / Advanced**: o formulário de edição de uma fila fixa (os campos de sempre, em duas
  abas; **Keep History** em Advanced); numa fila dinâmica, os valores só para leitura.
- **Traffic**: download e upload a cada 1 s nos últimos 1, 5 ou 15 min, com o max-limit de cada
  lado tracejado; cartões com a taxa (% do limite), o atraso na fila (agora e p95 de 5 min) e
  descartes/s, com o selo **at limit** depois de 10 s seguidos acima de 95% do max-limit; pausa,
  CSV da janela e atalhos para o Torch e o Sniffer com o endereço do alvo.
- **Statistics**: por sentido, taxa, pacotes/s, bytes, pacotes, descartes (com a fração), espera
  agora e p95, tempo no limite, estado da rajada (pronta, em rajada com o tempo restante,
  esgotada) e a média contra o limiar; numa fila PCQ, os endereços ativos.
- **History**: hora, dia e semana do histórico (`system.graph.query` de `queue:<nome>`), com o p95.

Na lista, a coluna Rate ganha o selo **near limit** (ícone de medidor) quando um sentido está a 90%
do max-limit ou mais (`near_limit` em `queue.simple.list`), e o rodapé conta quantas.

```sh
C="corerouter-cli --connect 127.0.0.1:7979 run"
$C queue.simple.stats '{"id":"camera"}'            # uma fila: contadores, rajada, p95, no limite
$C queue.simple.graph '{"id":"<pppoe-ana>","graph":true}'   # guardar o histórico de uma dinâmica
$C system.graph.set '{"dynamic_queues":true}'      # ou de todas as dinâmicas (custa memória)
$C system.graph.query '{"series":"queue:camera","range":"day"}'
```

- **`queue.simple.stats`** acha uma fila e os seus contadores sem resolver o plano: o índice de
  nomes da lista (ou o id), o mapa de contadores por chave que o serviço `queue` enche a cada
  segundo e, numa sessão, o backend pelo id (`PppBackend::session`, O(1) no daemon). O que pede
  duas leituras (pacotes e descartes por segundo, média da rajada, tempo no limite, p95 da espera)
  vem de um anel de até 15 min **só das filas que alguém olha** (`QueueWatch`): cada chamada é uma
  amostra (no máximo uma por segundo), e uma fila sem chamada há 30 s sai; no máximo 64 ao mesmo
  tempo (a 65ª recebe "busy").
- **Rajada**: como no RouterOS, liberada enquanto a média no `burst-time` estiver abaixo do
  `burst-threshold` (0 = o max-limit). A média e o tempo restante — (limiar − média) × janela /
  (taxa − média) — são **estimados** das leituras de 1 s; o relógio exato fica no plano de dados
  (G4.9h).
- **Histórico**: uma série `queue:<nome>` (upload e download em bits/s, descartes/s, atraso da
  descida em ms) no `/tool graphing`, com as mesmas resoluções das interfaces. Guardam histórico
  as filas fixas com `graph` (padrão sim), as dinâmicas marcadas por nome (`queue_include`; o
  assinante que reconecta continua na mesma série) e todas as dinâmicas com `dynamic_queues`;
  `queues: false` desliga todas. O teto de memória dos gráficos vale para tudo: o que não cabe
  fica de fora, com uma linha no log e a contagem em `system.graph.print` (`refused_queues`).
- **No laboratório virtual** o shaper é simulado (`hal::queue::lab`): conta como se cada fila
  levasse tráfego (40–110% do max-limit, um ciclo de 2 min, rajada no começo de cada ciclo),
  para a janela e o histórico se mexerem; nada é moldado e a lista diz isso.

### Medido (G4.9g)

Notebook de desenvolvimento, build `bench` (release), 2026-10-26 (`cargo bench -p corerouter-engine
--bench queue_live`, `cargo bench -p corerouter-ui --bench frames`):

| | 10 000 filas | 100 000 filas |
|---|---:|---:|
| `queue.simple.stats` (a cada segundo, fila já resolvida) | 2,2 µs | 2,2 µs |
| primeira chamada (acha a fila) | 3,6 µs | 3,7 µs |
| primeira chamada depois de um `move` (ids fora de ordem) | 3,8 µs | 3,8 µs |

Histórico: **438 KiB por fila** (448 728 bytes, um ano de 4 valores); 10 000 filas marcadas
seriam **4,18 GiB**, acima do teto máximo (4 GiB) e do limite de 4096 séries: cabem 4087. Com o
teto padrão (64 MiB) cabem 136 filas. Um segundo de histórico (serviço `queue`, sob o lock da
sessão): 

| filas fixas (guardadas) | teto | antes | depois |
|---|---|---:|---:|
| 1 000 (1 000) | 4096 MiB | 387 µs | 105 µs |
| 4 000 (4 000) | 4096 MiB | 2,29 ms | 0,75 ms |
| 10 000 (136, 9 864 recusadas) | 64 MiB (padrão) | 1,83 ms | 0,41 ms |
| 10 000 (4 087, 5 913 recusadas) | 4096 MiB | 4,16 ms | 1,25 ms |

"Antes" é a primeira versão desta mesma parte, que alocava por fila a cada segundo (o conjunto
de nomes recusados, as chaves clonadas, um mapa de descartes); "depois", sem alocar por fila
(−68% a −77%).

Um quadro da UI (1400×900, `cargo bench -p corerouter-ui --bench frames`):

| | antes | depois |
|---|---:|---:|
| janela Queues sozinha | — | 0,10 ms |
| + "Queue <nome>" em Traffic (900 pontos, 15 min) | 2,21 ms | 0,20 ms |
| + "Queue <nome>" em Statistics | 2,17 ms | 0,18 ms |

O "antes" era o modal de lista montando o texto dos comandos (o registro inteiro) a cada quadro,
mesmo numa aba que não o mostra; nas abas ao vivo ele não é mais montado (−91%). As abas de
formulário (General/Advanced) continuam pagando ~2 ms por quadro, como todo modal de edição hoje.

## Pesquisa

Fontes abertas em 2026-10-26.

- **MikroTik RouterOS v7**: Queues (help.mikrotik.com/docs/spaces/ROS/pages/328088/Queues), a
  referência de `/queue simple` e `/queue type`
  (manual.mikrotik.com/docs/7.25/cli-reference/queue/simple/, …/queue/type/), HTB e `bucket-size`
  (help.mikrotik.com/docs/spaces/ROS/pages/137986076; apresentação do MUM EU 2017 sobre o balde =
  max-limit/10 antes do 6.35), DHCP server (manual.mikrotik.com/docs/7.25/network-management/dhcp/server:
  `rate-limit` só em lease estático, cria uma simple queue dinâmica `dhcp-ds<…>` com
  `insert-queue-before` e `parent-queue`; não vale para tráfego em FastTrack), PPP AAA
  (`Mikrotik-Rate-Limit`: `rx[/tx] [burst] [threshold] [time] [prio] [min]`, rx = upload do cliente).
  - simple queue: `target`, `max-limit`, `limit-at`, `burst-limit/threshold/time`, `bucket-size`,
    `priority` 1–8, `queue` (tipo de cada sentido), `parent`, `packet-marks`, `time`; ordem estrita
    (primeira que casa; um pacote da fila 1000 passa pelas 999 de cima);
  - burst: `burst-threshold` liga e desliga a rajada pela média sobre `burst-time` ("não é a duração
    da rajada"); o limiar deve ficar entre `limit-at` e `max-limit`;
  - tipos: `pfifo`/`bfifo`, `pcq` (`pcq-rate`, `pcq-classifier`, `pcq-limit` 50 KiB, `pcq-total-limit`
    2000 KiB, máscaras v4/v6, burst próprio), `fq-codel` (target 5 ms, interval 100 ms, limit 10240,
    ECN ligado), `cake` (rtt 100 ms, diffserv3, triple-isolate), `codel`, `red`, `sfq`;
  - dor de campo: uma simple queue por sessão PPP (uma CPU a 100% perto de 550 filas) e as filas
    dinâmicas nascendo como `default-small`.
- **Google, "An Internet-Wide Analysis of Traffic Policing"** (research.google/pubs/pub45411): fluxos
  policiados perdem ~6× mais pacotes e o goodput cai; o balde do policer devia ser da ordem de
  RTT × taxa. **Carousel** (pub46460): o lock do HTB por dispositivo custou 30% do TCP-RR com espera
  p99 de até 1 s; policers erraram a taxa alvo em até 10×; EDT (um horário de saída por pacote e uma
  fila temporal) escala sem lock.
- **Cilium bandwidth manager** (LPC 2020, "Replacing HTB with EDT and BPF"): `skb->tstamp` gravado
  no tc de saída e `fq` com MQ nas filas da placa; `edt.h` é sem lock e aproximado.
- **xdp-cpumap-tc / LibreQoS**: XDP espalha por assinante para uma CPU (cpumap), cada CPU tem a sua
  árvore HTB com folhas `fq_codel` ou `cake`, sem lock disputado; exige XPS desligado.
- **accel-ppp**: subida = policer por padrão, descida = `tbf`, `htb` ou `clsact`, folha `sfq` ou
  `fq_codel`, uma netdev por sessão.
- **Juniper MX (CoS hierárquico por assinante)**: taxa de shaping vinda do RADIUS por assinante,
  filas por assinante em hardware. **Cisco ASR 9000**: H-QoS por sessão com policy-map dinâmico.
- **eBPF**: `bpf_spin_lock` existe em XDP mas não permite chamar helpers com ele preso; atômicos
  (cmpxchg) desde o 5.12; `bpf_res_spin_lock` no 6.15; qdisc em BPF (`struct_ops`) no 6.16.
- **RFCs**: 8289 (CoDel: target 5 ms, interval 100 ms, controle por √count), 8290 (FQ-CoDel), 3168
  (ECN), 2697/2698 (srTCM/trTCM, policers de referência), 7567 (recomendações de AQM: preferir AQM a
  cauda; não policiar TCP sem necessidade).

O que adotamos:

- Nomes, pares `upload/download`, tipos, burst e `bucket-size` do RouterOS v7; PCQ como dois tipos e
  uma simple queue (o que uma importação do MikroTik produz, G4.3n).
- Primeira-que-casa do RouterOS, mas resolvida no commit (alvos sombreados não são instalados) para o
  plano de dados usar uma trie: O(log) por pacote em vez de O(n filas).
- Descida com shaper (fila), subida com policer de balde RTT × taxa (Google), como o accel-ppp.

Melhorias sobre o MikroTik:

- **Origem de cada fila à vista** (selo fixed / PPPoE / IPoE / DHCP lease / DHCP network) e os
  avisos de precedência e sombreamento no próprio comando, não depois na operação.
- **Dinâmica vence fixa no próprio endereço** de forma explícita (no RouterOS depende da posição
  `insert-queue-before` e dá surpresa).
- **`rate_limit` por rede do DHCP**: todo cliente de uma rede ganha a sua fila sem lease estático.
- **`fq-codel-default` como padrão das dinâmicas**, não uma FIFO de 10 pacotes.
- Tudo é comando: transação, Safe Mode, diff, rollback e MCP valem para as filas.

Fica de fora (gaps): a hierarquia `parent`/`limit-at`/`priority` (G4.9e), `packet-marks` e `time`
(dependem do mangle e do agendador), `dst` (fila só para um destino), tipos `red`/`sfq`/`codel`.

### Uma fila ao vivo (G4.9g)

- **RouterOS v7** ([Queues](https://help.mikrotik.com/docs/spaces/ROS/pages/328088/Queues),
  [Graphing](https://help.mikrotik.com/docs/spaces/ROS/pages/22773810/Graphing)): a janela de uma
  simple queue tem General, Advanced, Statistics (rate, packet rate, bytes, packets, dropped,
  queued bytes/packets por sentido) e Traffic (gráfico ao vivo); o histórico é do
  `/tool graphing queue add simple-queue=… store-on-disk=…`, uma regra por fila. A rajada:
  liberada enquanto a média no `burst-time` (medida em 16 fatias) estiver abaixo do
  `burst-threshold`. O WinBox não mostra o estado da rajada nem a espera na fila.
- **Outros:** pfSense/OPNsense (Status › Queues: pps, banda, descartes, tamanho da fila por fila
  ALTQ, ao vivo, sem histórico); Juniper (`show class-of-service interface … queue` com
  tail-drops e taxas por fila); Linux `tc -s qdisc` e o CAKE (backlog, drops e atraso de pico,
  médio e "sparse" por tin); UniFi (gráfico de tráfego por cliente). Ninguém junta o ao vivo de
  uma fila, a rajada e o histórico de assinante numa tela, nem trata o custo do histórico de
  10 mil filas.
- **Normas:** RFC 2697/2698 (balde de fichas, base do policer e da rajada), RFC 8289 (CoDel: o
  alvo de 5 ms que torna a espera na fila o número a olhar).
- **Adotado:** as abas e os contadores do WinBox; histórico opt-in por fila (fixas sim,
  dinâmicas não, marcação por nome); a consulta de uma fila só a 1 Hz com a janela aberta.
  **Melhorias:** estado e tempo restante da rajada, espera e p95, "no limite" sustentado, selo
  "near limit" na lista, atalhos Torch/Sniffer, CSV.

## Extras e riscos

- **Risco: fila fixa larga engolindo assinantes.** Resolvido pela precedência e avisado nos dois
  lados.
- **Risco: alvo sombreado sem efeito.** O RouterOS aceita calado; aqui o comando avisa e a fila
  aparece com o aviso na lista.
- **Risco: 100 mil sessões no plano.** O plano é linear: cada alvo dinâmico é testado contra as filas
  fixas por até 33 (IPv4) ou 129 (IPv6) consultas de hash, não contra cada fila (teste
  `big_plans_stay_linear`: 100 mil sessões × 1000 filas fixas). A lista pede ao serviço PPP só a
  página que mostra.

## Desempenho e paralelismo

- **Trabalho por item:** o plano custa O(filas fixas + dinâmicas), com uma consulta de hash por
  comprimento de prefixo por alvo dinâmico; nada cresce com o produto. **Medido** no teste
  `big_plans_stay_linear` (build de teste, Ryzen AI Max+ 395, 2026-10-26): 100 000 sessões contra
  1000 filas fixas em < 1 s em debug.
- **Threads:** o plano roda sob o lock da sessão, no comando ou no serviço `queue` (uma vez por
  mudança); não há trabalho por pacote no userspace.
- **Plano de dados (G4.9b):** O(1) por pacote (hash ou LPM, um `cmpxchg`), plano de 1 a 10 mil
  alvos. Escala com núcleos sem lock: cada CPU faz o seu pacote e só disputa a palavra do alvo; o
  `fq` é um por fila de transmissão (XPS). Medido com 16 remetentes num assinante: erro −0,35% e
  zero `contended` nos testes de vazão. O HTB por CPU foi medido e descartado (tabela em
  `docs/architecture.md`).
- **Aplicar:** 10 000 filas em ~0,9 s (escritas em mapa, **medido**) contra 7–9 s de HTB numa raiz
  e mais de 23 min com uma árvore HTB por CPU.
