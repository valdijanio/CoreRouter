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
  mudança); não há trabalho por pacote no userspace. O caminho quente é o plano de dados (G4.9b), que
  é por CPU e sem lock.
