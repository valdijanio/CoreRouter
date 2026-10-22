# Ferramentas de diagnóstico (Tools)

Status: G6.1 (tarefas), G6.2 (Ping, vários destinos, descoberta de MTU) , G6.3 (MTR) e G6.3b (nomes, ASN, privado/CGNAT e MPLS no MTR) feitos. Inspirado no `/tool ping` do RouterOS, com mais para ver: gráfico, perdas,
jitter, percentis, histograma, alertas e exportação.

## 1. Tarefas (G6.1)

Uma ferramenta não responde na hora: ela **inicia uma tarefa** no roteador e devolve o id; quem
pediu acompanha por consulta incremental. O mecanismo é genérico (traceroute, torch e
bandwidth-test entram nele depois).

| Comando | Faz |
|---|---|
| `tool.ping.start {…}` | inicia um ping → `{id, task_id, targets, columns}` |
| `tool.ping.mtu {…}` | inicia uma descoberta de MTU → `{id, task_id, columns}` |
| `tool.mtr.start {…}` | inicia um MTR → `{id, task_id, columns}` |
| `tool.task.poll {id, after_seq?, max?, text?}` | eventos com `seq > after_seq` (até 256), o resumo e o estado; com `text: true`, também `header`, `lines` e (ao terminar) `summary_lines` no formato do RouterOS |
| `tool.task.stop {id}` | pede a parada (a tarefa termina em ≤ ~100 ms) |
| `tool.task.list {}` | tarefas guardadas: id, tipo, título, estado, motivo, dono, idade |

Resposta do `poll`: `{id, kind, title, state: running|done|stopped|failed, done, reason,
summary, events: [{seq, …}], next_seq, more, lost}`. Repita com `after_seq = next_seq` até
`done: true` (`done` só fica verdadeiro depois de todos os eventos lidos; `more: true` = há mais
eventos já prontos, peça de novo sem esperar). `lost` conta eventos que saíram do buffer antes
de serem lidos — o `summary` nunca se perde.

Regras (todas do engine, `crates/engine/src/tasks.rs`):

- **Operacional, não config:** comandos `query`; não entram no journal, não geram revisão, nada
  é salvo. No G0.3 valem como **leitura** (grupo `read`).
- **Sem threads nem relógio no engine** (ele compila para wasm32): o app instala um `Runner`
  (`corerouter_control::ThreadRunner`, uma thread std por tarefa) com `Session::set_runner`. O
  daemon, a GUI nativa em lab e o CLI/MCP headless instalam; a GUI web em `?lab` não tem, e os
  comandos de ferramenta ficam desabilitados com o motivo (conecte a GUI a um daemon).
- **Nunca sob o lock da sessão:** o job recebe um `Prober` (`Send + Sync`) do `Hal` e escreve
  numa `TaskCell` própria (mutex só dela).
- **Limites:** até 8 tarefas rodando e 32 guardadas (as terminadas mais antigas saem primeiro);
  1024 eventos por tarefa (anel); `poll` devolve até 256.
- **Expiração** (pelo relógio da sessão, `Session::tick`): tarefa rodando que ninguém consulta
  há 60 s é parada (`abandoned`); tarefa terminada some 300 s depois da última consulta. Fechar
  a conexão **não** para a tarefa (um CLI pode iniciar numa conexão e consultar noutra); a GUI
  para as suas ao fechar a janela.
- **Cancelamento limpo:** `stop` liga uma flag; o job dorme em fatias de 50 ms e espera o socket
  em fatias de 100 ms, e termina com o resumo final (`state: stopped`). Pânico no job vira
  `failed` ("the task crashed"), nunca derruba o daemon.

## 2. Ping (G6.2)

`tool.ping.start` — parâmetros (o `params` do registro é o contrato):

| Parâmetro | Padrão | Notas |
|---|---|---|
| `address` | — | 1–16 destinos: IPv4, IPv6 ou nome DNS; string separada por vírgula ou lista |
| `count` | 0 | 0 = até parar |
| `interval_ms` | 1000 | 10–60000; um probe por destino por intervalo, sem esperar a resposta anterior (como o RouterOS) |
| `timeout_ms` | 1000 | 10–10000 |
| `size` | 56 | pacote IP inteiro, como o `size` do RouterOS (28 = IPv4 sem payload; IPv6 sobe para 48) |
| `ttl` | sistema (64) | 1–255 |
| `dscp` | 0 | 0–63 (vai no TOS / traffic class) |
| `do_not_fragment` | false | IPv4: DF ligado e nada fragmenta localmente |
| `src_address` | — | mesma família dos destinos literais |
| `interface` | — | `SO_BINDTODEVICE` (precisa de `CAP_NET_RAW`) |
| `routing_table` | main | VRF do G1.5: liga o socket ao device da VRF (ou à `interface`, que deve ser membro dela) |

Nomes são resolvidos na thread da tarefa; um nome que não resolve vira erro só daquele destino.

**Evento por resposta:** `{seq, target, host, address, icmp_seq, status, rtt_ms, size, ttl,
from?, detail?}` com `status` ∈ `ok`, `timeout`, `ttl-exceeded`, `unreachable` (`detail`:
"host unreachable", "administratively prohibited"…), `too-big` ("fragmentation needed (mtu
N)"), `error`. `from` aparece quando quem respondeu não é o destino (o roteador que reportou).

**Resumo** (`summary.targets[i]`, um por destino, contínuo): `sent`, `received`, `finished`,
`loss_pct`, contadores por status, `duplicates`, `min_ms`, `avg_ms`, `max_ms`, `stddev_ms`,
`jitter_ms`, `last_ms`, `p50_ms`, `p95_ms`, `p99_ms`, `histogram {bounds_ms, counts}`, `error`.

Definições (`crates/engine/src/tools/stats.rs`):

- **Perda** conta só probes terminados: um ainda em voo não é recebido nem perdido.
- **min/avg/max/desvio padrão** sobre todas as respostas desde o início (desvio populacional,
  método de Welford — sem guardar tudo).
- **Jitter:** estimador do RFC 3550 §6.4.1 aplicado a RTTs consecutivos:
  `J += (|D| − J) / 16`, `D` = diferença entre os RTTs de duas respostas seguidas (um timeout no
  meio não zera). É o mesmo número que um operador vê em ferramentas de VoIP.
- **Percentis** p50/p95/p99 por posto mais próximo (nearest rank) sobre as **últimas 4096**
  respostas (memória limitada num ping contínuo de dias).
- **Histograma:** limites fixos em ms `<1, 1–2, 2–5, 5–10, 10–20, 20–50, 50–100, 100–200,
  200–500, 500–1000, >1000`, sobre todas as respostas.

## 3. Vários destinos

Uma tarefa com N destinos (até 16): um socket por tarefa (dual-stack), números de sequência
de fio únicos na tarefa, `icmp_seq` próprio por destino e estatísticas por destino. A GUI desenha
uma linha por destino, cada um com sua cor.

## 4. Descoberta de MTU

`tool.ping.mtu {address, max_size? (1500), timeout_ms?, retries? (2), dscp?, src_address?,
interface?, routing_table?}` — busca binária com DF:

1. o menor tamanho (28 / 48) precisa responder, senão é "unreachable"/"no answer", não "MTU
   pequeno";
2. tenta `max_size`; se passa, é o MTU;
3. senão, busca binária entre o maior que passou e o menor que falhou; um "fragmentation
   needed" / "packet too big" que traz o MTU do próximo salto pula direto para ele; um probe
   perdido `retries` vezes conta como grande demais (é assim que um buraco negro de PMTU se
   parece).

Eventos por probe `{size, payload, status, rtt_ms?, mtu?}`; resumo `{address, mtu, payload,
smallest_failing, probes, state}` com `mtu` = maior pacote IP que passa (MTU do caminho) e
`payload` = `mtu − 28` (IPv4) / `− 48` (IPv6), o número do `ping -s` do Linux.

## 4.1 MTR (G6.3)

`tool.mtr.start {address, count? (rodadas, 0 = até parar), interval_ms? (1000, mín. 100),
timeout_ms? (1000), max_hops? (30, 1–64), size?, dscp?, src_address?, interface?,
routing_table?}` — traceroute contínuo, IPv4 e IPv6:

- cada rodada manda, de uma vez, um probe por TTL de 1 até o fim conhecido do caminho; o
  roteador do salto N responde "TTL exceeded", o destino responde o eco;
- quando o destino (ou um roteador com "unreachable") responde no salto N, as rodadas seguintes
  param em N e os saltos depois dele somem do resumo;
- cada salto tem as estatísticas do §2 (`loss_pct`, `last_ms`, `avg_ms`, `best_ms` = mínimo,
  `worst_ms` = máximo, `stddev_ms`, jitter, percentis) e até 4 endereços (`hosts`: caminhos com
  balanceamento respondem de vários); qualquer resposta do salto conta como recebida (como o
  `mtr`); `note` guarda "host unreachable" etc.;
- eventos por probe `{round, hop, address, rtt_ms, status}` (`ok`, `ttl-exceeded`,
  `unreachable`, `too-big`, `timeout`); resumo `{host, address, rounds, reached, max_hops, hops}`.

Perda que começa num salto e continua até o destino é um enlace com perda; perda num salto só
(o resto 0 %) é um roteador que limita respostas ICMP — a leitura é a mesma do `mtr`.

### 4.2 Nomes, ASN, privado/CGNAT e MPLS (G6.3b)

`tool.mtr.start` ganha `use_dns?` (padrão `true`, como o `mtr`; no RouterOS o `use-dns` do
`/tool traceroute` vem desligado) e `as_lookup?` (padrão `false`, como o `-z` do `mtr`: manda os
endereços dos saltos, via o DNS configurado, ao serviço público da Team Cymru). No terminal:
`/tool traceroute 8.8.8.8 use-dns=no as-lookup=yes`.

- **Nome (PTR).** O resolvedor do roteador (`/ip dns`, G4.1a) consulta
  `<endereço invertido>.in-addr.arpa` (RFC 1035 §3.5) ou `ip6.arpa` (RFC 3596 §2.5), com o mesmo
  cache. A consulta **não espera**: o prober responde `Pending`, o daemon faz a consulta em 4
  threads próprias (fila de até 256) e o MTR pergunta de novo na volta seguinte; o IP aparece
  na hora e o nome entra quando chega. Uma execução com `count` espera até 3 s no fim pelos
  nomes que faltam. Respostas (e falhas) ficam 5 min na fila do daemon; o cache do resolvedor
  segue o TTL.
- **ASN.** Duas consultas TXT: `<invertido>.origin.asn.cymru.com` (IPv6: `origin6`) →
  `"3356 | 4.0.0.0/9 | US | arin | …"` (com vários prefixos, o mais específico; com várias
  origens, a primeira) e `AS3356.asn.cymru.com` → nome curto (`LEVEL3`).
- **Privado/CGNAT.** `10/8`, `172.16/12`, `192.168/16` (RFC 1918) e `fc00::/7` (RFC 4193) são
  `private`; `100.64.0.0/10` (RFC 6598) é `cgnat`; `169.254/16`/`fe80::/10` `link-local`;
  loopback. Esses não são consultados: a RFC 6598 §4 diz que a reversa do espaço compartilhado
  "MUST NOT be forwarded to the global DNS", e a RFC 6303 §3 manda servir as zonas reversas
  privadas localmente.
- **MPLS.** O roteador que descarta o probe dentro de um LSP cita a pilha de rótulos que
  recebeu no objeto MPLS Label Stack (RFC 4950, classe 1, C-Type 1), dentro das extensões ICMP
  da RFC 4884. Codec puro em `crates/hal/src/icmp_ext.rs`: comprimento do datagrama original no
  octeto 5 (ICMPv4, palavras de 32 bits) ou 4 (ICMPv6, 64 bits), mínimo de 128 octetos, versão
  2, checksum certo ou zero (§7); sem comprimento, procura em 128 como manda o §5.5 para
  remetentes antigos (o `mtr` só faz isso). Só o **raw socket** vê os rótulos: o ping socket
  recebe pela fila de erros o nosso probe, não a mensagem do roteador.

Resumo por salto (do primeiro endereço): `name`, `asn`, `as_name`, `scope`, `mpls_text`
(`L=24017` ou `L=16005/24003`, topo primeiro) e `hosts_info: [{address, name, name_pending, asn,
as_name, as_prefix, scope, mpls: [{label, tc, bottom, ttl}], mpls_text}]`; o evento por probe
ganha `mpls`. O texto do terminal mostra `nome (IP) [private]`, a coluna `ASN` (`AS3356 LEVEL3`,
`AS???` sem resposta) e uma linha `MPLS L=… TC=… S=… TTL=…` por rótulo, como o `-e` do `mtr`.
A janela Tools › MTR tem as caixas **Use DNS** e **AS lookup**, o nome em cima e o IP embaixo
(menor), e as colunas ASN e MPLS quando há o que mostrar.

## 5. Quem envia os pacotes

O engine só fala com o trait `corerouter_hal::probe::Prober` (L1): `resolve`, `open` →
`ProbeSocket` (`send(Probe)`, `recv(wait)`). O RTT é medido pelo socket (do `sendto` ao
`recvmsg`), então o engine não precisa de relógio.

### 5.1 `hal-linux` (produção, `--backend linux`)

`crates/hal-linux/src/icmp.rs`, sem `unsafe` (socket2, nix, rustix). Por família, nesta ordem:

1. **ping socket** (`SOCK_DGRAM` + ICMP): sem privilégio, quando o grupo do processo está em
   `net.ipv4.ping_group_range` (por namespace; vale também para IPv6). O kernel escolhe o
   identificador e só entrega as nossas respostas; erros ICMP sobre os nossos probes (TTL
   exceeded, unreachable, frag needed) chegam pela fila de erros (`IP_RECVERR`), o TTL num
   control message.
2. **raw socket** (`SOCK_RAW`): precisa de `CAP_NET_RAW` (o daemon de produção tem); vê todo
   ICMP do host, então casa pelo identificador e pelo probe citado dentro dos erros ICMP.

DF via `IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER` (`DO`; sem DF, `DONT` no IPv4), TOS/traffic class,
`SO_BINDTODEVICE`, `bind` na origem. `recv` espera nas duas famílias de uma vez (`poll`).
Sem nenhum dos dois: o comando falha com a dica (`setcap cap_net_raw+ep corerouter-daemon` ou
`sysctl net.ipv4.ping_group_range="0 2147483647"`).

### 5.2 Lab virtual (`--backend virtual`, padrão)

`corerouter-daemon --lab-ping auto|host|sim` (padrão `auto`):

- `host`: a pilha de rede deste computador (o mesmo `HostProber`), para pingar alvos reais do
  lab — precisa de ping socket liberado ou `CAP_NET_RAW`; falha na partida se não houver.
- `sim`: a **rede simulada determinística** (`crates/hal/src/sim.rs`), roda em qualquer SO, em
  wasm e na CI, sem tocar a rede.
- `auto`: `host` quando permitido, senão `sim` (o log diz qual). Muitas distros vêm com
  `ping_group_range = "1 0"` (ping socket desligado): aí o lab sem root usa `sim`.

O resumo diz qual (`summary.prober`). Regras da rede simulada (primeira que casa):

| Destino | Comportamento |
|---|---|
| `127.0.0.0/8`, `::1` | loopback: 1 salto, ~0,03 ms |
| `192.0.2.0/24`, `2001:db8:2::/48` | "host unreachable" a partir do 3º salto |
| `198.51.100.0/24`, `2001:db8:51::/48` | túnel com MTU 1400 e perda de 25 % a partir do meio do caminho, 6 saltos, ~40 ms |
| `203.0.113.0/24`, `2001:db8:113::/48` | buraco negro: roteadores respondem, o host nunca |
| qualquer outro | 2–11 saltos, 2–81 ms, jitter de 10 %, MTU 1500 (por hash do endereço) |

Nomes resolvem para `198.18.0.0/15` (faixa de benchmark, RFC 2544), exceto `localhost`
(`127.0.0.1`, `::1`) e nomes sob `.invalid` (não encontrados). O enlace local do roteador
simulado tem MTU 1500 (DF maior falha localmente). Roteadores intermediários respondem TTL
exceeded (um em cada sete fica calado): o 1º salto de `10.0.0.x` (privado; IPv6 `fd00::1:x`), o
2º de `100.64.2.x` (CGNAT), os outros de `198.19.<salto>.x` (IPv6 `2001:db8:ffff::<salto>:x`).
Os públicos têm nome `ae…-<salto>.core….sim-transit.example` (um em cada cinco sem PTR), os
saltos 3–5 são AS64500 `SIM-ACCESS`, os seguintes AS64510 `SIM-TRANSIT` e os destinos AS64999
`SIM-DEST` (`host-a-b-c-d.sim-dest.example`); ASNs de uso privado (RFC 6996). Em caminhos de 5
saltos ou mais, do 3º ao antepenúltimo há rótulo MPLS, o do meio com dois.

A GUI nativa sem `--connect` (lab no processo) usa sempre a rede simulada.

## 6. Onde usar

- **GUI** — Tools › Ping (janela flutuante, maximizável, tema claro/escuro): abas General
  (endereços separados por vírgula, contagem, intervalo, tamanho, limites de alerta) e Advanced
  (TTL, DSCP, timeout, DF, origem, interface, tabela/VRF); Start (Enter) / Stop (Esc; com nada
  rodando, Esc fecha); gráfico de latência ao vivo por destino (cores, perdas marcadas com × em
  vermelho, linha tracejada no limite de latência); tabela de estatísticas com ALERTA quando
  perda % ou latência (média ou última) passam do limite; histograma por destino; últimas 200
  respostas; **Export CSV** (`target,host,address,seq,status,rtt_ms,size,ttl,from,detail`, até
  20 000 respostas: arquivo em `$COREROUTER_EXPORT_DIR`, `~/Downloads` ou o diretório atual na
  nativa, download no navegador); **Discover MTU** (primeiro endereço). Botões cinza com o motivo
  (G1.16). Fechar a janela para as tarefas dela.
- **GUI** — Tools › MTR: endereço, rodadas, intervalo, saltos máximos, origem, interface,
  tabela; Start (Enter) / Stop (Esc); tabela por salto ao vivo (Hop, Host, Loss %, Sent,
  Last, Avg, Best, Worst, StDev) com a perda colorida e uma barra da média relativa ao salto
  mais lento.
- **Terminal** (G0.8 + G6.5) — como no RouterOS: `ping 8.8.8.8`, `/ping 8.8.8.8`,
  `/tool ping 8.8.8.8 count=5 size=1400`, `/tool ping address=…`; `traceroute 8.8.8.8`,
  `/tool traceroute …` ou `mtr …` para o MTR; `/tool ping mtu 198.51.100.3`. Sem `count` roda
  até Ctrl+C (que chama `tool.task.stop` e mostra o resumo). Linha a linha `SEQ HOST SIZE TTL
  TIME STATUS` e no fim `sent=… received=… packet-loss=…% min-rtt=… avg-rtt=… max-rtt=…` — o
  engine renderiza (`tool.task.poll {text: true}` → `header`, `lines`, `summary_lines`) e o
  terminal só imprime.
- **CLI** — `corerouter-cli [--connect HOST:PORT] watch tool.ping.start
  '{"address":"8.8.8.8,1.1.1.1","count":4}'` imprime as linhas no formato do RouterOS
  (`engine::tools::text`) e o resumo por destino; `watch tool.mtr.start '{"address":"…"}'`
  termina com a tabela por salto; Ctrl+C para.
- **MCP** — tool `run_task {command, params, wait_secs?}`: inicia, junta os eventos até
  terminar ou `wait_secs` (padrão 10, máx. 60), para se ainda roda e devolve `summary` + últimos
  50 eventos. Para sessões longas: `run_command` com `tool.task.poll`/`tool.task.stop`.
- **Canal de controle / WebSocket** — são comandos comuns (`engine.execute`), então funcionam
  igual por TCP, TLS e WebSocket (GUI remota do G0.4).

## Histórico de revisão

- 2026-10-22 — versão inicial (G6.1 tarefas, G6.2 ping, vários destinos, MTU).
- 2026-10-22 — G6.3 (MTR).
- 2026-10-22 — G6.5: formas do RouterOS no terminal, `text` no `tool.task.poll`.
