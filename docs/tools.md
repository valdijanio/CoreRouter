# Ferramentas de diagnóstico (Tools)

Status: G6.1 (tarefas), G6.2 (Ping, vários destinos, descoberta de MTU) , G6.3 (MTR), G6.3b (nomes, ASN, privado/CGNAT e MPLS no MTR), G6.4a (Torch e Packet Sniffer), G6.4b (Bandwidth Test com o protocolo do iperf3) e G6.4c (traceroute de uma passada, UDP/TCP e Paris) feitos. Inspirado no `/tool ping` do RouterOS, com mais para ver: gráfico, perdas,
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

### 4.1b Traceroute, sondas UDP/TCP e Paris (G6.4c)

O traceroute é um **modo do MTR**, não uma janela nova (Tools › MTR, selos MTR | Traceroute):

- `tool.traceroute.start {address, probes? (3, 1–10), timeout_ms?, max_hops?, size? (60),
  dscp?, src_address?, interface?, routing_table?, use_dns?, as_lookup?, protocol?, port?,
  paris?}` — **uma passada**: `probes` sondas por salto (as de um salto saem a 50 ms uma da
  outra: roteadores limitam suas respostas ICMP), o RTT de cada uma em `rtts` por salto, e no
  terminal (`/tool traceroute 8.8.8.8 protocol=tcp port=443`) a tabela clássica do `traceroute`
  (`*` sem resposta, `!H`/`!N`/`!P`/`!F`/`!X`, nome, `[AS…]`, `<MPLS …>`). O resumo tem
  `mode: traceroute`.
- `tool.mtr.start` ganhou os mesmos `protocol`, `port` e `paris`.
- **`protocol`**: `icmp` (eco, padrão), `udp` (porta 33434; o destino responde "port
  unreachable") ou `tcp` (SYN para a porta, padrão 80; o destino responde SYN-ACK ou RST — passa
  por firewalls que descartam ICMP e UDP). Nenhum usa socket raw: os erros ICMP chegam pela fila
  de erros do socket (`IP_RECVERR`/`IPV6_RECVERR`, ip(7)), com o roteador que os mandou
  (`SO_EE_OFFENDER`). No TCP o handshake é completo e resetado na hora (`SO_LINGER` 0), como o
  `tcpconn` do `traceroute -T` e o `mtr --tcp`: o serviço do destino vê uma conexão aberta e
  fechada. Fim do caminho: `reached` e `note` = `port unreachable`, `syn-ack` ou `rst`.
- **`paris`** (padrão **ligado**; Augustin et al., "Avoiding traceroute anomalies with Paris
  traceroute", IMC 2006): toda sonda é o mesmo fluxo para um balanceador por fluxo — mesmas
  portas (UDP/TCP) e, no ICMP, o mesmo checksum (uma palavra da carga compensa a sequência:
  `seq + palavra = 0xFFFF` em complemento de um). Assim o traço segue **um** caminho ECMP real.
  Desligado (clássico), cada sonda é um fluxo: um salto atrás de ECMP mostra os roteadores
  alternando (selo `ECMP n` na janela). Paris sobre UDP e TCP manda **uma sonda por vez**: um
  roteador que cita só os 8 bytes da RFC 792 não deixa distinguir duas sondas do mesmo fluxo
  (no UDP Paris a sequência vai na carga, que roteadores RFC 1812 §4.3.2.3 citam); a passada
  fica mais lenta quando há saltos mudos (um timeout cada).
- Lab: na rede simulada, caminhos de 6 saltos ou mais têm um par ECMP no salto 3 (`sim.rs`).

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

### 4.3 DNS Lookup (G6.6)

`tool.dns.query {name, type?, server?, recursion?, dnssec?, tcp?, trace?, compare?, explain?,
as_client?}` — um `dig`
como tarefa (`tool.task.poll`/`stop`): a espera pela rede é numa thread do runner, nunca sob o
lock do `Session`. Terminal: `/tool dns-lookup example.com type=MX dnssec=yes` (ou
`dns-lookup …` de qualquer menu). Janela: Tools › DNS Lookup.

- `name`: um nome, ou um endereço (pergunta o PTR, como o `dig -x`). `type`: A (padrão), AAAA,
  ANY, CAA, CNAME, DNSKEY, DS, HTTPS, MX, NS, PTR, SOA, SRV, SSHFP, SVCB, TLSA, TXT (AXFR/IXFR
  não: transferência de zona não é consulta).
- `server`: vazio ou `router` (padrão) é o **próprio roteador**: a pergunta desce a cadeia do
  encaminhador da LAN (G4.1b: acl → limit → special → adlist → static → zones → cache →
  upstream) dentro do
  processo, como um cliente da LAN seria atendido, e a resposta diz a **etapa** que respondeu
  (`;; STAGE: cache`; na janela, o selo `from cache · etapa cache` ou `etapa upstream`). Um IP
  pergunta direto a ele (UDP; TCP com `tcp`, ou quando a resposta vem truncada, RFC 7766 §5).
  `https://…` (DoH, RFC 8484, id 0) e `tls://…` (DoT, RFC 7858) usam o cliente da G4.1d (o
  `verify_doh_cert` do servidor configurado vale). `all` é o mesmo que `compare`.
- `recursion` (padrão `true`) é o bit RD (`+norecurse` do `dig`); `dnssec` liga o DO (RFC 3225)
  com EDNS(0) de 1232 bytes. As assinaturas aparecem (RRSIG, DS e DNSKEY no formato da RFC
  4034), mas **não são validadas** (G4.1f): o flag `ad` é o que o servidor afirma.
- **Resposta** (evento `answer`): status (`NOERROR`, `NXDOMAIN`, `SERVFAIL`…), flags
  (`qr aa tc rd ra ad cd`), tempo, servidor e transporte, tamanho, EDNS e as seções Answer,
  Authority e Additional, um registro por linha (`name`, `ttl`, `class`, `type`, `data` no
  formato de apresentação, RFC 1035 §5.1). Os endereços ganham o AS de origem (eventos `asn`,
  a mesma consulta Team Cymru do MTR). O campo `dig` traz o texto no formato do `dig` (cabeçalho
  `;; ->>HEADER<<-`, `OPT PSEUDOSECTION`, seções, `Query time`, `SERVER`, `MSG SIZE`): é o que o
  terminal imprime e o que **Copy as dig** copia.
- **`compare`**: a mesma pergunta a todos os upstreams (`servers` e `use_doh_server`), em
  paralelo (o mais lento dita o tempo, não a soma). Cada servidor dá status, tempo e dados; o
  resumo marca `diverge` em quem respondeu diferente da maioria estrita (sem maioria, todos
  divergem) e `timeout` em quem não respondeu (3 s). Endereços comparam pelo **AS** de origem
  quando ele é conhecido: uma CDN entrega a cada resolvedor seus próprios servidores (mesmo AS)
  e isso não é divergência; um sinkhole (`0.0.0.0`) ou um sequestro para outra rede é.
- **`trace`**: da raiz até a resposta (RD desligado, DO ligado), uma linha por delegação: zona,
  servidor perguntado, tempo e resposta (`referral: com. (13 NS)` ou os registros). O selo
  `assinada` diz que veio um DS da zona filha (ou RRSIG na resposta final); sem eles, `sem
  assinatura`. Começa num servidor raiz escolhido pelo relógio (os 13 do `named.root`);
  servidores sem glue são resolvidos pelo resolvedor do roteador (IPv4 primeiro); até 3
  servidores por zona e 12 delegações; uma indicação que não chega mais perto do nome é
  recusada (laço).
- Texto vindo da rede sai só com ASCII imprimível (o resto como `\DDD`), limitado por campo e
  por seção (64 registros).

#### Why this answer e Ask as (G6.8)

- **`explain`** (só com o roteador como servidor): o evento `why`, um por etapa da cadeia (acl,
  limit, special, adlist, static, zones, cache, upstream), diz o que ela decidiu (`passed`,
  `answered`, `dropped` ou `not-reached`, quando uma etapa anterior já respondeu) e por quê,
  com a regra exata: a entrada static (id e `name=`/`regexp=`), a adlist e a **linha** que
  bloqueou (número e texto da linha como a lista tinha), o grupo de forwarders de um FWD, a
  zona, o servidor que respondeu, o `serve-stale` (RFC 8767) e o nome retido no cache de
  falhas (RFC 9520 §3.2, com os segundos que faltam). Campos: `stage`, `outcome`, `why` (id
  estável), `args`, `text` (inglês) e `rule` (`{kind: static|adlist|forwarders|zone, id|name}`).
  Terminal: uma linha `;; WHY <etapa> <decisão> <texto>` por etapa. Janela: a seção "Why this
  answer" abaixo da resposta, o texto no idioma das explicações (G0.15) e o botão **Open
  entry**/**Open list**/**Open group**/**Open zone** que abre a janela da regra com ela
  selecionada.
- **`as_client`** (só com o roteador): pergunta como se fosse um IP da LAN, sem pacote de
  verdade: a ACL `allowed_from`, o limite por cliente e as regras por origem veem esse endereço
  (`203.0.113.9 is not in allowed_from: REFUSED`). Não gasta ficha do limite, não conta nas
  estatísticas nem no `match-count` da adlist e não põe endereço em address list. Janela: campo
  **Ask as** (vazio = o próprio roteador); o selo do servidor mostra `router · as <IP>`.
- A adlist guarda, por nome, a linha de onde veio (4 bytes) e qual dos textos de linha da lista
  era (1 byte; até 255 textos distintos por lista, o que cobre `0.0.0.0 <nome>` e `||<nome>^`).
  Linha com texto próprio além disso (comentário por linha) mostra a regra refeita a partir do
  nome. São +5 bytes por nome (**medido**: 36,8 MB contra 31,8 MB para 1 milhão de nomes).
- A janela alarga com as tabelas (Answer, Authority, Additional, Compare, Trace) até a largura
  da área de trabalho, como a altura já crescia: o selo do AS sai inteiro (`AS8075
  MICROSOFT-CORP-MSN-AS-BLOCK`), e um valor só termina em "…" (com o todo no tooltip) quando não
  cabe nem assim.

#### Watch e Upstreams (G6.8)

- **`tool.dns.watch {name, type?, server?, interval_ms?, count?, tcp?}`** (`/tool dns-watch`,
  aba **Watch**), como o `dnsping` do dnsdiag: a mesma pergunta a cada `interval_ms` (100 a
  60 000, padrão 1000) até o Stop (ou Esc na janela), ou `count` consultas (no máximo 100 000).
  Cada consulta é um evento `watch` (hora UTC, latência, status, etapa do roteador, menor TTL e
  a resposta comparável: sem TTL e em ordem). `changed` quando a resposta difere da anterior;
  `spike` quando a latência passa de 3× a mediana até ali e de 20 ms a mais (depois de 5
  respostas). Janela: gráfico latência × tempo (picos em vermelho, mudanças em âmbar, perdas
  como ×) e a tabela, mais nova primeiro, com os selos `changed` e `spike`.
- **`tool.dns.upstreams {count?, hijack?}`** (`/tool dns-upstreams`, aba **Upstreams**), como
  o `dnseval` e o namebench: cada servidor que o roteador pode perguntar (`ip.dns servers`,
  `use_doh_server` e os servidores de cada grupo de forwarders, uma linha só por servidor com
  os grupos que o citam) recebe `count` consultas (padrão 200, 10 a 2000), alternando nomes
  populares (em cache no servidor) e nomes aleatórios abaixo deles (nunca em cache: mede a
  recursão do próprio servidor). Até 48 consultas em voo; um servidor que dá 6 timeouts
  seguidos antes de responder é dado como fora do ar e não é mais perguntado.
  - Por servidor: p50 e p99, perda, % de SERVFAIL, transporte (UDP, DoH, DoT), TCP (uma
    consulta por TCP: o caminho da resposta truncada, RFC 7766 §5) e EDNS (o buffer que o
    servidor oferece; sem OPT na resposta é a falha da RFC 8906 §8.2).
  - **Check hijack** (servidores sem cifra): dois nomes aleatórios `.com` que não existem; uma
    resposta no lugar de NXDOMAIN é `NXDOMAIN hijacked` (o teste do namebench). E quem chega aos
    autoritativos: `whoami.ds.akahelp.net` TXT (o par `"ns"` é o resolvedor; o `"ip"` é o
    endereço público deste roteador) e `o-o.myaddr.l.google.com` TXT. Se esse resolvedor é da
    **rede do próprio cliente** (o AS do IP público do roteador) e não da do servidor, é
    `proxy on the path` (Liu et al., USENIX Security 2018: a interceptação responde de dentro
    do provedor). Se é de outra rede que não a do cliente, vira só uma nota `other network`:
    o Quad9 sai por redes de parceiros (no lab: 9.9.9.9 por 200.25.72.0/24, AS7195). Servidor
    em endereço privado ou CGNAT é um encaminhador: a nota diz por onde ele sai.
  - **Recomendação** (`summary.recommend`): sai quem sequestra NXDOMAIN, é interceptado, nunca
    respondeu, perde ≥ 10% ou dá SERVFAIL em ≥ 10%; sai também quem tem p50 ≥ 3× (e 20 ms a
    mais) o melhor **do mesmo tipo** (DoH/DoT comparados entre si: pagam o handshake pela
    privacidade); dos que ficam, os dois mais rápidos (p50, depois p99) são os indicados.
    Notas: sem TCP, sem EDNS, outra rede, encaminhador. Cada item tem `why` (id) e `args`; a
    janela mostra o texto no idioma das explicações.

Codec em `crates/proto-dns/src/dig.rs` (sem sockets, compila em WASM); a tarefa em
`crates/engine/src/dns_lookup.rs`; o transporte no daemon em
`apps/corerouter-daemon/src/service/dns_lookup.rs` (`DnsBackend::exchange`).

### 4.4 Torch (G6.4a)

O `/tool torch` do RouterOS: o tráfego de uma interface ao vivo, **por fluxo**.

`tool.torch.start {interface, group?, src_address?, dst_address?, port?, protocol?, vlan_id?,
dscp?, mac_address?, sampling?, duration?, interval_ms?, top?, as_lookup?}` — tarefa como o
Ping (`tool.task.poll` / `tool.task.stop`); no terminal, `/tool torch ether1` ou `torch ether1`.

- **Agrupamento** (`group`): `src`, `dst`, `proto`, `port`, `vlan`, `dscp`, `mac` (padrão
  `src,dst`). Campo fora do agrupamento não separa linhas (o `0.0.0.0/0` do RouterOS). `vlan`
  inclui as interfaces VLAN da interface (cada quadro é contado uma vez, na VLAN dele).
- **Orientação:** cada linha é uma conversa vista da interface. `src` é o lado da interface (quem
  manda o que chega: num acesso, o assinante), `dst` o outro lado; **Rx** é o que chegou pela
  interface e **Tx** o que o roteador mandou por ela. O filtro usa a mesma orientação.
- **Por intervalo** (`interval_ms`, padrão 1 s, o *freeze-frame* do RouterOS) um evento com as
  `top` linhas mais pesadas (padrão 64; o resto soma em `others`), `total`, os **contadores da
  própria interface** (`kernel`) e quanto deles a captura leu (`seen_pct`). Taxas em bit/s e
  pacotes/s.
- **AS do destino** (`as_lookup`, padrão ligado): o mesmo do MTR (`Prober::origin_as`, Team
  Cymru ou a tabela BGP), sem esperar; privados e CGNAT ganham `dst_scope` e não são
  consultados.
- **Amostragem** (`sampling`): `auto` (padrão) lê tudo até **500 kpps**; acima, um em
  N = ⌈pps / 250 k⌉ (no máximo 4096), escolhido ao acaso **no kernel** (filtro BPF clássico,
  `SKF_AD_RANDOM`), e cada quadro lido conta N vezes; volta a ler tudo abaixo de 300 kpps
  (histerese; só troca N quando muda 2× ou mais). As linhas viram estimativas (`estimated`,
  aviso em `warnings`). `off` lê sempre tudo (avisa quando `seen_pct` < 90 %); `2..4096` fixa N.
- **Assinante:** a GUI pede `ip.identity.lookup` (G0.25) para as origens, quando o roteador tem o
  comando, e mostra o selo ao lado do endereço.

Captura: `corerouter_hal::capture::PacketCapture` (L1). `hal-linux` (`capture.rs`): um socket
`AF_PACKET` (`SOCK_RAW`, `ETH_P_ALL`) por dispositivo, preso a ele (endereço do `getifaddrs`), lido
por `recvmsg` com `MSG_TRUNC` (tamanho real no fio) em lotes de 1024, numa thread de tarefa, fora
do lock. O filtro BPF de cada socket faz a amostragem e, no pai de VLANs capturadas à parte,
descarta os quadros com tag (tirada pela NIC, `SKF_AD_VLAN_TAG_PRESENT`, ou no quadro). Sem
`unsafe`: nada de `TPACKET_V3` (anel em `mmap`) nem `PACKET_AUXDATA` (opção sem API segura); o
caminho rápido futuro é um backend XDP (G2.5) atrás do mesmo trait. O lab virtual tem
`SimCapture`: tráfego determinístico (assinantes CGNAT e privados, uma VLAN 100, um fluxo IPv6)
para os destinos da rede simulada (§5.2), com contadores próprios.

Números (**medido**, 2026-10-23, release, 32 CPUs, veth num namespace,
`hal-linux/benches/netns_capture.rs` e `engine/benches/torch.rs`): uma thread de captura lê até
**~2,0 Mpps** sem amostrar (100 % de um núcleo; com 8,3 Mpps oferecidos vê 25 %); com 1:8 no
kernel cobre 11,3 Mpps (100 % estimado) a 87 % de CPU, e com 1:64 cobre 12,8 Mpps a 35 %.
Agrupar custa 75–83 ns por quadro (12–14 milhões/s), então o socket domina. Com `auto`, 500 kpps
custam ~30 % de um núcleo e acima disso o custo fica em ~250 kpps lidos.

### 4.5 Packet Sniffer (G6.4a)

O `/tool sniffer` do RouterOS, limitado: grava os quadros de uma interface num **pcap** (formato
clássico da libpcap, `draft-ietf-opsawg-pcap`: magic `A1B2C3D4`, versão 2.4, LinkType 1
Ethernet, carimbo em µs) para abrir no Wireshark.

- `tool.sniffer.start {interface, src_address?, dst_address?, port?, protocol?, vlan_id?,
  mac_address?, snaplen?, file_limit?, duration?}` — o mesmo filtro do Torch; `snaplen` bytes de
  cada quadro (64–9216, padrão **128 = só cabeçalhos**); `file_limit` em KiB (1–65536, padrão
  4096); `duration` em s (1–3600, padrão 60). Termina sozinho no prazo ou no limite
  (`end: duration reached | file limit reached | stopped`); pacotes além do limite contam em
  `dropped_by_limit`.
- `tool.sniffer.download {id, offset?, length?}` — o arquivo em pedaços de até 4 MiB (base64),
  com `total` e `complete`; a GUI junta e salva como o CSV do Ping (`$COREROUTER_EXPORT_DIR`,
  `~/Downloads`; download no navegador).
- O arquivo fica **na memória** do roteador (o engine não tem disco: roda em wasm também) até a
  tarefa sumir (300 s depois da última consulta) ou outra captura precisar do lugar: no máximo
  **2 capturas** guardadas (≤ 128 MiB no pior caso).
- **Privacidade:** quadros inteiros são dados dos assinantes. `tool.sniffer.start` exige o grupo
  **write** (o Torch, só cabeçalhos agregados, fica em `read`); a GUI mostra o selo âmbar
  `payloads` quando `snaplen` > 128.

### 4.6 Bandwidth Test (G6.4b)

Teste de vazão com o **protocolo do iperf3**: o roteador testa contra qualquer `iperf3 -s` (3.x)
e responde a qualquer `iperf3 -c`. Não é o btest do MikroTik (formato proprietário, decisão G5 em
`docs/gaps.md`): um RouterOS não responde a ele, e ele não responde ao `/tool bandwidth-test` do
RouterOS.

**Cliente** — `tool.bandwidth-test.start {address, port?, protocol?, direction?, streams?,
duration?, bandwidth?, length?, dscp?, force?}` (tarefa; terminal `/tool bandwidth-test
198.51.100.7` ou `bandwidth-test …`):

| Parâmetro | Padrão | Notas |
|---|---|---|
| `address` | — | IP ou nome (DNS do roteador) de um servidor iperf3 |
| `port` | 5201 | a do iperf3; os streams de dados usam a mesma porta, TCP e UDP |
| `protocol` | `tcp` | `udp`: taxa fixa, mede perda e jitter (RFC 1889 §6.3.1) |
| `direction` | `send` | `receive` = `-R`; `both` = `--bidir`; `transmit` é sinônimo de `send` (RouterOS) |
| `streams` | 1 | 1–128 (`-P`) |
| `duration` | 10 | 1–300 s: **prazo máximo** do teste |
| `bandwidth` | TCP ilimitado, UDP `10M` | por stream, bit/s com k/M/G (×1000, como o `-b`) |
| `length` | TCP 128 KiB, UDP 1460 | bloco TCP / carga UDP |
| `force` | não | testar pela porta desta conexão fora do Safe Mode |

- **Risco (lotar um enlace):** a resposta traz `warning` ("fills the path with 1.2 Gbit/s for 8 s
  through ether1") e a interface de saída (`ip.route.lookup`); se ela carrega a conexão de quem
  pediu, o teste é **recusado** fora do Safe Mode (sem `force`) — encher o enlace de gerência é
  perder o acesso. A GUI pede confirmação antes de todo Start.
- **Eventos** por segundo: `tx_bps`, `rx_bps`, UDP `lost`/`packets`/`jitter_ms`, e `cpu` = a CPU
  do **roteador inteiro** (`/proc/stat`, todos os núcleos) — a pergunta é "o teste carregou o
  roteador?". **Resumo:** médias e picos, `samples` (o gráfico), `cpu_avg`/`cpu_max` e, no fim,
  `upload`/`download` com o que o **receptor** contou (no `send`, o número do servidor), perda %,
  jitter, retransmissões (quando o outro lado informa), `remote_cpu` e o relatório de texto do
  servidor (`get_server_output`).
- Sem daemon (lab no processo da GUI/CLI) o teste roda num backend **simulado** determinístico
  (940 Mbit/s; `198.51.100.0/24` com 25 % de perda no UDP), marcado `simulated`.

**Servidor** — `tool.bandwidth-server.set {enabled?, port?, allowed_addresses?, max_duration?,
max_streams?, max_rate?}` (config, journal e rollback) e `tool.bandwidth-server.get` (configuração
e `status`: `state` stopped/listening/testing/failed, `tests_served`, `refused`, o teste atual e o
último, `last_error`):

- **Desligado por padrão**; ligar exige `allowed_addresses` (`0.0.0.0/0`, `::/0` = qualquer um).
  Cliente fora da lista recebe o "servidor ocupado" do iperf3 (`ACCESS_DENIED`) antes de qualquer
  leitura e conta em `refused` (com linha no log).
- Um teste por vez (o próximo recebe "busy"); limites `max_duration` (padrão 60 s, até 3600),
  `max_streams` (8), `max_rate` (total do teste; com limite, TCP sem `-b` é recusado). Recusa
  com o código de erro do iperf3 (37 duração, 6 streams, 27 taxa), que o `iperf3 -c` imprime.
- Serviço `bandwidth-server` sob o supervisor (G0.10): System › Services mostra o estado e a
  porta; a cada segundo relê a config (porta nova religa, `enabled=no` fecha).
- Autenticação RSA do iperf3 (`--username`/`--rsa-public-key-path`) fica para a G6.11; a ACL e
  os limites cobrem o uso num ISP.

Implementação: protocolo puro em `crates/proto-iperf` (estados de um byte, cookie de 37 bytes,
JSON com tamanho em 4 bytes big-endian, parâmetros e resultados com os tipos que o iperf3 lê,
cabeçalho UDP de 32 ou 64 bits, perda e jitter; proptest); sockets no daemon
(`service/iperf.rs`: uma thread por stream, timeouts de 200 ms, ritmo por stream; UDP com buffer
de recepção de 4 MiB; `service/bandwidth_server.rs`). Especificação do protocolo, lida do código
do iperf3 3.22: nota de pesquisa da G6.4b.

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
- **GUI** — Tools › MTR: modo MTR ou Traceroute, endereço, rodadas (ou sondas por salto),
  protocolo, porta, Paris (ⓘ em cada um), intervalo, saltos máximos, origem, interface,
  tabela; Start (Enter) / Stop (Esc); tabela por salto ao vivo (Hop, Host, Loss %, Sent,
  Last, Avg, Best, Worst, StDev) com a perda colorida e uma barra da média relativa ao salto
  mais lento.
- **GUI** — Tools › Torch: interface, agrupamento em selos, filtro (origem, destino, porta,
  protocolo), amostragem; tabela ao vivo com a pílula do AS no destino, `CGNAT`/`privada` e o
  selo do assinante na origem, selos de amostragem e de cobertura (`seen`), totais e os
  contadores da interface embaixo; ⓘ em cada campo. Tools › Packet Sniffer: interface, filtro,
  bytes por quadro, limite e duração; barra do arquivo e **Download .pcap**.
- **GUI** — Tools › Bandwidth Test: aba Test (endereço, porta, protocolo, direção, streams,
  duração, taxa; confirmação antes do Start; gráfico Tx/Rx por segundo; selos da CPU do roteador
  e da remota; tabela por direção com média, pico, perda, jitter e retransmissões) e aba Server
  (estado, testes atendidos e recusados, último teste, formulário com ⓘ em cada campo).
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
