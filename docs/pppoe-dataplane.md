# PPPoE — plano de dados dos assinantes em XDP (G4.3c)

O BNG do CoreRouter (G4.3) é Rust puro (decisão do usuário em 2026-10-24, contra o accel-ppp).
Esta parte é o **plano de dados**: o tráfego dos assinantes não passa por `/dev/ppp` nem por uma
interface `pppN` por sessão. O mesmo programa XDP da G2.5 (`crates/dataplane-ebpf`) ganha um
estágio PPPoE na frente do filtro e outro depois do fast path do CGNAT. O plano de controle
(descoberta, LCP, PAP/CHAP, IPCP/IPV6CP, RA) é a G4.3a (`proto-pppoe`, userspace); a G4.3d
(serviço BNG do daemon) preenche os mapas daqui.

| Peça | Onde |
|---|---|
| Layout dos mapas, decisão de subida/descida, encapsulamento (`no_std`, sem `unsafe`) | `crates/dataplane-ebpf-common/src/pppoe.rs` |
| Policer por assinante, semântica de burst do RouterOS | `crates/dataplane-ebpf-common/src/policer.rs` |
| Mapas e estágios no kernel | `crates/dataplane-ebpf/src/main.rs` |
| Carregador: liga o PPPoE, põe e tira sessões, lê contadores | `crates/hal-linux/src/xdp_pppoe.rs` |
| Testes de host (proptest) | `crates/dataplane-ebpf-common/tests/pppoe_props.rs` |
| Testes com root (diferencial, tráfego, escala, policer, medições) | `crates/hal-linux/tests/xdp_root.rs` (`pppoe_*`) |

## Por que não `/dev/ppp` e uma interface por sessão

- O caminho do kernel (`pppoe` + `ppp_generic`) pede ioctls em `/dev/ppp` (`PPPIOCATTCHAN`,
  `PPPIOCCONNECT`, `PPPIOCNEWUNIT`), ou seja `unsafe`, proibido fora do `dataplane-ebpf`.
- É o gargalo conhecido no Linux: uma netdev e uma fila de transmissão por sessão (o accel-ppp
  documenta casos presos em ~1,9 Gbit/s), sem GRO para PPPoE (só um patch RFC em 2026) e shaping
  por sessão com HTB, que serializa num lock de qdisc.
- No MikroTik a dor de campo é a mesma: uma *simple queue* dinâmica por sessão (uma CPU a 100%
  por volta de 550 filas) e o PPPoE preso num núcleo.

## Caminho de um pacote

Um programa por porta (o XDP só aceita um), em estágios que são funções BPF separadas
(`#[inline(never)]`: cada uma tem a própria pilha de 512 bytes; inline, a pilha estourava):

1. **`up_stage`** (só com o PPPoE ligado). Quadro de sessão (0x8864, até duas tags VLAN):
   - RFC 2516 §4: VER/TYPE 1/1, CODE 0, LENGTH ≥ 2 e dentro do quadro. Errado: descarta
     (`malformed`).
   - Protocolo PPP (RFC 1661 §2): IPv4 (0x0021) e IPv6 (0x0057) seguem; 0x4000 em diante (LCP,
     PAP, CHAP, IPCP, IPV6CP, LQR…) vai **intacto** para o userspace (`XDP_PASS`, socket
     AF_PACKET da G4.3a); outro protocolo de dados também (o userspace responde LCP
     Protocol-Reject). Descoberta (0x8863) idem.
   - Sessão pela chave (porta, VLAN externa, VLAN interna, SESSION_ID, MAC do cliente). Sem
     sessão: descarta (`unknown-session`: SID forjado ou velho). Índice reaproveitado (os campos
     não batem com o quadro): idem.
   - MAC de destino diferente do MAC do BNG na sessão: não é nosso, segue para o kernel.
   - **Anti-spoofing**: IPv4 de origem tem de ser o do IPCP; IPv6 de origem dentro do /64 do RA ou
     do prefixo delegado; ou, nos dois, dentro de um bloco roteado à própria sessão (G4.3cd). Link-local (fe80::/10), `::` ou destino multicast (RS, NS, DAD, MLD) vai
     para o userspace, que é o "host" do enlace. Fora disso: descarta (`spoofed`).
   - **Policer de upload** (abaixo). Acima da taxa: descarta (`up-policed`).
   - **Decapsulação**: `bpf_xdp_adjust_head` tira as tags e o cabeçalho PPPoE; o quadro vira
     Ethernet sem tag com os mesmos MACs (o destino é o BNG, então o kernel o aceita como seu).
     Um deslocamento constante por número de tags (8, 12 ou 16 bytes): o verificador quer offsets
     conhecidos depois de mexer na cabeça.
2. **`filter_stage`**: o filtro da G2.5a (listas, taxa por origem, malformados) vale também para
   o tráfego dos assinantes, já decapsulado.
3. O **fast path do CGNAT** (G2.5b) no mesmo estágio: uma conexão que o conntrack já traduziu sai
   traduzida, inclusive a de um assinante PPPoE. No sentido de volta, se o destino traduzido é um
   assinante, `nat_to_subscriber` traduz e encapsula direto para a porta de acesso (a conexão foi
   aceita pelo kernel, então dispensa `F_FAST_DOWN`).
4. **`down_stage`**:
   - Pacote limpo (sem tag, ou com uma ou duas tags no uplink, G4.3cd) para um endereço de
     assinante (`PPPOE_V4` exato, `PPPOE_V6` LPM no /64 ou no prefixo delegado) ou para um bloco
     roteado a ele (`PPPOE_RT4`/`PPPOE_RT6`, LPM, só quando o primeiro falha): com `F_FAST_DOWN`, TTL > 1, tamanho ≤ MTU da
     sessão e dentro da taxa de download, desconta o TTL (checksum incremental, RFC 1624),
     `bpf_xdp_adjust_head` negativo, grava MACs, tags, PPPoE e protocolo e `bpf_redirect` para a
     porta de acesso. Vale também entre dois assinantes (hairpin). As tags do uplink saem só
     quando o pacote vai pelo XDP (`pppoe::untag`); o que vai ao kernel segue com elas.
     A decisão inteira é `pppoe::to_subscriber`, a mesma função no programa e no modelo de teste.
   - Pacote de um assinante com `F_FAST_UP`: `bpf_fib_lookup` (IPv4 ou IPv6), TTL − 1, MACs,
     `bpf_redirect`. Sem `F_FAST_UP` ou se a FIB não resolve: o kernel.

### Caminho lento (o kernel faz)

| Caso | Para onde | Motivo (contador) |
|---|---|---|
| Controle PPP, descoberta, IPv6 link-local/multicast | userspace, quadro intacto | `control`, `discovery`, `ipv6-control` |
| Subida sem `F_FAST_UP` (há firewall/fila no caminho de forward) | kernel, já decapsulado | `up-kernel` |
| Subida que a FIB não resolve (sem rota, sem vizinho, MTU) | kernel, decapsulado | `up-fib` |
| Descida com TTL ≤ 1 | kernel: ICMP time exceeded | `down-ttl` |
| Descida maior que o MTU da sessão | kernel: fragmenta ou manda ICMP "fragmentation needed"/"packet too big" (RFC 1191, RFC 8201) com o MTU da rota do assinante | `down-mtu` |
| Descida para sessão sem `F_FAST_DOWN` | kernel | `down-kernel` |
| Fragmentos IPv4, ICMP de erro, IP com opções no CGNAT | kernel (regras da G2.5b) | `NAT_MISS` |

Contadores da G4.3cd em `PPPOE_STATS`: `down-tagged` (descida vinda de um uplink com tag,
encapsulada no XDP; também conta em `down-fast`) e `down-routed` (descida para um bloco roteado,
qualquer que tenha sido o destino depois).

A entrega pelo kernel ao assinante (rota do assinante → encapsulamento num programa tc de saída,
uma interface `bng0` para todas as sessões, sem uma por sessão) e o shaping EDT são a parte
seguinte (G4.3ca). Até lá, o sentido de descida do caminho lento depende dela: o que a tabela
acima manda ao kernel no sentido de descida só chega ao assinante com a G4.3ca.

Por que as flags `F_FAST_UP`/`F_FAST_DOWN` existem: encaminhar no XDP pula o `forward` do
nftables e as filas. O daemon (G4.3d) as liga quando nada no caminho precisa ver o pacote (como o
fasttrack do RouterOS); o padrão é o kernel. Fluxos do CGNAT já aceitos pelo conntrack sempre
podem ir rápido.

## Mapas

`dataplane-ebpf-common::maps` tem a tabela completa. Tipos `#[repr(C)]` com codificação explícita
(`Session::to_words`, `SessionKey::to_bytes`): nem o daemon nem o carregador precisam de `unsafe
impl Pod`.

| Mapa | Tipo | Chave → valor | Tamanho com PPPoE ligado |
|---|---|---|---|
| `PPPOE_KEYS` | hash | `SessionKey` (16 B) → índice | 131 072 |
| `PPPOE_SESSIONS` | array | índice → `Session` (19 palavras) | 131 072 |
| `PPPOE_V4` | hash | IPv4 → índice | 131 072 |
| `PPPOE_V6` | LPM trie | /64 ou prefixo delegado → índice | 262 144 |
| `PPPOE_POLICER` | array | índice × 2 + sentido → estado (13 palavras) | 262 144 |
| `PPPOE_COUNTERS` | array | índice → 8 contadores | 131 072 |
| `PPPOE_STATS` | per-CPU array | `pppoe::Stat` → pacotes | 20 |
| `IPOE_PORTS` | hash | ifindex da porta de acesso IPoE → flags (G4.3f) | 256 |
| `PPPOE_RT4` | LPM trie | bloco IPv4 roteado a um assinante → índice (G4.3cd) | 65 536 |
| `PPPOE_RT6` | LPM trie | bloco IPv6 roteado a um assinante → índice (G4.3cd) | 65 536 |

- Os arrays são pré-alocados: ~64 MiB com PPPoE ligado (**estimado**). Desligado, o carregador
  os cria com 1 entrada; ligar ou desligar recarrega o objeto e as sessões conhecidas voltam
  (o carregador guarda o espelho).
- Ordem de escrita: na inclusão, sessão e policer primeiro, depois as chaves que apontam para
  ela; na remoção, as chaves primeiro, depois a sessão é zerada (`F_ACTIVE` desligado).
- `Session` espelha o descritor da G4.3a: MAC do cliente, SID, porta, VLAN externa e interna,
  TPID externo, MTU (MRU do cliente; 1492 por padrão, até 1500 com RFC 4638), MAC do BNG, IPv4,
  /64 IPv6, prefixo delegado, taxas de subida e descida. Os nomes finais se acertam com a G4.3a.
- Contadores por sessão (`PppoeCounters`): pacotes e bytes IP em cada sentido, descartes pelo
  policer em cada sentido, spoofing, enviados ao kernel. Somados com adição atômica BPF (exatos
  com várias CPUs), para os interims de accounting (RADIUS) e gráficos.

## IPoE nos mesmos mapas (G4.3f)

Um assinante IPoE (um lease DHCP que o serviço `ipoe` do daemon fez sessão) é mais uma entrada de
`PPPOE_SESSIONS`, com a flag `F_IPOE`, chaveada em `PPPOE_KEYS` pela porta e pelo MAC com
SESSION_ID 0 (a RFC 2516 §5 nunca dá id 0 a uma sessão PPPoE: as chaves não colidem) e em
`PPPOE_V4` pelo endereço. O carregador recusa IPoE com SID ≠ 0 ou com tag, e PPPoE com SID 0. O
`SETTINGS` da posição `pppoe::SETTINGS_SLOT` ganha o bit 1 (`ipoe::SETTINGS_BIT`), ligado quando há
porta em `IPOE_PORTS`; os mapas de sessão são dimensionados quando PPPoE **ou** IPoE está ligado.
O serviço IPoE aloca os índices do topo para baixo (`SESSIONS_MAX - 1`, …) e o PPPoE de baixo para
cima.

- **Subida**, numa porta de `IPOE_PORTS`, quadro IPv4 sem tag: DHCP para a porta 67 passa ao daemon
  (`ipoe-dhcp`); o MAC que o mapa não conhece segue como sem IPoE (o kernel decide); do MAC de uma
  sessão para o MAC do BNG, a origem tem de ser o endereço da sessão ou estar num bloco roteado a
  ela (G4.3cd) (amarração IP↔MAC, TR-146 R-38; senão `spoofed` e descarte), depois o policer e os contadores, e o quadro segue **intacto**
  (não há cabeçalho a tirar) para o filtro, o CGNAT rápido e o kernel.
- **Descida**: o mesmo policer e os contadores, e o kernel encaminha como sempre
  (`ipoe-down-kernel`): o firewall `forward` e o ARP do kernel continuam vendo o tráfego, e o caminho
  do kernel até o assinante existe (não há encapsulamento). Só o fluxo que o conntrack já aceitou
  (CGNAT rápido) sai pelo XDP, com os MACs reescritos (`ipoe::rewrite`).
- **Só quadros sem tag**: com VLAN por assinante ou por serviço, o programa vai na interface VLAN
  (o XDP genérico a vê sem a tag). IPv6 IPoE fica para depois (gap).

## Policer (taxa por assinante)

Semântica do `rate-limit` do RouterOS (`/ppp profile` e atributo `Mikrotik-Rate-Limit`):
`rx-rate[/tx-rate] [rx-burst-rate[/tx-burst-rate] [rx-burst-threshold[/tx-burst-threshold]
[rx-burst-time[/tx-burst-time]]]]`, rx = upload do cliente, tx = download, bits por segundo.

- Token bucket em bytes com profundidade de 50 ms da taxa (mínimo 3200 bytes, dois quadros).
- **Burst**: a média dos últimos `burst-time` fica em 16 fatias de `burst-time/16`. Enquanto a
  média está abaixo do `burst-threshold`, o balde enche na `burst-rate`; ao alcançá-lo, volta à
  taxa normal. Exemplo do próprio RouterOS (1M, burst 2M, limiar 1,5M, 8 s): 6 s a 2M, depois 1M;
  quando os segundos a 2M saem da janela a rajada volta, e a média de longo prazo fica no limiar
  (teste `routeros_burst_example`).
- Sem burst informado, sem limite de burst; limiar ausente = a taxa; tempo ausente = 1 s (como no
  RouterOS).
- O estado é compartilhado entre CPUs, sem lock: duas CPUs no mesmo assinante ao mesmo tempo podem
  perder ou ganhar uma ficha (taxa aproximada nessa corrida, nunca memória inválida). O
  `bpf_spin_lock` (mapa com BTF) fica para a G4.3cc se a medição numa placa real mostrar erro.

O policer é o primeiro passo. O shaping de descida com **EDT** (programa tc que grava
`skb->tstamp` por assinante, `fq` nas filas da porta de acesso, sem HTB por sessão, como o
bandwidth manager do Cilium) e a comparação EDT × HTB a 1k e 10k assinantes são a G4.3ca: o
`XDP_REDIRECT` não passa por qdisc, então o EDT só vale no caminho com `skb`.

## Pesquisa

Fontes (abertas em 2026-10-24):

- **MikroTik RouterOS v7**: o `rate-limit` do PPP profile e o `Mikrotik-Rate-Limit` do RADIUS
  (manual.mikrotik.com/docs/7.25/authentication-authorization-accounting/ppp-aaa) e o burst
  das filas (help.mikrotik.com/docs/spaces/ROS/pages/328088/Queues): `burst-threshold` liga e
  desliga a rajada pela média calculada sobre o `burst-time` ("não é a duração da rajada"). O
  servidor PPPoE (`/interface pppoe-server server`) cria uma interface dinâmica por sessão e a
  taxa vira uma simple queue dinâmica por sessão.
- **accel-ppp**: usa o `pppoe` do kernel com uma netdev `pppN` por sessão e shaper por interface
  (tbf/htb + policer de ingress): o modelo que o CoreRouter evita.
- **VPP, plugin pppoe**: o plano de dados em userspace (DPDK) guarda as sessões numa tabela com
  chave (interface, SESSION_ID, MAC do cliente), decapsula e encapsula sem interface por sessão e
  manda o controle para um "cp interface" — a mesma divisão daqui, em XDP em vez de DPDK.
- **Juniper MX / Cisco ASR 9000 (BNG)**: policers e HQoS por assinante em hardware, perfil
  dinâmico vindo do RADIUS, anti-spoofing de origem (uRPF por sessão), contadores por sessão para
  o accounting.
- **Cilium bandwidth manager** (LPC 2020, "Replacing HTB with EDT and BPF"; netdev 0x14 de Eric
  Dumazet sobre EDT e `fq`): o tempo de partida por pacote no `skb->tstamp` e `fq` por fila
  substituem a árvore HTB com lock global; não há benchmark independente EDT × HTB publicado,
  por isso a G4.3ca mede.
- **RFCs**: 2516 (PPPoE: tipos 0x8863/0x8864, cabeçalho VER/TYPE/CODE/SESSION_ID/LENGTH; sem
  errata técnica que mude o quadro de sessão), 4638 (PPP-Max-Payload: MRU acima de 1492 quando a
  rede aguenta 1508), 1661 §2 (faixas do campo de protocolo) e §6.1 (MRU), 5072 (IPv6 sobre PPP:
  identificador de interface pelo IPV6CP, endereços link-local no enlace), 1191 e 8201 (PMTU), 1624
  (checksum incremental, já usado na G2.5b).

O que adotamos: nomes e semântica de taxa e burst do RouterOS (o operador já os tem nos perfis e
no RADIUS); chave de sessão como a do VPP; o controle vai intacto ao userspace como no VPP;
anti-spoofing por sessão como Juniper/Cisco.

Melhorias sobre os outros:

- **Nenhuma interface por sessão**: escala com mapas (100 mil sessões medidas), sem a fila de
  transmissão e o lock de qdisc por sessão do Linux e sem a simple queue por sessão do RouterOS.
- **Anti-spoofing de origem por sessão** no XDP (IPv4 do IPCP, /64 e prefixo delegado), antes de
  o kernel alocar o pacote.
- **CGNAT rápido para assinantes PPPoE**: o fast path da G2.5b vale no sentido de subida e o de
  descida encapsula direto.
- **Diferencial kernel × host**: o mesmo código decide no kernel e nos testes, byte a byte,
  milhares de quadros.
- Contadores por motivo (`PPPOE_STATS`) e por sessão, prontos para RADIUS interim e gráficos.

Fica de fora (gaps novas, em `docs/changes/G4.3c.md`): entrega pelo kernel ao assinante e EDT
(G4.3ca), comparação com o PPPoE do kernel e medição em placa real (G4.3cb), lock no policer
(G4.3cc), uplink com VLAN e `Framed-Route` (G4.3cd).

## Testes

- `crates/dataplane-ebpf-common/tests/pppoe_props.rs` (host, proptest, 2000 casos por
  propriedade, 256 no policer):
  - ruído (sozinho ou depois de um cabeçalho válido) nunca dá panic, e uma sessão só é aceita
    se cabe no quadro;
  - ida e volta nos dois sentidos com 0, 1 e 2 tags, IPv4 e IPv6: a subida sai como o quadro IP
    que levava (mesmos MACs, checksums certos), a descida sai como quadro de sessão com SID, MACs,
    tags, LENGTH e TTL − 1 certos;
  - quadro cortado em qualquer ponto nunca segue como sessão; padding Ethernet não muda nada;
  - spoofing (origem, SID, MAC, porta, VLAN) descartado; link-local IPv6 para o userspace;
  - campo de protocolo pelas faixas da RFC 1661; caminho lento de descida (TTL, MTU, sessão
    lenta, fluxo aceito pelo conntrack);
  - o policer nunca passa do balde mais a taxa (de burst) e, sob carga, entrega ao menos a taxa.
- `crates/dataplane-ebpf-common/src/policer.rs`: o exemplo de burst do RouterOS, taxa exata.
- `crates/hal-linux/tests/xdp_root.rs` (root, `cargo xtask xdp-root`):
  - `pppoe_kernel_and_host_agree`: **diferencial** de 6000 quadros (subida, descida, hairpin,
    cortados, corrompidos, SID trocado, protocolo arbitrário, padding, ruído) pelo programa real
    (`BPF_PROG_TEST_RUN`) e pelo modelo do host, com as mesmas 300 sessões: ação e cada byte de
    saída iguais (rodada: 1177 descartados, 3334 passados, 1489 redirecionados);
  - `pppoe_traffic_both_ways`: tráfego real entre namespaces; um cliente fala PPPoE cru por
    AF_PACKET, um servidor UDP ecoa; sessão rápida nos dois sentidos pelo XDP, sessão lenta pelo
    kernel, descoberta para o userspace, SID forjado descartado, contadores por sessão;
  - `pppoe_scale_100k_sessions`: 100 000 sessões nos mapas, custo por pacote e cada sessão
    respondendo pelo próprio endereço (amostra de 5000);
  - `pppoe_policer_accuracy`: 1, 100 e 10 000 assinantes acima da taxa, ±5% exigido;
  - `perf_pppoe_forward`: kpps pelo roteador.
- `crates/hal-linux/src/xdp_pppoe.rs`: validação das sessões e o objeto com os mapas.

## Desempenho

**Medido** na máquina do usuário (AMD Ryzen AI Max+ 395, kernel 7.0.0-38, objeto release,
testes em build de teste, 2026-10-24).

Custo por pacote no kernel, `BPF_PROG_TEST_RUN` com uma execução por chamada (o test run com
`repeat` reaproveita o buffer sem reiniciá-lo, e um cabeçalho empurrado ficaria empurrado), média
de 20 000; o piso é o mesmo test run de um quadro que não é de ninguém, e inclui o custo fixo da
chamada, que o driver não tem:

| sessões nos mapas | piso (passa) | descida: encapsula + redirect | subida: decapsula para o kernel |
|---:|---:|---:|---:|
| 1 | 87 ns | 123 ns | 139 ns |
| 100 000 | 86–90 ns | 124–127 ns | 137–139 ns |

- O PPPoE custa ~36 ns na descida e ~50 ns na subida sobre o piso, **plano** de 1 a 100 mil
  sessões (hash e array: O(1)).
- Incluir 100 000 sessões: 527 ms (5,3 µs por sessão, sete chamadas de mapa cada); remover:
  414 ms.

Encaminhamento em veth (XDP generic), remetente AF_PACKET de quadros UDP de 64 bytes em 2 s,
contados ao chegar no namespace do outro lado (remetente e roteador dividem a CPU; uma comparação
de custos, não a taxa de uma placa):

| caminho | kpps entregues |
|---|---:|
| kernel encaminhando IPv4 puro, sem PPPoE (o piso do kernel) | 1410 |
| XDP: decapsula + FIB + redirect | 913 |
| XDP: decapsula, o kernel encaminha | 816 |
| PPPoE do kernel (`pppoe` + netdev ppp) | não medido: sem pppd/pppoe-server (G4.3cb) |

Em veth o XDP generic não ganha do kernel puro (o mesmo da G2.5: o veth já entrega um `skb`, e o
generic copia o quadro para ter headroom); o número que decide é o de uma placa em modo native
(G4.3cb), e o PPPoE do kernel ainda paga a netdev e a fila por sessão.

Policer no kernel, cada assinante com ao menos três vezes a própria taxa oferecida, 3 s, erro dos
bytes passados (descontado o primeiro balde) contra a taxa:

| assinantes | taxa de cada | enviados | pior erro |
|---:|---:|---:|---:|
| 1 | 1000 Mbit/s | 1598 kpps | −0,00% |
| 100 | 20 Mbit/s | 1515 kpps | −0,02% |
| 10 000 | 0,2 Mbit/s | 1476 kpps | −1,53% |

(Com 10 000 a 0,2 Mbit/s cada um passa ~73 pacotes de 1028 bytes em 3 s: o último pacote que não
coube já vale ~1,4%.)
