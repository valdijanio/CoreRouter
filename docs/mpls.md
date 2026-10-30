# MPLS e LDP (G3.5)

Comutação por rótulos no kernel do Linux e distribuição de rótulos pelo LDP (o `ldpd` do FRR), com
os nomes do RouterOS v7: `/mpls settings`, `/mpls interface`, `/mpls ldp`, `/mpls ldp interface`,
`/mpls ldp neighbor` e `/mpls forwarding-table`. Mais `/mpls static` (LSP estático, que o RouterOS
não tem).

## Como funciona

- **Plano de dados: o kernel** (`mpls_router`, `CONFIG_MPLS_ROUTING`). Ele troca rótulos e faz o
  PHP. O CoreRouter só programa e lê a tabela, em Rust, pelo próprio netlink
  (`crates/hal-linux/src/mpls.rs`):
  - lê com `RTM_GETROUTE`, família `AF_MPLS`;
  - grava os LSPs estáticos com `RTM_NEWROUTE`/`RTM_DELROUTE`, várias requisições por `sendmsg`;
  - ajusta `net.mpls.platform_labels`, `ip_ttl_propagate` e `conf/<if>/input`.

  O LDP não passa por aí: quem instala os rótulos dele é o zebra do FRR.
- **Detecção do módulo:** os comandos que adicionam ficam desabilitados com o motivo quando não
  existe `/proc/sys/net/mpls` (sem `mpls_router`), como o `ip.vrf.add` sem VRF.
  - A checagem só lê um arquivo. Nunca abre uma requisição `AF_MPLS`, então nada pede ao kernel
    para carregar o módulo.
  - A imagem do `os/` já tem `CONFIG_MPLS_ROUTING=y` e `CONFIG_MPLS_IPTUNNEL=y`, embutidos.
- **Plano de controle: o `ldpd` do FRR.** O `proto-mpls` gera o contexto `mpls ldp`, e o `hal-frr`
  aplica só a diferença (o mesmo caminho do BGP e do OSPF).
  - O RFC 5443 vai para dentro de `router ospf` (`mpls ldp-sync`, com `holddown` se configurado).
  - A faixa dinâmica, quando não é a padrão, vai ao zebra (`mpls label dynamic-block`, FRR 9.1+).
    Assim o LDP nunca entrega um rótulo que um LSP estático usa.
- **Estado:** a cada 2 s, o serviço `frr` lê do `ldpd` vizinhos, ligações e interfaces, e do
  `ospfd` o estado do sync. O serviço `mpls` lê a tabela do kernel e monta as linhas da Forwarding
  Table. Os dois trabalham fora do lock da sessão; o serviço `mpls` só lê enquanto a janela está
  aberta.

## Pesquisa

Fontes:

- **RouterOS v7.** O help.mikrotik.com congelou; a documentação atual está em
  manual.mikrotik.com:
  - <https://manual.mikrotik.com/docs/7.25/cli-reference/mpls/ldp/>, com as subpáginas
    `interface`, `neighbor`, `accept-filter`, `advertise-filter`, `local-mapping` e
    `remote-mapping`;
  - `/mpls/settings`, `/mpls/forwarding-table` e `/mpls/interface`;
  - <https://help.mikrotik.com/docs/display/ROS/MPLS+MTU%2C+Forwarding+and+Label+Bindings>.
- **FRR ldpd:** <https://docs.frrouting.org/en/latest/ldpd.html>; código em `ldpd/ldp.h`,
  `ldpd/ldp_vty_exec.c` (campos do JSON), `ospfd/ospf_ldp_sync.c`, `lib/ldp_sync.h` e
  `zebra/zebra_mpls.c`.
- **Cisco IOS-XE:**
  <https://www.cisco.com/en/US/docs/ios/mpls/configuration/guide/mp_ldp_igp_synch.html>.
- **Junos:**
  <https://juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/ldp-synchronization-edit-protocols-ospf-mp.html>.
- **Nokia SR OS:** <https://documentation.nokia.com/acg/24-7-2/books/mpls-classic/c134-ldp-igp-sync.html>.
- **RFCs:** a cadeia de atualizações e a errata vieram do rfc-editor.org (`rfcNNNN.json` e
  `/errata/`). Nenhuma delas está obsoleta.

  | RFC | Assunto | Atualizada por | Errata |
  |---|---|---|---|
  | 3031 | arquitetura MPLS | 6178, 6790 | 17 (8 editoriais verificadas) |
  | 3032 | codificação da pilha | 3270, 3443, 4182, 5129, 5332, 5462, 5586, 7274, 9017 | 4 (editoriais) |
  | 5036 | LDP | 6720, 6790, 7358, 7552 | 11 |
  | 5561 | capacidades do LDP | — | 0 |
  | 6720 | GTSM no LDP | 7552 | 0 |
  | 7552 | LDP sobre IPv6 | — (atualiza 5036 e 6720) | 0 |
  | 5443 | LDP-IGP sync | 6138, 10041 (set. 2026) | 1 (rejeitada) |
  | 8029 | LSP ping | 8611, 9041, **9570** | 6 (7639 técnica, verificada) |

  - Kernel: `Documentation/networking/mpls-sysctl.rst` e `net/mpls/af_mpls.c`.

### Como o MikroTik faz

- `/mpls ldp` é uma lista de instâncias com `afi`, `lsr-id`, `transport-addresses`,
  `preferred-afi`, `use-explicit-null`, `distribute-for-default`, `loop-detect`, `hop-limit`,
  `path-vector-limit` e `vrf`.
- `/mpls ldp interface`: hello-interval 5 s, hold-time 15 s, `accept-dynamic-neighbors`.
- `/mpls ldp neighbor`:
  - configurável: `transport` e `send-targeted`;
  - flags: D (dinâmico), O (operacional), T (em backoff de 120 s) e outras.
- `/mpls forwarding-table`: label, prefix e nexthops (`{label=impl-null; nh=…; interface=…}`).
- `/mpls settings`: `dynamic-label-range` 16-1048575, `propagate-ttl` sim.
- `/mpls interface`: `mpls-mtu` 1508, `input` sim.
- **Não documenta** LDP-IGP sync, GTSM, senha TCP MD5 nem LSP ping.

### Como os outros fazem

- **Cisco:**
  - `mpls ldp sync` no OSPF/IS-IS espera o LDP indefinidamente;
  - `mpls ldp igp sync holddown` limita a espera;
  - também têm `mpls ldp neighbor X password`, `session protection`, `mpls mtu`, e `ping/traceroute mpls ipv4`.
- **Junos:**
  - por padrão o LDP só anuncia o loopback (`egress-policy` amplia), um padrão mais seguro;
  - `ldp-synchronization { hold-time }` por interface do OSPF, infinito por padrão;
  - `ping mpls ldp`.
- **Nokia:**
  - `ldp-sync-timer` (1-1800 s) por interface, que termina cedo com End-of-LIB (RFC 5919);
  - há uma saída manual do sync;
  - `oam lsp-ping` / `lsp-trace`.
- **FRR:**
  - `mpls ldp-sync [holddown]` em `router ospf` (desligado por padrão, holddown 0 = espera
    infinita);
  - `ttl-security disable` por família: o GTSM vem ligado no IPv4, e no IPv6 é obrigatório;
  - `dual-stack transport-connection prefer ipv4` (o padrão é IPv6, RFC 7552).

### O que adotamos (entra agora)

- Os nomes e padrões do RouterOS v7, com uma instância só: o `ldpd` do FRR roda LDP apenas na
  tabela principal. Pedir uma segunda dá erro com o motivo.
- **LDP-IGP sync ligado por padrão** (RFC 5443). Sem `holddown`, espera o LDP o tempo que for, como
  FRR, Cisco e Junos; a RFC não define padrão.
- **GTSM ligado por padrão** (RFC 6720 §2.2: o LSR capaz anuncia a flag G). No IPv6 ele não
  desliga (RFC 7552 §9).
- **Senha TCP MD5 por vizinho** (RFC 5036 §2.9), selada na config como a chave do BGP.
- **Validação com a regra** (citada no erro):
  - hello ≥ hold é recusado (RFC 5036 §3.5.2.1);
  - LDP sobre IPv6 sem endereço de transporte global é recusado (RFC 7552 §6.1);
  - os rótulos 0-15 são reservados, e 3 nunca vai no fio (RFC 3032 §2.1);
  - no máximo 30 rótulos empilhados (o `MAX_NEW_LABELS` do Linux);
  - **um LSP estático dentro da faixa dinâmica é recusado.** O erro sugere a faixa livre, porque o
    LDP poderia entregar aquele mesmo rótulo.
- **Checagem de MTU** (RFC 3032 §3): 4 bytes por rótulo sobre o pacote IP (`payload_mtu`, 1500 por
  padrão).
  - Aparece num selo vermelho `MTU 1500 < 1504` nas interfaces LDP e nas linhas da tabela.
  - A prévia do modal também avisa.
- **Motivo de cada FEC sem rótulo:**
  - egress (a FEC é deste roteador);
  - sem rótulo local;
  - nenhum vizinho operacional;
  - nenhum vizinho anunciou;
  - o rótulo veio de quem não é o próximo salto do IGP;
  - ainda não está no kernel.
- **Rótulos em IP › Routes:** selo azul `MPLS 20` no gateway (o padrão do `docs/ui-style.md`).
- **LSPs estáticos** (`/mpls static`), da Cisco e do Junos.

### O que ficou de fora (vira gap)

- **LSP ping/traceroute** (G3.5b, feito: seção abaixo): RFC 8029, com a correção da RFC 9570, que proíbe o Router
  Alert. Precisa de um socket UDP 3503 com destino em 127/8, TTL 1 e a pilha de rótulos da FEC. A
  pilha sai por `RTA_ENCAP`/`MPLS_IPTUNNEL_DST` numa rota de host temporária ou por `AF_PACKET`.
  Também precisa do lado que responde. Fica para um PR próprio (~8 h, **estimado**).
- **VPLS/L2VPN** (RFC 4762, `/interface vpls`), **L3VPN** (RFC 4364), **SR-MPLS** (RFC 8665) e
  **fast path MPLS em XDP**: G3.5c a G3.5f.
- Filtros `accept-filter`/`advertise-filter` do RouterOS e a política "só loopbacks" do Junos:
  hoje o `ldpd` rotula todas as rotas do IGP. O Junos faz melhor aqui; fica na G3.5g.

## Teste com FRR real (VM do laboratório)

`cargo xtask vm-lab run -- scripts/frr-ldp-live.sh`: três LSRs em linha, R1 é o FRR da VM, que o
teste (`crates/hal-frr/tests/frr_ldp_live.rs`) configura pelo `hal-frr` (OSPF + LDP, a loopback
num template ponto a ponto passivo); R2 e R3 são instâncias do FRR (`zebra`, `ospfd`, `ldpd`) em
namespaces. Rodado em 2026-10-27 com o FRR 10.7.1, **medido**:

- o render é a forma canônica do FRR (um segundo sync não digita nada);
- sessão LDP com R2 operacional 6,0 s depois do commit;
- 10.255.0.3/32 (R3) sai do R1 com o rótulo do R2 (`encap mpls 17`); o R2 tira o rótulo (R3 pediu
  implicit null, RFC 3032 §2.1) e o ping passa pelo LSP 6,1 s depois do commit; o tcpdump no R2
  mostra `MPLS (label 17, …) IP 10.255.0.1 > 10.255.0.3`;
- sync LDP–IGP (RFC 5443) "achieved" no enlace 10,1 s depois do commit: o `ldpd` espera 10 s
  fixos depois da sessão para declarar a troca inicial completa, e até lá o `ospfd` anuncia o
  enlace com custo 65535. Com um caminho só, o tráfego passa assim mesmo.

Defeitos que a rodada achou e o mesmo PR corrigiu:

- **Loopback num template ponto a ponto passivo não era anunciada.** O `ospfd` toma um /32 numa
  interface point-to-point como enlace não numerado e não põe o stub no router-LSA; o R2 nunca
  aprendia o loopback do R1 e a sessão LDP (transporte no loopback) não subia. O render agora
  escreve `broadcast` para template passivo ponto a ponto (sem vizinho, o tipo só decide o que se
  anuncia).
- **"Sync not required: non-p2p link"** (loopback, enlace broadcast) virava "esperando" na
  Forwarding Table para sempre; agora a linha não aparece (o RFC 5443 não se aplica ali). O JSON do
  `show ip ospf mpls ldp-sync json`, que não tinha sido confirmado, é o que o parser lê.

## Desempenho e paralelismo

Medido em 2026-10-27, nesta máquina, build release, criterion.

| Caminho | Antes | Depois |
|---|---|---|
| Montar a Forwarding Table (100 mil rótulos, 10 mil FECs) | 38,9 ms | 22,5 ms (busca binária na tabela ordenada, sem mapa; menos alocação) |
| Página de 500 linhas sob o lock (`mpls_page/cached`) | 39 ms (montava a cada página) | **1,1 ms** |
| Busca numa página (`find`) | 25 ms (uma alocação por linha) | **0,48 ms** (texto de busca pronto) |
| Montagem das linhas com o texto de busca (`service_build`) | — | 47 ms **fora do lock**, no serviço, a cada 2 s com a janela aberta (~2 % de um núcleo) |

Trabalho por item:

- a página percorre todas as linhas (O(n), ~10 ns por linha) e só serializa as 500 da página;
- a montagem custa O(n log n) pela busca binária;
- a anotação de IP › Routes é O(ligações) + O(linhas da página).

Paralelismo:

- **Kernel:** a leitura é um dump só, que o kernel responde em ordem. Dividir pediria vários dumps
  da mesma tabela.
- **Montagem:** daria para dividir as linhas entre threads, mas 47 ms a cada 2 s não pagam um pool
  (o engine também roda em wasm, sem threads).
- **Programação de rótulos:** em lotes de 64 KiB por `sendmsg`, com os ACKs lidos depois. A
  alternativa é uma ida e volta por rótulo. Na VM do laboratório (kernel 7.0 com `mpls_router`,
  build release, 2026-10-27, `tests/netns_mpls.rs` com `MPLS_LABELS`), **medido**:

  | Rótulos | Em lote | Um a um | Dump (leitura) |
  |---|---|---|---|
  | 10 mil | 10,1 ms | 15,9 ms | 2,8 ms |
  | 100 mil | 98,4 ms | 159,4 ms | 33,7 ms |

  O lote é 1,6× mais rápido e o custo por rótulo é constante (~1 µs em lote, ~1,6 µs um a um): o
  trabalho é do kernel, não das idas e voltas. O dump de 100 mil cabe com folga no ciclo de 2 s da
  Forwarding Table. Paralelizar a escrita não ajuda: a tabela de rótulos do kernel é uma só, sob o
  RTNL.

## LSP ping e traceroute (G3.5b)

`tool.mpls.ping.start` e `tool.mpls.traceroute.start` (no terminal, `/tool lsp-ping 10.255.0.3` e
`/tool lsp-traceroute`), a janela **Tools › LSP Ping** (modos Ping e Traceroute; atalho "LSP Ping…"
no clique direito de uma FEC em MPLS › Forwarding Table) e o respondedor, serviço `lsp-ping` do
daemon. Como as outras ferramentas, cada comando abre uma tarefa (`tool.task.poll`).

### Como funciona

- **Envio** (`hal-linux/src/lsp/host.rs`): a rota da FEC (`RTM_GETROUTE` com `RTM_F_FIB_MATCH`)
  dá o próximo salto, a interface e os rótulos (`RTA_ENCAP`/`MPLS_IPTUNNEL_DST`). O quadro
  Ethernet inteiro sai por `AF_PACKET` para o MAC do próximo salto (tabela de vizinhos; sem
  entrada, um datagrama ao próximo salto faz o kernel resolver, até 300 ms):
  - pilha de rótulos com o TTL do topo em 255 (ping) ou 1, 2, 3… (traceroute), TC = EXP;
  - IP para 127.0.0.1 (IPv6: `::1`, RFC 9570 §4), TTL IP 1, **sem Router Alert** (RFC 9570 §4
    troca o "MUST" da RFC 8029 §4.3 por "MUST NOT");
  - UDP para 3503, da porta de um socket UDP do processo, por onde a resposta volta como IP
    comum. O socket carimba o TimeStamp Sent (NTP) e mede o RTT pelo número de sequência.
- **Traceroute** (`engine/src/tools/lsp.rs`): o pedido de TTL 1 leva o DDMAP do próprio ingress
  (próximo salto e rótulo); cada resposta "label switched" traz o DDMAP do salto seguinte, que vai
  no próximo pedido (§4.6). Assim cada LSR confere a interface e o rótulo que o anterior anunciou
  (código 5 numa divergência, com o Interface and Label Stack de quem recebeu). Termina no egress
  (3), no primeiro código de erro ou em `max_hops`. Sem resposta num salto, segue (como o Cisco).
- **Respondedor** (`hal/src/lsp/respond.rs`, sans-IO; E/S em `HostResponder`): em cada interface
  que aceita MPLS, três sockets `AF_PACKET` presos a um protocolo com filtro BPF clássico:
  - MPLS com TTL do topo ≤ 1 (o kernel descarta sem ICMP) ou explicit null;
  - IPv4 UDP 3503 para 127/8, sem fragmento (o kernel descarta como marciano; o tap vê antes);
  - IPv6 UDP 3503 para `::1` ou `::ffff:127/104`.

  A resposta (§4.5) sai de um socket UDP na porta 3503 com TTL 255, para a origem e a porta do
  pedido. A decisão segue §4.4 passo a passo: rótulo sem entrada no ILM → 11; entrada →
  8 com um DDMAP por próximo salto (MTU, endereço, rótulos de saída, `implicit-null` no PHP);
  DDMAP do pedido que não bate com a interface ou o rótulo recebidos → 5; FEC verificada (§4.4.1)
  → 4 sem rota, 10 quando o rótulo comuta para outro próximo salto que o da rota da FEC; sem
  rótulos → egress, 3 se a FEC é um endereço deste roteador, 4 se não. TLV obrigatório
  desconhecido → 2 com o Errored TLVs; malformado → 1. Não responde: reply mode 1, flag T com TTL
  > 1, pedido que não é request (evita laço entre respondedores), origem não unicast.
- **O que o LSR sabe** (`HostView`): a tabela de rótulos (um dump, guardado 1 s), endereços e MTUs
  (1 s) e a rota de cada FEC perguntada (1 s, 1024 no máximo). O kernel não guarda a ligação
  FEC→rótulo do LDP; a checagem do código 10 compara a entrada do rótulo com a rota da FEC, que o
  zebra instala a partir da mesma ligação.
- **Segurança** (RFC 8029 §5): limite de taxa por token bucket (`/mpls settings
  lsp-ping-rate`, padrão 100 respostas/s, rajada de 1 s) **antes** de qualquer trabalho; resposta
  nunca maior que 1500 bytes e só para a origem do pedido (não amplifica). O Pad TLV com "copy"
  só é copiado se o pedido coube nesse limite. `lsp-ping-responder=no` desliga. Contadores em
  `mpls.settings.get` (`lsp_ping_counters`).
- **Laboratório:** `hal/src/lsp/sim.rs` tem LSPs fixos (`10.255.0.2`–`10.255.0.6`, um LSP
  quebrado em `10.255.9.9` com código 11 no salto 2, um rótulo de outra FEC em `10.255.8.8` com
  código 10), cada salto respondido pelo mesmo `respond()`.

### Pesquisa

- **RFC 8029** (obsoleta a 4379), §2–§5 inteiras, com as que a atualizam:
  - **RFC 9570**: Router Alert proibido no pedido (§4), reply mode 3 depreciado (§2.2: aqui é
    respondido como o 2), destino IPv6 `::1` (§4);
  - **RFC 8611** (LAG/multipath em L2): fica de fora (gap abaixo);
  - **RFC 9041**: só os registros da IANA, sem efeito no código.
  - **Errata:** 7639 (verificada, técnica: o texto do reply mode 3 vale para IPv4 e IPv6) e
    **8788** (retida para atualização, técnica: no DDMAP IPv6 não numerado a interface é um
    índice de 4 octetos, não 16; implementado assim e testado).
- **MikroTik RouterOS v7:** não tem LSP ping. O `/tool traceroute` só mostra os rótulos que os
  roteadores põem nos erros ICMP (RFC 4950), o que o nosso MTR já faz (G6.3b).
- **Cisco IOS-XE:** `ping mpls ipv4 <fec>/32 [repeat] [size] [exp] [ttl] [reply mode]` e
  `traceroute mpls ipv4`; as letras de retorno (`!` `L` `.` `N` `F` `f` `D` `M` `m`…) são o padrão
  que os operadores conhecem: adotadas como selos na janela e no texto do terminal.
- **Junos:** `ping mpls ldp <fec>` / `traceroute mpls ldp`, contagem padrão 5 (adotada).
- **Nokia SR OS:** `oam lsp-ping` / `lsp-trace`, com o "downstream mapping" detalhado por salto.

**Adotado agora:** os nomes `tool.mpls.*` (o RouterOS não tem), FEC LDP e genérica (LSP
estático), V ligado por padrão (acha rótulo vazando para o LSP errado), DDMAP em todo traceroute
com o pedido do Interface and Label Stack (mostra com que rótulo o pedido chegou numa
divergência), letra + texto do código, caminho de saída na janela (selos `MPLS n`, ECMP avisado),
respondedor ligado por padrão com limite de taxa.

**Ficou de fora** (gaps abaixo): multipath/ECMP (§3.4.1.1 e RFC 8611), FECs de VPN/RSVP/PW,
lista de origens aceitas (§5 "RECOMMENDED"), teste ponta a ponta com dois daemons.

### Desempenho e paralelismo

- **Por pedido** (release, criterion, esta máquina, 2026-10-28, **medido**): codificar com DDMAP
  117 ns, ler 104 ns, resposta de trânsito completa com 100 mil rótulos e FECs 363 ns
  (`cargo bench -p corerouter-hal --bench lsp_echo`). Busca no ILM e nas FECs é O(log n) num
  `BTreeMap`; o custo que cresce com o total é o dump da tabela de rótulos, no máximo uma vez por
  segundo e só quando chega pedido.
- **Thread:** o respondedor roda na thread nomeada do supervisor (serviço `lsp-ping`); o lock da
  sessão só para ler o plano (a cada 2 s) e publicar os contadores (1 s). Uma thread basta: a
  100 respostas/s são ~36 µs de CPU por segundo; dividir por núcleo só dividiria o limite de taxa.
  O envio roda na thread da tarefa, fora do lock, uma por tarefa.
- **Custo no caminho de dados:** o filtro BPF roda no kernel para cada quadro MPLS e IP recebido
  nas interfaces MPLS (uns 10 instruções, **estimado** < 20 ns por pacote, sem cópia para quem
  não casa). Sockets por protocolo não são chamados nos pacotes enviados (o `ETH_P_ALL` seria, com
  um clone cada).
- **Latência adicional contra o ICMP comum:** veth no namespace de teste, 9,2 µs de ida e volta
  com o respondedor em espaço de usuário (build debug, **medido**, `tests/netns_lsp.rs`). Na VM do
  laboratório (2026-10-28, build debug, **medido**, `scripts/lsp-ping-live.sh`), lsp1 → lsp3 por
  dois saltos com os rótulos do ldpd do FRR:

  | Caminho | mín. | mediana / média | p95 | máx. |
  |---|---|---|---|---|
  | ICMP do kernel (`ping`, 200 pacotes) | 11 µs | 17 µs (média) | — | 39 µs |
  | LSP ping (200 pedidos, respondedor do CoreRouter em lsp3) | 69 µs | 90 µs (mediana) | 590 µs | 4,0 ms |

  O custo a mais (~70 µs) é o do respondedor em espaço de usuário (cópia do tap, `poll`, resposta
  por socket UDP), contra o echo do kernel, e o build debug. Para um teste de LSP não pesa; a
  cauda de 4 ms é o escalonamento da VM.

### Teste real (VM)

`flock vm/root.lock cargo xtask vm-lab run -- scripts/lsp-ping-live.sh`: três namespaces, cada um com
zebra + ospfd + ldpd do FRR 10.7.1 e MPLS do kernel. O ldpd distribuiu os rótulos (lsp1 empilha 17
para 10.255.0.3, lsp2 retira: PHP). Resultado (`tests/lsp_live.rs`, **medido**): 200 de 200 pings
com código 3 do egress; traceroute com o salto 1 (lsp2) "label switched" e `implicit-null`
abaixo, salto 2 (lsp3) egress; rótulo desconhecido com TTL 1 → código 11 em lsp2. O `netns_lsp`
com `mpls_router` também passou na VM (TTL que expira no LSR de trânsito, código 10 quando o rótulo
é de outro mapeamento).

## ICMP de TTL vencido em pacote rotulado (G3.9d)

O MPLS do kernel Linux descarta em silêncio o pacote rotulado cujo TTL do topo chega a 0 ou 1
(`net/mpls/af_mpls.c`, `mpls_forward`: `if (dec.ttl <= 1) goto err`, só conta `rx_errors`): não há
`icmp_send` no arquivo nem sysctl que ligue o erro, até o `master` de 2026. Um traceroute através
do LSP mostrava `*` no salto do CoreRouter. Agora o próprio respondedor do LSP ping manda o erro.

### Como funciona

- **Captura:** os taps do respondedor (G3.5b, acima) já copiam os quadros MPLS com TTL do topo
  ≤ 1 (filtro BPF clássico no kernel). O que não é MPLS echo request (UDP 3503 para 127/8 ou
  `::1`) vira um "expirado" (`hal/src/lsp/expired.rs`, sans-IO; `classify` em `hal-linux`).
- **O erro** (RFC 3032 §2.3.1; RFC 792 / RFC 4443 §3.3): ICMP tipo 11 / ICMPv6 tipo 3, código
  0, citando os primeiros 128 octetos do pacote IP sob a pilha (completados com zeros, RFC 4884
  §4) e a estrutura de extensão com o objeto da pilha de rótulos **como chegou** (RFC 4950: o
  traceroute do RouterOS mostra `MPLS:L=…`, o `traceroute -e` do Linux `<MPLS:L=…,E=…,S=…,T=…>`).
  Sai de um endereço da interface de entrada (global antes de link-local), IP TTL 255, DSCP CS6
  como os erros do próprio Linux.
- **Não manda** (RFC 1812 §4.3.2.7, RFC 4443 §2.4(e)): erro sobre erro ICMP, fragmento que não é
  o primeiro, destino multicast/broadcast, origem que não é unicast.
- **Como volta** (RFC 3032 §2.3.2, o padrão do Cisco):
  - **um rótulo** e rota IP até a origem: pela tabela IP (socket `IPPROTO_RAW`);
  - **mais rótulos** (VPN), ou um rótulo sem rota de volta (núcleo sem BGP): **pelo próprio LSP**:
    a pilha copiada, o rótulo do topo trocado como a tabela de rótulos manda, todos os TTL em
    255, num quadro inteiro ao MAC do próximo salto. O egress roteia o erro até a origem. Assim
    um endereço de cliente que coincide com um do núcleo nunca recebe o erro de outro.
- **Configuração:** `/mpls settings icmp-ttl-exceeded` (padrão ligado, como RouterOS, Cisco e
  Junos) e `icmp-rate` (padrão 100 erros/s, até 10 000); contadores em `mpls.settings.get`
  (`icmp_counters`: expirados ouvidos, enviados, descartados pela taxa e por motivo). Janela
  **MPLS › Settings**. O serviço `lsp-ping` escuta enquanto uma das duas funções está ligada.

### Pesquisa

- **Kernel:** `af_mpls.c` do `master` e do 7.0 desta máquina: descarte sem ICMP; sysctls só
  `platform_labels`, `ip_ttl_propagate`, `default_ttl`, `conf.<if>.input`. Nenhuma versão gera o
  erro.
- **RFC 3032** §2.4.2: pacote com TTL vencido "MUST NOT be further forwarded" e MAY ir ao
  tratamento de erro da camada de rede; §2.3.2: copiar a pilha para o ICMP e comutá-lo pelo LSP
  quando o LSR não alcança a origem, com TTL longo. **RFC 4950** (objeto da pilha), **RFC 4884**
  (extensões e o comprimento em palavras), **RFC 1812** §4.3.2.7 (quando não mandar), **RFC
  4443** §2.4 (ICMPv6).
- **MikroTik RouterOS v7:** `propagate-ttl` (padrão sim) decide se o núcleo aparece; os saltos
  MikroTik mostram os rótulos. Sem opção de túnel de ICMP; relatos no fórum de saltos que somem
  em VPN.
- **Cisco IOS:** por padrão o erro segue pelo LSP com a pilha original;
  `mpls ip ttl-expiration pop <n>` usa a tabela IP até `n` rótulos. **Junos:** tabela IP por
  padrão, `icmp-tunneling` para seguir pelo LSP até o PE. **Nokia SR OS:** `icmp-tunneling`.
- **Adotado:** a regra do Cisco com o limiar fixo em 1 rótulo (VPN sempre pelo LSP, núcleo
  global pela tabela IP, que é o caminho mais curto) e o limite de taxa antes de qualquer trabalho.
- **Descartado:** XDP no `dataplane-ebpf`. Exigiria `unsafe` e revisão humana, e o XDP não tem a
  tabela de rótulos (`bpf_fib_lookup` não faz MPLS; seria preciso espelhar o ILM num mapa) para
  um evento raro, limitado por taxa. O caminho lento custa menos de 1 µs de CPU por erro (abaixo).
- **Ficou para a G3.9da** (seção abaixo): ICMP "fragmentation needed" para pacote rotulado maior
  que o MTU do LSP (o kernel também descarta) e limite de taxa por origem.

### Desempenho e paralelismo

- **Por pacote no caminho de dados:** o ICMP não acrescenta nada; o custo é o dos taps que o
  respondedor já tinha (G3.5b, ligados por padrão), e este trabalho o mediu e o reduziu.
  `benches/netns_mpls_ttl.rs` (veth → LSR → dummy, quadros de 64 bytes com rótulo, troca de
  rótulo, um núcleo; VM do laboratório, build release, 2026-10-29, **medido**; os valores
  absolutos variam muito entre rodadas na VM, compare só na mesma rodada):

  | Caso (mesma rodada) | Mpps | contra sem taps |
  |---|---|---|
  | sem taps | 1,90 | — |
  | um tap MPLS **preso à porta** (como era no G3.5b) | 1,47 | −23% |
  | os três taps do respondedor **sem bind** (agora) | 1,53 | −19% |

  Preso à porta, o socket fica na `ptype_specific`, que o kernel percorre depois da
  `ptype_base`: o `mpls_rcv`/`ip_rcv` recebe o skb compartilhado e o clona (`skb_share_check`).
  Sem bind, o tap fica na `ptype_base` à frente deles e solta o quadro antes (o filtro passou a
  conferir que o device é Ethernet, `SKF_AD_HATYPE`; a interface vem do `sll_ifindex`). Isso
  devolveu ~4 pontos; o resto (~125 ns por pacote nesta VM) é o próprio `packet_rcv` com o
  filtro, inerente a qualquer tap `AF_PACKET`. Num enlace real com várias filas o custo se
  divide pelos núcleos que recebem. Quem não precisa de LSP ping nem do ICMP recupera tudo com
  `lsp-ping-responder=no icmp-ttl-exceeded=no`; um tap em XDP/tc (eBPF) é a gap G3.9db.
- **Por erro** (release, criterion, esta máquina com outras sessões compilando, 2026-10-29,
  **medido**, `cargo bench -p corerouter-hal --bench mpls_icmp`): ler o quadro 74 ns; o erro
  pela tabela IP 0,59 µs, pelo LSP com 100 000 rótulos 0,82 µs, pilha de VPN 0,77 µs. A busca do
  rótulo é O(log n) no `BTreeMap` da visão (relida no máximo a cada segundo).
- **Thread:** a do serviço `lsp-ping` (uma, nomeada), sem o lock da sessão no envio. A 100
  erros/s são < 0,1 ms de CPU por segundo; dividir por núcleo só dividiria o limite de taxa. Uma
  enxurrada de TTL 1 custa ao kernel a cópia para o socket (fila limitada pelo `SO_RCVBUF`; o
  excedente o kernel descarta) e ao serviço um contador por pacote além da taxa.

## ICMP de pacote rotulado grande demais e taxa por origem (G3.9da)

O MPLS do kernel também descarta calado o pacote rotulado que não cabe no enlace de saída
(`net/mpls/af_mpls.c`, `mpls_forward`: `if (mpls_pkt_too_big(skb, mtu - new_header_size)) goto
tx_err`, que só conta `tx_errors` na interface de saída; igual no 6.18.59 da imagem e no
`master`). Sem o ICMP, a descoberta de MTU do caminho (PMTUD, RFC 1191/8201) através do LSP vira
buraco negro: o TCP abre e trava no primeiro segmento cheio. Agora o respondedor manda o erro.

### Como funciona

- **Captura:** com `icmp-too-big` ligado, o filtro BPF do tap MPLS também guarda os quadros mais
  longos que a **menor saída da tabela de rótulos** (MTU do enlace − 4 × rótulos empilhados + 4,
  sobre todas as entradas; recalculado quando a tabela ou um MTU muda, no máximo uma vez por
  segundo, e o filtro é trocado no socket, o que é atômico). Numa rede de MTU igual nenhum
  quadro passa desse limite: zero cópia. O que passa é cortado em 14 + 1336 octetos (a pilha e a
  citação mais longa), então um quadro jumbo não é copiado inteiro.
- **Quando é grande demais** (`hal/src/lsp/too_big.rs`, sans-IO; a mesma conta do kernel): o
  pacote sob o rótulo do topo mais os rótulos que a entrada empilha não cabe no MTU do enlace de
  saída. Com ECMP o kernel escolhe por um hash que não vemos: vale a menor saída. O TTL vem
  antes (um pacote expirado recebe time exceeded, como no kernel).
- **IPv4 com DF** (RFC 3032 §3.4): Destination Unreachable código 4, com o Next-Hop MTU (RFC
  1191 §4) = MTU do enlace − a pilha que sairia, 128 octetos citados e o objeto da RFC 4950 com a
  pilha como chegou (o tipo 3 aceita extensões, RFC 4884 §4.1). **Sem DF:** a RFC deixa o LSR
  descartar calado ("MAY silently discard"), e é o que o kernel já fez; contado.
- **IPv6** (RFC 3032 §3.5): Packet Too Big com esse MTU, citando o que couber no MTU mínimo de
  1280 (RFC 4443 §3.2; o tipo 2 não tem extensão RFC 4884, então vai sem a pilha). Pacote de até
  1280 octetos com cabeçalho de fragmento deveria ser fragmentado (§3.5 passo 4): contado.
- **Não manda, e como volta:** as mesmas regras do time exceeded (acima): nunca sobre erro ICMP,
  fragmento não inicial, origem que não é unicast; um rótulo com rota até a origem pela tabela
  IP, pilha de VPN ou núcleo sem BGP pelo próprio LSP. Packet Too Big pode ser sobre destino
  multicast (RFC 4443 §2.4(e.2)).
- **Taxa por origem:** antes do balde global de `icmp-rate` (100/s), um balde de
  `icmp-rate-per-source` (padrão 10/s, até 10 000) por endereço que receberia o erro, como o
  `icmp_ratelimit` por destino do Linux. Uma enxurrada de TTL 1 de um host gasta a parte dele, e
  o traceroute dos outros continua vendo o salto. A tabela guarda até 4096 origens; as ociosas
  (um segundo sem erro, balde cheio de novo) saem no máximo uma vez por segundo; cheia de
  origens ativas (enxurrada com origem forjada), uma origem nova não recebe erro — o balde
  global estaria vazio de qualquer jeito. `hal/src/lsp/rate.rs`, sem relógio (compila no WASM).
- **Configuração:** `/mpls settings icmp-too-big` (padrão ligado) e `icmp-rate-per-source`;
  contadores em `mpls.settings.get` (`icmp_counters`: `too_big` ouvidos, `too_big_sent`,
  `rate_limited_source` à parte de `rate_limited`, e os motivos de descarte: "fits the way out",
  "DF not set…"). Janela **MPLS › Settings**, com ⓘ.

### Pesquisa

- **Kernel** (`net/mpls/af_mpls.c`, 6.18.59 da imagem e `master`, lidos): `mpls_forward` confere
  o TTL (`dec.ttl <= 1`) antes do MTU; `mpls_pkt_too_big` só aceita o pacote maior que o MTU se
  for GSO e os segmentos couberem (`skb_gso_validate_network_len`); `mpls_dev_mtu` é o `dev->mtu`
  (não há MTU de MPLS por interface no Linux). No LER de entrada, `mpls_iptunnel.c` declara o
  `headroom` da pilha no lwtunnel, e o IP já desconta isso do MTU da rota: o `ip_forward` manda o
  ICMP lá. Só o LSR de trânsito ou penúltimo precisa deste trabalho. O `icmp.c` do Linux não
  limita "fragmentation needed" (`icmpv4_mask_allow`: "Don't limit PMTU discovery"); aqui ele
  passa pelos baldes porque cada erro custa uma cópia ao espaço de usuário.
- **RFC 3032** §3 (sem errata técnica em §3; a única de §3.4 é tipográfica; atualizada por 3443,
  4182, 5332, 5462, 7274, que não mexem em §3): §3.3 quando é "too big", §3.4 IPv4 (DF: MUST
  ICMP com o MTU − N; sem DF: MAY descartar ou fragmentar), §3.5 IPv6, §3.6 PMTUD. **RFC 1191**
  §4 (Next-Hop MTU), **RFC 8201** (PMTUD IPv6), **RFC 4443** §3.2 e §2.4(e), **RFC 4884** §4.1,
  **RFC 4950** (o objeto vai em time exceeded e destination unreachable), **RFC 1812** §4.3.2.8
  (limitar erros ICMP).
- **MikroTik RouterOS v7:** `/mpls interface mpls-mtu` (padrão 1508, ≤ L2MTU) e o ICMP "need
  fragmentation" que imita o IP, comutado até o fim do LSP; recomenda o mesmo MPLS MTU em todo
  o núcleo ([wiki MPLS](https://wiki.mikrotik.com/wiki/MPLS),
  [help.mikrotik.com](https://help.mikrotik.com/docs/x/KwCiBQ)). `/ip settings icmp-rate-limit`
  limita os erros do roteador.
- **Cisco IOS:** `mpls mtu` por interface; pacote rotulado com DF maior que ele é descartado e o
  "frag needed" segue pelo LSP (log `MPLS: ICMP: dst frag. needed and DF set unreachable sent`,
  [fórum](https://community.cisco.com/t5/mpls/mpls-df-bit-set/m-p/2499658),
  [MPLS Fundamentals](https://www.oreilly.com/library/view/mpls-fundamentals/1587051974/1587051974_ch03lev1sec6.html)).
  **Junos:** o erro de MTU em pacote rotulado de VPN só com `icmp-tunnelling` em `protocols mpls`
  ([Feature Explorer](https://apps.juniper.net/feature-explorer/feature/8329), 23.4R1).
  **Nokia SR OS:** `icmp-tunneling` também. Relatos de PMTUD em núcleo MPLS:
  [lostintransit](https://lostintransit.se/2024/09/11/pmtud-in-mpls-enabled-networks/).
- **Adotado:** a conta exata do kernel (o erro só sai quando ele de fato descarta), o MTU já
  descontado da pilha que sai (RFC 3032 §3.4) e a mesma regra de volta do time exceeded.
- **Melhor que os outros:** limite por origem antes do global, contadores com o motivo de cada
  descarte, e o filtro que só copia o que pode ser grande demais (nenhuma cópia com MTU igual).
- **Ficou de fora:** fragmentar IPv4 sem DF no LSR (§3.4 3.a: o kernel descarta, a RFC permite;
  fragmentar em espaço de usuário seria caminho de dados lento); `mpls-mtu` por interface como o
  RouterOS (o Linux usa o `dev->mtu`; precisaria de patch no kernel); e um GSO grande que chegue
  por veth é copiado e cai em "fits the way out" (o BPF clássico não vê o `gso_size`; o tap em
  eBPF da G3.9db vê).

### Desempenho e paralelismo

- **Por pacote no caminho de dados:** duas instruções a mais no filtro (comprimento e comparação)
  para quadro que não é TTL ≤ 1 nem explicit null; nenhuma cópia enquanto o quadro couber na
  menor saída. **Medido** (VM `corerouter-lab`, 4 vCPU, kernel 6.18, build release,
  2026-10-29, `benches/netns_mpls_ttl.rs`, quadros MPLS de 64 octetos num núcleo): sem taps
  2,083 Melem/s (2,080 no fim da rodada); os três taps do respondedor 1,633; com o filtro de
  "grande demais" ligado 1,644. O filtro novo não custa nada mensurável; o custo dos taps
  `AF_PACKET` (~21%) é o que a G3.9db tira.
- **Recalcular o limiar:** O(rótulos) quando a tabela é relida (no máximo uma vez por segundo, já
  era o custo da releitura), na thread do serviço.
- **Por erro:** `too_big::answer` é uma busca no `BTreeMap` de rótulos e a montagem do pacote,
  como o time exceeded (~0,6–0,8 µs, medido na G3.9d). A taxa por origem é uma busca num
  `HashMap` de no máximo 4096 entradas, antes de qualquer trabalho.
- **Thread:** a mesma do serviço `lsp-ping`; um núcleo a mais só dividiria os baldes (que teriam
  de ser compartilhados com lock). O que cresce com a carga é a cópia do kernel, limitada pelo
  `SO_RCVBUF`.

