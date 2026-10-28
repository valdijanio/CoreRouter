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
