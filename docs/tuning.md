# System › Tuning (G1.26)

Ajusta o kernel e o hardware de uma máquina que **encaminha pacotes**. O CoreRouter faz isso
sozinho, em Rust puro, sem `tuned`, `irqbalance`, `ethtool` nem `sysctl.conf`:

- sysctl: arquivos de `/proc/sys`;
- placa: ethtool netlink (G1.26b);
- IRQ, RPS/XPS e cpufreq: `/proc` e `/sys` (G1.26c);
- C-states: `/dev/cpu_dma_latency` (G1.26c);
- parâmetros de boot: a cmdline da imagem (G1.26d).

Cada ajuste é um comando `system.tuning.*` e fica na config (`system.tuning`), então vale para
ele o que vale para o resto: transação, `config.diff`, Safe Mode, histórico e rollback.

Partes:

| Parte | O quê | Estado |
|---|---|---|
| G1.26a | Resumo (hardware, diagnóstico, perfil), Kernel (sysctl), Perfis, medida de pps | este documento |
| G1.26b | Interfaces: anel, filas, coalescência, offloads, flow control, txqueuelen, qdisc, `rp_filter` por porta | este documento (RSS: G1.26g) |
| G1.26c | CPU e IRQ: afinidade por nó NUMA, RPS/XPS, governor, C-states por PM QoS, watchdog | este documento |
| G1.26d | Boot: parâmetros da imagem A/B (modelo, comandos e tela; aplicação na imagem: G1.26h) | este documento |

## Como funciona

- **Catálogo** (`corerouter_model::tuning::PARAMS`): os parâmetros que existem aqui, com a seção,
  a faixa, a unidade, os valores nomeados (`rp_filter`: 0 off, 1 strict, 2 loose), o padrão fixo do
  kernel e as marcas:
  - `init_ns_only`: só o namespace de rede inicial tem;
  - `obsolete`: o kernel ignora;
  - `control_plane`: afeta só os sockets do próprio roteador.

  Um nome fora do catálogo nunca vira caminho em `/proc/sys`.
- **Config**: `system.tuning.sysctl` guarda só o que o operador (ou um perfil) definiu.
  - Um parâmetro ausente fica como o kernel tem.
  - Tirar um parâmetro devolve o valor que o kernel tinha antes da primeira mudança do CoreRouter
    (o mesmo modelo das opções Ethernet, G1.20).
  - **Exceção: o encaminhamento IPv4 e IPv6 nasce ligado** (G1.26i, seção "Encaminhamento ligado
    por padrão"). Ele não entra na config: é o padrão do CoreRouter enquanto ela não disser 0.
- **HAL**:
  - `system_info` lê a máquina: CPUs, nós NUMA, RAM, kernel.
  - `sysctls` lê os valores atuais.
  - `kernel_stats` lê os contadores do diagnóstico.
  - `apply` grava, tudo ou nada: se um valor é recusado (ausente, só leitura, ou o kernel guardou
    outro), os já gravados voltam e o commit falha com o motivo.
  - O `ip_forward` é gravado antes dos outros, porque mudá-lo reinicia parâmetros de configuração
    (`ip-sysctl.rst`; no kernel 6.18 são o `conf/all/accept_redirects`, o `conf/default/forwarding`
    e o `forwarding` de cada interface, `inet_forward_change` em `net/ipv4/devinet.c`).
  - O laboratório virtual simula uma máquina de 16 CPUs, 2 nós NUMA e 32 GiB, com contadores que
    disparam o diagnóstico.
- **Engine** (`crates/engine/src/tuning.rs`, puro, testado sem kernel):
  - perfis calculados da máquina;
  - faixas que dependem da RAM;
  - diagnóstico.

  Cada recomendação traz o motivo em inglês (CLI, MCP) e um id de modelo com argumentos, que a GUI
  mostra no idioma das explicações (G0.15).

## Comandos

| Comando | O que faz |
|---|---|
| `system.tuning.parameter.print {profile?, tab?}` | Parâmetros com atual, configurado, recomendado (e motivo), faixa, unidade, marcas |
| `system.tuning.print {}` | Só o que a config define, `[{name, value}]` (o `/export` o devolve como `set`) |
| `system.tuning.set {name, value}` | Define um parâmetro. Valida faixa (com o teto da RAM) e `gc_thresh1 ≤ 2 ≤ 3`; recusa obsoleto e ausente (com o motivo: conntrack não carregado, só no host…) |
| `system.tuning.unset {name}` | Tira da config: o kernel volta ao valor de antes |
| `system.tuning.profile.diff {profile?}` | O que o perfil mudaria, com o motivo |
| `system.tuning.profile.apply {profile, names?}` | Aplica o perfil (ou só `names`) num commit só |
| `system.tuning.hardware {}` | CPUs, NUMA, RAM, kernel e por porta: driver, velocidade, nó NUMA, filas, anéis, `rx_missed` |
| `system.tuning.diagnose {}` | Achados dos contadores, do pior para o melhor, com o parâmetro e o valor sugeridos |

No terminal: `/system tuning parameter print`, `/system tuning print` (o que está definido), `/system tuning set name=net.core.netdev_budget value=600`.

## Perfis

Cada perfil é **calculado para a máquina**, não copiado de uma tabela:

- **Conservador**: só o que é seguro em qualquer lugar.
  - encaminhamento ligado (já é o padrão do CoreRouter: o perfil não grava nada);
  - ECMP por camada 4;
  - `kernel.panic = 10`, `panic_on_oops = 1`;
  - `tcp_syncookies = 1`.

  O resto fica como o kernel tem.
- **Balanceado**: um roteador com NAT.
  - backlog dimensionado pela soma das portas (`pow2(Gb/s × 1000)`, de 4096 a 65 536);
  - `netdev_budget` 600 e `_usecs` 8000;
  - `rp_filter` solto;
  - conntrack com 1/16 da RAM a ~320 B por entrada, buckets = max/4;
  - timeouts: established 1 dia, udp_stream 180 s, icmp 60 s;
  - `gc_thresh3` = 2048 por GiB (de 4096 a 65 536), com 1/2 e 1/8 nos outros dois limites;
  - `min_free_kbytes` = RAM/256;
  - buffers de socket de 16 MiB para o BGP.
- **Alto desempenho**: backlog ×2, budget 1200, `rp_filter` desligado, conntrack 1/8 da RAM.
  Timeouts nos limites das RFCs:
  - established 7440 s (RFC 5382 REQ-5);
  - udp_stream 120 s (RFC 4787 REQ-5);
  - icmp 60 s (RFC 5508 REQ-1);
  - udp 10 s, generic 120 s.
- **Baixa latência**: rodadas curtas (budget 300, 2000 µs) e backlog de 4096.

"Aplicar com Safe Mode" entra em Safe Mode (se esta conexão ainda não está nele) e aplica o perfil
num commit. O operador confirma no botão da barra de cima; se a conexão cair, tudo volta.

## Diagnóstico

Os contadores são desde o boot:

| Contador | Achado | Sugestão |
|---|---|---|
| `softnet_stat` `dropped` | backlog cheio | `netdev_max_backlog` |
| `softnet_stat` `time_squeeze` (> 1 por 10 000 pacotes) | rodada sem budget | `netdev_budget` |
| `nf_conntrack_count / max` ≥ 80 % (crítico a partir de 95 %) | tabela quase cheia | `nf_conntrack_max` |
| `table_fulls` de `/proc/net/stat/{arp,ndisc}_cache` | estouro da tabela de vizinhos | `gc_thresh3` |
| `rx_missed_errors` com anel abaixo do máximo | a placa ficou sem descritor | aba Interfaces (G1.26b) |
| `ip_forward = 0` | o roteador não roteia | crítico, com o botão `Set net.ipv4.ip_forward = 1` |
| `ipv6.conf.all.forwarding = 0` | o roteador não roteia IPv6 | aviso, com o botão |

Desde a G1.26i o encaminhamento nasce ligado, então esses dois achados só aparecem quando o
operador gravou 0 (`system.tuning.set`) ou quando o kernel recusou o padrão (um `/proc/sys` só de
leitura, num container: o log do roteador diz).

Quando o parâmetro já tem o valor sugerido (ou mais), o achado fica como nota, sem botão. Os
contadores não zeram, e o diagnóstico por taxa é o G1.26e.

## Janela System › Tuning

- **Abas**: Resumo, Kernel, Interfaces, CPU e IRQ, Boot e Perfis. Interfaces, CPU e IRQ e Boot dizem
  em que gap chegam.
- **No alto**: o seletor de perfil, que a coluna Recomendado e o Resumo seguem.
- **Kernel**:
  - lista de propriedades agrupada por seção, que abre e fecha;
  - Find;
  - colunas Parâmetro, Atual, Configurado, Recomendado (motivo no tooltip), Faixa e ⓘ;
  - selos:
    - `differs`: valor diferente do recomendado;
    - `not applied`: configurado, mas o kernel tem outro;
    - `control plane`, `obsolete`;
    - `needs reboot` e `flaps link` (b, d).
  - Clicar numa linha abre o editor embaixo: valor (ou lista, para os nomeados), Set, Unset e Use
    recommended.
- **ⓘ**: modal no idioma das explicações com "O que faz", "Quando aumentar/mudar", "Cuidado",
  "Recomendado aqui" (o valor calculado e o motivo) e o comando equivalente.
- **Resumo**:
  - hardware e portas;
  - diagnóstico com selo de gravidade e botão "Set <parâmetro> = <valor>";
  - quantos parâmetros diferem do perfil;
  - "Show differences" (modal com o motivo de cada um) e "Apply with Safe Mode".
- **Perfis**: os quatro lado a lado, com o atual; em negrito o que muda.

## Encaminhamento ligado por padrão (G1.26i)

Um CoreRouter recém-instalado, e a ISO live, **roteiam sem configuração nenhuma**. O Linux sobe
como host (`net.ipv4.ip_forward = 0`, `net.ipv6.conf.all.forwarding = 0`; RFC 1122 §3.1 manda a
função de gateway de um host nascer desligada). Antes da G1.26i só aplicar um perfil ligava o
encaminhamento, e a janela Tuning de uma instalação nova abria com o achado crítico "o
encaminhamento IPv4 está desligado".

- **Onde mora**: `corerouter_model::tuning::DEFAULTS` (`ip_forward = 1` e
  `ipv6.conf.all.forwarding = 1`). O `Tuning::effective_sysctl` é o padrão com a config por cima.
- **Quem aplica**: o HAL do Linux, em todo `apply` (o primeiro é o da partida do daemon), antes
  dos outros parâmetros (`Sysctl::keep_defaults`, `crates/hal-linux/src/tuning.rs`). Não há nada
  no init nem na imagem (`sysctl.conf`): o daemon rodando numa máquina qualquer se comporta igual.
- **Melhor esforço**: um kernel sem IPv6 ou um `/proc/sys` só de leitura (container) gera uma
  linha de aviso no log, uma vez, e nunca recusa um commit. O que o operador define continua tudo
  ou nada.
- **O 0 do operador vale**, por família: `system.tuning.set name=net.ipv4.ip_forward value=0`
  desliga o IPv4 e deixa o IPv6; o achado crítico aparece com o botão que religa. `unset` volta ao
  padrão do CoreRouter (1), não ao 0 do kernel.
- **Config já gravada**: o formato não mudou. Uma config sem `system.tuning` passa a rotear; uma
  que tem `ip_forward: 1` (um perfil aplicado antes) ou `0` continua valendo como está.
- **Na janela**: a coluna Configurado mostra `1 (on)` com o selo `router default` em vez de "–";
  o ⓘ dos dois parâmetros explica. No comando, `system.tuning.parameter.print` traz
  `router_default`.
- **Algo desligou por fora** (um `echo 0`, outro programa): o próximo `apply` religa.

### O que o kernel faz ao ligar (lido no fonte do 6.18.59 da imagem)

| Efeito | Onde | O que o CoreRouter faz |
|---|---|---|
| IPv4: `conf/all/accept_redirects = 0`, `conf/default/forwarding = 1`, `forwarding` de cada interface, LRO desligado em todas as portas | `inet_forward_change`, `net/ipv4/devinet.c:2423` | Grava o `ip_forward` antes de qualquer outro parâmetro. Um roteador não obedece a redirects (RFC 1812 §4.3.3.2) e continua enviando (`send_redirects = 1`, RFC 1812 §5.2.7.2; o RouterOS também) |
| IPv4: `rp_filter` | não muda (fica 0, o padrão do kernel) | Nada: a RFC 1812 §5.3.8 manda a validação de origem nascer desligada; os perfis a ligam em modo solto |
| IPv6: `default` e cada interface passam a `forwarding = 1`; entram nos grupos all-routers (`ff02::2`) e anycast | `addrconf_fixup_forwarding` e `dev_forward_change`, `net/ipv6/addrconf.c:873` e `:806` | Nada: é o que um roteador faz (RFC 4861 §6.2) |
| IPv6: **apaga as rotas aprendidas por RA** de toda interface cujo `accept_ra` não é 2 | `rt6_purge_dflt_routers`, `net/ipv6/route.c:4516`, chamado em `addrconf.c:914` | **Acerta o `accept_ra` das interfaces que já existem antes de ligar o encaminhamento** (`LinuxHal::apply_links`): a WAN que já tinha a rota padrão por RA não a perde |
| IPv6: RA ignorado e nenhum Router Solicitation enviado, a não ser com `accept_ra = 2` | `ipv6_accept_ra`, `include/net/ipv6.h:531`; `ndisc.c:1276`; RS só no fim do DAD, `addrconf.c:4351` | O `accept_ra = 2` já era posto onde o IPv6 › Settings manda aceitar (G4.7b: por padrão, onde roda um cliente DHCPv6). **Novo: ao pôr 2 numa porta já no ar, o CoreRouter envia ele mesmo um Router Solicitation** (RFC 4861 §4.1 e §6.3.7, `crates/hal-linux/src/ra.rs`), senão a rota padrão só viria no próximo RA periódico, até 600 s (`MaxRtrAdvInterval`, RFC 4861 §6.2.1) |
| IPv6: redirects ignorados | `rt6_do_redirect`, `net/ipv6/route.c:4272` | Nada (RFC 4861 §8.2: um roteador não muda a tabela por um redirect) |

Como a WAN continua com SLAAC e rota padrão por RA: uma WAN com cliente DHCPv6 fica com
`accept_ra = 2` (RFC 7084 W-1 e W-3: a WAN age como host). Sem cliente DHCPv6, o padrão `auto`
não aceita RA em lugar nenhum, como o RouterOS (`accept-router-advertisements =
yes-if-forwarding-disabled` com `forward=yes`); `ipv6.settings.set
accept_router_advertisements=yes` aceita.

### ISO live

A live roteia como o disco instalado (o padrão está no HAL, não na config). Ela também passou a
aceitar `system.tuning.set`, `system.tuning.unset` e `system.tuning.profile.apply` (os parâmetros
de kernel, em tempo de execução; nada persiste, a live não tem disco), mais `config.safe-mode.*`,
que só desfaz. Continuam recusados na live: os ajustes de porta (anéis e filas piscam o link por
onde a instalação é feita), os de CPU (um watchdog de hardware reiniciaria a live) e os de boot
(não há próximo boot).

### "Balanced: N parâmetros diferem" numa instalação nova

Numa máquina em que ninguém configurou nada, o Resumo passa a dizer "Balanced: nada foi
configurado ainda, valem os valores do próprio kernel. N parâmetros mudam ao aplicar este perfil",
em vez de "N parâmetros diferem deste perfil". Com algo configurado volta a contagem de
diferenças.

Nascer com o perfil Balanced aplicado ficou para a G1.26j, e não é só mudar o padrão:

- os valores do perfil são **calculados da máquina** (RAM, soma das portas). Gravados na config
  na primeira partida, ficariam congelados: a config levada para outra máquina, ou a mesma
  máquina com mais RAM, teria valores errados;
- a aplicação de hoje é tudo ou nada, e parte dos parâmetros não existe em todo lugar (o
  conntrack só com o módulo carregado, os `netdev_*` e `gc_thresh` só no namespace inicial). Um
  padrão que recusa a config no boot é pior que um valor do kernel;
- RouterOS, VyOS, OpenWrt e OPNsense trazem padrões de roteador, mas como base **do sistema**,
  não como config do operador. O equivalente aqui é o daemon seguir um perfil (calculado em cada
  partida, melhor esforço, com a config do operador por cima), o que muda modelo, engine, HAL e
  janela.

### Testes

- modelo e engine: o padrão, o 0 respeitado, config antiga, o `unset`, o achado
  (`a_router_forwards_unless_the_config_says_no`,
  `a_router_forwards_by_default_and_an_explicit_off_is_kept`,
  `a_config_from_before_the_default_loads_the_same`);
- `crates/hal-linux/tests/netns_tuning.rs`, no kernel, num namespace sem root:
  - `a_router_forwards_by_default_and_the_config_can_turn_it_off`;
  - `the_wan_keeps_its_ra_route_when_forwarding_turns_on` (mostra também o kernel sozinho
    apagando a rota);
  - `an_interface_that_starts_accepting_asks_for_an_ra` (o RS com a opção de endereço de enlace);
- `apps/corerouter-daemon/tests/netns_dhcp6.rs`: o daemon com o encaminhamento ligado recebe
  endereço, prefixo e a rota padrão por RA;
- a imagem no QEMU: `cargo xtask os forward-test` (três VMs, `a ── r ── b`, mais a ISO live).

## Interfaces (G1.26b)

Os ajustes de cada porta ficam em `system.tuning.ports` (porta → chave → valor), com o catálogo
`PORT_PARAMS`:

| Seção | Chaves | Como o CoreRouter grava |
|---|---|---|
| Anéis e filas | `rx_ring`, `tx_ring`, `combined_channels`, `rx_channels`, `tx_channels` | ethtool netlink `RINGS_SET`, `CHANNELS_SET` (**pisca o link**) |
| Coalescência | `adaptive_rx`, `rx_usecs`, `adaptive_tx`, `tx_usecs` | `COALESCE_SET` |
| Offloads | `gro`, `lro`, `tso`, `gso` | as opções Ethernet da porta (`interface.ethernet.set`, G1.20) |
| Controle de fluxo | `rx_pause`, `tx_pause` | idem |
| Fila de transmissão | `txqueuelen`, `qdisc` (fq_codel, fq, pfifo_fast, mq, noqueue) | rtnetlink (`IFLA_TXQLEN`, `RTM_NEWQDISC` raiz) |
| Filtragem | `rp_filter` | `/proc/sys/net/ipv4/conf/<porta>/rp_filter` |

Comportamento:

- **Faixa**: o máximo de anéis e filas vem da própria placa (`*_MAX` do ethtool).
- **Chave que a placa não tem** (veth sem anel, coalescência não suportada): recusada com o motivo.
  Na aplicação, um valor que o driver não guardou desfaz a mudança toda da porta.
- **Offloads e controle de fluxo** ficam num lugar só: as opções Ethernet da porta, que o
  `interface.ethernet.set` também edita. Ligar o LRO aqui é recusado; o caminho com `force` do
  G1.20 continua valendo para porta que só termina tráfego.
- **Só portas gerenciadas**: os ajustes alcançam apenas as portas que o CoreRouter gerencia (a regra
  de posse do G1.18); um link de outro programa nunca é tocado.
- **Tirar uma chave da config** devolve o valor que a porta tinha.

Comandos:

| Comando | O que faz |
|---|---|
| `system.tuning.interface.parameter.print {name?, profile?}` | Por porta: atual, configurado, recomendado (e motivo), faixa da placa, `link_flap`, `fixed` |
| `system.tuning.interface.print {}` | Só o que a config define, `[{name, key, value}]` (o `/export` o devolve como `set`) |
| `system.tuning.interface.set {name, key, value}` | Define; avisa quando a mudança pisca o link |
| `system.tuning.interface.unset {name, key}` | Tira da config: a porta volta ao próprio valor |
| `system.tuning.interface.apply {profile, names?}` | Aplica o perfil em todas as portas (ou em `names`) num commit |

Recomendação por porta:

- **Anéis**: 2048 no balanceado, o máximo da placa no alto desempenho, 1024 na baixa latência.
- **Filas**: uma por CPU do nó NUMA da porta, até o máximo da placa.
- **Coalescência**: adaptativa; na baixa latência, desligada com 0 µs.
- **Offloads**: GRO ligado; LRO desligado; TSO/GSO sem recomendação (irrelevantes para o
  encaminhamento).
- **Controle de fluxo**: desligado.
- **`txqueuelen`**: 1000.
- **Qdisc**:
  - `mq` em placa de várias filas;
  - `fq_codel` em placa de fila única;
  - `noqueue` mantido em porta virtual (medido: `fq_codel` ali custa 7 %).
- **`rp_filter`**: o mesmo valor do `all` do perfil (o kernel usa o maior dos dois).

Diagnóstico novo:

- **LRO ligado** numa porta: aviso.
- **Controle de fluxo ligado**: nota.

Na janela, a aba Interfaces tem:

- o seletor de porta;
- a mesma lista de propriedades, com os selos `flaps link` e `fixed`;
- ⓘ por chave, com o comando `/system tuning interface set name=… key=… value=…`;
- "Apply to all ports with Safe Mode".

Teste em netns (`tests/netns_tuning.rs`), num veth de 4 filas:

- canais, `txqueuelen`, qdisc e `rp_filter` mudam e voltam;
- um anel (o veth não tem) desfaz a mudança toda;
- uma porta `--unmanaged` fica intacta.

O `netdevsim`, que teria anel e coalescência, precisa de root no namespace do host para criar o
dispositivo, então fica fora dos testes sem root.

## CPU e IRQ (G1.26c)

Ajustes da máquina em `system.tuning.cpu` (catálogo `CPU_PARAMS`), todos por arquivo, sem
`irqbalance`, `cpupower` nem `tuned`:

| Chave | O quê | Como |
|---|---|---|
| `governor` | performance, schedutil, ondemand, powersave, conservative | `scaling_governor` de toda política do cpufreq; recusa o que o driver não oferece (`scaling_available_governors`) |
| `cpu_dma_latency` | C-state máximo, como a latência de despertar em µs (1 = C1, 0 = polling) | requisição PM QoS em `/dev/cpu_dma_latency` (s32 binário), **mantida aberta pelo daemon**: se ele cair, o limite some (falha segura); sem reboot |
| `hw_watchdog` | watchdog de hardware | `/dev/watchdog` aberto e alimentado a cada `poll`; desligar envia o fechamento mágico (`V`) |

Por porta (chaves de porta da seção "CPU and IRQ", nos comandos `system.tuning.interface.*`):

| Chave | O quê |
|---|---|
| `irq_affinity` | `local node`: uma IRQ de fila por CPU do nó NUMA da porta (fila *i* → CPU *i* do nó), em `/proc/irq/<n>/smp_affinity_list`; `kernel`: todas as CPUs |
| `rps` | `rps_cpus` das filas de recepção = CPUs do nó (placa de fila única) |
| `xps` | `xps_cpus`: cada fila de transmissão com uma CPU do nó (placa de várias filas) |

Como funciona:

- **IRQs da porta**: os vetores MSI cujo nome em `/proc/interrupts` cita a porta (`eth0-TxRx-3`); o
  vetor de administração fica de fora.
- **IRQ gerenciada** (o driver fixa a CPU, como a flag `o` do MikroTik): a escrita falha com EIO e
  o CoreRouter diz o motivo.
- **Valor original**: o de IRQ, RPS e XPS fica guardado na primeira mudança; desligar o devolve
  (inclusive o mapa de XPS que o driver tinha feito).

**Por que não `irqbalance`.** Ele move as IRQs a cada 10 s pela carga, ignora o nó NUMA quando o
firmware não o informa e sobrescreve a afinidade manual (`scaling.rst`): o trabalho troca de CPU,
o cache esfria e os fluxos chegam fora de ordem. O guia da Intel série 800 manda desligá-lo. O
diagnóstico avisa quando ele roda (laboratório incluído).

Recomendação:

- `governor` performance;
- `cpu_dma_latency` 1 µs só no perfil de baixa latência;
- watchdog ligado onde existe;
- por porta:
  - afinidade no nó local;
  - RPS só em fila única;
  - XPS só com várias filas.

O conservador não muda nada disso.

Janela, aba CPU e IRQ:

- o aviso do irqbalance;
- a lista da CPU (governor, C-states, watchdog);
- o seletor de porta, com o mapa "IRQ: CPUs" e as chaves `irq_affinity`, `rps` e `xps`.

Testes:

- unidade sobre um `/proc`, `/sys` e `/dev` de mentira: governor, PM QoS (o valor binário),
  watchdog com fechamento mágico, espalhamento de IRQ, máscaras de RPS/XPS, recusa e restauração;
- engine;
- headless.

Fora do namespace de teste nada disso é seguro de gravar: são arquivos do host.

## Boot (G1.26d)

São parâmetros da linha de comando do kernel **da imagem**: o CoreRouter não tem GRUB, a imagem é
imutável e A/B (`docs/architecture.md`). Valem no próximo boot; um boot que falha volta para a
imagem anterior, com a linha de comando dela.

| Parâmetro | Valores | Recomendado |
|---|---|---|
| `isolcpus`, `nohz_full` | lista de CPUs (`2-7,10`); a CPU 0 fica com o sistema | nunca (dependem do que roda; o encaminhamento do kernel roda em softirq na CPU da IRQ) |
| `intel_idle.max_cstate`, `processor.max_cstate` | 0–9 | 1 na baixa latência (o `cpu_dma_latency` da aba CPU faz o mesmo sem reboot) |
| `pcie_aspm` | off, force | off na baixa latência |
| `iommu` | pt, nopt, off | pt no alto desempenho e na baixa latência |
| `mitigations` | auto, auto,nosmt, off | **nunca**; `off` exige `confirm=yes` e aparece com o selo vermelho "security risk" |

Os valores ficam em `system.tuning.boot` e passam pela validação de `model::tuning::boot_value`:

- só caracteres de uma lista de CPUs, um número ou uma das opções;
- nada de espaço, aspas ou `=`, porque o valor vai direto para a linha de comando (impede
  `isolcpus=2 init=/bin/sh`);
- CPU que a máquina não tem é recusada.

Comandos:

- `system.tuning.boot.print`: o configurado, para o `/export`;
- `….parameter.print {profile}`: em uso (`/proc/cmdline`), próximo boot, recomendado com o motivo e
  a faixa;
- `….set {key, value, confirm?}`;
- `….unset {key}`.

Na janela, a aba Boot mostra:

- a linha "em uso" e a do "próximo boot";
- o selo "next boot" em cada valor pendente;
- o editor, que só libera `mitigations=off` depois da caixa "I understand the security risk".

**A imagem A/B ainda não existe** (G1.6): os parâmetros ficam gravados na config, e a imagem os lê
quando existir (G1.26h: gravar na cmdline do slot inativo, trocar de slot e voltar ao anterior se o
boot falhar).

## Medida antes e depois

`crates/hal-linux/benches/netns_forward.rs` (rode com `cargo xtask bench netns_forward`) mede, num
namespace sem root:

- quadros UDP de 64 bytes, para 256 destinos, injetados por `AF_PACKET` no veth `fa`;
- eles entram pelo par `fb`, são roteados e saem pelo dummy `fo`;
- o `tx_packets` de `fo`, lido por rtnetlink, conta o que foi encaminhado.

Uma CPU faz tudo. Os números estão em `docs/perf.md`. Um terceiro caso (G1.26b) põe `fq_codel` na
porta de saída virtual.

Limite da medida: num namespace só há os parâmetros por namespace. `netdev_budget`,
`netdev_max_backlog` e os `gc_thresh` são do host e só podem ser medidos na máquina real, como
root (G1.26f).

## Pesquisa

Pesquisa completa nas notas da sessão (`G1.26-research.md`). Resumo:

- **MikroTik RouterOS v7**: o manual novo fica em manual.mikrotik.com; o help.mikrotik.com está
  congelado.
  - `/system resource irq`: `cpu=auto|N` por IRQ; flag `o` = fixo pelo hardware.
  - `/system resource irq rps`: só liga/desliga por interface. A doc manda **não** usar quando a
    placa já tem várias filas.
  - `/interface ethernet` não tem anel, filas nem coalescência.
  - `/ip settings`:
    - `rp-filter=no`;
    - `ipv4-multipath-hash-policy=l3`;
    - `max-neighbor-entries` pela RAM, de 2048 a 16384 (é o `gc_thresh3`).
  - `/ip firewall connection tracking`:
    - timeouts muito menores que os do kernel: established 1 d, udp-stream 3 min, icmp 10 s,
      fechamentos 10 s;
    - `max-entries` só leitura, pela RAM, até 1 048 576.
- **VyOS**:
  - `system option performance`: delega ao `tuned-adm`.
  - `system option kernel`: reescreve a cmdline do GRUB (mitigations, max_cstate, isolcpus,
    nohz_full, rcu_nocbs, hugepages).
  - Por interface: `ring-buffer`, `offload gro|gso|lro|rps|rfs|sg|tso`.
  - RPS: em todas as CPUs menos a 0.
  - `system conntrack table-size` (262144) e `hash-size` (65536).
  - `system ip arp table-size` (8192): gc_thresh3 = n, gc_thresh2 = n/2, gc_thresh1 = n/8.
  - `multipath layer4-hashing`.
  - Base: `kernel.panic=60`, `panic_on_oops=1`.
- **OPNsense/pfSense Tunables**:
  - uma lista Tunable/Value/Description, com o padrão quando não há override;
  - o pfSense não valida o valor e deixa os de boot fora do backup.
- **Kernel**:
  - `networking/scaling.rst`:
    - RSS com uma fila por CPU do nó da placa;
    - o irqbalance sobrescreve ajustes manuais;
    - RPS para placa de fila única;
    - RFS só ajuda tráfego terminado no host.
  - `sysctl/net.rst` e `net/core/hotdata.c`: backlog 1000, budget 300, budget_usecs 2·10⁶/HZ,
    dev_weight 64, rmem/wmem_max 4 MiB.
  - `ip-sysctl.rst`:
    - rp_filter efetivo = max(all, interface);
    - fib_multipath_hash_policy de 0 a 3;
    - route/max_size obsoleto no IPv4 desde o 3.6 e no IPv6 desde o 6.3;
    - gc_thresh 128/512/1024;
    - mudar `ip_forward` reinicia a configuração.
  - `nf_conntrack-sysctl.rst` e `nf_conntrack_core.c`:
    - buckets = RAM/131072, até 262144;
    - max = buckets;
    - buckets gravável só no namespace inicial;
    - timeouts (established 432000, udp 30/120, icmp 30, generic 600).
  - `/proc/net/softnet_stat`: 15 colunas; a 13ª é o id da CPU.
  - ethtool-netlink: RINGS, CHANNELS, COALESCE, PAUSE, FEATURES, RSS.
  - PM QoS: `/dev/cpu_dma_latency` vale enquanto o fd está aberto.
- **Guias de placa**:
  - Intel ice: coalescência adaptativa por padrão; `rx-usecs 80` dá ~12,5 mil interrupções/s; a
    série 800 manda parar o irqbalance e usar `set_irq_affinity -X local`.
  - Flow control: desligado no ice, ligado no ixgbe.
  - Mellanox: perfis `mlnx_tune IP_FORWARDING_*` e `rx_cqe_compress`.
  - Com forwarding ligado, o kernel desliga o LRO; o GRO é seguro em roteador.
- **tuned**:
  - `network-throughput` só mexe em buffers TCP;
  - `network-latency` mexe em busy_poll, THP, numa_balancing, nmi_watchdog e `force_latency`.

  Quase tudo é para tráfego que termina no host, não para encaminhamento.

### O que adotamos

- Perfis próprios para encaminhamento, calculados da máquina. O VyOS delega ao `tuned`, feito para
  servidor.
- A lista do OPNsense (atual, configurado, recomendado, faixa, ajuda), mas **com validação**: faixa,
  teto pela RAM e ordem dos `gc_thresh`.
- O conntrack exposto (o MikroTik deixa só leitura), com a memória estimada no motivo e um perfil de
  CGNAT dentro dos mínimos das RFCs 5382, 4787 e 5508. Os timeouts de 5 a 10 s do MikroTik
  violariam esses mínimos.
- Os vizinhos com a regra 1/2 e 1/8 do VyOS e o tamanho pela RAM do MikroTik.

### Melhorias propostas

- Entra agora:
  - diagnóstico pelos contadores, com botão de correção;
  - "Ver diferenças" e "Aplicar com Safe Mode";
  - ajuda por parâmetro em dois idiomas, com o valor recomendado aqui e o comando;
  - seção "plano de controle" separada;
  - restauração do valor original ao tirar;
  - aplicação tudo ou nada;
  - `ip_forward` gravado primeiro;
  - medida de pps antes e depois.
- Vira gap:
  - RSS: hash e tabela de indireção (G1.26g);
  - diagnóstico por taxa (G1.26e);
  - medida no host com root (G1.26f);
  - flowtable (o fasttrack do Linux), XDP (G2.5), RSS_SET, cpusets.

### Ficou de fora

- `dev_weight` sem recomendação além do padrão: só importa com RPS (G1.26c).
- `tcp_rmem`/`tcp_wmem`: tráfego terminado no host.
- `busy_poll`: não serve ao encaminhamento.

## Achados dos testes

O que os testes e as medidas mostraram e mudou o código ou as explicações (o ⓘ de cada parâmetro
traz o que for dele, numa seção "Medido" quando há número):

- **`rp_filter` estrito custa ~12 % de encaminhamento** (1,61 contra 1,82 Mpps, uma CPU, veth). E
  desligar só o `all` não basta: o kernel usa o maior entre `all` e o da interface, e a interface
  nova herda o `default`.
  - Por isso o catálogo tem `conf.default.rp_filter` e o `rp_filter` de cada porta.
  - O perfil põe os três no mesmo valor.
- **`fq_codel` numa porta virtual custa 7 %** (1,82 para 1,70 Mpps). O perfil mantém `noqueue` em
  porta virtual e só põe `fq_codel` em placa de fila única; com várias filas, `mq`.
- **Mudar `ip_forward` reinicia outros parâmetros** (`ip-sysctl.rst`). O CoreRouter sempre o grava
  primeiro, senão um valor gravado antes podia voltar ao padrão. Lido no fonte do 6.18.59
  (G1.26i): hoje o kernel só mexe no `accept_redirects` do `all` e no `forwarding` do `default` e
  de cada interface; o `rp_filter` não muda.
- **Ligar o encaminhamento IPv6 apaga as rotas de RA** das interfaces que não estão com
  `accept_ra = 2` (G1.26i). O CoreRouter acerta o `accept_ra` antes de ligar e pede um RA ao
  ligar o aceite numa porta já no ar (seção "Encaminhamento ligado por padrão").
- **Num namespace (container, teste)**:
  - `netdev_budget`, `netdev_max_backlog` e os `gc_thresh` não existem;
  - `rmem_max`, `kernel.panic`, `vm.min_free_kbytes` e `nf_conntrack_max` são só leitura;
  - a janela mostra "–" e o comando recusa com o motivo;
  - a medida desses parâmetros fica para o host com root (G1.26f).
- **`/sys/class/net` dentro de um namespace mostra o host**, não o namespace (o sysfs é do
  namespace que o montou). Por isso:
  - o bench conta os pacotes por rtnetlink;
  - os testes de IRQ, RPS e XPS usam um `/sys` de mentira, nunca o real.
- **Os contadores do diagnóstico são desde o boot.** Depois de aplicar a sugestão o achado não
  some sozinho. Quando o parâmetro já tem o valor sugerido, ele vira nota sem botão; a taxa recente
  fica para o G1.26e.
- **O `/export` do terminal vira `print` + `set`.** Uma visão rica no `print` quebraria o export.
  Por isso `system.tuning.print` lista só o configurado e a visão completa fica em
  `….parameter.print`.
- **Veth não tem anel nem coalescência; seus canais são RX/TX, não combinados.** O caminho "a
  placa não tem" é o normal, não erro.
- **Veth e dummy só são gerenciados quando listados** (`--manage`), e um veth com o par no mesmo
  namespace já é gerenciado. Os ajustes de porta respeitam a mesma regra de posse.
- **`netdevsim` não serve sem root**: criar o dispositivo exige o namespace do host.
- **Um valor de boot vai cru para a linha de comando do kernel**: `isolcpus=2 init=/bin/sh` tomaria
  a máquina. Só passam listas de CPU, números e opções do catálogo, sem espaço nem `=` (teste no
  model e no comando).
- **A fonte da GUI não tem "→", "⚠", "ⓘ", "▸", "▾"** (viram um quadrado). Para não depender deles:
  - ⓘ e as setas das seções são desenhados;
  - um teste impede esses glifos nos catálogos;
  - o System › Log ainda usa "→" (G0.15c).
