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
| G1.26c | CPU e IRQ: afinidade por nó NUMA, RPS/XPS, governor, C-states por PM QoS, watchdog | aberto |
| G1.26d | Boot: parâmetros da imagem A/B | aberto |

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
- **HAL**:
  - `system_info` lê a máquina: CPUs, nós NUMA, RAM, kernel.
  - `sysctls` lê os valores atuais.
  - `kernel_stats` lê os contadores do diagnóstico.
  - `apply` grava, tudo ou nada: se um valor é recusado (ausente, só leitura, ou o kernel guardou
    outro), os já gravados voltam e o commit falha com o motivo.
  - O `ip_forward` é gravado antes dos outros, porque mudá-lo reinicia parâmetros de configuração
    (`ip-sysctl.rst`).
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
  - encaminhamento ligado;
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
| `ip_forward = 0` | o roteador não roteia | crítico |

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
