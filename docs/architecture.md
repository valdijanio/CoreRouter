# CoreRouter — arquitetura

Status: esqueleto v0.1.0 (motor arquitetural pronto; sem data plane real). Números marcados como
**estimado** não foram medidos neste repositório.

## 1. Sistema base e stack de rede

### 1.1 Sistema operacional do roteador

**Decisão: imagem imutável construída com Buildroot, operada só pela API (filosofia Talos).**

| Opção | Prós | Contras | Veredito |
|---|---|---|---|
| **Buildroot** | Imagem de 30–60 MB (estimado), só o que compilamos, kernel e config sob controle total, reprodutível, cross-compile trivial (x86_64, aarch64) | Sem gerenciador de pacotes (é o objetivo) | **Produção** |
| Alpine imutável | musl, apk, comunidade grande | Ainda é uma distro de uso geral; superfície maior; atualização por pacote não é atômica | Lab/dev |
| Talos-like (custom init) | Sem shell, API-only, atômico | Talos é específico para Kubernetes; copiamos a filosofia, não o produto | Filosofia adotada |

Layout da imagem:

- Kernel LTS com `nftables`, `nf_flow_table` (+ offload), XDP/eBPF (BTF), MPLS (`mpls_router`,
  `mpls_iptunnel`), VRF, bonding, 802.1Q, bridge VLAN filtering, WireGuard.
- rootfs **squashfs read-only + dm-verity**, partições **A/B** (atualização atômica, volta para
  a partição anterior se o boot falhar), `/config` (ext4) gravável só pelo daemon.
- PID 1 mínimo (BusyBox init ou init em Rust) sobe `corerouter-daemon`; FRR, accel-ppp e
  serviços são filhos supervisionados pelo daemon. Sem SSH/shell por padrão; console de
  emergência atrás de flag de boot.
- Perfil de desenvolvimento: VM QEMU/Alpine ou Debian com o daemon em `--backend linux` dentro
  de network namespaces (gap G1.6).

#### 1.1.1 A imagem do G1.6a

Buildroot **2025.02 LTS** em `os/` (`BR2_EXTERNAL`), kernel **6.18 LTS** com tudo `=y`, EFI
stub sem bootloader, squashfs + `/config` ext4 e o slot `rootfs-b` reservado para o A/B do
G1.6b. O PID 1 é **`corerouter-init` em Rust** (não o busybox init): faz só montagem,
`/config`, supervisão do daemon com backoff, prontidão medida e desligamento limpo; o
busybox fica só como shell de manutenção atrás de `corerouter.shell=<tty>`. Para o G1.6b, a
recomendação é um atualizador próprio em Rust em vez do RAUC (a atualização tem de ser um
comando com journal e Safe Mode; boot por EFI stub). Comparação, fontes e números em
`docs/os-image.md`.

#### 1.1.2 A/B e atualização (G1.6b)

**Decisão: o gerenciador de boot da UEFI é o bootloader, e o `BootNext` é o contador de boot de
uma tentativa.** Cada slot tem um `Boot####` com a sua linha de comando (dm-verity por
`dm-mod.create`, sem initramfs; parâmetros do Tuning › Boot); `BootOrder` = confirmado, depois o
outro; o teste é um `BootNext`, que o firmware apaga ao usá-lo: qualquer falha volta ao
confirmado. Confirmar = reescrever o `BootOrder`. Comparado com um bootloader nosso (GRUB ou
systemd-boot com contador): nenhum binário a mais no caminho do boot e nada a decrementar, ao
custo de uma tentativa só (que é o que um roteador quer: cada tentativa ruim é tempo fora do ar)
e de depender do firmware honrar o `BootNext` (o init detecta quando não honra).

O código é o crate `corerouter-sysupdate` (L1, plataforma: só apps e xtask o usam): pacote
`.crpkg` (manifesto JSON assinado com Ed25519 do `ring`), árvore do dm-verity (formato do
`veritysetup`), variáveis por efivarfs, GPT, estado do teste em `/config/package/`. O engine só
enfileira (`system.package.*`, `crate::package`); o serviço `package` do daemon faz a E/S fora do
lock; o `corerouter-init` decide no boot (marca o teste, restaura a config depois de um teste
que falhou) e reinicia no prazo. Atualizador próprio × RAUC reavaliado com números (passou de
1.500 linhas): fica o próprio; comparação e números em `docs/os-image.md`, "A/B e atualização
segura".

### 1.2 Data plane, firewall e CGNAT

| Critério | Kernel nativo (Netlink + nftables) | **eBPF/XDP com `aya`** | DPDK / VPP |
|---|---|---|---|
| Desempenho | 1–3 Mpps/core no slow path; flowtable (fast path) muito mais (estimado) | 10–25 Mpps/core em XDP nativo (estimado) | 20–40+ Mpps/core (estimado) |
| Integração | Total: rotas, conntrack, tc, ferramentas Linux | Convive com o kernel; slow path continua no kernel | Tira a NIC do kernel; tudo precisa ser reimplementado ou espelhado |
| Segurança / Rust | `rtnetlink`/`netlink-packet-*` em Rust puro, sem `unsafe` nosso | `aya` em Rust puro; programas `no_std` exigem `unsafe` isolado; verificador do kernel limita o estrago | FFI C, hugepages, muito `unsafe` |
| Operação | Simples | Média (mapas, versões de kernel) | Cores dedicados, NICs suportadas, debugging difícil |

**Decisão: híbrido atrás do trait `Hal` (L1).**

1. **Fase 1–2:** kernel nativo. `rtnetlink`/`netlink-packet-route` para links, VLAN, bridge,
   endereços, rotas e rotas MPLS; nftables via netlink batch (transação atômica do kernel) para
   firewall/NAT; **flowtables** para o fast path de conexões estabelecidas.
2. **Fase 2+:** `dataplane-ebpf` (XDP com `aya`) para o que o kernel não escala bem: **CGNAT
   determinístico com port-block allocation** (RFC 6888/7422 — log por bloco, não por sessão),
   ACL de borda e mitigação de DDoS. Programas no crate isolado `dataplane-ebpf` (único lugar
   com `unsafe`), tipos compartilhados em `dataplane-ebpf-common`, loader no `hal-linux`.
   **G2.5a (feito):** filtro anti-DDoS em XDP (`docs/xdp.md`). Escolhas e porquê: programa em
   Rust (`aya-ebpf`) em vez de C/libbpf (uma linguagem só; a lógica de parse e decisão é a mesma
   função no kernel e nos testes do host, com diferencial kernel × host no CI); objeto
   pré-compilado com hash das fontes em vez de compilar no build normal (o workspace continua
   estável, sem nightly nem `bpf-linker`); mapas com chaves e valores de inteiros/arrays (o
   loader não precisa de `unsafe impl Pod`); links por processo (daemon morto = fail-open).
   Medido no CI: a LPM custa ~17 ns por pacote, plana até um milhão de prefixos; em veth o XDP
   (402–409 kpps) **não** ganha do nftables raw (471 kpps), porque o veth já entrega um `skb`. A
   razão de ser do XDP (não alocar o `skb`) só aparece no modo native de uma placa real: a medida
   que confirma ou derruba esta decisão é o roteiro do `docs/xdp.md`, no hardware do usuário.
   **Licença do XDP (G2.5b, decisão do usuário):** `dataplane-ebpf`, `dataplane-ebpf-common` e
   `cgnat-map` são GPL-2.0-or-later (o programa declara `"GPL"`), para o kernel liberar os helpers
   `gpl_only` como o `bpf_fib_lookup` do fast path do CGNAT; o resto do projeto continua
   AGPL-3.0-or-later, com que GPL-2.0-or-later combina (`docs/xdp.md` § Licença).
3. **DPDK/VPP:** não entra no caminho crítico. Se um cliente precisar de >100 Gbit/s de CGNAT
   por caixa, vira um terceiro backend do mesmo trait (VPP pela API binária).

#### 1.2.1 nftables: netlink direto × o binário `nft` (G2.3b, **medido**)

O CGNAT fala com o nf_tables por **nfnetlink**, num lote atômico (`NFNL_MSG_BATCH_BEGIN/END`), sem
o programa `nft`. O encoder é próprio, em `crates/hal-linux/src/nfnl.rs`, sem `unsafe`.

Descrição única: `corerouter_firewall::program::Table`. Dela saem tanto o texto de "Ver regras"
quanto as mensagens.

Números do CGNAT: AMD Ryzen AI MAX+ 395 (32 threads), kernel 7.0, nft 1.0.9, build release,
netns sem root, 2026-10-23, `cargo bench -p corerouter-hal-linux --bench netns_cgnat`.

| Operação | netlink (Rust) | `nft -f` |
|---|---|---|
| tabela com 1 Ki assinantes | 17,5 ms | 23,7 ms |
| tabela com 16 Ki assinantes | 26,5 ms | 90,0 ms |
| tabela com 64 Ki assinantes | 66,0 ms | 303 ms |
| um assinante a mais numa tabela de 64 Ki (com o diff) | 0,155 ms | 2,40 ms |

**Por que netlink:**

- É 4,6× mais rápido para carregar e 15× para mudar um elemento.
- O `nft` precisa de uma correspondência de protocolo para mapear portas; o kernel, não. Por
  isso uma regra só cobre TCP, UDP, ICMP e o resto, e o mapa `a_` por pool deixou de existir.
- Sem um processo externo nem texto gerado para outro parser, a mudança vai como diferença de
  elementos. Os mapeamentos UDP vivos (EIM) sobrevivem a uma mudança que não remapeia ninguém.
- O kernel continua dono da atomicidade: o lote entra inteiro ou nada.

**O que se paga:**

- Mantemos os números de atributo da UAPI (`nf_tables.h`, que só cresce por acréscimo) e um
  subconjunto pequeno de expressões: `payload`, `meta`, `cmp`, `bitwise`, `ct`, `lookup`, `nat`,
  `dynset`, `counter`, `immediate`.
- Os testes em netns conferem que o kernel aceita e que o `nft list` lê o que foi carregado.
- Os crates Rust disponíveis não cobriam faixas na NAT, `dynset` nem dados de mapa com faixa:
  `rustables` 0.9 (GPL, bindgen e `unsafe`) e `netlink-packet-netfilter` 0.4 (sem `nat`, `ct` e
  `dynset`).

**Limite em user namespace:**

- Lá o `SO_SNDBUFFORCE` é recusado e o lote cabe em 2 × `wmem_max`, cerca de 8 MiB, ou seja, uns
  150 mil assinantes (**estimado**).
- No roteador o daemon é root e o limite some.

O firewall do G2.1 passou para o mesmo encoder na G2.8 (abaixo).

**G2.8, o firewall (`inet corerouter`) por nfnetlink (medido).** Mesma máquina, kernel 7.0,
nft 1.0.9, build release, netns sem root, 2026-10-27,
`cargo bench -p corerouter-hal-linux --bench netns_firewall`. "nft" é o caminho de antes
(`nft -j list` + `nft -f` do ruleset inteiro, com o texto antigo de sets anônimos):

| Operação | nfnetlink | `nft` (antes) |
|---|---|---|
| carregar 100 / 1 000 / 10 000 regras | 17,4 / 24,6 / 112 ms | 22,8 / 49,3 ms / 4,09 s |
| mudar 1 regra em 100 / 1 000 / 10 000 | 15,8 / 22,3 / 109 ms | 26,7 / 99,4 ms / 6,91 s |
| 1 000 entradas dinâmicas | 0,92 ms (um lote) | 2,37 s (um `nft` por entrada) |
| 100 000 entradas dinâmicas | 116 ms | não cabe ("Message too long"); 383 ms num `add element` único |
| ler 1 000 / 100 000 entradas dinâmicas | 0,24 / 246 ms | 3,3 / 636 ms (`nft -j`) |

- **Só a diferença:** o commit lê os handles do kernel (um dump), confere que a tabela é a que
  carregamos e manda num lote só as regras que saíram (`DELRULE`), as que entraram no lugar
  (`NEWRULE` com posição), os elementos e as chains/sets que mudaram. Regra igual mantém o handle
  e os contadores. Tabela alterada por terceiros ou set com outra definição: troca inteira.
- **O kernel é o gargalo do commit:** qualquer lote que remove algo espera um período de graça
  RCU, 12–28 ms (o próprio `nft delete rule` leva isso); só acrescentar custa ~0,5 ms.
- **Sets anônimos custam O(sets) cada no kernel** (nome e busca por nome varrem a lista da
  tabela): 10 000 regras com `th dport { 22, 80, 443 }` levavam 22 s, com `ct state { … }` 3,2 s,
  no `nft` e em nós. Listas de portas viraram sets nomeados compartilhados por conteúdo
  (`ports_22_80_443`) e `ct state a,b` máscara (o estado é um bit): 77 ms e 63 ms.
- **Paralelismo:** o programa antigo, o novo e o dump do kernel são independentes e rodam em
  threads (10 000 regras: 15 + 15 + 38 ms em série). Os lotes não paralelizam: o nfnetlink segura
  o mutex do nf_tables por lote inteiro; 100 000 entradas em 4 threads/4 sockets ≈ 1 lote só,
  dentro do ruído, e com corrida entre lotes do mesmo set. Em 100 000 entradas o kernel leva
  ~97 ms e o espaço de usuário ~8 ms (merge em `u128`, era 10 ms com `Vec<u8>`).
- **O dump fica:** 12 500 regras são 6,3 MB e 25–28 ms só de kernel; é o que detecta a tabela
  mexida por outro. Guardar handles e conferir o `genid` evitaria o dump, mas o genid muda a cada
  commit de qualquer tabela (o CGNAT muda por assinante), então o cache quase nunca valeria.
- O `nft` não roda mais em produção; a imagem perde o jansson (`nft -j`).

#### 1.2.2 CGNAT sem portas: nfqueue só dos quase cheios (G2.7, **medido**)

A RFC 6888 REQ-11b pede um ICMP ao assinante cuja conexão nova não acha porta. O kernel derruba essa
conexão no `confirm` do conntrack, depois de todo gancho. As opções comparadas:

- **`reject` no nftables:** não vê a falha (e nem vale em `postrouting`). Descartado.
- **XDP ou TC:** também não veem a falha. Um programa eBPF num tracepoint do `kfree_skb` exigiria
  root e BTF e ficaria fora do crate isolado. Descartado.
- **nfqueue de todas as conexões novas:** levaria ao userspace ~255 mil por segundo. Descartado.
- **nfqueue só dos assinantes acima de 80 % da faixa** (adotado):
  - Rust puro, sem processo externo;
  - quatro filas com uma thread cada e consulta da tupla pelo ctnetlink;
  - custo no caso normal dentro do ruído (280 557 × 285 774 conexões novas/s, sem × com a chain);
  - 125 µs até o ICMP e 188 mil recusas/s por thread.

Números e método em `docs/cgnat.md` §1.9 e §6.7.

### 1.3 Control plane (BGP, OSPF, MPLS/LDP, BFD)

**Decisão: orquestrar FRRouting sob a camada transacional do engine; avaliar holo como segundo
backend.**

- Reescrever BGP/OSPF/LDP/BFD com interoperabilidade de produção custa anos (estimado); FRR é
  maduro, usado por operadores e testado contra os grandes fabricantes.
- O engine continua dono da verdade: o candidate é validado pelos `proto-*` (L2), que
  **renderizam** a config FRR (`proto-bgp::render_frr`). O driver `hal-frr` (G3.1, plataforma,
  só as apps o usam) implementa o trait `hal::routing::RoutingDaemon`: a cada commit que muda
  `routing`, depois do `Hal::apply`, ele lê a config que cada daemon roda, aplica só a
  diferença e, se o FRR recusar uma linha, desfaz o que digitou; o engine então desfaz o
  `Hal::apply` e o commit falha. Nunca reinicia o FRR nem derruba sessão que o commit não muda.
- **Como falar com o FRR (G3.1, medido).** Comparamos três formas no FRR 10.7.1 da VM do
  laboratório (8 vCPUs, build release, 2026-10-27, duas rodadas; `scripts/frr-compare.sh`). As
  tabelas completas estão em `docs/perf.md`.
  - **(a) `frr-reload.py` + `vtysh -c '… json'`.** É Python, abre um `vtysh` por passo e diffa
    o texto inteiro.
  - **(b) o socket vty de cada daemon, falado em Rust** (`/var/run/frr/<daemon>.vty`, o mesmo
    protocolo do `vtysh`: comando terminado em NUL, resposta + `\0\0\0<código>`,
    `lib/vty.c`). O diff é feito em Rust, e os daemons são configurados em paralelo, um thread
    nomeado por daemon.
  - **(c) misto: diff em Rust + `vtysh -f`.** Um processo a mais a cada apply.

  | Medida | (b) | (c) | (a) |
  |---|---|---|---|
  | mudança pequena | 1,1–7,2 ms | 13–22 ms | 0,14–0,98 s |
  | +10 mil entradas de prefix-list | 1,65–1,77 s | 1,6–2,9 s | 3,7–4,1 s |
  | −5 mil entradas | 2,5–2,7 s | 2,6–2,8 s | 3,7–4,0 s |
  | ler 100 sessões | 2,3–2,6 ms | — | 10–12 ms (`vtysh -c`) |
  | memória do processo | 4–16 MiB | 23 MiB | 18–36 MiB |

  - **Paralelismo.** Um prefix-list é digitado no mgmtd (que o repassa ao zebra) e no bgpd. Em
    série, o (b) levava 3,3–5,2 s (+10 mil) e 4,9–5,5 s (−5 mil). Com um thread por daemon, o
    commit leva o tempo do mais lento, não a soma. O tempo restante é do FRR: o `vtysh -f` gasta
    o mesmo, e o parse e o diff em Rust de 10 mil linhas levam ~1 ms (criterion).
  - **1 M de rotas.** O `show ip route json` leva ~13 s pelos dois caminhos e gera 537 MiB: o
    custo é do zebra. Interpretar isso como `serde_json::Value` passou de 5 GiB. Estado de rota
    vem do resumo (`… summary json`, 0,13 s) ou de consultas por prefixo, nunca da tabela
    inteira.
  - **mgmtd e gRPC (b original) não servem ao BGP hoje.** O mgmtd do FRR 10.x só cobre zebra,
    staticd, ripd e ripngd; bgpd e ospfd ainda não foram convertidos. O gRPC northbound é
    experimental e não vem nos pacotes do deb.frrouting.org. Para o que já é dele (os filtros
    do zebra), o driver fala com o mgmtd pelo mesmo socket vty, com `configure terminal
    file-lock`. O mesmo trait recebe um backend mgmtd nativo quando o bgpd for convertido, ou o
    holo (G3.8).
  - **Decisão: (b).** Nenhum processo externo nem Python, e é a forma mais rápida ou empatada
    em todas as medidas. O lote vai entre `XFRR_start_configuration` e
    `XFRR_end_configuration`, como o `vtysh -f` faz: prefix-lists e route-maps do northbound
    viram um commit só, e o bgpd segura os vizinhos novos até o fim, de modo que a sessão não
    sobe antes da política digitada junto.
  - **Armadilha medida.** Um filtro compartilhado precisa ir a todo daemon que o guarda. O
    `vtysh` mostra as cópias somadas, então um daemon esquecido esconde a diferença: o
    `frr-reload.py` chegou a pular 10 mil linhas que só a cópia do zebra tinha.
- **Contextos do CoreRouter.** O driver só toca nos contextos da tabela `hal_frr::render::OWNED`
  (hoje `router bgp`). O resto da config do FRR (`hostname`, `log`, interfaces) fica como está.
  O diff é por contexto e trata o conteúdo como conjunto; uma configuração de valor único
  (`bgp router-id`, `neighbor X remote-as`) é reescrita por cima, e não apagada antes, porque
  `no neighbor X remote-as` remove o vizinho inteiro.
- **Estado fora do lock.** O serviço `frr` do daemon (`--frr <dir>`) lê as sessões a cada 2 s
  numa conexão própria e só pega o lock do `Session` para copiar a parte `routing` e guardar a
  amostra. Quando o FRR volta depois de cair, a config em execução é reinstalada
  (`Session::routing_resync`), sob o lock, para não intercalar com um commit. Um restart
  mais rápido que a leitura é visto pelos PIDs dos daemons (`<daemon>.pid`). Dentro de um
  daemon o envio é sequencial: ele atende um comando por vez por conexão, e o custo é dele.
- **RPKI e tabelas BGP (G3.2c, `docs/rpki.md`).** Quem descarta inválidas é o FRR
  (`bgpd_rpki`, route-map `CR-RPKI-IN` com `soft-reconfiguration inbound`, que a revalidação do
  FRR exige). O CoreRouter tem o seu próprio cliente RTR em Rust (`proto_bgp::rtr`, uma thread por
  validador no serviço `rpki`) e uma árvore de VRPs para os selos e o `rpki-check`: consultar o
  FRR rota a rota ou ler a `prefix-table` inteira a cada mudança custaria mais e não daria versão,
  serial nem expiração. Listas de rotas e "Por que essa rota?" leem o bgpd num job do runner,
  nunca sob o lock, com o JSON lido em streaming direto do socket para uma tabela compacta (24 B
  por rota); as páginas saem da memória. Números em `docs/perf.md` (G3.2c).
- **RFC 8212.** O perfil `traditional` do FRR liga `bgp ebgp-requires-policy` e o render não
  desliga. Uma sessão eBGP sem política não aceita nem anuncia rota (no teste com FRR real,
  `prefix_count` é 0 com o par anunciando). As políticas chegaram com a G3.2b (abaixo).
- **Políticas BGP: `/routing filter` compilado para route-map (G3.2b, `docs/bgp-policy.md`).**
  O texto das regras (linguagem do RouterOS v7) é parseado em Rust (`proto-bgp::filter`), avaliado
  em Rust para a prévia e o impacto no commit, e **compilado** para route-maps do FRR (testes com
  `on-match goto` só para a frente, `jump` expandido, fim `deny 65535`). Comparado: (a) render
  ingênuo regra → entrada, que não exprime `if/else`, `||` nem `not`; (b) `call` do FRR para
  `jump`, que não distingue "a chain chamada aceitou" de "caiu no fim" — o RouterOS distingue;
  (c) avaliar só no FRR (sem avaliador próprio), que não dá prévia antes do commit. Ficamos com
  avaliador + compilador e um proptest que exige que os dois deem o mesmo veredito e os mesmos
  atributos (20 000 casos). Números (**medido**, 32 núcleos, release, 2026-10-27): prévia de 1 M
  rotas 311 ms em 1 thread, 48 ms em 8, 30 ms em 16 (dividida por faixa de rotas, política
  compartilhada sem lock); compilar 10 000 regras 30 ms (era 146 ms: regex checada só na
  sintaxe e compilada uma vez, parse e regex em threads); render 15 ms (era 98 ms); diff no FRR
  de 10 000 regras com uma mudada 14,6 ms; FRR real aplica a mudança de uma regra em 2,7 ms (14
  linhas). As rotas da prévia com FRR são lidas pela thread do FRR do daemon, fora do lock
  (`engine::bgp_routes`), e `keep_received` (`soft-reconfiguration inbound`, padrão sim, como o
  RouterOS guarda as rejeitadas) mantém as recebidas antes da política.
- **Vizinhos BGP no modelo RouterOS v7 (G3.2a, `docs/bgp.md`).** `routing.bgp_templates` e
  `routing.bgp_connections` (`corerouter_model::bgp`). Os templates são **achatados** no render:
  cada vizinho vai ao FRR com os valores em vigor, sem `peer-group`. Um template do RouterOS
  tem vários pais e qualquer valor é sobrescrito na conexão; um peer-group tem um pai só, e
  alguns parâmetros não se sobrescrevem por membro. Mudar um template digita as linhas que
  mudaram em cada vizinho que herda o valor, e nada mais. Medido com FRR 10.7.1 real (VM do
  laboratório, debug do nosso lado, 2026-10-27): 1 000 conexões aplicadas em 329 ms (5 006
  comandos), uma mudada entre 1 000 em 28 ms (3 comandos), todas removidas em 197 ms.
  - **Ordem do diff.** Um vizinho existe da linha `neighbor X remote-as` até `no neighbor X
    remote-as`, que leva junto todas as outras linhas dele, nas famílias também. O diff define
    os vizinhos novos antes das mudanças dentro das famílias (o `activate`) e remove os
    vizinhos apagados por último, com um comando só.
  - **Chave TCP MD5.** Fica selada (`sealing`, a mesma AES-256-GCM das senhas PPP). O backend
    recebe do engine um `SecretOpener` ao ser ligado e abre a chave só no render. O
    `hal-frr` mascara `password` em erro e log.
  - **`routing` é uma seção `CowArc`, e o delta do histórico é por conexão.** Antes, a seção
    era serializada inteira duas vezes em todo commit (o delta do histórico e o arquivo da
    revisão anterior), até nos commits de firewall. Medido com 1 000 conexões, release:
    mudar uma passou de 8,1 ms para 1,5 ms por commit (criterion, `engine/benches/bgp.rs`), e
    um commit que não toca `routing` não copia nem serializa a seção.
- **OSPF no modelo RouterOS v7 (G3.4, `docs/ospf.md`).** `routing.ospf` (`corerouter_model::ospf`):
  instâncias, áreas, ranges, interface templates, vizinhos estáticos e key chains. O FRR roda o
  protocolo e o SPF; o `proto-ospf` resolve os templates em interfaces (o primeiro que casa por
  nome, lista ou rede) e renderiza um contexto `interface X` por interface (`ip ospf area`, não
  `network … area`, que o FRR não mistura e que não carrega valores por template). O `hal-frr`
  ganhou a posse parcial de um contexto (`render::CHILDREN`): no `ospfd` as linhas `ip ospf …`, no
  `ospf6d` as `ipv6 ospf6 …`, e a `description` do zebra que eles imprimem fica de fora. Chave
  cripto sempre por key chain `CR-…` (o `ospfd` só faz HMAC-SHA por key chain), selada como a
  chave TCP MD5 do BGP. A `out_filter_chain` reaproveita o compilador da G3.2b
  (`proto-ospf` → `proto-bgp`, lateral permitido) com listas renomeadas `CR-O2-`/`CR-O3-`, porque
  o `ospfd` recusa as linhas BGP dos route-maps do `bgpd`. Índice de templates por nome: 4 000
  interfaces × 1 000 templates em 10,9 ms (era 145,7 ms, **medido**).
- **holo** (suíte de roteamento em Rust, modelo YANG) é o candidato a backend Rust-nativo do
  mesmo trait (G3.8) — sem mudar UI, comandos ou MCP.
- FSMs próprias só para o **simulador** (sessões BGP/OSPF entre roteadores virtuais no lab, G3.7)
  e onde não houver implementação madura.
- **Simulador de rede (G3.7, `docs/netsim.md`).** `crates/netsim` (L2, puro, wasm) roda OSPF,
  BGP e BFD simplificados por eventos discretos num relógio virtual; cada roteador virtual é um
  `Session` sobre o `VirtualHal`, configurado por comandos, e o simulador lê a running dele.
  Comparado: (a) emular o FRR real em contêineres (containerlab, CML, GNS3), fiel mas sem wasm,
  sem relógio virtual e com GBs por nó; (b) só análise estática da config (Batfish), rápida mas
  sem o tempo de convergência; (c) FSMs simplificadas próprias. Ficamos com (c) para a janela e o
  CI, conferindo o processo de decisão contra `proto_bgp::decision` (proptest) e, na G3.7c, as
  melhores rotas contra o FRR real. Paralelismo por janelas conservadoras (lookahead = menor
  latência) com um pool de threads persistente; números em `docs/perf.md` (G3.7).

### 1.4 Serviços de borda

| Serviço | Escolha | Observação |
|---|---|---|
| DNS: resolvedor do roteador, encaminhador com cache, estáticos, servidor autoritativo | Hickory DNS, Rust puro (decisão do usuário, 2026-10-22): `hickory-proto` no resolvedor (G4.1a), `hickory-server` no servidor (G4.1c) | Num processo só, integrado aos comandos e às transações; veja "DNS (G4.1)" na seção 3 e `docs/dns.md` |
| DHCPv4/DHCPv6 (+PD) e relay | Rust puro (decisão do usuário, 2026-10-22). DHCPv4: codec `dhcproto` atrás de um saneador no cliente; o servidor (G4.2a) lê pedidos com leitor próprio e responde pelo `dhcproto`; DHCPv6: codec próprio (G4.7b: o `dhcproto` 0.15 v6 dá panic/dessincroniza com bytes hostis); servidor e diário de concessões próprios | Diário só de acréscimo em `/config` com `fdatasync` antes do ACK e compactação atômica; veja "Servidor DHCP (G4.2)" e `docs/dhcp.md` |
| PPPoE / IPoE (BNG) | Rust puro (decisão do usuário, 2026-10-24): plano de controle próprio sans-IO (`proto-pppoe`, G4.3a: Discovery, LCP, PAP/CHAP/MS-CHAP, IPCP/IPv6CP) sobre AF_PACKET, RADIUS em `proto-radius` (G4.3b), plano de dados em XDP (G4.3c); substitui a orquestração do `accel-ppp` | Desempenho (sem netdev `ppp` por sessão no kernel, o gargalo com dezenas de milhares de assinantes), nenhum ioctl `unsafe` do `/dev/ppp` fora do `dataplane-ebpf`, sessões, transações e MCP no próprio motor; correção garantida por teste em massa (100 mil sessões, rede hostil, ataques) em vez da maturidade de um processo externo; veja `docs/pppoe.md` |
| Alta disponibilidade do BNG (par ativo/espera) | Rust puro (G4.3h): `proto-ha` sans-IO (máquina de papéis com cerca por maioria de três, sync de sessões por snapshot + deltas sobre o canal de controle TLS, hello autenticado no acesso), em vez de VRRP/keepalived em volta do serviço | VRRP/keepalived só troca o MAC: as sessões PPPoE morreriam (o estado mora no nosso processo); o sync precisa do estado do `proto-pppoe` e da contabilização. **Medido**: 1 milhão de mudanças/s num núcleo, 216 B por sessão no fio, snapshot de 100 mil em 55 ms; veja `docs/bng-ha.md` |
| NTP | Cliente SNTP próprio (G4.6: `proto-ntp` L2 puro + thread no daemon); `ntpd-rs` fica como opção para o servidor NTP e a disciplina do relógio (G4.6b/G4.6c) | Medir o offset é um pacote de 48 bytes e quatro timestamps (RFC 5905 §8/§14): um processo externo a mais não paga isso, e o status vai direto para `system.ntp.client.get` sem parsear saída. Ajustar o relógio (slew/step, `CAP_SYS_TIME`) e servir hora são outra conversa: lá a maturidade do `ntpd-rs`/chrony pesa mais |
| Syslog remoto | Codec RFC 5424 próprio (`proto-syslog`, só encode) + UDP (RFC 5426) no daemon | Regras e ações estilo `/system logging` do RouterOS no engine; TCP/TLS (RFC 5425) depois |
| Gerência remota | `rustls` + provedor `ring` (TLS do canal de controle e do WebSocket), `rcgen` (certificado autoassinado), `argon2` (hash de senha), `keyring` ("Remember password" da GUI nativa); `russh` (CLI SSH) depois | G0.3 feito |
| Telemetria | `prometheus-client`; fluxos IPFIX/NetFlow v9 em Rust puro (`proto-flow`, G4.4b), dos eventos do conntrack; sFlow depois | Veja 1.4.1 e `docs/traffic-flow.md` |
| Histórico de longo prazo (métricas, logs, fluxos, NAT) | ClickHouse **externo e opcional**, alimentado pelo serviço `analytics` do daemon (G4.4f): `INSERT … JSONEachRow` com gzip pela interface HTTP, cliente HTTP/TLS próprio (rustls), sem driver em C nem processo auxiliar | O roteador fica leve e não guarda nada de longo prazo; veja "Exportador ClickHouse (G4.4f)" na seção 3 e `docs/analytics.md` |

#### 1.4.1 Fluxos: eventos do conntrack em Rust (G4.4b, **medido**)

O exportador de fluxos lê os eventos `NEW`/`DESTROY` do conntrack por ctnetlink, monta os registros
num medidor puro (`proto-flow`) e codifica IPFIX/NetFlow v9 sem processo externo.

| Opção | Por que não |
|---|---|
| **ipt-netflow** (módulo de kernel) | Módulo fora da árvore: precisa ser recompilado a cada kernel e pode derrubar o roteador. Os eventos de NAT saem com `natEvent` 1/2 (Historic na RFC 8158). Para o NAT ele já usa os eventos do conntrack, a mesma fonte que adotamos |
| **softflowd / pmacctd** (pcap) | Copia cada pacote para o espaço do usuário: inviável a 10–100 Gbit/s. Não vê a tradução do NAT |
| **amostragem por pacote** (sFlow, NFLOG) | Perde conexões curtas, e o NAT de cada uma é exatamente o que o Marco Civil pede para guardar |

Números (`docs/traffic-flow.md`): o codec faz 16 M registros/s. Ponta a ponta, em netns e com o
daemon sem otimização, 20 mil conexões com NAT saem em 0,24 s, a 4,7 µs de CPU por registro, sem
perda. A interface de cada fluxo vem da tabela de rotas; a fonte XDP (G2.5) pode dar a interface
real depois, sem mudar o codec.

#### 1.4.2 IPFIX sobre SCTP e TLS em Rust (G4.4j, **medido**)

| Opção | Decisão |
|---|---|
| **SCTP do kernel** por `socket2` (`socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)`) | Adotado. Sem `unsafe`, sem crate novo: o kernel faz associação, retransmissão, PMTU e SHUTDOWN; uma mensagem IPFIX por `send`. No CI completo o módulo `sctp` é carregado (`ci/kernel-modules/sctp`) |
| SCTP em espaço de usuário (sobre UDP, RFC 6951) | Recusado: reimplementar SCTP é risco de bug sem ganho; coletores esperam SCTP nativo |
| **TLS** com rustls (já no projeto, `custom_tls_config` do G4.4f) | Adotado: TLS 1.2/1.3, mútuo |
| DTLS (UDP/SCTP) | Fora: rustls não tem DTLS; as alternativas em Rust são grandes e assíncronas (tokio) ou ligam OpenSSL. Gap G4.4k |

Cada coletor de stream tem a sua thread de envio (`tf-send-<id>`) com fila limitada em bytes: a
cifra de cada coletor roda num núcleo próprio e um coletor lento não segura os outros nem o
exportador. Rajada de 100 mil conexões com NAT (release, netns): os 100 mil eventos de criação
saíram pelo TCP 0,38 s após o início, 1,6 µs de CPU do daemon por registro, sem descarte.

## 2. Camadas do workspace

Regra central: dependência só para baixo; nada abaixo de L5 depende de egui/eframe/winit/wgpu.
Imposta por `cargo xtask layers` (`xtask/src/layers.rs`, com testes).

| Camada | Crate | Responsabilidade | Pode depender de |
|---|---|---|---|
| L0 | `crates/model` | Tipos (Asn, VlanId, IfName, MacAddr, ItemId, Gateway, RoutingTable, prefixos `ipnet`), árvore `Config`, `ConfigStore` (candidate/running, commit, rollback, diff, histórico), `route` (resolução de gateway e rotas conectadas), `users` (contas e grupos, salvos fora das revisões), `firewall` e `interface_list` (G2.1), `cgnat` (G2.3: pools e a função de mapeamento `Layout`, RFC 7422, a mesma para engine, kernel e XDP; `docs/cgnat.md`) | serde, ipnet, thiserror |
| L0 | `crates/buildinfo` | Versão e commit do build (`COREROUTER_COMMIT` pelo `build.rs`): `server.info` e o aviso de daemon de outro commit na GUI. Crate à parte para um commit novo não recompilar o workspace | nada do workspace |
| L1 | `crates/hal` | Trait `Hal` (discover, apply transacional, poll, relógio, features, `prober`, entradas dinâmicas de address-list, transporte do cliente DHCP `dhcp_port`/`DhcpPort`, G4.7; DHCPv6 `dhcp6_port`/`Dhcp6Port` e o que o kernel aprendeu por RA `ipv6_learned`/`Learned`, G4.7b; `sfp_module`/`cable_tester`, G1.20) + `VirtualHal` (lab, wasm, CI; guarda o ruleset que aplicaria; simula um SFP+ e o teste de cabo); `probe` (trait `Prober`/`ProbeSocket` das ferramentas), `sim` (rede simulada determinística, G6.2) e `sff` (EEPROM SFF-8472/8636 decodificado em código puro, G1.20) | L0, `firewall` (lateral permitido) |
| L1 | `crates/firewall` | Firewall puro (G2.1): validação, grafo de jumps e render nftables da tabela `inet corerouter`; a tabela `ip corerouter_cgnat` do CGNAT (`cgnat`, G2.3); o flowtable `inet corerouter_fastpath` (`fastpath`, G2.4); sem I/O, compila para wasm. L1 (e não `proto-*`) porque o `hal-linux` também renderiza. Veja `docs/firewall.md` | L0 |
| L1 | `crates/hal-linux` | Backend Linux: `apply` via rtnetlink (links, VLAN, bridge, dummy, VRF, endereços, rotas estáticas; G1.2/G1.5), descoberta/contadores via rtnetlink (`RTM_GETLINK`, G1.18) com política de posse (`owner`); I/O de descoberta de vizinhos (`l2`: LLDP por `AF_PACKET`, escuta MNDP em UDP 5678; G5.2, só bytes); ICMP das ferramentas (`icmp`: ping socket ou raw, G6.2); firewall por `nft -f -` (módulo `nft`, G2.1); CGNAT e fast path por nfnetlink (`nfnl`, `cgnat`, G2.3b; `fastpath`, flowtable e eSwitch por devlink, G2.4) e conntrack por ctnetlink (`ctnl`, G2.2; eventos `NEW`/`DESTROY` para o Traffic Flow, `ctnl::Events`, G4.4b); estado/hardware/contadores das portas por ethtool e devlink netlink (`genl`, `ethtool`, `nic`, `pci_ids`; G1.19, sem ioctl — veja `docs/interfaces.md`); cliente DHCP (`dhcp`: `AF_PACKET` com filtro BPF, UDP 68, sonda ARP; G4.7); cliente DHCPv6 (`dhcp6`: UDP 546 → `ff02::1:2`) e RA (`ra`: `accept_ra` por interface a cada apply, limpeza do aprendido; G4.7b); configuração Ethernet, EEPROM do módulo e teste de cabo por ethtool netlink (`ether`, G1.20). **Plataforma** | L0, `hal`, `firewall` (laterais permitidos) |
| L2 | `crates/proto-{bgp,ospf,mpls,cgnat,dns,dhcp}` | `validate(&Config) -> Vec<Issue>` + render para o backend (FRR, nftables…); `proto-dhcp` também tem o codec DHCPv4 (`dhcproto` atrás de um saneador), a máquina de estados pura do cliente e o servidor simulado do lab (G4.7, `docs/dhcp-client.md`); o mesmo para DHCPv6 com codec próprio (`v6`, `client6`, `lab6`; G4.7b) | L0, L1 |
| L2 | `crates/netsim` | Simulador de rede do lab (G3.7): roteadores virtuais com OSPF, BGP e BFD simplificados, eventos discretos num relógio virtual, janelas paralelas (pool de threads só no nativo), falhas, linha do tempo e convergência; topologias prontas (`preset`). Puro, compila em wasm. Veja `docs/netsim.md` | L0, `proto-bgp` (lateral permitido: filtros e processo de decisão) |
| L2 | `crates/hal-frr` | Driver do FRR (G3.1): `conf` (árvore do `frr.conf`, diff por contexto), `render` (render dos `proto-*` por daemon, contextos do CoreRouter, posse parcial de `interface` por daemon: G3.4), `vty` (socket vty dos daemons, sem `vtysh`), `state` (sessões BGP do JSON do bgpd); implementa `hal::routing::RoutingDaemon`. **Plataforma** | L0, `hal`, `proto-bgp`, `proto-ospf` (lateral permitido) |
| L2 | `crates/proto-discovery` | CRDP, protocolo de descoberta próprio: codec puro (`Announcement::encode`/`decode`) + `validate` das configurações de descoberta. Veja `docs/discovery.md` | L0 |
| L2 | `crates/proto-flow` | Exportação de fluxos (G4.4b): IPFIX (RFC 7011) e NetFlow v9 (RFC 3954), codificador e decodificador; eventos de NAT (RFC 8158); o medidor que transforma eventos do conntrack em registros (timeouts, amostragem, cache limitado). Puro, compila em wasm. Veja `docs/traffic-flow.md` | L0, L1 |
| L2 | `crates/proto-{lldp,mndp}` | Codecs puros de descoberta: LLDPDU (`decode`/`encode`) e anúncio MNDP (só `decode`; nunca anunciamos MNDP). Veja `docs/lldp-mndp.md` | nada do workspace |
| L3 | `crates/engine` | `Session::execute`, `CommandSpec`/`cmd!`, checagem de params, **permissão por grupo** (`auth`: `Principal` do `Caller`, Argon2id), guard de panic, commit/rollback, batch, journal (sem segredos), tabela de vizinhos (estado operacional), tarefas das ferramentas (`tasks`, `tools/`: ping, MTU, MTR; G6.1–G6.3), clientes DHCP em execução (`dhcp_client`: `Session::dhcp_service`, concessões como entradas dinâmicas vistas pelo HAL em `Session::effective`; G4.7; DHCPv6 em `dhcp6_client`, com os endereços `from_pool` resolvidos no mesmo `effective`, G4.7b) | L0–L2 (nunca plataforma) |
| L4 | `crates/control` | Canal JSON-por-linha (TCP em loopback ou TLS em qualquer endereço), WebSocket com lista de `Origin` (+ arquivos da GUI web), `dispatch`, `Host`, `Client`; G0.3: `auth::Gate` (login, tokens, limite de força bruta), `local_token`, `tls` (rustls, pinagem), `known_hosts` (TOFU), `dial`; `ThreadRunner` das tarefas (G6.1) | L0–L3 |
| L4 | `crates/discovery` | Runtime do CRDP (sockets UDP + threads std, `socket2`): `Agent` do daemon (anuncia, escuta, alimenta `Session::record_neighbor`) e `Listener` passivo da GUI nativa; não compila para wasm | L0–L3 |
| L4 | `crates/storage-fs` | `ConfigStorage` em diretório (`/config`): `running.json` + `.prev`, um `rev-<n>.json` por revisão e o journal de commits `journal-config.log` (G0.22), escrita atômica | L0–L3 |
| L4 | `crates/shell` | Terminal estilo RouterOS gerado do `engine.list`: parser, Tab, cores, `print`, `/export`/`/import`. Puro (sem I/O, wasm): pede chamadas do canal de controle ao front end (janela da GUI, `corerouter-cli shell`, SSH). Veja `docs/terminal.md` | `serde_json` (nada do workspace; testes usam o engine) |
| L4 | `crates/mcp` | Servidor MCP stdio; backends `Headless`/`Remote` | L0–L3, `control` (lateral permitido) |
| L5 | `crates/ui` | Painéis WinBox em egui puro (sem eframe); trait `Backend` assíncrono + `Local`; janelas novas são **painéis** (`panel.rs`: `pub(crate) const PANEL` num arquivo, descoberto pelo `build.rs` com os módulos e os testes de `src/tests/`) | L0–L4 + egui |
| L6 | `apps/corerouter-{daemon,gui,cli}` | Binários; únicos que escolhem backend de plataforma e janela | tudo |
| L7 | `xtask` | `cargo xtask ci`, `layers`, `wasm`, `agents-sync`, `bench` (criterion, G0.9; `docs/perf.md`), `docs` (arquivos de mudança por PR em `docs/changes/`; `docs fold` consolida na fila de entrada, `scripts/land.sh`) | nenhum crate do workspace |

```
CoreRouter/
├── Cargo.toml            # workspace, lints sem panic, [workspace.dependencies]
├── clippy.toml           # unwrap/expect/panic/indexing liberados só em testes
├── rust-toolchain.toml   # stable + rustfmt, clippy, wasm32-unknown-unknown
├── .cargo/config.toml    # alias: cargo xtask
├── AGENTS.md = CLAUDE.md
├── ROADMAP.md
├── docs/{architecture,gaps,mcp,control-protocol,lldp-mndp,tools,dhcp-client}.md
├── crates/
│   ├── model/            # L0
│   ├── hal/              # L1 (traits + virtual)
│   ├── hal-linux/        # L1 plataforma
│   ├── dataplane-ebpf-common/ # L1 plataforma: parse/decisão do XDP, no_std (G2.5)
│   ├── dataplane-ebpf/   # programas XDP (bpfel, nightly; fora do workspace) (G2.5)
│   ├── firewall/         # L1 puro: validação + render nftables (G2.1)
│   ├── proto-bgp/ proto-ospf/ proto-mpls/ proto-cgnat/ proto-dns/ proto-dhcp/   # L2
│   ├── proto-lldp/ proto-mndp/   # L2: codecs de descoberta (G5.2)
│   ├── proto-ntp/ proto-syslog/  # L2: cliente SNTP e mensagens syslog (G4.6)
│   ├── proto-discovery/  # L2: codec do CRDP (G5.1)
│   ├── engine/           # L3: src/cmd/{mod,args,interface,ip,routing,system,config}.rs
│   ├── control/          # L4
│   ├── mcp/              # L4
│   ├── storage-fs/       # L4: persistência da config em arquivo
│   ├── discovery/        # L4: runtime do CRDP (sockets, threads)
│   ├── shell/            # L4: terminal RouterOS gerado do registro (G0.8)
│   └── ui/               # L5
├── apps/
│   ├── corerouter-daemon/
│   ├── corerouter-gui/   # nativo + wasm (index.html para trunk)
│   └── corerouter-cli/
└── xtask/                # L7
```

`crates/hal-frr` (G3.1) é a plataforma do FRR, classificada na L2 ao lado dos `proto-*`, cujo
render ela usa. `crates/dataplane-ebpf` (programas XDP,
fora do workspace, `cargo xtask ebpf`) e `crates/dataplane-ebpf-common` (L1 plataforma, usado só
pelo programa e pelo `hal-linux`) existem desde a G2.5a.

## 3. Fluxo de um comando

```
UI (CoreRouterUi::run) ─┐
CLI / terminal (shell) ─┤
canal de controle ──────┼──► Session::execute(id, params)
MCP (Headless/Remote) ──┘        1. acha o CommandSpec (ou "did you mean")
                                 2. check_params contra o doc `params`
                                 3. enabled → Err(motivo legível)
                                 4. snapshot do candidate
                                 5. guard::run (catch_unwind) → run(&mut Session, params)
                                 6. modo immediate: validate_all (proto-*) → Hal::apply → commit
                                 7. erro em qualquer passo → restaura o snapshot
                                 8. journal
```

Modos: `immediate` (RouterOS: cada comando vira revisão) e `transactional` (VyOS/Junos:
`config.diff` → `config.commit`; `config.rollback {revision}` carrega histórico).

Cópias da config (G0.16): as seções grandes (`interfaces`, `ip` e, dentro dele, endereços,
rotas, firewall com cada tabela e as address lists, DNS estático, zonas, servidor DHCP) são
`model::cow::CowArc` — um `Arc` que copia só quando alguém escreve (`Arc::make_mut`). O
snapshot do passo 4, a running, as revisões do histórico e o store da entrada do Safe Mode
compartilham o que ninguém escreveu: clonar a `Config` custa alguns contadores de referência, e
um comando paga a cópia só das seções que escreve (com 10 000 rotas, um `interface.set` em modo
transacional caiu de 90 µs para 4 µs, **medido**). A igualdade compara o ponteiro primeiro, e o
`ConfigStore` só compara candidate × running depois de alguém pedir `candidate_mut`. Comparado
com estruturas persistentes (`im`/`imbl`, cópia O(log n) também dentro de uma lista): elas
trocariam o tipo de toda lista da config (centenas de usos como slice) e trariam uma
dependência nova; fica para quando uma lista sozinha for o gargalo (hoje, acrescentar a uma
address list de 60 000 entradas ainda copia a lista: ~0,6 ms, **medido**).

### Safe Mode (G1.4)

Como no RouterOS: `config.safe-mode.enter` guarda a config running da entrada (a própria
`Config`, não um número de revisão: o histórico é limitado a 64). Toda mudança feita depois —
de qualquer cliente, como no RouterOS — roda no data plane, vira revisão marcada `[safe mode]`
e **não é salva** no `ConfigStorage`. Fim:

| Evento | Efeito |
|---|---|
| `config.safe-mode.exit` | confirma: salva e mantém |
| `config.safe-mode.cancel`, conexão dona fecha, `timeout_secs` expira | a config da entrada é commitada como revisão nova ("safe mode undo: …"); journal registra o automático |
| daemon reinicia no meio | o disco ainda tem a config da entrada: sobe nela |

Quem é o dono: `Session::execute_as(&Caller, …)` (também `batch_as`, `inspect_as`); o canal de
controle dá um `Caller` por conexão TCP/WebSocket (`control::new_caller`) e, quando ela fecha,
chama `control::hang_up` → `Session::hang_up(id)`. `Session::execute` sem `_as` é o
`Caller::local()` (GUI em lab, testes). Só um dono por vez: outro `enter` recebe "held by
`<conexão>` since `<UTC>` (N s ago)"; `exit`/`cancel` de outro cliente pedem `force: true`
(o "release"/"unroll" do RouterOS).

Relógio: o engine não tem (wasm32). O tempo vem de `Hal::now_unix` ou de `Session::tick(unix)`,
que o daemon e a GUI em lab chamam a cada segundo (`control::spawn_clock`); expiração é
conferida em cada tick e antes de cada comando. Sem relógio (wasm `?lab`), Safe Mode funciona
sem timeout. Uma conexão TCP ociosa morta (rede caiu sem FIN) só é percebida pelo timeout: por
isso o botão oferece 1/5/10 min no clique direito.

### Persistência (G0.6)

Todo commit bem-sucedido grava running + histórico (`model::persist::encode`, JSON com
`format_version`) num `ConfigStorage` (trait do engine, sem I/O). No boot,
`Session::with_storage` tenta o slot `current` e depois o `previous`; o que não decodifica
(truncado, lixo, versão desconhecida, invariantes quebradas) vai para quarentena (`*.corrupt`) e
gera `storage.boot_errors` no `state.inspect`. Nada legível → config descoberta dos ports. O
candidate nunca é gravado (edição não commitada não sobrevive a reinício, como no Junos/VyOS).
O arquivo é JSON compacto e limitado a 32 MiB (`SAVE_BUDGET_BYTES`): quando não cabe, as
revisões mais antigas ficam de fora (`storage.revisions_not_saved`), nunca a running; um commit
cuja config sozinha passaria de ~15 MiB é recusado. A leitura aceita até 256 MiB, para arquivos
de versões anteriores. Em Safe Mode qualquer gravação escreve o store da entrada. Se a config
restaurada não chega ao plano de dados no boot, `storage.boot_apply_error` mostra o motivo, o
tick tenta de novo a cada segundo e o próximo commit aplica a config inteira.

Histórico em arquivos (G1.23): num backend com `revision_files()` (os dois de baixo) o slot guarda
só a running e a revisão mais nova (o mesmo formato, com histórico de uma entrada, que versões
anteriores leem), e cada revisão mais antiga vira um arquivo próprio (`rev-<n>.json`), escrito uma
vez e apagado quando sai do histórico. O commit serializa a config uma vez (o texto vai para o
slot), então o custo é o tamanho da config, não do histórico: `commit/routes/10000` com 64
revisões em disco (fsync) caiu de 396 ms para 11,0 ms (**medido**, `storage_fs/commit/*`). Ordem:
arquivos de revisão que faltam → slot → apagar os que saíram. Um arquivo da revisão do slot ou
mais novo (gravação interrompida, ou boot pelo slot `previous`) é ignorado no boot e reescrito.
Arquivos de versões anteriores (histórico inteiro no slot) carregam e migram no primeiro commit.
O limite de 32 MiB vale para a soma dos arquivos de revisão.

Revisões como diferença (audit-history): com uma cópia inteira por arquivo, o limite guardava só
6 das 64 revisões de uma config de 5 MiB e 3 de uma de 10 MiB (**medido**); a running nunca se
perdia, mas o rollback depois de um reboot sim. Agora o arquivo da revisão `k` guarda a diferença
para a revisão seguinte, `k+1` (`base`), e não a config: delta reverso, como o RCS. A mais nova
não tem arquivo (o slot a guarda inteira); o arquivo de `k` é escrito pelo commit de `k+1`, uma
vez. No boot a cadeia é percorrida do slot para trás, cada diferença aplicada à árvore da revisão
seguinte. Comparado com delta para a frente + cópia inteira a cada K revisões: o reverso não
precisa de cópia inteira nenhuma além do slot (com K=16 seriam 4 cópias de 10 MiB, de novo acima
do limite), o arquivo nunca é reescrito quando a revisão mais velha sai do histórico, e a revisão
que mais importa (a anterior à running) depende só do slot. O preço: um arquivo ilegível no meio
custa ele e todos os mais velhos (dependem dele), relatados em `storage.boot_errors` (`revisions
a..b: N left out`); a running e as revisões mais novas não são afetadas. O boot pelo slot
`previous` não perde nada: a cadeia começa nele. Arquivo inteiro de versão G1.23 (`config` em vez
de `base` + `delta`) é lido sozinho, recomeça a cadeia, e o próximo commit o regrava como
diferença.

A diferença (`model::json_delta`) é estrutural, sobre o JSON da config. Objetos por chave
(`{"o": {…}, "d": […]}`). Listas por `id` (toda lista da config tem `id` único `*1A`), em trechos
copiados `[início, tamanho]` e itens novos `{"i": […]}`. Listas sem id, por prefixo e sufixo
comuns. Trocar uma entrada numa address-list de 65 536 grava essa entrada e dois trechos (menos de
200 bytes); trocar a seção inteira gravaria a lista toda (~4 MiB).

Journal da config (G0.22): com o histórico em arquivos o commit ainda reescrevia o slot com a
config inteira (e a serializava para medir o tamanho): 219 ms por `ppp.secret.add` com 100 mil
secrets, 6 ms por commit com 10 mil rotas (**medido**). Num backend com `config_journal()` (os dois
de baixo) o commit grava só uma linha no journal `config` (`journal-config.log`): a diferença
para a frente da revisão anterior para a nova, no formato dos arquivos de revisão
(`persist::encode_journal_line`). O slot só é reescrito num *checkpoint*: com mais de 1024 linhas
ou mais de ¼ da config (no mínimo 1 MiB) em linhas, com usuários mudados, ou enquanto não existem
os dois slots. No boot as linhas que encadeiam a partir do slot carregado são reaplicadas (por
bloco: um trecho copiado reaproveita os blocos da `CowList`); linha que não encadeia ou ilegível
encerra o replay (`storage.boot_errors`), última linha cortada (queda no meio do append) só é
descartada, e o próximo save faz checkpoint em vez de anexar depois dela. No checkpoint o journal
fica só com as linhas posteriores à revisão que virou o slot `previous`, então `previous` + journal
sempre dão a revisão mais nova: perder o slot corrente não perde mais o último commit (antes
perdia). O limite de tamanho por commit usa um teto (config do slot + bytes das linhas desde ele;
uma linha só pode crescer a config com o que carrega) e mede a config de verdade só quando o teto
passa do limite. Comparado com só gravar o slot sem fsync, ou um banco embutido: o journal mantém
o formato que versões anteriores leem no slot, um fsync pequeno por commit e nenhuma dependência.
Um build anterior ao G0.22 que bootar este diretório lê só o slot e perderia as linhas desde o
último checkpoint: por isso o daemon faz um checkpoint no desligamento limpo (G0.27,
`Session::checkpoint`, depois do lock final do `SIGTERM`/`SIGINT`). O journal não muda de
formato: ele guarda as linhas que o slot `previous` ainda precisa, e o boot seguinte as pula
(revisão já no slot), sem replay. Risco que sobra: uma queda (sem desligamento limpo) seguida de
uma volta de versão perde as linhas desde o último checkpoint.

As seções grandes são `CowArc` (G0.16), e `model::config_delta` trabalha seção por seção nos dois
sentidos:
- **No commit**, uma seção que a revisão nova divide com a anterior (mesmo ponteiro) nem é
  serializada: o arquivo custa o que o commit mudou.
- **No boot**, a revisão `k` é um clone da `k+1` com só as seções que o delta toca reconstruídas;
  as outras continuam a mesma alocação. As 64 revisões em memória custam perto de uma config.

Na leitura o delta é entrada hostil: profundidade limitada, cada trecho conferido contra a base e
usado uma vez só (o arquivo não multiplica a lista), e o resultado tem de ser uma `Config` válida.

Números (**medido**, `storage_fs/history64/*`, 64 revisões, fsync em disco, contra a `main` com
G0.16):

| config | commit | boot | pico de RSS no boot | revisões restauradas | em disco |
|---|---|---|---|---|---|
| 5 MiB | 28,7 → 26,6 ms | 260 → 149 ms | 79 → 79 MiB | 6 → 64 | 51 → 20 MiB |
| 10 MiB | 44,1 → 42,9 ms | 297 → 208 ms | 147 → 149 MiB | 3 → 64 | 68 → 39 MiB |

Os 63 deltas somam 0,01 MiB; o resto do disco são os dois slots.

| Backend | Onde | Uso |
|---|---|---|
| `MemoryStorage` | engine | GUI, wasm, testes, daemon em lab sem `--config-dir` |
| `FileStorage` | `storage-fs` (L4) | daemon: temp + fsync → rename current→prev → rename temp→current → fsync do diretório; `rev-<n>.json` (temp + fsync + rename) antes do slot |

### GUI como cliente do daemon (G0.4)

A GUI não segura a `Session`: fala com um `Backend` (trait de `crates/ui`) por requisição e
resposta, com os métodos do canal de controle (`engine.execute`, `state.inspect`, …).
`submit(method, params) -> RequestId` enfileira e volta na hora; `poll()` entrega as respostas
que chegaram, em qualquer ordem; `link()` diz conectando/conectado/desconectado (barra
superior). Contrato: todo id recebe exatamente uma resposta (erro se a conexão cair).

```
CoreRouterUi::run(id, params) ─► Backend::submit("engine.execute") ─► pending[id] = Action{then}
frame N+k: Backend::poll() ─► log + refresh + efeito (fecha diálogo, abre a interface criada…)
refresh (1 s, um por vez): state.inspect + 5 listas ─► cache; resposta mais velha que a já
aplicada no mesmo campo é descartada
```

| Backend | Onde | Transporte |
|---|---|---|
| `Local` | `crates/ui` | `Session` no processo; responde na hora (testes headless, `corerouter-gui` sem `--connect`, `?lab` na web) |
| `Remote` | `apps/corerouter-gui` (nativo) | `control::Client` numa thread de trabalho com canais std; reconecta a cada 2 s; requisição sem conexão falha na hora (nunca fica para "depois") |
| `WsBackend` | `apps/corerouter-gui` (wasm) | `web_sys::WebSocket`; eventos do navegador só enchem uma fila lida em `poll` |

O daemon serve o WebSocket com `control::ws` (thread por conexão, `tungstenite` síncrono) e
pode servir os arquivos da GUI web na mesma porta (`--web-root`, modelo WebFig); a lista de
`Origin` impede que uma página qualquer comande o roteador local. Detalhes em
`docs/control-protocol.md`.

### Autenticação e TLS (G0.3)

Quem decide **o que** cada um pode é o engine; quem decide **quem é** cada um é o canal de
controle. Cada conexão tem um `Caller`; a cada requisição o `control::auth::Gate` troca o
`token` pelo `Principal` (`Local` = processo ou token local, `User(nome)`, `Anonymous`) e o põe
no `Caller` antes de `Session::execute_as`. O engine olha o grupo **atual** da conta no `Users`
da sessão e compara com `auth::required_group` (consulta `read`, ação `write`, `user.*` `full`),
recusando com `EngineError::Denied` e marcando `enabled: false` no `engine.list` daquele
chamador (botões cinza da GUI, G1.16). A senha é verificada pelo `Gate` **fora** do lock da
sessão (Argon2 é lento de propósito); a sessão só entrega o hash e registra o login
(`user.active.list`). Contas ficam no mesmo arquivo da config, fora das revisões: rollback nunca
restaura senha. O token local (arquivo 0600 do usuário do sistema que roda o roteador) dá a CLI
e o MCP locais sem senha; TCP puro só aceita loopback, qualquer outro endereço é TLS
(`--listen`, `--ws-listen`) com login, e os clientes nativos fixam o certificado no primeiro uso
(`known_hosts`). Primeiro acesso (G0.3b, RouterOS 7): `Session::bootstrap_admin` (só na partida
do daemon, não é comando) cria `admin` sem senha (`password_hash: None`); o `Gate` aceita senha
vazia só de loopback e recusa todo login da rede enquanto houver conta `full` sem senha; a UI e o
`corerouter-shell` sabem disso por `auth.whoami` (`no_password`) e pedem a senha pelo
`user.set` normal. Detalhes em `docs/control-protocol.md`.

### Preferências da janela (G1.11)

Tema (Sistema/Claro/Escuro) e "Inline Comments" de cada tabela são estado da janela, não do
roteador: não passam pelo engine nem pelo journal. `CoreRouterUi::prefs()` devolve um JSON
pequeno que o app grava pela persistência do eframe (`App::save`, a cada 2 s e ao sair):
arquivo `app.ron` em `~/.local/share/corerouter-gui` (o `app_id` separa da pasta de config do
daemon) ou `localStorage` na web; `apply_prefs` o lê na criação e ignora o que não entende. A
memória do egui (posição das janelas) não é persistida.

### Descoberta de vizinhos (G5.1)

Protocolo próprio, o CRDP (`docs/discovery.md`); LLDP e MNDP passivo (G5.2) entram na mesma
tabela. Os vizinhos são **estado operacional**, como os contadores de link: ficam na `Session`
(`neighbors.rs`), nunca no `Config`, nunca no `running.json`. Só as configurações (`enabled`,
`interfaces`, `interval_secs`) são config, em `ip.neighbor_discovery`.

```
daemon: corerouter_discovery::Agent (3 threads std)
  tx (1 s): lock → expire_neighbors(now) + cópia da running → solta → anuncia nas interfaces ativas
  rx4/rx6: datagrama → proto_discovery::decode → interface de chegada → lock → record_neighbor
daemon --backend linux: link_discovery (1 thread std, G5.2)
  1 s: lock → expire + cópia da running → solta → hal_linux::l2::LldpIo abre/fecha portas,
       proto_lldp::encode → send (TTL 0 na porta que sai)
  200 ms: LldpIo::recv / MndpListener::recv → proto_lldp/proto_mndp::decode → lock → record_neighbor
ip.neighbor.list ◄── Session::neighbors() filtrada pelas interfaces ativas da running
```

`record_neighbor` não é comando: é dado da rede, não ação do operador (não passa pelo journal
nem gera revisão), e a sessão descarta o que chega por interface sem descoberta ativa. O relógio
é o de quem grava (`last_seen` em segundos Unix), então a tabela não depende do `Hal::now_unix`
e roda igual em wasm/testes. Índice de interface (para `ff02::1%if` e para saber por onde um
link-local chegou) vem de `/proc/net/if_inet6`, que é do network namespace de quem lê; o
`LinkInfo` do `Hal` ainda não tem índice.

A GUI nativa abre na tela de conexão (`ui::ConnectScreen`) quando não recebe `--connect`; a tela
só coleta a escolha, e o app (`apps/corerouter-gui`, trait `Platform`) fornece os vizinhos
(`Listener` no nativo, `ip.neighbor.list` do daemon na web), guarda a lista Saved e conecta. O
canal `--control` da GUI segue o alvo escolhido (`Target::Choosing` responde `server.info` e
`ui.screenshot`).

### `hal-linux`: aplicação no kernel (G1.2)

`LinuxHal::apply(from, to)` tem duas metades:

1. **Plano puro** (`crates/hal-linux/src/plan.rs`, compila em qualquer plataforma): o diff
   `from` → `to` vira uma lista ordenada de `Op` — remover endereços → soltar portas de bridge →
   apagar links (filhos VLAN antes do pai) → criar links (pai antes) → MTU (reduções dos filhos
   para o pai, aumentos do pai para os filhos) → prender portas → adicionar endereços → up/down.
   Mudou o tipo ou o VLAN id de um link virtual: apaga e recria, junto com as VLANs empilhadas
   nele (o kernel as apagaria de qualquer jeito). Porta física nunca é criada nem apagada.
2. **Executor** (`netlink.rs`, só Linux): roda cada `Op` com `rtnetlink` num runtime tokio
   *current-thread* criado dentro do `apply` (o trait `Hal` continua síncrono). Antes de cada
   mudança lê o link no kernel e guarda o desfazer; se o passo N falha, desfaz N-1..0 na ordem
   inversa e devolve `HalError::Rejected` dizendo o passo, o motivo e se o rollback foi completo.
   Mudança já em vigor (MTU igual, endereço presente) é no-op sem desfazer.

**Recursos do kernel (G1.14).** `Hal::features()` diz o que a plataforma suporta (hoje só
`vrf`), para um comando recusar de antemão com o motivo (`enabled`) em vez de falhar no
`apply`. O `LinuxHal` sonda uma vez, na primeira consulta, com um link descartável por recurso
(nome livre, apagado em seguida; links existentes nunca são tocados) e guarda o resultado num
`OnceLock`. Um kernel de terceiros sem `CONFIG_NET_VRF` deixa `ip.vrf.add` desabilitado; as
imagens do G1.6 vêm com `CONFIG_NET_VRF=y`.

### `hal-linux`: descoberta e posse dos links (G1.18)

**Uma fonte só.** `discover_links`, `poll` e o `apply` falam com o kernel do mesmo network
namespace: um dump `RTM_GETLINK` (`netlink::links`) dá nome, índice, `IFLA_INFO_KIND`, tipo
`ARPHRD_*`, master, `IFLA_LINK_NETNSID` (par em outro namespace), MTU, MAC, `IFF_UP`, operstate e
`stats64`. O sysfs saiu: `/sys/class/net` mostra o namespace de quem montou `/sys` (num
`unshare --net` sem remontar, o do host), e a descoberta via sysfs semeava as interfaces do host
num daemon que aplicava no namespace — `ip.address.add` falhava e o boot tentava mudar o MTU de
`br-…` do Docker.

**Posse** (`crates/hal-linux/src/owner.rs`, puro, testado em qualquer plataforma). Cada link é
`Managed`, `External(motivo)` ou `Conflict(motivo)`; primeira regra que casa:

1. nome que o modelo não aceita (`IfName`) → externo;
2. o loopback do kernel (`ARPHRD_LOOPBACK`, `lo`) → externo (é do SO);
3. nome em `--unmanaged` (nome ou `prefixo*`) → externo, até porta física;
4. porta de um master externo (a veth de container dentro do `docker0`) → externo;
5. nome que a config declara: gerenciado se o tipo do kernel serve (`vlan`/`bridge`/`dummy`/`vrf`
   para o que o CoreRouter cria; física, `veth` ou `dummy` para uma porta `ether`). Porta `ether`
   sobre outra coisa (config antiga que semeou o `docker0`) → externo; link virtual de outro tipo
   → conflito (listado como não gerenciado; o executor recusa com a mensagem dele e faz rollback);
6. porta física (sem `IFLA_INFO_KIND`, `ARPHRD_ETHER`) → gerenciada;
7. `veth` com o par no mesmo namespace (um cabo dentro deste roteador) → gerenciada; com o par em
   outro namespace (de container) → externa, salvo `--manage`;
8. `veth`/`dummy` em `--manage` → gerenciada;
9. o resto (`bridge`, `vlan`, `ppp`, `tun`, `wireguard`, … criados por outro programa) → externo.

Porta com MTU fora de 68..=9216 também é externa (o modelo não a representa sem mudar o kernel).

**Efeitos.** `discover_links` devolve só portas gerenciadas, com `up` (admin): o seed do engine
copia MTU, MAC e `disabled = !up`, então o primeiro `apply` (padrão → seed) não muda nada no
kernel (porta que estava down continua down; parte do G1.3). `poll` devolve todos os links com
`kind`, `mtu`, `mac` e `unmanaged: Option<motivo>`; `interface.list` mostra as interfaces da
config (com `kind` do kernel, `managed`, `unmanaged_reason`) e depois os links fora da config,
sempre `managed: false`. `Hal::unmanaged()` (padrão vazio; o lab virtual não tem) alimenta
`refuse_unmanaged` nos comandos que mudam interfaces (`interface.set`, `*.add` com o nome,
`vlan.add` no pai, `bridge.port.*`, `ip.address.add`, `ip.vrf.add/set`): "'docker0' is not managed
by CoreRouter: a bridge created outside CoreRouter". `interface.remove` aceita apagar uma porta
`ether` da config cujo link é externo (limpeza de seed antigo). No `apply`, ops sobre links
externos são descartadas com aviso no log, antes do executor: nem MTU, nem up/down, nem
endereço chegam a eles. A GUI deixa as ações cinza com o mesmo motivo e a linha esmaecida.

`corerouter-daemon --manage <nomes>` / `--unmanaged <nomes>` ajustam a regra (labs com veth entre
namespaces usam `--manage ether*`, como `tests/netns_l2.rs`). Na imagem de produção (G1.6) as
portas físicas são gerenciadas pela regra 6, sem flag.

### Firewall (G2.1)

`ip.firewall` (filter, nat, mangle, address-lists) e `interface_lists` são config; entradas de
address-list com timeout são estado operacional na `Session` (`firewall_dyn.rs`), como os
vizinhos. O commit valida com `corerouter_firewall::validate`; o `LinuxHal::apply` troca a
tabela `inet corerouter` inteira por `nft -f -` (atômico no kernel) **antes** do plano netlink, e
recarrega o ruleset anterior se o plano falhar; sem mudança no firewall o `nft` não roda. Detalhes,
mapeamento RouterOS → nftables e o porquê do `nft` em `docs/firewall.md`.

G2.1b: o `Caller` carrega o `Link` da conexão TCP (cliente e endereço local, preenchido pelo
`control::server::accept_loop`). `Session::commit_candidate` chama `engine::lockout`, que passa os
pacotes dessa conexão pelo firewall atual e pelo candidato com `corerouter_firewall::eval` e
recusa (`EngineError::Lockout`, texto `lockout: …`) o que os cortaria, salvo `force: true` no
comando (`Session::lockout_ack`, vale até o fim do comando ou do batch) ou Safe Mode; o desfazer do
Safe Mode usa `commit_restoring`, sem a checagem. O crate `firewall` ganhou `eval` (destino de um
pacote), `shadow` (regras sombreadas) e `describe` (frase em português), todos puros. Defaults,
modelos e zonas são comandos do engine (`cmd/firewall_assist.rs`, `cmd/firewall_zone.rs`) que
escrevem regras comuns pelo mesmo `add` dos comandos de regra; a GUI só junta parâmetros
(`ui::firewall_assist`) e segura a recusa de lockout para o operador decidir (`ui::lockout`).

G2.1c (diagnóstico): `corerouter_firewall::path` (o caminho de um pacote por raw, mangle, NAT, decisão
de rota e filter; a rota vem do engine por closure, o crate segue puro) e `diff` (diff de linhas do
ruleset). Contadores e trace **não** passam pelo `Hal`: o serviço `fw-diag` do daemon lê o kernel
com o lock do `Session` solto (`hal-linux::nft_counters`, um dump `NFT_MSG_GETRULE` da tabela;
`nft_trace`, tabela `inet corerouter_trace` + grupo `NFNLGRP_NFTRACE`) e entrega por
`Session::firewall_counters_feed` / `firewall_trace_push` (estado em `ext`, `engine::firewall_diag`).
Decisão medida (netns, 10 000 regras, release): **nfnetlink 10,7 ms × `nft -j` + JSON 190 ms**
(17,7×) e sem processo externo por leitura; por isso o dump é próprio. A aplicação do ruleset
continua por `nft -f` até o G2.8.

### Rotas estáticas e VRF (G1.5)

- **Modelo:** `ip.routes` (`RouteEntry`: `dst_address`, `gateway`, `distance`, `routing_table`,
  `disabled`, `comment`; ids `*N` próprios, `ip.next_route_id`). Rotas conectadas não são
  guardadas: derivam de `ip.addresses`. Um VRF é uma interface `InterfaceKind::Vrf { table }`
  (o device `vrf` do Linux; nome = nome da tabela) e cada membro guarda `Interface.vrf`, que é
  o `IFLA_MASTER` dele — por isso porta de bridge e membro de VRF se excluem.
- **Uma regra só para "a rota vale agora":** `model::route::reach(cfg, rota)` resolve o gateway
  dentro da tabela da rota e devolve `Active { link, gateway }`, `Inactive(motivo)` (rota,
  interface, VRF ou endereço desabilitado) ou `Invalid { campo, motivo }` (gateway fora de toda
  rede conectada, famílias trocadas, tabela/interface inexistente, endereço do próprio
  roteador, link-local sem interface). O engine usa para validar (`validate::route_issues`,
  também chamado pelos comandos) e para as flags de `ip.route.list` (X A D C S, ordem do
  RouterOS v6; ativa = usável e de menor distância no par tabela+destino); o `hal-linux` usa
  para decidir o que fica no kernel. Assim nunca divergem.
- **Kernel:** distance vira a métrica (o kernel também prefere a menor), protocolo `static`;
  rota sem gateway em IPv4 tem escopo `link`. O plano ganhou o passo 0 (remover rotas) e o 9
  (adicionar rotas). O kernel apaga sozinho rotas de link que desce, é recriado, entra/sai de
  VRF ou perde o último IPv4, e apaga os IPv6 de link que desce ou entra em VRF
  (`keep_addr_on_down=0`): o plano remove essas rotas/endereços explicitamente antes e os
  recoloca depois, para que o desfazer de uma falha devolva tudo. Rota existente no kernel só é
  adotada se for idêntica (static, mesma tabela/métrica/next hop); outra rota no mesmo destino e
  métrica faz o apply falhar e desfazer.
- **ECMP (G1.27a):** rotas de mesma distância ao mesmo destino formam um grupo (como no RouterOS
  v7). O plano e o drift continuam vendo um `KernelRoute` por caminho; quem junta é o executor
  netlink: o primeiro op de rota de um apply lê as rotas `static` do kernel uma vez (cache do
  apply), e acrescentar/tirar um caminho de um grupo reescreve a rota inteira com
  `RTA_MULTIPATH` (`NLM_F_REPLACE`). Só caminhos que o config de origem ou de destino põe no
  kernel entram num grupo: uma rota `static` de outro programa no mesmo destino e métrica
  continua fazendo o apply falhar. Escolhido em vez de mudar o `Op` do plano para "grupo" porque
  o IPv4 apaga a rota multipath inteira se o delete casa só o primeiro caminho, então o executor
  precisa da visão do kernel de qualquer jeito, e o plano (e os testes dele) ficam como estão.
  Custo: uma leitura de links e rotas por apply que mexe em rota (`hal_linux_apply/routes` em
  `docs/routes.md` e no `docs/perf.md`). Detalhes da janela, do motivo e do lookup:
  `docs/routes.md`.

Proteções do host: só interfaces do config entram no plano; o `lo` do kernel não é descoberto;
link existente só é adotado se tiver o mesmo tipo (e VLAN id/pai) do config, e nunca se apaga
um link cujo tipo no kernel difere do config. Testes de integração (`tests/netns.rs`) rodam
num network namespace descartável sem root: `cargo xtask netns` (passo do `cargo xtask ci`,
que vira `skip` onde `unshare` sem root não é permitido).

### Tarefas das ferramentas (G6.1–G6.3)

Ping, MTU e (G6.3) MTR levam segundos ou não terminam: o comando valida, inicia um **job** e
devolve o id; o resultado chega por `tool.task.poll`. Estado operacional, como os vizinhos:
fora do `Config`, do journal e do disco.

```
tool.ping.start ─► Session::start_task(kind, título, job)        (sob o lock, rápido)
                     Hal::prober() ─► Arc<dyn Prober>            (L1: hal-linux::icmp | hal::sim)
                     Runner::spawn(job)                          (thread std do app; engine não tem)
job (fora do lock): Prober::open ─► ProbeSocket::send/recv ─► TaskCtx::emit / summary ─► TaskCell
tool.task.poll ─► TaskCell (mutex próprio): eventos > after_seq, resumo, estado
Session::tick (1 s): tarefa sem poll há 60 s ─► stop; terminada há 300 s ─► some
```

O engine não tem relógio nem threads (wasm32): o `Runner` dá a thread e o `Clock` (tempo
monotônico e `sleep`) do job; o RTT é medido pelo socket. Os jobs (`engine/src/tools/`) são
lógica pura sobre `ProbeSocket` + `TaskCtx` e são testados com a rede simulada e um relógio
falso (sem esperar de verdade). Detalhes, limites e a rede simulada: `docs/tools.md`.

**Captura (G6.4a, Torch e Sniffer):** `Hal::packet_capture()` → `PacketCapture` (L1) → um
`CaptureSocket` que enche um `FrameBatch`; o decodificador de cabeçalhos e o pcap são puros no
`hal`, a agregação no engine (`tools/torch.rs`). Decisão, com números (**medido**,
`docs/tools.md` §4.4): **Rust puro** com `AF_PACKET` + filtro BPF clássico, em vez de orquestrar
`tcpdump`/libpcap — tira um processo externo e o parsing de texto, dá dados estruturados por
quadro e a amostragem 1:N no kernel (o que mantém a CPU sob controle acima de 500 kpps: 1:64
cobre 12,8 Mpps a 35 % de um núcleo). Fica de fora por ora o `TPACKET_V3` (anel em `mmap`, exige
`unsafe`): sem amostrar, `recvmsg` lê ~2 Mpps por thread, e o caminho mais rápido de verdade é
contar fluxos num mapa XDP (G2.5) atrás do mesmo trait, sem copiar quadros.

**Bandwidth Test (G6.4b):** o protocolo do iperf3 em Rust (`proto-iperf`, L2, puro; sockets no
daemon), em vez de orquestrar o binário `iperf3`: um processo externo a menos, dados
estruturados por segundo (o binário só dá JSON no fim, ou texto), limites e ACL do servidor
aplicados antes de ler qualquer coisa, e interoperabilidade mantida porque o formato é simples e
estável desde a 3.0 (testes contra o `iperf3` quando instalado). Números (**medido**, loopback):
`docs/changes` da G6.4b.

### DNS (G4.1)

**Decisão do usuário (2026-10-22):** o DNS inteiro é **Hickory DNS, em Rust puro**, embutido no
daemon. São três partes sobre a mesma config (`/ip dns`) e o mesmo cache:

- **G4.1a**, resolvedor do próprio roteador: mensagens com `hickory-proto`, sem runtime async.
- **G4.1b**, encaminhador com cache para a LAN (`allow_remote_requests`, `/ip dns static`),
  em partes: base (cadeia de etapas, ACL, limite, estáticos, serve-stale), depois Statistics
  (G4.1e), Adlist/Forwarders/DoT-DoH (G4.1d) e Zones (G4.1c), cada uma como etapas novas.
- **G4.1c**, servidor completo estilo BIND (zonas autoritativas, DNSSEC) com `hickory-server`.

Por que não orquestrar Unbound, Knot ou PowerDNS, como o FRR no roteamento: um processo só
elimina um ponto de falha e uma config paralela. Estáticos, servidores do DHCP e o cache viram
comandos, entram em transações e no Safe Mode e aparecem no MCP. Os erros chegam estruturados,
sem parsear saída. **Risco aceito:** o Hickory é menos testado em escala de ISP que
Unbound/Knot/PowerDNS. Ele será medido com benchmarks (consultas/s, latência com cache quente e
frio, memória por entrada) na G4.1c, e a decisão pode ser revista com esses números.

```
ping/MTR/MTU ─► Session::tool_prober ─► RouterResolver::resolve ─┐
cliente NTP ─► service::dns::resolve ────────────────────────────┤ (sem lock do Session)
                                                                 ▼
               proto-dns::Resolver: cache (lock curto) ─► fetch: servidores um a um
                                                                 │ Transport
               service/dns.rs: UDP (+TCP no TC) ◄────────────────┘
thread "dns" (1 s): Session::dns_settings (running ip.dns + DHCP use_peer_dns) ─► configure
```

O `proto-dns` não abre socket: compila em wasm e é testado com um transporte falso e um relógio
falso. Sem daemon registrado, as ferramentas usam o resolvedor do prober (o simulado, no lab).

**Encaminhador da LAN (G4.1b): Hickory para o protocolo, nossa camada de regras na frente.** O
`hickory-server` 0.26 tem forwarder com cache, DNSSEC, DoT/DoH/DoQ e ACL, mas exige tokio, não
tem limite por cliente, não lista nem limpa o cache e não fala as estatísticas no formato do
RouterOS (e o README ainda diz "not recommended in production"). Por isso o encaminhador usa só o
`hickory-proto` (mensagens) e passa cada consulta por uma **cadeia de etapas**
(`proto-dns/src/server/stage/*.rs`, achadas pelo `build.rs`, ordenadas pelo `order` de cada uma):
`acl → limit → special → adlist → static → zones → cache → upstream`. Sem runtime async: no
daemon (`service/dns_server.rs`) uma thread por socket responde o que a cadeia resolve sem rede
(cache, estáticos) na hora, e cada falta de cache ganha uma thread, no máximo
`max_concurrent_queries`. Medido: 0,8 µs por consulta respondida do cache (bytes a bytes), ~1,2 M
consultas/s por núcleo sem contar o socket.

**Zonas autoritativas (G4.1c-1): a busca é nossa, numa etapa da cadeia.** O plano era servir as
zonas pelo `hickory-server`. A versão 0.26.3 não tem IXFR, NOTIFY (enviado ou recebido), zona
secundária nem ACL de IP para AXFR, e a busca dela é async (tokio), fora da cadeia síncrona que
compila em wasm. Então a etapa `zones` (`proto-dns/src/zone/`) faz a busca da RFC 1034 §4.3.2 sobre
registros do `hickory-proto`. Transferências e NOTIFY são atendidos antes da cadeia, e o serviço
`dns zones` do daemon faz o NOTIFY enviado e as secundárias. Medido: 1,04 µs por resposta de zona
(como um acerto de cache), nada para quem não tem zonas. Na assinatura DNSSEC (G4.1c-2) o
`hickory-server` também ficou de fora: o `InMemoryZoneHandler::secure_zone_mut` dele assina o NS
de delegação e a glue (a RFC 4035 §2.2 proíbe), marca RRSIG no bitmap de delegações sem DS e não
tem rotação de chaves. A criptografia é a do `hickory-proto` (ring, feature `dnssec` do proto-dns,
ligada só pelo daemon: engine, GUI e wasm não ligam o ring); a cadeia NSEC3, as provas e as
rotações são nossas. As chaves ficam fora da config versionada (estado operacional
`dnssec-keys`), para um rollback nunca tirar uma chave cujo DS está no pai. Medido: 24 ms para
assinar 1000 registros, 1,56 µs por resposta assinada. Detalhes em `docs/dns.md`, "G4.1c —
Zonas".

```
UDP/TCP 53 ─► Forwarder::start (thread do socket) ─► acl, limit, special, adlist, static, zones, cache
                                                          │ falta de cache: Step::Wait
                                                          ▼
                     thread por consulta (≤ max_concurrent_queries) ─► upstream: Resolver::resolve
                                                          │ (o mesmo cache do roteador)
efeitos (address-list) ─► thread "dns-effects" ─► Session::dns_address_list
```

**Adlist e HTTPS do daemon (G4.1d).** As listas de bloqueio ficam fora da config e fora do lock
do `Session`: o serviço `service/dns_adlist.rs` baixa, lê e ordena cada lista numa thread própria
e troca o conjunto da etapa `adlist` de uma vez (`proto-dns::adlist::Adlists`). O conjunto é uma
arena de texto ordenada com deslocamentos (busca binária por rótulo), não um `HashSet<String>`:
**medido** 31,8 MB para 1 M nomes (~32 B/nome, contra ~70 B estimados no `HashSet`), 230 ms para
ler e montar, 80–110 ns por consulta. O download usa um cliente HTTP/1.1 nosso
(`service/https.rs`, rustls + raízes Mozilla do `webpki-roots`) e não o `ureq`/`reqwest`: o
roteador não tem resolvedor do sistema nem loja de CAs, então o nome do servidor passa pelo
resolvedor do roteador, e todos os limites (cabeçalho, corpo, redirecionamentos) são nossos. O
mesmo cliente serve o DoH da G4.1d-2.

**DoT/DoH upstream (G4.1d-2): rustls e o nosso HTTP/1.1, sem tokio.** O `hickory-proto` tem
clientes DoT/DoH, mas só sobre tokio; o daemon é por threads. O `proto-dns` monta a consulta (id 0,
padding de 128 bytes) e o resolvedor escolhe o servidor; o daemon (`service/dns_secure.rs`) fala
TLS (RFC 7858) ou `POST application/dns-message` (RFC 8484) e guarda até 4 conexões ociosas por
servidor por 20 s. HTTP/1.1 em vez de HTTP/2 (que a RFC 8484 §5.2 recomenda): com a conexão
reaproveitada a diferença some. **Medido** (2026-10-22, release, cache vazio, 15 nomes populares
pelo 1.1.1.1 a ~48 ms de RTT): UDP 48–51 ms, DoT 47–49 ms, DoH 49–53 ms por consulta. Revisar se um
servidor exigir HTTP/2 ou se o pipelining (várias consultas na mesma conexão) fizer falta.

Detalhes, regras de RFC e pesquisa: `docs/dns.md`.

### Supervisor de serviços do daemon (G0.10)

Os serviços do daemon (`apps/corerouter-daemon/src/service/<nome>.rs`: `dns-resolver`,
`dns-server`, `ntp-client`, `remote-logging`, `metrics`) rodam sob um supervisor
(`service/supervisor.rs`), para que uma thread que morre ou um bind que falha não vire queda
silenciosa.

- **Interface.** `Service { name, flags, topic, enable, depends, start }`. O `start(&Ctx)` roda
  uma vez no boot, lê as flags (erro = o daemon não sobe, como antes) e devolve o corpo
  `Run = Fn(&Health) -> Result<(), String>`, que o supervisor roda numa thread própria e de novo
  a cada falha. O laço do corpo usa `while health.sleep(TICK) { health.beat(); … }` e informa
  `listen`, `event`/`error` e `disabled(motivo)`; `health.spawn` conta as threads auxiliares e
  contém o panic delas. O guia completo está no topo de `service/mod.rs`.
- **Política.** Reinicia sempre (systemd `Restart=always`, Erlang `permanent`): o corpo que
  termina sem ser pedido, devolve `Err` ou dá panic (`catch_unwind`; o perfil de release é
  `panic = "unwind"`) volta depois de 1 s, 2 s, 4 s… até 60 s (systemd 254 `RestartSteps` /
  `RestartMaxDelaySec`); uma execução de 60 s zera a espera. Com 5 falhas em 60 s desiste e fica
  `failed` (`StartLimitBurst`/`StartLimitIntervalSec`, intensidade/período do OTP), com linha
  `critical` no log do roteador (o syslog remoto a encaminha). `start` e `reset-failures`
  tentam de novo.
- **Estados.** `disabled` (roda ocioso porque a config o desliga, com o motivo), `starting`
  (sem heartbeat ainda, ou esperando uma dependência), `running`, `restarting` (com os segundos
  que faltam), `stopped` (pelo admin, até o próximo boot; a config não muda) e `failed`.
- **Engine.** O engine não tem threads e não depende do daemon: o supervisor publica as linhas
  em `ServiceTable` (`s.ext_mut`, `corerouter_model::service`) a cada 200 ms e retira os pedidos
  que `system.service.start|stop|restart|reset-failures` enfileiram (no máximo 64). Um lock
  curto por volta e nenhum outro lock enquanto isso. Sem daemon (lab, WASM) a tabela fica vazia
  e as ações explicam por quê.
- **`control`.** A linha do canal de controle é `protected`: `stop` e `restart` são recusados
  com o motivo (cortariam a própria sessão de gestão).
- **Uma thread não se mata.** `stop` pede (`Health::stopping`) e o corpo devolve; um heartbeat
  com mais de 30 s aparece como motivo ("no heartbeat for N s"), sem reinício forçado.
- **Métricas.** `system.metrics` traz `services`, e o exportador gera `corerouter_service_up` e
  `corerouter_service_restarts_total` por `name`.

### Servidor DHCP (G4.2)

**Decisão do usuário (2026-10-22):** servidor DHCP em **Rust puro** sobre o `dhcproto`, dentro do
daemon, em vez de orquestrar o Kea ou o dnsmasq.

| | Rust puro (G4.2a) | Kea (OPNsense/VyOS) | dnsmasq (OpenWrt) |
|---|---|---|---|
| Processo | nenhum a mais | `kea-dhcp4` + `kea-lfc` + `kea-dhcp-ddns` | um |
| Config | comandos, transações, Safe Mode, MCP | JSON próprio, recarga por API de controle | arquivo, recarga por sinal |
| Concessões no motor | direto (`ip.dhcp-server.lease.print`, make-static, release) | API de controle ou leitura do CSV | arquivo de leases |
| DHCP → DNS e firewall | chamada direta (`dns_dynamic_lease`, address-list dinâmica) | D2 + RFC 2136 com TSIG | hosts locais, sem PTR remoto |
| Vazão do núcleo | **medido**: 171–214 k leases/s (§9 de `docs/dhcp.md`) | milhares de leases/s com memfile (**estimado**; o ISC publica números com `perfdhcp`) | **estimado**: alguns k/s |
| Maturidade, interoperabilidade | nova; testada contra o nosso cliente, o lab e a RFC | muito alta | alta |

Por que Rust puro ganhou: um processo e um ponto de falha a menos; concessões dentro das
transações, do Safe Mode e do MCP; integração direta com o DNS e o firewall sem protocolo no meio;
números de vazão acima do que um roteador de borda precisa. O gargalo do servidor no daemon é o
disco: uma `fdatasync` por rodada, com todas as concessões da rodada (group commit).
**Risco aceito:** clientes estranhos (CPEs, ONUs, IoT) que o Kea já viu e nós não. Mitigação:
leitor de pedidos tolerante e testado com proptest, comportamento do RouterOS como referência, e
a decisão pode ser revista com números de campo.

Camadas: o servidor é L2 puro (`proto-dhcp/src/server/`, compila em wasm: o lab do navegador
também o roda), o engine guarda o estado e aplica os efeitos, o daemon só o dirige
(`service/dhcp_server.rs`) e o `hal-linux` só carrega bytes (`dhcp_server.rs`).

### Tuning do sistema (G1.26)

**Decisão: Rust puro, sem `tuned`, `irqbalance`, `ethtool` nem `sysctl.conf`.**

**Comparado:**

- **Números.** Aplicar um perfil grava ~40 arquivos de `/proc/sys`: < 1 ms em Rust (**estimado**),
  contra ~200 ms para subir o `tuned-adm`, um processo Python (**estimado**). Não é o gargalo de
  ninguém. O que pesa é o resto.
- **O que pesa:**
  - Os perfis do `tuned` são para servidor: buffers TCP, busy_poll, THP. Os de roteador precisam
    de outros valores.
  - O `irqbalance` move as IRQs a cada 10 s e sobrescreve a afinidade manual (`scaling.rst`), o
    contrário do que um roteador quer.
  - Nenhum dos dois tem transação nem rollback, nem diz por que escolheu um valor.
  - Os dois são processos externos e superfície a mais na imagem.

**Como fica:**

- Os valores vivem na config (`system.tuning`) e passam pelo mesmo caminho de tudo: comando, diff,
  Safe Mode, journal, rollback.
- O `hal-linux` (`tuning.rs`) grava tudo ou nada, com o valor original guardado na primeira mudança
  (tirar da config o restaura).
- O engine (`tuning.rs`) calcula perfis, faixas e diagnóstico, puro e testado sem kernel.
- Medida de pps em netns: `docs/tuning.md`.

### Menu lateral e ícones (G0.23)

O menu é uma árvore (grupo › subgrupo › janela) montada de uma **tabela central**,
`crates/ui/src/menu.rs` (`CATALOG`, indexada pela chave da janela): subgrupo, rótulo curto,
ícone, caminho no RouterOS, comandos e sinônimos de busca. Os painéis continuam declarando só o
grupo (`WinDef::group`); a tabela evita editar cada painel (arquivos de outras sessões) e um teste
garante que toda janela tem entrada, ícone, explicação em EN e PT e sinônimos. Os comandos do ⓘ
vêm do `engine.list` do roteador, filtrados pelos prefixos da tabela: a UI não mantém lista
própria. Grupos abertos são preferência da janela (`prefs.rs`, chave `menu`).

**Ícones: Phosphor Icons (MIT), fonte embutida em subconjunto, sem dependência nova.**

- **Comparado:** o crate `egui-phosphor` (MIT/Apache-2.0) era o caminho óbvio, mas a 0.14 (a mais
  nova, 2026-09) depende de egui 0.36 e o workspace está no 0.37: seriam duas versões do egui no
  build (tempo de compilação, wasm maior) só para ler bytes e constantes. Ícones desenhados à mão
  (como o ⓘ do G0.15) não escalam para ~50 desenhos.
- **Como fica:** `crates/ui/assets/phosphor/Phosphor-subset.ttf` (16,0 KB, 50 ícones, **medido**;
  a fonte completa tem 489 KB) é cortado da `Phosphor.ttf` do próprio crate `egui-phosphor`
  0.14.0 por `scripts/icons-subset.sh` (pyftsubset), a partir dos códigos listados em
  `crates/ui/src/icons.rs`. A fonte entra numa família própria (`FontFamily::Name("phosphor")`),
  porque a fonte de emoji do egui usa os mesmos códigos da área privada para outros desenhos.
  Compila em `wasm32-unknown-unknown` (é só `include_bytes!`). O teste `the_font_has_every_icon`
  reprova ícone sem glifo. Quando o `egui-phosphor` acompanhar o egui do workspace, dá para trocar
  o subconjunto pelo crate (macro `subset!`) sem mudar `icons.rs`.

### Exportador ClickHouse (G4.4f)

Histórico de longo prazo **fora** do roteador (decisão do usuário, 2026-10-23): o serviço
`analytics` do daemon envia métricas, logs, fluxos e eventos de NAT a um ClickHouse que o operador
mantém. Desenho, esquema e operação em `docs/analytics.md`.

- **Caminho:** o engine só guarda a configuração (`system.analytics`) e o status
  (`s.ext::<AnalyticsStatus>()`, escrito pelo daemon); rede só no daemon (L6). A cada 250 ms o
  serviço copia sob o lock o que é novo no log (`log_since`) e, a cada `metrics_interval`, o
  resultado de `system.metrics` (o mesmo texto do `/metrics`, convertido em linhas); envia sem o
  lock. O Traffic Flow (G4.4b) entrega fluxos e sessões de NAT por `submit_records` (lista com
  teto, sem lock da sessão); os blocos do CGNAT (G2.3c) chegam pelo próprio log.
- **Comparado** (Rust puro × externo, como pede o AGENTS.md):
  - *Vector ou Fluent Bit ao lado do daemon*: maduros, mas um processo a mais para supervisionar,
    configurar fora das transações e atualizar, e o roteador ainda teria de exportar para ele;
    reenvio, fila com teto e descarte contado, que são o que eles agregam, cabem em ~1400 linhas com comentários (**medido**: `analytics.rs`, `analytics_queue.rs`, `analytics_rows.rs`, sem os testes).
  - *Crate `clickhouse` (HTTP, RowBinary)*: puxa `hyper`/`tokio` para um daemon que é síncrono, e
    `RowBinary` amarra a ordem das colunas ao esquema (uma coluna nova no servidor quebra o
    envio). *Drivers nativos* (protocolo TCP 9000): em C++ ou com FFI; fora (sem C).
  - **Escolhido:** o cliente HTTP/1.1 do daemon (`service/https.rs`, rustls, já usado pelas
    adlists) com `JSONEachRow` + gzip (`flate2` com `miniz_oxide`, puro Rust).
- **Números** (**medidos**, release, 32 núcleos, ClickHouse 26.9 na mesma máquina, 2026-10-23):
  codificar + comprimir ~510 000 linhas de log/s num núcleo (≈ 1,9 µs de CPU por linha) e
  ~1,1 milhão de linhas de métrica/s; enviar ao ClickHouse ~665 000 linhas/s em lotes de 10 000
  (CPU do roteador desprezível no envio). Um roteador de borda gera dezenas a milhares de linhas
  por segundo: o JSONEachRow não é o gargalo, e `RowBinary` fica para quando for (G4.4h). Com o
  servidor fora do ar 10 minutos, a fila guardou tudo e esvaziou em segundos quando ele voltou,
  sem perda (`docs/perf.md`).
### Histórico de tráfego (G4.5)

O roteador guarda um histórico **leve e local** de cada interface escolhida (bps, pps, erros e
drops) e dele mesmo (CPU, memória, conntrack), estilo RRDtool, em resolução decrescente:
1 s na última hora, 1 min no último dia, 5 min na última semana, 1 h no último ano. O ClickHouse
(G4.4f) é externo e opcional; ele lê daqui (`system.graph.export` ou `GraphDb::export`).

- **Onde mora:** `engine::graph` (puro, compila em wasm): o formato (`graph::rrd`), a coleta e as
  consultas. A coleta vai no `Session::tick` que já faz a varredura de links por segundo
  (`poll_links`): sem dump extra de netlink. CPU, memória e conntrack vêm de `Hal::resources`
  (`/proc/stat`, `/proc/meminfo`, `nf_conntrack_count`). O disco é do daemon
  (`service/graphing.rs`, `<config-dir>/graphs/`): o engine entrega `Patch`es e recebe os
  arquivos de volta no boot, sem I/O próprio. A GUI sem daemon tem o histórico só em memória.
- **Formato próprio × `redb` × `fjall` (decisão, com números):** um RRD tem tamanho fixo e é
  escrito sempre no mesmo lugar; o que se quer é **zero amplificação de escrita** (flash) e
  teto de disco natural. Formato próprio: um arquivo por série (cabeçalho + quatro anéis de
  `f32`, média e máximo por slot), escrito no lugar: um store de 5 min grava só os baldes de
  1 min, 5 min e 1 h fechados desde o último (~0,5 KB por interface, **medido** no teste
  `a_restart_reads_back_what_was_stored`), e o anel de 1 s (o grosso) só no desligamento
  limpo. O `redb` (B-tree copy-on-write) reescreve páginas inteiras e a raiz a cada commit
  (4 KiB+ por série por store, mais o fsync do arquivo inteiro) e cresce até o `compact`; o
  `fjall` (LSM) reescreve tudo nas compactações e precisa de tuning de memória — os dois resolvem
  um problema (chave-valor geral, transações) que o RRD não tem, e acrescentariam um crate
  grande ao daemon. Ficou o formato próprio (~500 linhas com testes).
- **Teto:** o tamanho de uma série é fixo (672.984 bytes por interface, 336.600 a do sistema);
  `max_memory_mib` (64 MiB por padrão, ~90 interfaces) recusa o que não cabe, registra no log e
  lista em `system.graph.print`. Memória e disco são o mesmo número.
- **Custos (medidos, release, `cargo bench -p corerouter-engine --bench graph`, 2026-10-23):**
  um segundo de coleta 1,9 µs / 20 µs / 355 µs com 8 / 64 / 512 interfaces (dentro do lock da
  sessão); tirar as mudanças de um store 4,7 µs / 33 µs / 547 µs; consultar um ano de uma
  interface 1,36 ms. Daemon inteiro em `docs/changes/G4.5a.md`.
- **Revisitar se:** o operador quiser cobrança mensal exata (p95 de amostras de 5 min por 30
  dias, que o anel de 5 min de uma semana não tem: um quinto anel de 5 min × 35 dias custa
  +168 KB por interface — gap G4.5b) ou milhares de interfaces (aí o anel de 1 h pode ficar só
  no disco e ser lido sob demanda).

### Log do sistema operacional (G4.8b)

O serviço `os-log` do daemon lê `/dev/kmsg` e o journal fora do lock da sessão e entrega as
linhas em lote ao `OsLogBook` (ext do `Session`); `log.os.print` só lê o livro. `Hal::os_log`
serve o laboratório (linhas inventadas, nunca bloqueia, roda sob o lock). Detalhes e pesquisa em
`docs/os-log.md`.

**Decisão: `journalctl` externo agora, leitor Rust depois (G4.8ba).** Comparado: o `journalctl
-o json --after-cursor` custa ≤ 10 ms por chamada a cada 2 s num journal de 2,0 GB (**medido**),
dá JSON estruturado com cursor, e o formato dos arquivos do journal é extenso (hash tables,
compressão xz/lz4/zstd, arquivos em rotação) — escrever o leitor agora seria risco de bug sem
ganho medido. O processo roda sem shell, com teto, prazo e grupo próprio (morto e colhido). Na
imagem de produção (sem systemd) só há kmsg, lido em Rust puro. Rever com o G4.8ba se o custo do
processo aparecer nos números de um roteador de verdade.

### Plano de controle PPPoE em vários núcleos (G4.3g)

**Divisão entre workers:**

- Cada worker tem um `Bng` próprio: servidores, sessões, timers e perguntas ao RADIUS.
- A tabela ativa, o histórico e os pools ficam compartilhados.
- Num servidor, o SESSION_ID é repartido por faixa (`sid_lane`), sem lock.

**Recepção: um leitor, um canal por worker.** A thread do serviço lê as portas de acesso e o
`bng0` do caminho lento e entrega cada quadro ao worker do MAC do cliente, como o RSS
(`Bng::lane_of`), por um canal de até 65 536 quadros. O canal é também o que absorve a rajada
de PADIs de uma volta de energia.

**Decisão: o leitor único fica; o socket filtrado por worker foi medido e descartado.**

- **Socket por worker:** cada worker abre os próprios sockets AF_PACKET com um filtro BPF
  clássico que só deixa passar os clientes dele (`ld [8]`,
  `mul #0x9E3779B1`, `rsh #16`, `mod #N`, `jeq #faixa`, via `SO_ATTACH_FILTER` do socket2).
  - Num netns, a parte serial caiu: a thread receptora mais ocupada passou de 550–1050 ns para
    150–350 ns por quadro (200 mil PADIs, **medido**; o código e o teste,
    `tests/netns_pppoe_lanes.rs`, estão no commit 8c3859f e saíram com a decisão).
  - No laboratório com o BNG Blaster (VM corerouter-lab, 8 vCPUs, 100 mil sessões, **medido**),
    ficou abaixo do leitor:

    | | 1 worker | 6 workers |
    |---|---:|---:|
    | leitor + canal (rodada 3) | 15,2 mil/s | **57,9 mil/s** (leitor a 51%) |
    | leitor + canal, com o filtro de saída e o `rx_dropped` (rodada 6) | 14,5 mil/s (30 967 quadros perdidos) | **57,7 mil/s** (0 perdidos) |
    | socket por worker, sem fila (rodada 4) | 10,5 mil/s | 22,4 mil/s |
    | socket por worker + fila de 65 536 no worker (rodada 5) | 14,3 mil/s (46 234 quadros perdidos) | 24,0 mil/s (0 perdidos) |

  - **Sem fila,** um socket de 4 MiB guarda 8739 PADIs, e o BNG Blaster manda 100 mil em
    1,5 s: o kernel descartava, e o CPE repetia o PADI segundos depois.
  - **Com fila,** com 6 workers nada se perdeu e mesmo assim deu 24 mil/s, com o BNG Blaster
    a 91% de um núcleo (69–73% com o leitor a 57,9 mil/s). Gastou cerca de 3× mais CPU por
    sessão.
  - **Hipótese, não confirmada:** o CPE retransmite mais por latência e não por perda. O worker
    esvazia o socket inteiro na fila antes de atender, e as respostas de LCP e IPCP esperam
    atrás de uma rajada de PADIs. Com o leitor, cada worker recebe a sua parte já dividida e
    em ordem de chegada. Confirmar exige os contadores de retransmissão por sessão do BNG
    Blaster.
- **PACKET_FANOUT por MAC:** precisa do modo CBPF com `PACKET_FANOUT_DATA` (a `sock_fprog`
  por setsockopt); o modo HASH usa o hash de fluxo L3/L4, que a descoberta PPPoE não tem.
  - Nem o socket2 nem o nix 0.30 expõem essas opções. A macro `sockopt_impl!` do nix
    expandiria `unsafe` no nosso crate, contra a regra.
  - O crate `netring` (0.32, um autor) e o `afpacket` (licença MirOS) não passaram no
    critério de dependência madura.
- **`recvmmsg` no leitor:** não entrou. O leitor ficou a 51% de um núcleo a 57,9 mil/s; ele
  ainda não é o gargalo.
- **Do trabalho do socket por worker, ficou:**
  - o filtro das portas descarta as cópias do que o próprio BNG envia (`PACKET_OUTGOING`);
  - as perdas do kernel por socket (`SO_RXQ_OVFL`) e as do canal saem no
    `interface.pppoe-server.monitor` (`rx_dropped`).

### Filas: EDT × HTB (G4.9b)

Decisão (2026-10-26, **medida**): a descida das filas é moldada com **EDT** — um programa tc na
saída da porta dá a cada pacote o horário de saída (`skb->tstamp`) pelo relógio do alvo (uma
palavra, `cmpxchg`) e o `fq` (sob `mq`, um por fila de transmissão) o segura —, não com uma árvore
HTB por alvo. Comparado no laboratório em VM (8 vCPUs, veth com 4 filas, RPS/XPS, 1,5× da taxa
total oferecida em pacotes de 128 B, `shaper_root::perf_edt_vs_htb`):

| alvos | caso | montar | entregue × taxa | CPU ocupada |
|---:|---|---:|---:|---:|
| 1 000 | EDT | 1,0 s | +0,0% | 28,7–31,6% |
| 1 000 | HTB uma raiz + fq_codel | 0,06 s | −9,9% | 30,2–32,4% |
| 1 000 | HTB por CPU (mq, RPS/XPS: o cpumap do LibreQoS no kernel) | 0,4 s | +13,8…+15,7% | 34,9–37,1% |
| 10 000 | EDT | 0,9 s | +7,1% (sobra da fila no começo da janela) | 28,5% |
| 10 000 | HTB uma raiz | 7,4–9,2 s | −10,3% | 35,6–39,0% |
| 10 000 | HTB por CPU | não terminou em 23 min (40 000 classes) | — | — |

- **Por que EDT:** exato na taxa, a menor CPU, montagem que não cresce com o número de alvos (o
  EDT escreve mapas; o HTB cria classes e filtros, ~1 ms por alvo numa raiz e muito mais com uma
  árvore por CPU), nenhum lock de qdisc por alvo (o `fq` de cada fila de transmissão é da CPU que a
  usa), e a mesma peça molda PPPoE, IPoE, DHCP e redes fixas. O HTB por CPU entregou acima da taxa:
  com mais de um fluxo por alvo o RPS espalha o alvo por filas, e cada árvore tem a sua classe.
- **O que o EDT não faz:** intercalar os fluxos **dentro** de um alvo (saem na ordem de chegada). O
  CoDel na espera prevista mantém a fila curta (TCP a 50 Mbit/s com 20 ms de RTT: 35 retransmissões
  contra 1663 do policer, ping +15 ms sem GSO). Se um operador precisar de justiça por fluxo dentro
  do assinante, o caminho é a qdisc em BPF (`struct_ops`, kernel 6.16+), não o HTB.
- **Revisar** com placa real (G4.3cb) e quando a qdisc BPF estiver nos kernels das distribuições.

### BFD próprio em Rust puro (G3.6)

**Decisão (do usuário, 2026-10-27): o BFD é nosso (`crates/proto-bfd` + serviço `bfd` do
daemon), não o `bfdd` do FRR.** O FRR continua com BGP, OSPF e LDP; a ligação (G3.6b) será
pelo *distributed data plane* do `bfdd` (`--dplaneaddr`, protocolo `bfddp`), com o nosso motor no
papel do data plane, ou, se ele não servir, derrubando o vizinho pelo vty.

- **Por que Rust puro aqui** (a regra geral de "Desempenho e escolha de implementação"): BFD é
  um protocolo pequeno e fechado (RFC 5880/5881/5883), a parte cara é o relógio e o caminho do
  pacote, e o nosso motor ganha o que o `bfdd` não tem (multithread, jitter e folga por sessão,
  dampening, histórico, comandos e Safe Mode).
- **Divisão em N threads:** sessão por `discriminador mod N`; socket por thread no grupo
  `SO_REUSEPORT` com cBPF que lê o Your Discriminator; timer wheel por thread; nada de lock no
  caminho do pacote. Uma thread leva 1000 sessões a 50 ms × 3 com ~10 % de um núcleo e jitter
  p99 de 69 µs (**medido**, `docs/bfd.md`); o padrão é uma thread por 500 sessões, até 4.
- **Revisar** com a comparação medida contra o `bfdd` na VM (G3.6b) e se aparecer pedido de
  dezenas de milhares de sessões ou 3,3 ms (BFD em XDP, G3.6f).

### MPLS: kernel por netlink próprio, LDP no FRR (G3.5)

**Comparado:**

- Encaminhamento: o kernel (`mpls_router`) contra o XDP (G2.5). O kernel ficou. O fast path MPLS
  em XDP é a G3.5f, só se o kernel se mostrar o gargalo num laboratório com tráfego.
- Programação e leitura dos rótulos: três caminhos possíveis.
  - `ip -f mpls`: um processo por lote e texto para interpretar;
  - o crate `rtnetlink`: assíncrono, e o resto do `hal-linux` já é síncrono por socket
    (`neigh.rs`);
  - netlink próprio: codec puro de ~200 linhas, com proptest e muitas requisições por `sendmsg`.
    **Ficou este.**
- LDP: implementar em Rust contra o `ldpd` do FRR. Ficou o FRR, pela regra do projeto: protocolo
  maduro, interoperabilidade antes de desempenho, e o gargalo não está no plano de controle.

**Números:**

- Montar a Forwarding Table de 100 mil rótulos e 10 mil FECs: 22,5 ms, **medido**.
- Isso vai para a thread do serviço `mpls`. A página sob o lock fica em 1,1 ms e a busca em
  0,48 ms, **medidos** (`docs/mpls.md`).
- Lote × um a um no kernel: medido no CI completo / na VM (`tests/netns_mpls.rs`), pendente
  aqui.

**Revisar se:**

- vier um LDP em Rust (holo, G3.8);
- o kernel não aguentar a vazão MPLS.

### LSP ping e traceroute em Rust puro (G3.5b)

**Comparado:** não há ferramenta externa a orquestrar. O FRR não tem LSP ping (o `ldpd` não
responde MPLS echo), o iproute2 também não, e o kernel não manda nem entrega pacotes para 127/8
por uma interface. Ficaram três peças em Rust puro:

- codec (RFC 8029 §3) e lógica do respondedor (§4.4), sem E/S, no `corerouter-hal`
  (`hal/src/lsp/`), ao lado do `icmp_ext.rs`: o `hal-linux` é L1 e não pode usar um `proto-*`,
  e o laboratório responde com o mesmo código (`lsp/sim.rs`);
- envio por `AF_PACKET` (o quadro inteiro, com a pilha de rótulos da rota da FEC, lida por
  `RTM_GETROUTE` + `RTA_ENCAP`), contra uma rota de host temporária com `encap mpls` (mexeria na
  tabela do roteador a cada ping) — ficou o `AF_PACKET`;
- recepção do respondedor por sockets `AF_PACKET` presos a um protocolo (MPLS, IPv4, IPv6) e às
  interfaces MPLS, com filtro BPF clássico, contra `ETH_P_ALL` (o kernel chamaria o socket em
  todo pacote enviado também, com um clone por pacote) e contra `route_localnet=1` (entregaria
  127/8 vindo da rede a qualquer serviço local: brecha). Ficaram os sockets por protocolo.

**Números:** pedido codificado em 117 ns, lido em 104 ns, resposta de trânsito completa (100 mil
rótulos) em 363 ns, **medidos** (`hal/benches/lsp_echo.rs`, release). Com o limite padrão de 100
respostas/s, ~0,004 % de um núcleo.

**Revisar se:** o filtro BPF por pacote IP nas interfaces MPLS aparecer num perfil do caminho de
dados (passar o respondedor para o XDP da G3.5f).

## Histórico de revisão

- 2026-10-21 — versão inicial (esqueleto v0.1.0).
- 2026-10-21 — G0.6: crate `storage-fs` (L4) e seção de persistência.
- 2026-10-21 — `hal-linux` aplica via rtnetlink (G1.2): plano puro + executor com rollback.
- 2026-10-21 — G0.4: trait `Backend` da UI, GUI remota (nativo e WebSocket), `control::ws`.
- 2026-10-21 — G1.11: preferências da janela (tema, comentários inline) fora do engine.
- 2026-10-21 — G5.2: crates `proto-lldp`/`proto-mndp` (L2) e módulo `l2` do `hal-linux`.
- 2026-10-21 — G1.5: rotas estáticas e VRF (`model::route`, passos 0 e 9 do plano).
- 2026-10-22 — G1.14: `Hal::features` e a sonda de recursos do `hal-linux`.
- 2026-10-22 — G1.4: seção Safe Mode (`Caller` por conexão, `hang_up`, relógio por `tick`).
- 2026-10-22 — G5.1: crates `proto-discovery` (L2) e `discovery` (L4), tabela de vizinhos no engine, tela de conexão.
- 2026-10-22 — G5.2 Parte 2: LLDP/MNDP no daemon (`link_discovery.rs`), cola L1+L2 na app.
- 2026-10-22 — G1.18: descoberta/contadores do `hal-linux` via rtnetlink e política de posse dos links.
- 2026-10-22 — G0.8: crate `shell` (L4) e o terminal no fluxo de um comando.
- 2026-10-22 — G0.3: `model::users`, `engine::auth`, `control::{auth,tls,local_token,known_hosts,dial}`, seção de autenticação.
- 2026-10-22 — G6.1/G6.2: tarefas das ferramentas (`tasks`, `tools/`, `Hal::prober`, `hal::sim`, `hal-linux::icmp`, `ThreadRunner`).
- 2026-10-22 — G2.1a: crate `firewall` (L1 puro), seção Firewall, `Hal::address_list_dynamic`.
- 2026-10-22 — G6.3: MTR nas tarefas das ferramentas.
- 2026-10-22 — G0.3b: primeiro acesso sem senha (bootstrap no engine, regra de rede no `Gate`, `ui::first_login`).
- 2026-10-22 — G1.19: `hal::nic` e os métodos `ethernet_monitor`/`hardware`/`counters` do `Hal`, genetlink do `hal-linux`, `engine::link_watch`.
- 2026-10-22 — G4.7a: cliente DHCPv4 (`proto-dhcp` codec/cliente/lab, `Hal::dhcp_port`, `hal-linux::dhcp`, `engine::dhcp_client`, relógio de serviço no `control`).
- 2026-10-22 — G1.20: `hal::sff`, `Hal::sfp_module`/`cable_tester`, `hal-linux::ether`, `engine::dom_watch`, `Interface::ethernet` no model.
- 2026-10-22 — G2.1b: `Caller::link`, `engine::lockout`, `firewall::{eval,shadow,describe}`, `ui::{firewall_assist,lockout}`.
