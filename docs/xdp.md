# XDP — filtro antes do kernel e fast path do CGNAT (G2.5)

O CoreRouter roda programas eBPF **escritos em Rust** (`aya-ebpf`) no driver da placa de rede
(XDP), antes de o kernel alocar o pacote. A G2.5a entrega a base e o **filtro anti-DDoS**
(IP › Firewall XDP); a G2.5b, o **fast path do CGNAT determinístico** (desenho no fim, depende
da G2.3).

| Peça | Onde | Camada |
|---|---|---|
| Programa XDP (`no_std`, alvo `bpfel-unknown-none`) | `crates/dataplane-ebpf` (fora do workspace) | plataforma |
| Parse, decisão, token bucket, layout dos mapas (`no_std`, sem `unsafe`) | `crates/dataplane-ebpf-common` | L1 plataforma |
| Objeto pré-compilado + hash das fontes | `crates/dataplane-ebpf/prebuilt/` | — |
| Carregador, mapas, contadores (aya, userspace) | `crates/hal-linux/src/xdp.rs` | L1 plataforma |
| Plano puro (config → prefixos, interfaces) e estado | `crates/hal/src/xdp.rs` | L1 |
| Config | `crates/model/src/xdp.rs` (`ip.xdp`) | L0 |
| Comandos `ip.firewall.xdp.*`, pps, lockout | `crates/engine/src/cmd/firewall_xdp.rs`, `engine/src/xdp.rs` | L3 |
| Janela IP › Firewall XDP | `crates/ui/src/xdp.rs` | L5 |

## Como usar

```sh
corerouter-cli run ip.firewall.address-list.add '{"list":"attackers","address":"203.0.113.0/24"}'
corerouter-cli run ip.firewall.address-list.add '{"list":"noc","address":"192.0.2.10"}'
corerouter-cli run ip.firewall.xdp.interface.add '{"interface":"ether1"}'          # auto: native, senão generic
corerouter-cli run ip.firewall.xdp.set '{"block_lists":"attackers","allow_lists":"noc","rate_limit":20000}'
corerouter-cli run ip.firewall.xdp.interface.list    # modo ativo, pps passando e descartados por motivo
corerouter-cli run ip.firewall.xdp.top '{"count":20}'
corerouter-cli run ip.firewall.xdp.reset-counters
```

Ordem da decisão (a mesma função no kernel e nos testes, `filter::decide`):

1. não IP (ARP, LLDP, MPLS, PPPoE): passa;
2. cabeçalho malformado: descarta se `drop_malformed` (motivo `malformed`); flags TCP impossíveis
   (tabela `tcp_valid_flags` do `nf_conntrack`): descarta se `drop_invalid_tcp_flags`
   (`tcp-flags`);
3. origem numa lista de exceção (`allow_lists`): passa, sem bloqueio nem taxa;
4. origem numa lista de bloqueio (`block_lists`, LPM trie IPv4 e IPv6): descarta (`blocked`);
5. limite de taxa por origem ligado: uma ficha do balde da origem (LRU hash), ou descarta
   (`rate-limit`);
6. passa.

Comportamento que o operador precisa saber:

- **Nada carrega** enquanto não houver interface configurada: um roteador sem XDP não faz
  nenhuma chamada BPF.
- `auto` tenta native e cai para generic (a coluna Nota diz o motivo da recusa); `native` falha
  onde o driver não tem XDP e o commit inteiro é desfeito (o `apply` do `hal-linux` aplica o XDP
  por último e, se ele recusar, volta o resto para a config anterior).
- Os links XDP pertencem ao processo do daemon (bpf_link): se ele morre, o kernel solta o filtro
  e o tráfego passa sem filtro (**fail-open**), nunca por mapas velhos.
- Listas: prefixos e faixas (viram blocos CIDR exatos) das address lists do firewall, inclusive
  as entradas dinâmicas com timeout; a sincronização é por diferença (uma chamada de mapa por
  prefixo que mudou, não uma recarga).
- **Lockout:** se a mudança faria o filtro descartar o endereço da própria sessão de gerência
  (na interface por onde ela chega), o commit é recusado como no firewall (G2.1b), a menos de
  `force: true` ou Safe Mode. A lista de exceção resolve.
- O comando avisa (`warnings`) de lista sem entradas e de taxa abaixo de 100 pps.
- No laboratório virtual o filtro é simulado (contadores crescem com o que está ligado).

## Licença

Decisão do usuário (2026-10-23, opção "c"): os crates do XDP — `crates/dataplane-ebpf`,
`crates/dataplane-ebpf-common` e `crates/cgnat-map` — são **GPL-2.0-or-later**; o programa declara
`"GPL"` ao kernel. Todo o resto do CoreRouter continua **AGPL-3.0-or-later**.

- **Por quê:** o kernel só deixa um programa com licença compatível com GPL chamar os helpers
  `gpl_only`, e o fast path do CGNAT (G2.5b) encaminha no próprio XDP com `bpf_fib_lookup`, que é
  um deles. Com a string AGPL o kernel trata o programa como não-GPL e recusa a chamada; a
  alternativa seria traduzir e devolver ao kernel (`XDP_PASS`), com ganho bem menor.
- **Por que "or-later":** GPL-2.0-or-later combina com a AGPL-3.0 do daemon (a GPLv3 é compatível
  com a AGPLv3 pela seção 13 de ambas); GPL-2.0-only não combinaria. O copyleft continua.
- **Onde está:** `license` nos três `Cargo.toml` (valor explícito, não o do workspace), o
  cabeçalho `SPDX-License-Identifier: GPL-2.0-or-later` em cada arquivo desses crates e a seção
  `license` do objeto (`*b"GPL\0"`). O teste `the_xdp_crates_and_object_are_gpl` do `hal-linux`
  confere o objeto embutido, os três manifestos e que o `hal-linux` segue com a licença do
  workspace.

## Toolchain do programa

O programa só compila com nightly (`-Z build-std=core`), o alvo `bpfel-unknown-none` e o
`bpf-linker`. O workspace estável nunca precisa disso:

- `crates/dataplane-ebpf/rust-toolchain.toml` fixa o nightly (`nightly-2026-10-22`) e
  `.cargo/config.toml` o alvo e o linker; o crate tem `[workspace]` próprio e está em `exclude`
  no workspace.
- `cargo xtask ebpf` compila e grava `prebuilt/corerouter-xdp.o` (o que o `hal-linux` embute com
  `include_bytes_aligned!`) e `prebuilt/corerouter-xdp.sources` (SHA-256 das fontes e do objeto).
- O passo `ebpf-check` do `cargo xtask ci` confere o hash **sem** nightly (fonte mudada sem
  recompilar = FAIL) e, onde o toolchain existe, compila o programa; sem ele, `skip` com o
  motivo.
- Instalar: `rustup toolchain install nightly-2026-10-22 --profile minimal -c rust-src` e o
  `bpf-linker` 0.12 do release oficial (`bpf-linker-x86_64-unknown-linux-musl.tar.zst` em
  github.com/aya-rs/bpf-linker/releases, com o sha256 da API do release conferido) ou
  `cargo binstall bpf-linker`. O `cargo install` do fonte pede o LLVM 23 do sistema.
- Licença do programa no kernel: `GPL` (o crate é GPL-2.0-or-later; veja § Licença).

## Testes

- `crates/dataplane-ebpf-common/tests/filter_props.rs` (host, proptest, 2000 casos por
  propriedade): ruído nunca dá panic; quadro montado (VLAN/QinQ, IPv4/IPv6, TCP/UDP/ICMP) volta
  igual do parse; quadro cortado em qualquer ponto do datagrama nunca sai limpo; padding Ethernet
  não muda nada; listas decidem como um LPM de referência linear; flags TCP seguem a opção; o
  limite de taxa é um token bucket (rajada exata, nunca acima de `burst + taxa × tempo`).
- `crates/hal-linux/tests/xdp_root.rs` (root, no CI): o verificador aceita; native e generic em
  veth; **diferencial kernel × host**: 4000 quadros gerados, cortados e corrompidos passam pelo
  programa real (`BPF_PROG_TEST_RUN`) e pelo `decide` do host com as mesmas listas, e o veredito
  tem de ser o mesmo; tráfego real (ping de outro namespace) para contadores, top origens,
  exceção vencendo o bloqueio e limite de taxa; medições (abaixo). Cada teste roda com prazo
  próprio (`timeout`), com a saída direto no log do CI.
- `crates/engine/src/cmd/firewall_xdp.rs` e `crates/engine/tests/xdp.rs`: sucesso, validação,
  rollback, lockout com `force`; `command_sweep` cobre parâmetros lixo.
- `crates/ui/src/tests/xdp.rs`: janela, formulário, top, explicações em PT e EN.
- `cargo xtask xdp-root`: só onde `COREROUTER_REQUIRE_XDP=1` (o runner do CI, que liga a variável
  pelo arquivo `ci/kernel-modules/veth`); roda o binário de teste com `sudo` num namespace
  descartável. Localmente vira `skip` e imprime o comando.

## Blocos `unsafe` (revisão humana)

Todos em `crates/dataplane-ebpf/src/main.rs`, cada um com `SAFETY:`:

1. `Frame::bytes`: `read_unaligned` de `[u8; N]` em `data + off` depois de conferir
   `data + off + N <= data_end` (a mesma checagem que o verificador exige).
2. `Maps::bucket`: `&mut *p` do ponteiro que o kernel devolve para o valor do LRU hash `RATE`
   (válido durante a execução, RCU); a corrida entre CPUs só aproxima a taxa.
3. `count`: incremento do valor por CPU de `COUNTERS` (só esta CPU o toca, sem preempção).
4. `top`: o mesmo para `TOP` (LRU por CPU).
5. `bpf_ktime_get_ns()`: helper sem argumentos.
6. Atributos `#[unsafe(link_section = "license")]` e `#[unsafe(no_mangle)]` do `LICENSE`.
7. `Frame::store` (G2.5b): `write_unaligned` de `[u8; N]` depois da mesma checagem de limite.
8. `fast_nat`: leitura (`*flow`) do valor de `NAT_FLOWS` que o kernel devolveu; o daemon troca
   valores inteiros e as CPUs só gravam palavras inteiras (último uso, pacotes).
9. `fast_nat`: `bpf_fib_lookup` com o contexto do programa e uma `bpf_fib_lookup` inteira na
   pilha, com o tamanho dela.
10. `fast_nat`: gravação do último uso e da contagem de pacotes do fluxo (palavras inteiras; uma
    corrida perde uma contagem, só estatística).
11. `fast_nat`: `bpf_redirect` com o índice de interface que a FIB devolveu.
12. `miss`: incremento do contador por CPU de `NAT_MISS`.

## Pesquisa

Fontes (abertas em 2026-10-23):

- **MikroTik RouterOS v7**: não tem XDP nem eBPF (só um pedido sem resposta no fórum:
  forum.mikrotik.com/t/feature-request-use-ebpf-xdp-in-the-back-end-of-routeros/155667). O
  equivalente é `/ip firewall raw` (`prerouting`, antes do connection tracking;
  manual.mikrotik.com/docs/7.25/cli-reference/ip/firewall/raw/) com `src-address-list` e o
  matcher `dst-limit=rate[/time],burst,mode[/expire]` no modo `src-address`
  (help.mikrotik.com/docs/spaces/ROS/pages/250708064/Matchers). O guia "DDoS Protection"
  (help.mikrotik.com/docs/spaces/ROS/pages/28606504/DDoS+Protection) detecta por `dst-limit`
  numa regra de filtro, põe atacante e alvo em address lists com timeout e descarta no `raw`.
- **VyOS**: `set interfaces ethernet ethX xdp` existiu na linha 1.3 e foi desligado como
  "highly experimental" (T2666, forum.vyos.io/t/xdp-option-missing-on-version-1-3/10326); a T8202
  tirou o XDP como driver do VPP (vyos.dev/T8202).
- **Junos** `system ddos-protection` (policer por protocolo do tráfego para o host) e BGP
  FlowSpec instalado no PFE; **Nokia SR OS** FlowSpec para mitigação; **Cisco** CoPP. Nenhum
  expõe um filtro programável antes da pilha como XDP. **OpenWrt**: protótipo de offload XDP/TC
  (GSoC 2024). **OPNsense/pfSense** (FreeBSD): sem XDP.
- **Cloudflare L4Drop** (blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/): regras do
  Gatebot em cBPF compiladas para eBPF, amostragem para userspace antes do descarte, >8 Mpps num
  servidor; o blog de arquitetura cita token buckets sem corrida como difíceis antes do
  `bpf_spin_lock`. **Katran** (Meta): LB L4 em XDP com tabela LRU de conexões, sem fragmentos.
  **Cilium prefilter** (`bpf/bpf_xdp.c`): mapas HASH (/32) e LPM_TRIE (CIDR) de origens
  descartadas. **xdp-filter** (xdp-tools): portas, IPs e MACs em PERCPU_HASH de 10 000 entradas,
  match exato, modos native/skb/hw, política allow/deny (deny pode trancar o operador).
  **Polycube**: "cubes" encadeados, NAT só IPv4.
- **Verificador** (docs.kernel.org/bpf/verifier.html, bpf_design_QA.html, LWN 794934): ~1 milhão
  de instruções exploradas, pilha de 512 bytes, laços limitados desde o 5.3, todo acesso ao
  pacote conferido contra `data_end`, tail calls até 33. LPM trie: chave big-endian,
  `BPF_F_NO_PREALLOC` obrigatório (docs.kernel.org/bpf/map_lpm_trie.html). LRU hash
  (docs.kernel.org/bpf/map_hash.html).
- **Drivers com XDP nativo** (bcc docs/kernel-versions.md): mlx4 4.8, mlx5 4.9, virtio_net 4.10,
  bnxt 4.11, ixgbe 4.12, i40e 4.13, veth 4.14, ice 5.5, ena 5.6, igb 5.10, igc 5.13; generic
  desde o 4.12. Números de terceiros: mlx5, 1 núcleo, XDP_DROP native 19,8 Mpps contra 8,4 no
  generic (prototype-kernel, xdp25_eval_generic_xdp_tx); artigo do XDP (CoNEXT 2018,
  doi.org/10.1145/3281411.3281443): 24 Mpps/núcleo de drop numa ConnectX-5, ~108 Mpps em 6
  núcleos, contra 4,8 Mpps da tabela raw do iptables e 1,8 Mpps com conntrack.
- **NAT em XDP**: einat-ebpf (TC, EIM/EIF); `bpf_csum_diff` existe em XDP desde o 4.16, mas os
  `bpf_l3/l4_csum_replace` são só de TC, então a reescrita de checksum no XDP é à mão (RFC 1624);
  nenhum CGNAT em XDP maduro e aberto encontrado.
- **RFCs**: 7422 (Informational, errata 4211 editorial; f1(IP interno) → (IP externo, faixa) e
  f2(IP externo, porta) → IP interno), 1624 (HC' = ~(~HC + ~m + m'); errata 4782: com m = m' e
  HC = 0 dá 0xFFFF, então não reescrever o que não mudou), 4787 (atualizada pelas 6888 e 7857:
  REQ-1 EIM, REQ-4 paridade, REQ-5 timeout UDP ≥ 2 min, REQ-9 hairpin, REQ-12 ICMP não destrói
  mapeamento, REQ-14 fragmentos), 1858 §3 (fragmento minúsculo e sobreposição).

O que adotamos:

- Nomes e modelo do RouterOS onde ele tem equivalente: as **address lists do firewall** são a
  fonte das listas (o operador já as alimenta, inclusive por regras com timeout), e o limite por
  origem segue o `dst-limit … src-address` (taxa + rajada).
- Do Cilium: LPM trie para CIDR (em vez do match exato do xdp-filter, que não serve para listas
  de reputação). Do xdp-filter: modos native/generic explícitos, com `auto` como padrão.
- Da tabela do `nf_conntrack`: quais flags TCP são válidas (nenhum descarte que o kernel não
  marcaria como inválido).

Melhorias sobre os outros:

- **Lista de exceção** que vence bloqueio e taxa, e **lockout** checado no commit (o
  xdp-filter documenta que o modo deny pode trancar o operador; aqui o commit é recusado).
- **Diferencial kernel × host** no CI: a mesma função de decisão compila para o kernel e para o
  host, e milhares de quadros gerados têm de dar o mesmo veredito nos dois.
- Tudo é comando: transação, Safe Mode, diff e rollback valem para o filtro como para o resto;
  MCP e CLI veem o mesmo.
- **Top origens** com motivo e lista, para alimentar uma regra ou investigar.

Fica de fora (gaps novas): entradas que regras `add-src-to-address-list` põem na lista (vivem
só no set do nftables; G2.5c), programas fixados no bpffs para sobreviver ao restart do daemon e
amostragem de pacotes descartados para userspace estilo L4Drop (G2.5c), PPPoE e MPLS no parse,
bloqueio por destino (RTBH local), FlowSpec alimentando as listas (G2.5d).

## Desempenho

**Medido** no runner do GitHub Actions (ubuntu-latest, 4 vCPUs, kernel do runner, 2026-10-23),
objeto XDP release, saída `PERF |` do `xdp_root.rs`.

Custo por pacote no kernel (`BPF_PROG_TEST_RUN`, 2 milhões de repetições, quadro UDP de 64 bytes,
média por execução; inclui o custo fixo do próprio test run, que não existe no driver):

| prefixos na LPM | carga dos prefixos | passa (origem fora da lista) | descartado (bloqueado) | passa com limite de taxa ligado |
|---:|---:|---:|---:|---:|
| 0 | 208 ms | 159 ns | — | 216 ns |
| 1 000 | 202 ms | 176 ns | 285 ns | 234 ns |
| 10 000 | 215 ms | 175 ns | 322 ns | 233 ns |
| 100 000 | 441 ms | 170 ns | 339 ns | 229 ns |
| 1 000 000 | 2 682 ms | 173 ns | 347 ns | 231 ns |

(Outra rodada no mesmo dia deu 123–131 ns no passe: o runner varia ~25%; as diferenças entre
colunas se mantêm.)

Leitura:

- **Custo da LPM**: ~17 ns por pacote com a árvore não vazia, e plano de mil a um milhão de
  prefixos (a busca percorre no máximo 32 níveis, não o número de entradas).
- O descarte custa mais que o passe porque grava a origem na tabela de top origens (LRU por CPU):
  ~110–170 ns. Se pesar numa placa real, a tabela pode virar amostrada (G2.5c).
- O limite de taxa soma ~60 ns (o balde da origem num LRU hash).
- Carga: um milhão de prefixos em 2,6 s (uma chamada de mapa por prefixo, só na primeira vez;
  depois só a diferença).
- O host faz a mesma decisão sem mapas em 13–18 ns (`benches/filter.rs`, AMD Ryzen AI Max+ 395,
  release): o resto é busca em mapa e o custo fixo do test run.

Remetente AF_PACKET em userspace num par veth, 2 s por caso, quadros UDP de 64 bytes de origens
aleatórias em 198.18.0.0/15 (o remetente e a recepção dividem um núcleo):

| caso | enviados (kpps) | tratados pelo filtro |
|---|---:|---|
| sem filtro (a pilha do kernel descarta) | 450 | 900 101 pacotes recebidos |
| nftables `raw` prerouting, `ip saddr 198.18.0.0/15 drop` | 471 | 941 056 no contador da regra |
| XDP generic, lista de bloqueio | 402 | 803 840 bloqueados |
| XDP native (veth), lista de bloqueio | 409 | 817 152 bloqueados |

**Em veth o XDP não ganha do nftables raw** (~14% mais lento aqui). O veth já entrega ao receptor
um `skb` pronto; o XDP generic ainda copia o quadro para ter o headroom que o XDP exige, e o
"native" do veth converte o `skb`. O ganho do XDP é **não alocar o `skb`**, e isso só acontece no
driver de uma placa real (artigo do XDP: 24 Mpps por núcleo de XDP_DROP contra 4,8 Mpps da tabela
raw do iptables numa ConnectX-5). Por isso a comparação que decide é a do roteiro abaixo, numa
placa em modo native. O pktgen do kernel ficou fora do CI: mesmo com `reset` antes de apagar a
interface, ele travou a VM do runner duas vezes (sem log).

O que só uma **placa real em modo native** mede, e que veth, modo generic e `BPF_PROG_TEST_RUN`
não mostram: a taxa de descarte no driver antes da alocação do `skb` (o ganho grande do XDP),
o espalhamento por filas (RSS) e a escala com núcleos, o limite do PCIe e do anel de recepção,
o efeito de cache com milhões de origens distintas e a latência sob carga.

### Roteiro para medir no seu hardware

Estes comandos rodam como root na **sua** máquina de teste (os agentes nunca usam `sudo`).
Precisa de duas máquinas: o roteador (com a placa, ex. ConnectX-4/5, Intel X710/E810) e um
gerador ligado a ela.

1. No roteador, compile e rode o daemon com o backend real (como você já faz no namespace
   `corerouter`):
   ```sh
   cargo build --release -p corerouter-daemon -p corerouter-cli
   sudo ./target/release/corerouter-daemon --backend linux --control 7979 --config-dir /var/lib/corerouter-hw
   ```
2. Ponha o filtro na porta de entrada em modo native, com uma lista que pega o tráfego de teste:
   ```sh
   C="./target/release/corerouter-cli --connect 127.0.0.1:7979"
   $C run ip.firewall.address-list.add '{"list":"bench","address":"198.18.0.0/15"}'
   $C run ip.firewall.xdp.interface.add '{"interface":"<porta>","mode":"native"}'
   $C run ip.firewall.xdp.set '{"block_lists":"bench"}'
   ```
3. No gerador, pktgen do kernel (64 bytes, origens aleatórias em 198.18.0.0/15, uma thread por
   fila; troque `<if>` e `<mac do roteador>`):
   ```sh
   sudo modprobe pktgen
   sudo /usr/src/linux/samples/pktgen/pktgen_sample05_flow_per_thread.sh -i <if> -m <mac do roteador> \
     -d 10.0.0.1 -s 64 -t 4 -n 0
   ```
   (sem as amostras do kernel: `Documentation/networking/pktgen.rst`, com `flag IPSRC_RND` e
   `src_min`/`src_max`.) Ao terminar, `echo reset > /proc/net/pktgen/pgctrl` antes de mexer na
   interface: um dispositivo que o pktgen ainda segura não termina de sair, com o lock de rede
   do kernel preso (foi o que travou a VM do CI).
4. No roteador, leia a taxa a cada segundo e a CPU:
   ```sh
   watch -n1 "$C run ip.firewall.xdp.interface.list"
   mpstat -P ALL 1
   ```
5. Repita com `"mode":"generic"`, com o filtro desligado e com a regra equivalente no nftables
   (`table inet t { chain raw { type filter hook prerouting priority -300; ip saddr 198.18.0.0/15 drop; } }`)
   para a comparação. Para o custo por regra da LPM no seu processador, rode o teste de medição
   (namespace descartável, nada sai dele):
   ```sh
   cargo test --release -p corerouter-hal-linux --test xdp_root --no-run
   sudo ip netns add crxdp
   sudo ip netns exec crxdp env COREROUTER_XDP_ROOT=1 target/release/deps/xdp_root-* perf_lpm_cost --nocapture
   sudo ip netns del crxdp
   ```
6. Mande a saída: entra no `docs/perf.md` como **medido** (máquina, placa, kernel, data).

## G2.5b — caminho rápido do CGNAT

Desenho escolhido pelo usuário (opção 1, 2026-10-24): **offload guiado pelo conntrack**, como a
flowtable da G2.4a, só que em XDP.

- **O kernel decide tudo.** Os primeiros pacotes de cada conexão passam pelo nftables da G2.3,
  que escolhe a porta dentro da faixa determinística do assinante (RFC 7422, a fórmula de
  `corerouter-cgnat-map`). Não há segunda escolha de porta: o "Quem era?" segue exato e não há
  colisão com o que fica no kernel.
- **O serviço `xdp-nat` do daemon** (`apps/corerouter-daemon/src/service/xdp_nat.rs`) ouve o
  conntrack (ctnetlink, grupos NEW, UPDATE e DESTROY). Quando uma conexão IPv4 TCP/UDP com NAT
  fica `ASSURED` (TCP em `established`), ele instala os dois sentidos no mapa `NAT_FLOWS`
  (LRU hash, chave = 5-tupla como chega, valor = origem e destino novos). Quando o conntrack a
  destrói, ou o TCP sai de `established`, ele os tira. Eventos perdidos (`ENOBUFS`) ou um mapa
  novo (o XDP recarregou) levam a uma releitura da tabela inteira. A política é pura
  (`corerouter_hal::xdp_nat::Book`) e testada em qualquer plataforma.
- **O XDP** (`fastnat` no `dataplane-ebpf-common`), depois do filtro: pacote de um fluxo
  conhecido, sem VLAN, sem opções IP, sem SYN/FIN/RST e com TTL > 1 tem o destino consultado
  na tabela de rotas (`bpf_fib_lookup`). Se ela resolver, troca endereço e porta, corrige os
  checksums IP e TCP/UDP de forma incremental (RFC 1624), desconta o TTL, grava os MACs e
  redireciona (`bpf_redirect`). Se não resolver, o pacote vai intacto para o kernel: nada é
  escrito antes da consulta dar certo. O motivo conta em `NAT_MISS` ("Enviado ao kernel" na
  janela): códigos da FIB (sem vizinho, MTU, sem rota…), VLAN, opções IP, controle TCP, TTL.
- **Timeout:** o conntrack não vê os pacotes do caminho rápido. A cada 2 s o serviço renova o
  timeout (`IPCTNL_MSG_CT_NEW` sem `NLM_F_CREATE`, `CTA_TIMEOUT`) das conexões que o XDP
  carregou desde a última vez, com o valor do próprio kernel para o estado (TCP established,
  UDP stream).
- **Fica no kernel:** IPv6, ICMP (inclusive os de erro com payload), fragmentos, ALG, o que vai
  para o próprio roteador e tudo o que não for uma conexão estabelecida.
- **Capacidade:** 262 144 conexões ao mesmo tempo (524 288 sentidos). O mapa é preallocado
  (~50 MiB, **estimado**) só com o caminho rápido ligado; ligar ou desligar recarrega o objeto.
- **Comando:** `ip.firewall.xdp.set fast_nat=yes` (avisa sem pool de CGNAT e com menos de duas
  interfaces com XDP); `ip.firewall.xdp.print` traz `fast_nat_flows`, `fast_nat_misses` e o
  estado do serviço; `ip.firewall.xdp.interface.list` traz `fast_nat_pps`.
- **Por que só IPv4 sem opções:** o verificador do kernel recusa aritmética de ponteiro de
  pacote com offset sem limite conhecido. Um `IpInfo` copiado pela pilha perde o limite que o
  verificador conhecia. Sem VLAN e sem opções, os offsets são constantes (IP em 14, transporte
  em 34). Pacotes com opções IP são raros e vão ao kernel.
