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

- **LSP ping/traceroute** (G3.5b): RFC 8029, com a correção da RFC 9570, que proíbe o Router
  Alert. Precisa de um socket UDP 3503 com destino em 127/8, TTL 1 e a pilha de rótulos da FEC. A
  pilha sai por `RTA_ENCAP`/`MPLS_IPTUNNEL_DST` numa rota de host temporária ou por `AF_PACKET`.
  Também precisa do lado que responde. Fica para um PR próprio (~8 h, **estimado**).
- **VPLS/L2VPN** (RFC 4762, `/interface vpls`), **L3VPN** (RFC 4364), **SR-MPLS** (RFC 8665) e
  **fast path MPLS em XDP**: G3.5c a G3.5f.
- Filtros `accept-filter`/`advertise-filter` do RouterOS e a política "só loopbacks" do Junos:
  hoje o `ldpd` rotula todas as rotas do IGP. O Junos faz melhor aqui; fica na G3.5g.
- O teste com dois `ldpd` reais sobre OSPF na VM (rótulos trocados e ping pelo LSP): a VM está com
  o disco cheio. Fica pendente na G3.5 até ela voltar.

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
  alternativa é uma ida e volta por rótulo. Os números (lote × um a um, 10 mil rótulos; dump de 100
  mil) saem do `tests/netns_mpls.rs` (`ten_thousand_labels_in_batches_and_one_by_one` imprime os tempos), que precisa do `mpls_router`.
  O host de desenvolvimento não tem o módulo carregado e a VM está fora, então eles rodam no CI
  completo (`ci/kernel-modules/mpls_router`) e ficam **pendentes** de medição aqui.
