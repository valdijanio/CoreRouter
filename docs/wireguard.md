# WireGuard (G1.31)

Interfaces WireGuard com os nomes e padrões do RouterOS v7.25 (`/interface wireguard` e
`/interface wireguard peers`). O caminho de dados é o WireGuard do kernel; a config e o estado
são nossos, em Rust, por generic netlink (decisão e números em `docs/architecture.md`).

Partes:

- **PR 1:** modelo, comandos, chaves, push para o kernel, estado por par, testes.
- **PR 2 (G1.31a):** janela Interfaces › WireGuard (abas Interfaces e Peers, modais com
  checagens e prévia dos comandos), abaixo em "Janela".
- **PR 3 (G1.31b):** config do cliente com QR, `wg-import`/`wg-export`, saúde "sem handshake",
  endpoint por nome DNS, assistente de firewall, MTU pela rota até o endpoint, Safe Mode na `wg`
  de gerência e a caixa "Create Routes" no modal do par, abaixo em "Extras".
- **G1.31c:** a VRF dos pacotes cifrados (`vrf`, RouterOS 7.21), abaixo em "VRF do socket
  cifrado".

## Comandos

| Comando | O que faz |
|---|---|
| `interface.wireguard.add {name?, listen_port?, mtu?, private_key?, vrf?, disabled?, comment?}` | Cria a interface. Nome padrão `wireguard1`, porta 13231 (ou a primeira livre acima), MTU 1420, chave privada gerada no roteador e selada. Devolve a chave pública. |
| `interface.wireguard.set {name, listen_port?, mtu?, private_key?, …}` | `private_key=auto` faz um par novo: todos os pares precisam da pública nova (aviso). |
| `interface.wireguard.remove/enable/disable {name}` | `remove` leva os pares junto. |
| `interface.wireguard.list {show_sensitive?}` | Porta, MTU, `vrf` dos pacotes cifrados, chave pública, `running`, pares e pares `up`, erro do último push. A privada só com `show_sensitive` (grupo `full`). |
| `interface.wireguard.peers.add {interface, name?, public_key? \| private_key?, preshared_key?, endpoint_address?, endpoint_port?, allowed_address, persistent_keepalive?, responder?, …}` | Nome padrão `peerN`, único no roteador. `private_key=auto` gera o par de chaves do cliente (para a config do cliente, PR 3). `preshared_key=auto` gera a PSK. |
| `interface.wireguard.peers.set {name, new_name?, …}` | Mesmos campos; `endpoint_address=""` volta a esperar o par. |
| `interface.wireguard.peers.remove/enable/disable {name}` | |
| `interface.wireguard.peers.list {interface?, show_sensitive?}` | Estado (`up`, `idle`, `no-handshake`, `never`, `disabled`), segundos desde o último handshake, rx/tx, endpoint atual e `roamed`, e uma dica quando não há handshake. |

| `interface.wireguard.preview {id?, name?, listen_port?, mtu?, private_key?, …}` | A prévia do modal da interface: roda o `add`/`set` numa cópia da config e diz a porta, o firewall `input` (UDP da WAN chega?), o MTU contra o da WAN − 80 e os comandos que o OK manda. Nunca falha por entrada ruim (vira checagem). |
| `interface.wireguard.peers.preview {id?, interface?, name?, public_key?, preshared_key?: bool, allowed_address?, …}` | A prévia do modal do par: prefixo de outro par (erro), o próximo endereço livre da rede da interface, laço da rota até o endpoint, keepalive atrás de NAT; num par novo sem chave, `private_key=auto`; ao editar, mantém as chaves (a pública sem mudança não vai). |

| `interface.wireguard.peers.show-client-config {name}` | O arquivo `wg-quick` do cliente (grupo `full`: leva a chave privada dele): `Address` = `client_address` ou o allowed address, `DNS`, `AllowedIPs` = `client_allowed_address` ou tudo, `Endpoint` = `client_endpoint` ou o endereço do roteador na WAN e a porta (aviso se for privado), a PSK. Par com a pública colada: o lugar da privada fica marcado, com aviso. A GUI mostra o QR. |
| `interface.wireguard.wg-export {name, show_sensitive?}` | A interface inteira como `wg-quick` (chave, porta, endereços, MTU, pares com `# Name =`); as chaves só com `show_sensitive` (grupo `full`). |
| `interface.wireguard.wg-import {text, name?}` | Lê um `wg-quick` e cria a interface, os endereços e os pares numa transação (tudo ou nada); prefixo repetido, chave repetida ou a chave da própria interface recusam o arquivo inteiro; `PostUp`, `DNS` etc. viram aviso. |

Os pares aceitam também `client_address`, `client_dns`, `client_endpoint`,
`client_allowed_address`, `client_keepalive` e `client_mtu` (os `client-*` do RouterOS 7.12), e
`endpoint_address` aceita nome DNS. Os comandos que mudam interface ou par aceitam `force`
(Safe Mode, abaixo).

Como interface comum, uma `wg` também aceita `interface.set` (renomear, MTU), `ip.address.add`,
rotas, firewall e interface lists.

```sh
corerouter-cli run interface.wireguard.add '{"name":"wg0"}'
corerouter-cli run ip.address.add '{"address":"10.9.0.1/24","interface":"wg0"}'
corerouter-cli run interface.wireguard.peers.add '{"interface":"wg0","name":"notebook","public_key":"<chave do cliente>","allowed_address":"10.9.0.2/32"}'
corerouter-cli run interface.wireguard.peers.list
```

## Janela (G1.31a)

Interfaces › WireGuard (`crates/ui/src/wireguard.rs`), a opção A do mockup, no padrão de lista
do G0.24:

- **aba Interfaces:** estado (`running`, `disabled`, `error` com o motivo embaixo,
  `not running`), nome em selo por hash, porta, MTU, chave pública curta, pares e quantos `up`;
  clique direito: copiar a chave pública, "Add Peer…" (abre o modal do par já nessa interface),
  "Regenerate Keys…" (pergunta antes: todos os pares precisarão da pública nova);
- **aba Peers:** selo de estado (`up`, `idle`, `no-handshake`, `never`, `disabled`, mais
  `responder`), último handshake ("7 s ago"), endpoint atual com selo `roamed`, prefixos, rx/tx,
  chave curta; filtros por interface e por estado; rodapé com as contagens; a linha embaixo da
  tabela dá a dica do engine para o par selecionado;
- **modais:** ⓘ em português em cada campo; a prévia do engine (acima) com as checagens e os
  comandos; o par novo cai na interface filtrada, senão na do par selecionado;
- as `wg` continuam em Interfaces (tipo `wireguard`, cadeado).

## Extras (G1.31b)

- **Endpoint por nome DNS:** `endpoint_address=vpn.exemplo.com.br`. O serviço `wireguard-dns` do
  daemon pergunta ao resolvedor do próprio roteador, fora do lock da sessão, o nome que nunca foi
  resolvido ou cujo par está sem handshake há mais de 180 s (`REJECT_AFTER_TIME`) e foi
  perguntado há 30 s ou mais — a regra do `wireguard_watchdog` do OpenWrt e do RouterOS. O
  endereço novo vai para o kernel na hora; uma falha mantém o anterior e aparece na lista
  (`resolve_error`) e na janela (selo `not resolved`). A config antiga, com IP, carrega igual (o
  campo continua texto).
- **Saúde:** `wireguard.handshake` avisa o par que o roteador chama (endpoint e keepalive, ou
  tráfego) e que não responde há 5 min ou mais ("nunca respondeu, tentando há 6 min" ou "sem
  handshake há 7 min"). Par que só espera (road warrior) ou fica ocioso não entra.
- **Assistente de firewall:** no modal da interface, "Accept in Firewall" acrescenta à transação
  um `ip.firewall.filter.add` `accept` de UDP na porta, logo antes da regra que derruba
  (`place_before`), quando o `ip.firewall.test` diz que o `input` derruba.
- **MTU pela rota:** a checagem usa a rota até cada endpoint e o overhead da família (60 bytes
  para IPv4, 80 para IPv6; 80 quando não há endpoint). A menor folga decide.
- **Safe Mode:** quando a sessão de gerência chega pelo túnel (a rota de volta ao operador sai pela
  `wg`), o lockout (`lockout.rs`) recusa sem `force` o que a derrubaria: chave nova ou porta nova
  na interface, e remover, desativar, trocar a chave ou tirar o endereço do operador do par por
  onde ele chega. O modal mostra o risco com "I understand" e o botão Safe Mode; os botões da lista
  passam pela janela de lockout da GUI.
- **Create Routes** (a "opção 2" escolhida pelo usuário): caixa no modal do par que acrescenta à
  mesma transação um `ip.route.add gateway=<wg>` por prefixo do par que ainda não tem rota para a
  `wg` (a rede da própria interface fica de fora). `0.0.0.0/0` pede um sim explícito e cita a rota
  padrão que já existe (as duas na distância 1 dividiriam o tráfego). As rotas são estáticas
  comuns: remover o par não as remove.
- **Segredos:** `preshared_key` entrou em `SECRET_KEYS` (um PSK colado ia para o journal em claro
  desde o PR 1), e as linhas `PrivateKey`/`PresharedKey` de um texto `wg-quick` são mascaradas no
  journal, no log e na barra de status da GUI.

## VRF do socket cifrado (G1.31c)

`vrf` (RouterOS 7.21, padrão `main`) é a VRF por onde saem e chegam os pacotes **cifrados**: o
UDP do túnel e os handshakes. Não é a VRF da interface `wg` (essa é o `vrf` da própria interface,
em `ip.vrf`). O caso de uso é o túnel que fala com o par por uma segunda operadora numa VRF, com o
tráfego de dentro do túnel na tabela principal.

```sh
corerouter-cli run ip.vrf.add '{"name":"wan2","interfaces":"ether2"}'
corerouter-cli run ip.route.add '{"dst_address":"0.0.0.0/0","gateway":"198.51.100.1","routing_table":"wan2"}'
corerouter-cli run interface.wireguard.add '{"name":"wg0","vrf":"wan2"}'
corerouter-cli run routing.rule.kernel   # a regra 1xx: fwmark da wan2, iif lo, lookup da wan2
```

**Como funciona.** O socket do WireGuard no kernel não se prende a interface nenhuma
(`drivers/net/wireguard/socket.c` do linux-6.18.59: `send4`/`send6` fazem
`ip_route_output_flow` com `flowi4_mark = wg->fwmark` e sem `oif`; `udp_sock_create` sem
`bind_ifindex`). Então um `commit` faz três coisas juntas:

1. o `fwmark` do link é a marca de roteamento da VRF (`mark_value(Routing, "wan2")`, a mesma
   que um `mark-routing=wan2` do mangle daria), enviado em `WGDEVICE_A_FWMARK` pelo push;
2. uma regra `fwmark <marca>/0xffff0000 iif lo lookup <tabela da VRF>` entra na faixa das
   marcas (prioridades 100–999, antes do `l3mdev` 1000) pelo mesmo `apply` que escreve as outras
   regras (`hal::policy::expected_rules`). `iif lo`: só os pacotes do próprio roteador. Sem ele,
   um pacote recebido que manteve a marca casaria a regra antes do `l3mdev` e voltaria pela VRF de
   onde veio. Isso aparece num veth no mesmo namespace, que não limpa o `skb->mark`: no teste, o
   pacote ficava em laço até o TTL. Se o mangle também usa o nome da VRF como marca, a regra é a
   do mangle, sem `iif`;
3. `net.ipv4.udp_l3mdev_accept=1`, enquanto houver uma `wg` habilitada com `vrf`. Um datagrama
   que chega numa porta da VRF só chega a um socket sem `bind` com esse sysctl
   (`inet_bound_dev_eq`, `include/net/inet_sock.h`; o mesmo vale para IPv6,
   `udp_sk_bound_dev_eq`, `include/net/udp.h`). Sem ele: `UdpNoPorts` e ICMP port unreachable
   (**medido** no laboratório). Volta ao valor anterior quando nenhuma `wg` tem `vrf`.

Tirar o `vrf` (ou `main`), desativar ou remover a interface desfaz os três no mesmo commit, e o
`config.rollback` também.

**Cuidados.**

- Com o `udp_l3mdev_accept` ligado, os serviços UDP do roteador que escutam em todos os
  endereços (DNS, NTP…) também ouvem nas portas das VRFs. O `add`/`set` avisa; filtre-os no
  `input`.
- `ip.vrf.remove` recusa uma VRF que uma `wg` usa.
- A prévia do modal procura a rota até cada endpoint na tabela da VRF. Avisa quando não há rota
  e mostra o firewall `input` e o MTU pela porta da VRF.
- O Safe Mode trata a troca de `vrf` do túnel por onde a sessão chega como corte.
- `routing.rule.kernel` descreve a regra como "the encrypted packets of WireGuard wg0".
- Uma marca de VRF que colide com outra marca de roteamento de nome diferente é recusada.

**Testado** num kernel real (`crates/hal-linux/tests/netns_wireguard_vrf.rs`, namespace sem root,
2,1 s), com duas VRFs ligadas por um veth, onde a tabela principal não alcança o outro lado:

- `wgva` (vrf=vblue) fecha o handshake com `wgvb` (vrf=vred);
- `wgvc`, igual mas sem `vrf`, não fecha;
- com `vrf=vblue`, `wgvc` fecha;
- sem os `vrf`, as regras saem e o sysctl volta.

## Validações (mais fortes que os avisos do RouterOS)

O kernel esconde três erros; o engine os recusa antes do commit:

- **o mesmo prefixo em dois pares da mesma interface:** o kernel o passa em silêncio para o último
  par configurado (`drivers/net/wireguard/allowedips.c`, `add()`), e o primeiro deixa de recebê-lo.
  O RouterOS só avisa desde a 7.24;
- **par com a chave pública da própria interface:** o kernel o ignora em silêncio (`netlink.c`,
  `set_peer`);
- **a mesma chave pública duas vezes numa interface.**

Também:

- a porta de outra interface WireGuard é recusada (o kernel recusaria o `bind`, `EADDRINUSE`);
  porta de serviço do roteador (DNS, NTP, DHCP, RADIUS, IPsec) gera aviso;
- `allowed_address` é obrigatório, normalizado para a rede (`10.20.1.0/16` vira `10.20.0.0/16`,
  com aviso, como o kernel guarda);
- `endpoint_address` e `endpoint_port` vão juntos;
- avisos: `0.0.0.0/0` num par que divide a interface com outros; endpoint dentro do próprio
  allowed address (laço se uma rota mandar o endpoint para dentro do túnel).

`allowed_address` não cria rota, como no RouterOS, no VyOS e no pfSense; a caixa "Create Routes"
do modal (G1.31b) cria, quando pedido.

## Estado de um par

Regra única no engine (`corerouter_model::wireguard::PeerState`), pelos timers do protocolo
(whitepaper §6.1, `drivers/net/wireguard/messages.h`):

| Estado | Quando |
|---|---|
| `up` | último handshake há ≤ 180 s (`REJECT_AFTER_TIME`) |
| `idle` | handshake mais velho e nada pede outro: par sem keepalive sem tráfego (normal) |
| `no-handshake` | o roteador tenta (endpoint e keepalive, ou tráfego para enviar) e não há resposta |
| `never` | nunca houve handshake e o roteador só espera (sem endpoint, ou `responder`) |
| `disabled` | par ou interface desativados |

## Como chega ao kernel

1. `Hal::apply` cria e apaga o link `wireguard` como qualquer outro (`LinkSpec::Wireguard`). As
   chaves e os pares não fazem parte do spec: mudar um par nunca recria o link.
2. Depois do commit, o engine abre as chaves seladas e chama `Hal::wireguard_set` para cada
   interface cujo estado desejado mudou (`crate::wireguard`). O relógio de serviço tenta de novo
   o que falhou e, a cada 30 s, compara com o que o link tem (um link recriado, um par apagado com
   `wg`).
3. O `hal-linux` lê o link (`WG_CMD_GET_DEVICE`, juntando um par que continua na mensagem
   seguinte) e manda só a diferença (`WG_CMD_SET_DEVICE`), em blocos de até 32 KiB.
   - Nunca usa `WGDEVICE_F_REPLACE_PEERS`, que derrubaria todas as sessões.
   - O endpoint só vai quando o par é novo ou quando o *configurado* mudou: o kernel segue o par
     que muda de IP (roaming), e o roteador não o puxa de volta.
4. A chave privada nunca aparece em log: o `Debug` de `WgDevice` a esconde, e o buffer da
   requisição é zerado depois do envio.

## Desempenho e paralelismo

- **Por item:** aplicar é O(pares que mudaram), não O(total). Ler o estado é um dump por
  interface: 5 ms com 1 000 pares e 63 ms com 50 000 (**medido**, VM do laboratório).
- **A janela (G1.31a):** a GUI pede `interface.wireguard.list` a cada refresh com a janela
  aberta, e `peers.list` só na aba Peers. O PR 1 casava cada par com o relatório do kernel
  andando a lista inteira (O(pares²)): com 20 000 pares, `peers.list` levava 413 ms e `list`
  362 ms. Agora um mapa por chave pública: 51 ms e 5,3 ms (**medido**, release, bench
  `wireguard_list`, Ryzen AI Max+ 395, `VirtualHal`, 2026-11-12). Os 51 ms que sobram são a
  montagem do JSON de 20 000 linhas; um cache por tick do dump não muda isso e fica de fora.
- **Núcleos:** a cifra é do kernel, que espalha os lotes por todos os núcleos online (decifra em
  paralelo e entrega em ordem por par). No caminho de dados não há trabalho nosso.
- **Plano de controle:** o push roda sob o lock da sessão, como o resto do commit. Uma mudança de
  par custa 3–6 ms (**medido**). Criar milhares de pares de uma vez cresce mais que linear no
  kernel (10 000 em 0,7 s, 50 000 em 11,7 s, **medido**). O perfil mostra IPI, provavelmente a
  alocação por CPU do `dst_cache_init` de cada par. Daí o teto de 20 000 pares por interface.

## Medição: kernel × espaço de usuário (2026-11-12)

Bare metal: o host de desenvolvimento (AMD Ryzen AI Max+ 395, Zen 5, 32 threads, kernel 7.0),
dentro de `unshare -Urnmp`, sem root. Quatro namespaces: cliente → roteador A → túnel →
roteador B → servidor. `iperf3` 3.16, 10 s por teste, mediana de 2. **Medido.**

| Teste | sem túnel | kernel | BoringTun 0.7.1 | wireguard-go 0.0.20250522 |
|---|---|---|---|---|
| TCP, 1 fluxo | 94,9 Gb/s | 7,3 Gb/s | 2,6 Gb/s | 16,8 Gb/s |
| TCP, 4 fluxos | 330 Gb/s | 7,1 Gb/s | 2,6 Gb/s | 10,7 Gb/s |
| UDP 64 B, 4 fluxos | 1 958 kpps | 631 kpps | 389 kpps | 338 kpps |
| UDP 1400 B, 1 fluxo | 6,2 Gb/s | 4,9 Gb/s, 444 kpps, 2 % perda | 4,5 Gb/s, 410 kpps, 55 % | 3,5 Gb/s, 316 kpps, 63 % |
| UDP 1400 B, 4 fluxos | 21 Gb/s | 6,7 Gb/s, 607 kpps | 3,4 Gb/s, 312 kpps | 3,5 Gb/s, 315 kpps |
| ping com 4 fluxos TCP | 0,012 ms | 13,5 ms | 0,30 ms | 9,8 ms |

Na VM do laboratório (8 vCPUs, kernel 7.0) o kernel cai para 1,5 Gb/s em TCP, contra 9,1 Gb/s
do wireguard-go. O perfil mostra:

- IPI (`asm_sysvec_call_function_single`, 4,8 %), lock e escalonador no topo;
- a cifra em AVX-512 (`chacha_8block_xor_avx512vl`, `poly1305_blocks_avx512`) com ~5 %;
- com os vCPUs presos acordados, nada mudou.

A causa é o despacho em rodízio por núcleo (`queueing.h`, `queue_work_on` no próximo núcleo
online): cada IPI sai para o hipervisor.

Os scripts ficaram fora do repositório (pasta de notas da sessão): `wg-host.sh` (bare metal),
`wg-bench.sh` e `wg-prof.sh` (VM).

## Pesquisa

**MikroTik RouterOS 7.25** (manual.mikrotik.com/docs/7.25, `virtual-private-networks/wireguard` e
`cli-reference/interface/wireguard`; o help.mikrotik.com antigo está congelado):

- interface: `listen-port` 13231 (única por interface desde 7.14), `mtu` 1420, `private-key`
  gerada (`auto`/`none` desde 7.12), `public-key` só leitura, `vrf` do socket cifrado (7.21);
- par: `public-key` ou `private-key=auto`, `preshared-key`, `endpoint-address/port` (IP ou nome),
  `allowed-address`, `persistent-keepalive`, `responder` e `name` (7.15), `client-*` e
  `show-client-config` com QR (7.12; QR sensível desde 7.21);
- estado: `last-handshake`, `rx`, `tx`, `current-endpoint-*` (roaming);
- `allowed-address` não cria rota; sobreposição só gera aviso (7.24+); refaz a consulta DNS do
  endpoint (7.10/7.11), sem parâmetro.

**Outros:**

- **VyOS:** valida no commit (chave duplicada, chave igual à da interface, porta), gera config de
  cliente com QR e refaz a consulta DNS quando o handshake passa de 360 s.
- **OPNsense:** cria rotas por padrão ("Disable routes"); o gerador de par escolhe o próximo IP e
  não guarda a privada.
- **pfSense:** refaz a consulta DNS a cada 300 s.
- **OpenWrt:** `route_allowed_ips` com rota de host para o endpoint; aplica com `wg syncconf` sem
  derrubar sessões; o `wireguard_watchdog` refaz a consulta DNS acima de 180 s.

**Protocolo:**

- Whitepaper (wireguard.com/papers/wireguard.pdf): §5.2 PSK; §5.4.6 overhead de 32 B por pacote,
  60/80 B com UDP e IP, daí 1420; §6.1 timers (REKEY_AFTER_TIME 120 s, REJECT_AFTER_TIME 180 s,
  REKEY_TIMEOUT 5 s, KEEPALIVE_TIMEOUT 10 s); §2.1 roaming.
- Não há `docs.kernel.org/networking/wireguard`. O contrato é `include/uapi/linux/wireguard.h`
  (e a especificação YNL do genetlink).

**Kernel 6.18.59** (o da imagem):

- `netlink.c`: `SET_DEVICE` incremental; a porta reabre o socket e falha antes do resto; a chave
  privada nova expira as sessões de todos os pares.
- `allowedips.c`: o prefixo repetido passa para o último par.
- `socket.c`: o pacote cifrado sai pela tabela principal com `fwmark`, sem `oif`.

**O que adotamos:**

- nomes e padrões do RouterOS;
- validação no estilo do VyOS, recusando o que o kernel esconderia;
- aplicação incremental do OpenWrt;
- estado do par pronto (nenhum dos outros o calcula).

**O que fica para depois** (gaps no `docs/changes/G1.31-motor.md`):

- VRF do socket cifrado (feito na G1.31c);
- clamp de MSS (feito na G1.31d, `action=change-mss` do mangle);
- fila na `wg`;
- medição em VM;
- PSK rotativa pós-quântica (Rosenpass).
