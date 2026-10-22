# Cliente DHCP (`/ip dhcp-client`)

Status: G4.7a (DHCPv4 estilo RouterOS + extras), G4.7b (DHCPv6 com endereço, prefixo delegado,
pools e controle de RA; §9–§13) e G4.7c (concessão lembrada com INIT-REBOOT, endereço de reserva,
`check_gateway`; §15) feitos.

O roteador pega endereço, rota padrão, DNS e NTP sozinho na WAN, como o `/ip dhcp-client` do
RouterOS: um cliente por interface, com os mesmos nomes de propriedade e a mesma regra para
as rotas. Os extras: opções enviadas à vontade, filtro de servidores permitidos (por IP ou MAC),
todas as opções recebidas visíveis e um histórico de eventos.

## 1. Comandos

| Comando | Faz |
|---|---|
| `ip.dhcp-client.add {interface, …}` | cria o cliente (habilitado) → `{id}` |
| `ip.dhcp-client.set {id, …}` | muda qualquer propriedade (inclusive a interface) |
| `ip.dhcp-client.remove {id}` | remove (a concessão sai do data plane no mesmo commit) |
| `ip.dhcp-client.renew {id}` | renova agora (preso a um servidor: unicast; sem concessão: recomeça) → `{id, status}` |
| `ip.dhcp-client.release {id}` | manda DHCPRELEASE ao servidor, devolve endereço e rotas e recomeça a procurar → `{id, status}` |
| `ip.dhcp-client.list {interface?}` | configuração + estado: `status`, `address`, `gateway`, `dhcp_server`, `expires_after`, DNS/NTP primário e secundário, domínio, rotas instaladas, notas, erro; flags `X` (desabilitado) e `I` (inválido) |
| `ip.dhcp-client.options {id}` | todas as opções da última ACK: `{code, name, value, hex}`, decodificadas quando conhecidas, hex quando não |
| `ip.dhcp-client.history {id?, after_seq?}` | eventos (anel de 512): `searching`, `offered`, `bound`, `renewed`, `lost`, `nak`, `refused`, `declined`, `ignored`, `error`, `stopped` |

Propriedades (nomes do RouterOS com `_`; o terminal mostra `-`):

| Propriedade | Padrão | Significado |
|---|---|---|
| `interface` | — | uma por cliente e um cliente por interface; não pode ser porta de bridge nem a própria VRF |
| `disabled` | `false` | no RouterOS o padrão do `add` é desabilitado; aqui o `add` já liga (o operador quer o IP) |
| `add_default_route` | `yes` | `yes`: rotas da opção 121 quando vier (a opção 3 é ignorada, RFC 3442), senão rota padrão pela opção 3; `special-classless`: as da 121 **e** a padrão pela 3 (se a 121 já tem `0.0.0.0/0`, ela vence e a nota diz); `no`: nenhuma rota |
| `default_route_distance` | `1` | distância de todas as rotas da concessão |
| `default_route_table` | vazio | vazio = a tabela da interface (`main` ou a VRF dela, G1.5); preenchido, tem de ser essa mesma tabela (vazar rota entre tabelas não existe ainda) |
| `use_peer_dns` / `use_peer_ntp` | `true` | os servidores recebidos ficam em `Session::dhcp_peer_dns()` / `dhcp_peer_ntp()` para o DNS (G4.1) e o NTP (G4.6) usarem |
| `host_name` | vazio | opção 12; vazio manda a identidade do sistema (só letras, dígitos e `-`) |
| `client_id` | vazio | opção 61; texto puro ou a sintaxe de opções; vazio manda `0x01` + MAC |
| `vendor_class` | vazio | opção 60; texto puro ou a sintaxe de opções |
| `extra_options` | `[]` | até 16 `code:valor` enviados em DISCOVER/REQUEST; códigos que o cliente preenche sozinho (0, 12, 50, 52–55, 57, 60, 61, 255) são recusados com o motivo |
| `allowed_servers` | `[]` | até 16 IPs (identificador do servidor ou origem do pacote) ou MACs (origem do quadro); vazio = qualquer servidor |

Sintaxe dos valores (a do `/ip dhcp-server option` do RouterOS, concatenável): `0x0a0b` (bytes),
`'texto'`, `'10.0.0.1'` (4 bytes), `'10'` (número big-endian no mínimo de bytes), `s'10.0.0.1'`
(texto sempre), `$(HOSTNAME)`, `$(CLIENT_MAC)`. Ex.: `0x01'cpe'$(CLIENT_MAC)`. Até 255 bytes.

## 2. Máquina de estados (RFC 2131 §4.4)

Pura, em `crates/proto-dhcp/src/client.rs`: recebe o tempo (ms de um relógio monotônico), os
datagramas e o resultado do ARP, e devolve ações (mandar, sondar ARP, instalar, retirar, logar).
Por isso todo temporizador é testado com relógio simulado.

```text
 INIT ─DISCOVER→ SELECTING ─OFFER→ REQUESTING ─ACK→ PROBING ─1 s→ BOUND
                 4,8,16,32,64,64 s   4 tentativas   ARP responde → DECLINE, 10 s, INIT
 BOUND ─T1→ RENEWING (unicast) ─T2→ REBINDING (broadcast) ─expira→ INIT (concessão perdida)
```

- A primeira OFFER aceitável vence (sem janela de coleta), como a maioria dos roteadores.
- Retransmissão com backoff exponencial ±1 s; em RENEWING/REBINDING, metade do tempo até a
  próxima etapa, no mínimo 60 s.
- T1/T2: opções 58/59 se coerentes (T1 < T2 < concessão), senão 50 % e 87,5 %; T1 nunca antes de
  5 s (ou metade de uma concessão menor). Concessão infinita (`0xffffffff`) não renova.
- NAK: perde a concessão e recomeça; NAKs seguidos esperam 0, 4, 8 … 64 s (um servidor que só
  diz não não é martelado).
- Desabilitar ou remover o cliente retira a concessão **sem** RELEASE (o provedor guarda o IP
  para nós, e o cliente o lembra, §15). Só `release` manda DHCPRELEASE.
- Cada resposta é conferida: `xid` e `chaddr` nossos; endereço utilizável (não 0, broadcast,
  multicast, loopback, classe E, rede ou broadcast da sub-rede); máscara contígua (sem ela, a
  classful).

## 3. O que a concessão instala

Endereço e rotas são **estado operacional** (como as entradas dinâmicas do RouterOS): nunca na
config, nunca salvos, com flag `D` em `ip.address.list` e `ip.route.list` (rota padrão do DHCP
ativa = `ADS`). `ip.address.remove` / `ip.route.remove` recusam essas entradas e dizem o que
fazer. O data plane as recebe pelo único caminho de sempre: o HAL vê a config **mais** essas
entradas (`Session::effective`), tanto num commit quanto quando a concessão muda — um commit não
apaga a concessão e a concessão não atrapalha o commit.

- Rotas: `0.0.0.0/0 via <gw>%<interface>` (e as da 121) na tabela da interface, com a distância
  configurada. Gateway fora da sub-rede da concessão não é instalado (nota no `list`); gateway
  `0.0.0.0` na 121 vira rota pela interface (RFC 3442). A opção 33 só aparece em `options`.
- Uma rota estática habilitada com a mesma tabela, destino e distância ganha: a do DHCP não entra
  (o kernel aceita uma). Para DHCP como reserva, distância maior (ela aparece `DS` sem `A`).
- Interface desabilitada ou removida, cliente desabilitado ou removido: a concessão sai do data
  plane no mesmo commit; o serviço para o cliente no próximo ciclo (`stopped` no histórico).
  A concessão continua lembrada (§15): ao voltar, o cliente pede o mesmo endereço (INIT-REBOOT).
- Servidor fora de `allowed_servers` é ignorado em OFFER, ACK **e** NAK (um servidor estranho
  não dá endereço nem tira o nosso); vira um `refused` por troca no histórico.

## 4. Onde roda

- `Session::dhcp_service(ms)` (engine, sem threads nem relógio: compila para wasm) faz tudo:
  abre/fecha clientes conforme a running, lê os sockets (até 32 datagramas por cliente por
  chamada), dispara temporizadores, aplica concessões. O `control::spawn_clock` a chama a cada
  250 ms com `Instant` (pulo do relógio de parede não expira concessão); o daemon e a GUI nativa
  em lab usam esse relógio. A GUI web em `?lab` não tem relógio: os clientes ficam `stopped` e
  `renew` explica por quê.
- **hal (`dhcp.rs`)**: `Hal::dhcp_port(iface) → DhcpPort` (send/recv sem bloquear, sonda ARP) e
  `DhcpResponder`, o servidor simulado.
- **hal-linux (`dhcp.rs`)**, sem `unsafe`: recebe por `AF_PACKET` (IPv4) com filtro BPF clássico
  (`socket2::attach_filter`: só UDP para a porta 68, sem fragmentos) — ouve o servidor antes de a
  interface ter endereço (sem `rp_filter`, sem descarte de OFFER unicast) e vê o MAC dele;
  broadcast sai como quadro Ethernet montado aqui (IP/UDP com checksum, origem 0.0.0.0 antes da
  concessão); unicast (renovar, release) sai por um socket UDP na porta 68 preso à interface
  (`SO_BINDTODEVICE`), roteado pelo kernel. Porta 68 ocupada (outro cliente DHCP no host):
  aviso no log e as renovações saem em broadcast (forma do REBINDING, aceita pelos servidores).
  Sonda ARP (RFC 5227) por um `AF_PACKET` de ARP só durante a sonda. Precisa de
  `CAP_NET_RAW`/`CAP_NET_ADMIN`; sem elas, o `list` mostra `error` com o motivo.
- **Lab** (`proto-dhcp/src/lab.rs`): atrás da porta `<nome>N` há `100.64.N.0/24`; servidor,
  roteador, DNS e NTP em `100.64.N.1`; endereço `100.64.N.H/24` (H = 10 + hash do MAC mod 200);
  concessão de 600 s; domínio `lab.test`; opção 121 com `0.0.0.0/0` via `.1` e `10.200.0.0/16`
  via `.254`; MAC do servidor `02:DC:00:00:00:N`. O engine oferece esse servidor ao HAL ao
  criar a sessão (`Hal::offer_dhcp_lab_server`); só o `VirtualHal` o usa. Testes trocam os
  `Knobs` (mudo, NAK, outro servidor, endereço já em uso).

## 5. Codec e entrada hostil

`proto-dhcp/src/v4.rs` codifica com `dhcproto` 0.15 (sem features padrão; no wasm o `getrandom`
do `rand` dele usa `wasm_js`). Pacote de rede é hostil:

- mensagem acima de 4096 bytes é recusada;
- o proptest achou dois `panic` dentro do `dhcproto` 0.15 com bytes malformados (`Message::chaddr`
  fatia por `hlen` > 16; `debug_assert!` no tamanho de algumas opções). Por isso o decode
  **reconstrói** a mensagem antes de entregá-la ao `dhcproto`: cabeçalho fixo com `hlen` ≤ 16 e só
  as opções que o cliente lê, com tamanho conferido aqui; opção opcional malformada é descartada,
  não a mensagem. O `chaddr` é lido direto dos bytes;
- a visão crua (`raw_options`) junta opções divididas (RFC 3396) e mostra tudo, decodificado
  quando conhecido e hex quando não; texto da rede sai sem caracteres de controle e com no
  máximo 255 caracteres;
- proptest: bytes aleatórios, respostas reais mutiladas, opções do operador ida e volta,
  requisições hostis ao servidor do lab.

## 6. GUI e terminal

- **IP › DHCP Client**: tabela G1.9 (comentário inline, cores, atalhos G1.15, maximizar G1.12,
  botões cinza com o motivo G1.16) com Interface, Use Peer DNS, Add Default Route, IP Address,
  Expires After, Status; Renew/Release na barra e no menu. Diálogo com as abas DHCP, Status,
  Advanced e Options (o que o servidor mandou; o hex aparece ao passar o mouse) e os botões
  Disable/Remove/Release/Renew. Os eventos do histórico entram no Log (os 20 mais novos na
  primeira consulta). Rotas e endereços dinâmicos ficam somente leitura em Routes e Addresses.
- **Terminal (G0.8)**: `/ip dhcp-client add interface=ether1 add-default-route=special-classless
  allowed-servers=192.0.2.1,AA:BB:CC:DD:EE:FF extra-options=77:'wan'`, `print`, `print detail`,
  `set 0 disabled=yes`, `renew 0`, `release 0`; `/ip address print` mostra `D - dynamic`.

## 7. Testes

| Onde | O quê |
|---|---|
| `proto-dhcp` | codec (proptest), sintaxe de opções, máquina de estados no relógio simulado: aquisição, T1 unicast, servidor morto → renewing → rebinding → perda, backoff 4…64 s, NAK, servidores permitidos por IP e MAC, DECLINE, release, stop, 4 REQUESTs sem resposta, temporizadores e máscaras estranhos |
| `engine/tests/dhcp_client.rs` | comandos (sucesso, validação sem efeito, rollback quando o HAL recusa), lab: concessão no data plane, commit não apaga a concessão, modos de rota, estática empata, renew/release, perda do servidor, NAK, servidores permitidos, DECLINE, desabilitar/remover/interface desligada, modo transacional, histórico |
| `hal-linux` (unit) | quadros IP/UDP e checksums, quadros hostis, ARP |
| `corerouter-daemon/tests/netns_dhcp.rs` | daemon `--backend linux` num namespace sem root, par veth até outro namespace com um servidor DHCP em Rust (thread com `setns`): endereço e rotas da 121 no kernel, ping ao servidor, renovação unicast, release tira endereço e rotas |
| `ui` | janela listada, diálogo com Status e Options, Renew, New com a primeira interface livre, histórico no Log |
| `shell` | `add`/`print`/`print detail`/`set`/`renew` e `D - dynamic` em `/ip address` |

## 8. Pesquisa

Fontes lidas (texto próprio, nada copiado):
[MikroTik RouterOS — DHCP](https://help.mikrotik.com/docs/spaces/ROS/pages/24805500/DHCP),
[VyOS — Ethernet, `dhcp-options`](https://docs.vyos.io/en/latest/configuration/interfaces/ethernet.html),
[OPNsense — Interfaces](https://docs.opnsense.org/manual/interfaces.html) e
[Settings](https://docs.opnsense.org/manual/interfaces_settings.html),
[OpenWrt — protocolo `dhcp`](https://openwrt.org/docs/guide-user/network/ipv4/configuration),
RFC 2131/2132 (protocolo e opções), RFC 3442 (rotas sem classe), RFC 3396 (opções longas),
RFC 5227 (detecção de conflito por ARP), RFC 4361 (client-id).

- **MikroTik (referência de nomes e comportamento):** `add-default-route` yes/no/special-classless
  (121 vence a 3; `special-classless` põe as duas), `default-route-distance`, tabelas de rota (na
  VRF da interface), `use-peer-dns`/`use-peer-ntp`, `host-name` (identidade se vazio), `client-id`
  (`0x01`+MAC se vazio), opções do cliente com a sintaxe das opções do servidor (`0x…`, `'…'`,
  `s'…'`, `$(HOSTNAME)`), `renew`/`release`, status `searching…/requesting…/bound/renewing…/
  rebinding…/stopped/error`, flags `X`/`I`. Também tem `check-gateway`, `script`,
  `allow-reconfigure`, `use-broadcast`.
- **VyOS:** `client-id`, `host-name`, `vendor-class-id`, `user-class`, `no-default-route`,
  `default-route-distance` e **`reject`** (ignorar concessões de um endereço ou sub-rede, ex.: o
  modem do provedor), além de scripts antes/depois.
- **OPNsense:** **"Reject Leases From"**, endereço alias fixo junto do DHCP, sobrescrever o MTU
  recebido, "Prevent release" (não manda RELEASE ao sair).
- **OpenWrt:** `broadcast`, `hostname`, `clientid`/`sendclientid`, `vendorid`, `defaultroute`,
  `peerdns`, `classlessroute`, `reqopts`/`sendopts` (`opção:valor`), `metric`, `norelease`.

O que adotamos: os nomes e as regras de rota do RouterOS; `vendor_class` (VyOS/OpenWrt);
`extra_options` como o `sendopts` do OpenWrt mas na sintaxe do RouterOS; filtro de servidores
como lista de **permitidos** por IP **ou MAC** (mais forte que o `reject` do VyOS/OPNsense: um
servidor desconhecido na WAN não entra, e o filtro vale também para o NAK); não mandar RELEASE ao
desabilitar (o "Prevent release"/`norelease` como padrão; `release` manda); todas as opções
recebidas visíveis (nenhum dos quatro mostra isso tão fácil); histórico consultável; DECLINE por
ARP; a concessão nunca vira config e passa pelo mesmo `apply` transacional.

Ficou de fora agora (candidatos a gap): lista de **rejeitados** além da de permitidos (VyOS/
OPNsense); aplicar o MTU da opção 26 (pedimos e mostramos, não aplicamos) com o "override MTU" do
OPNsense; `use-broadcast` (sempre pedimos broadcast, que é o que funciona antes de ter endereço
num socket comum); `script`/hooks (aqui tudo é comando e o MCP já reage a eventos pelo
`history`); `allow-reconfigure` (FORCERENEW, RFC 3203); `user-class` (dá para mandar como
`extra_options` 77). `check-gateway`, endereço de reserva e concessão lembrada são o G4.7c;
DHCPv6/PD/RA o G4.7b.

## 9. DHCPv6 (`/ipv6 dhcp-client`, G4.7b)

Na WAN IPv6 o roteador pede um endereço (IA_NA) e um **prefixo delegado** (IA_PD) ao provedor e
numera as LANs com ele, como `/ipv6 dhcp-client` + `/ipv6 address from-pool` do RouterOS. A
rota padrão vem, como manda a RFC 7084 (W-3), do Router Advertisement do provedor (§12).

| Comando | Faz |
|---|---|
| `ipv6.dhcp-client.add {interface, request, …}` | cria o cliente (habilitado) → `{id}` |
| `ipv6.dhcp-client.set` / `remove` | muda / remove (`remove` recusa enquanto um endereço usa o pool) |
| `ipv6.dhcp-client.renew` / `release` | Renew agora / Release ao servidor e recomeça |
| `ipv6.dhcp-client.list` | configuração + estado: `status`, `address` (/128), `prefix`, validades, T1/T2, servidor (link-local + DUID), nosso DUID, DNS, domínios, o que faltou (`missing`) |
| `ipv6.dhcp-client.options {id}` | todas as opções do último Reply (IA_NA/IA_PD decodificados) |
| `ipv6.dhcp-client.history` | eventos: `searching`, `advertised`, `bound`, `renewed`, `lost`, `status`, `refused`, `ignored`, `error`, `stopped` |
| `ipv6.pool.list` | os pools: prefixo, validade, endereços numerados a partir dele |
| `ipv6.settings.get` / `set` | política de RA (§12) e, por interface, se aceita e por quê |

| Propriedade | Padrão | Significado |
|---|---|---|
| `request` | — (obrigatório) | `address`, `prefix` ou `address,prefix` (`info` ainda não: vira gap) |
| `pool_name` | vazio | nome do pool do prefixo; obrigatório com `prefix`; um cliente por pool |
| `prefix_hint` | nenhum | `::/56` pede um /56; um prefixo inteiro pede aquele; `::/0` = sem dica |
| `accept_prefix_without_address` | `true` | com os dois pedidos, aceita só o prefixo (RFC 7084 WPD-6); `false` espera um servidor que dê os dois |
| `add_default_route` | `false` | `::/0` via o link-local do servidor (ou do relay) com `default_route_distance` |
| `use_peer_dns` | `true` | DNS recebidos em `Session::dhcp6_peer_dns()` para o G4.1 |
| `rapid_commit` | `true` | Solicit com Rapid Commit (2 mensagens quando o servidor aceita) |
| `custom_duid` | vazio | `0x…`; vazio = DUID-LL do MAC da interface |
| `allowed_servers` | `[]` | DUID (`0x…`), endereço IPv6 de origem ou MAC (dentro do DUID-LL/LLT) |

Identidade: DUID-LL do MAC da interface (estável sem armazenamento: RFC 7084 W-5 enquanto a placa
for a mesma) e IAID = hash do nome da interface (estável entre reinícios: RFC 9096 WPD-10). O
RouterOS usa um DUID por roteador; o nosso dispensa guardar estado e `custom_duid` cobre o resto.

## 10. Máquina de estados DHCPv6 (RFC 9915, ex-8415)

Pura, em `crates/proto-dhcp/src/client6.rs`, como a v4 (tempo, datagramas → ações), com a seção
da RFC citada no código e nos testes.

```text
 INIT ─0–1 s→ SOLICITING ─Advertise (melhor do 1º RT; preferência 255 na hora)→ REQUESTING ─Reply→ BOUND
 BOUND ─T1→ RENEWING (ao servidor) ─T2→ REBINDING (a qualquer um) ─validades acabam→ INIT
 Rapid Commit: Solicit → Reply → BOUND.   release: RELEASING (até REL_MAX_RC) → INIT
```

- Tempos da §7.6 e retransmissão da §15: RT = 2·RTprev ± 10 %, teto MRT ± 10 %; o 1º RT do
  Solicit é **estritamente** maior que IRT; Request desiste após REQ_MAX_RC = 10; Renew até T2;
  Rebind até a última validade; Release até REL_MAX_RC = 4. SOL_MAX_RT do servidor só de 60 a
  86400 s (§21.24). Limite de taxa da §14.1: no máximo 20 mensagens em 20 s por interface.
- Advertise sem endereço nem prefixo é ignorado (§18.2.9); um IA com T1 > T2 é descartado
  (§21.4/§21.21); endereço/prefixo com preferida > válida é descartado (§21.6/§21.22).
- T1 = T2 = 0: o cliente usa 0,5 e 0,8 da menor validade preferida (§21.4); T1 nunca antes de
  5 s; T2 ≤ 7/8 da validade. Validade infinita não renova.
- Reply com NoBinding a um Renew/Rebind → Request (§18.2.10.1); NotOnLink → Solicit; validade 0
  revoga; o que o Reply omite fica até a própria validade acabar. Nada concedido → Solicit de novo
  após 1, 2, 4 … 64 s.
- Release: para de usar antes de mandar (§18.2.7). Desabilitar, remover ou reiniciar **não** manda
  Release (RFC 9096 WPD-9: o provedor guarda o prefixo).
- Um endereço e um prefixo por cliente (o primeiro utilizável de cada IA); os IAs dividem o menor
  T1/T2 (como o `odhcp6c`). Prefixo maior que /64 não numera LAN e é recusado com o motivo.
- Reconfigure nunca é aceito (não mandamos Reconfigure Accept).

## 11. Pools e endereços da LAN (`from_pool`)

O prefixo delegado vira o pool `pool_name`. Um endereço com `from_pool` guarda só os bits **depois**
do prefixo, como o "general prefix" do Cisco e o `from-pool` do RouterOS:

```text
ipv6.dhcp-client.add interface=ether1 request=address,prefix pool_name=pd prefix_hint=::/56
ip.address.add address=::1/64        interface=ether2 from_pool=pd   → 2001:db8:1:100::1/64
ip.address.add address=0:0:0:1::1/64 interface=ether3 from_pool=pd   → 2001:db8:1:101::1/64
```

- O id da sub-rede é escolha do operador e **estável**: mudar o prefixo (renumeração do provedor)
  renumera as LANs com o mesmo id; tirar um endereço não desloca os outros (o RouterOS aloca do pool).
- Sem prefixo (cliente procurando, desabilitado, prefixo expirado) o endereço não vai ao data plane
  e aparece com flag `I` e o motivo em `ip.address.list`; volta sozinho quando o prefixo chega.
- Validação: só IPv6; o pool tem de ser de um cliente que pede prefixo; a mesma sub-rede do mesmo
  pool em duas interfaces é recusada; bits dentro do prefixo delegado ("o /60 não comporta o
  id 0x100") só se sabe com o prefixo na mão e viram o motivo do `I`.
- Os endereços entram no kernel sem validade (permanentes) e saem quando o prefixo sai: nunca
  sobrevivem ao prefixo (RFC 9915 §18.2.10.1, RFC 9096 L-15) e não ficam "deprecated" para
  sempre como no bug do RouterOS 7.23.3. Anunciar o prefixo na LAN (RA/DHCPv6 servidor) é outro item.
- `Session::effective` resolve os endereços: o HAL nunca vê `::1/64` cru.

## 12. Router Advertisements (`ipv6.settings`)

O kernel aceita RA sozinho (`accept_ra=1` com forwarding desligado): foi assim que o endereço do
provedor apareceu na `eno1` sem o CoreRouter saber. Agora quem decide é a config:

| `accept_router_advertisements` | Kernel (`net.ipv6.conf.<if>.accept_ra`) |
|---|---|
| **`auto`** (padrão) | `2` só nas interfaces com cliente DHCPv6 habilitado (a WAN); `0` no resto |
| `yes` | `2` (aceita mesmo roteando) |
| `no` | `0` |
| `yes-if-forwarding-disabled` | `1` (o padrão do RouterOS: o kernel decide pelo forwarding) |

`accept_router_advertisements_on` (lista de interfaces: `all`, `none` ou uma de `interface.list`)
restringe onde vale. **Padrão seguro** (`auto`): a LAN nunca aceita RA (um RA falso na LAN não
rouba a rota padrão nem renumera o roteador; e o receptor de RA fica desligado onde não precisa —
veja o CVE-2023-32154 do RouterOS), a WAN aceita quando o operador a declara WAN com um cliente
DHCPv6, que é quando a rota padrão IPv6 precisa vir do RA.

- O hal-linux escreve o sysctl de cada interface gerenciada a cada apply (e no primeiro apply ao
  subir, também com a config inalterada). Quando uma interface deixa de aceitar — e no primeiro
  apply depois de subir — o que o kernel aprendeu por RA nela (endereços sem `IFA_F_PERMANENT`,
  rotas `proto ra`) é **removido na hora** (o RouterOS pede reboot). Sem permissão para escrever
  em `/proc/sys` (contêiner): aviso no log, o commit não falha.
- O aprendido por RA aparece nas listas com flag `D` e `origin: ra` (`ip.address.list` com as
  validades, `ip.route.list` com distância 255 — a métrica 1024 do kernel perde para qualquer
  estática ou DHCP). Não se remove à mão: o erro diz para desligar o RA.
- No lab, o roteador atrás de cada porta N anuncia `2001:db8:0:N::/64` e ele mesmo como rota
  padrão (`fe80::dc:ff:fe00:N`); o lab roteia, então `yes-if-forwarding-disabled` não aceita nada.

## 13. Testes e onde roda (DHCPv6)

| Onde | O quê |
|---|---|
| `proto-dhcp` `v6` | codec: Reply de exemplo, ida e volta do Solicit, regras de opção da RFC, bytes hostis (Status Code de 0/1 byte, Preference longa — o que derruba o `dhcproto` v6), proptest (bytes aleatórios, Replies mutilados, `describe`) |
| `proto-dhcp` `client6` | relógio simulado: Rapid Commit, coleta no 1º RT, preferência 255, §15 (RT > IRT, ×2, teto), Renew em T1, servidor morto → Rebind em T2 → perda, NoBinding → Request, só prefixo × `accept_prefix_without_address`, backoff, Release (REL_MAX_RC), stop sem Release, servidores permitidos, T1/T2 = 0, T1 > T2, infinito, validade 0, respostas estranhas, limite de taxa |
| `engine/tests/dhcp6_client.rs` | comandos (sucesso, validação sem efeito, rollback), lab: endereço e pool, LAN do pool e renumeração, erros de pool, política de RA (auto/no/yes/lista), rota padrão pelo servidor, renew/release/NoBinding, só prefixo, servidores recusados, transação, config salva |
| `corerouter-daemon/tests/netns_dhcp6.rs` | daemon `--backend linux` em namespace sem root, veth até outro namespace com servidor DHCPv6 em Rust e RAs a cada 500 ms: o kernel autoconfigura sozinho antes; o daemon zera `accept_ra` e limpa; com o cliente: `accept_ra=2` na WAN, /128 e prefixo, `::1/64` da LAN no kernel, SLAAC e rota `proto ra` listados com origem; Renew; Release tira /128 e LAN; RA desligado limpa na hora |
| `ui`, `shell` | janelas IPv6 no teste headless; `/ipv6 dhcp-client`, `/ipv6 pool`, `/ipv6 settings` |

GUI: **IPv6 › DHCPv6 Client** (tabela G1.9, Renew/Release, diálogo com as abas DHCP, Status,
Advanced e Options), **IPv6 › IPv6 Pool** (prefixos e quem os usa) e **IPv6 › IPv6 Settings**
(política de RA e, por interface, se aceita e por quê); Addresses ganhou a coluna Origin (pool e
o motivo da espera, dhcp, dhcpv6, ra) e o campo "from pool". O histórico vai para o Log.

Transporte (hal-linux `dhcp6`): socket UDP na porta 546 preso à interface (`SO_BINDTODEVICE`,
`SO_REUSEADDR` para várias interfaces), tudo para `ff02::1:2` porta 547 saindo dela; o kernel
escolhe o link-local de origem e o servidor responde a ele. A Server Unicast foi aposentada pela
RFC 9915: nunca mandamos unicast. Antes do DAD do link-local o envio falha e a retransmissão cobre.
Porta 546 ocupada (outro cliente DHCPv6 no host) vira `error` com o motivo.

## 14. Pesquisa (G4.7b)

Fontes (texto próprio): MikroTik RouterOS 7.25
[`/ipv6 dhcp-client`](https://manual.mikrotik.com/docs/7.25/cli-reference/ipv6/dhcp-client/),
[DHCPv6 client](https://manual.mikrotik.com/docs/7.25/network-management/dhcp/dhcpv6-client/),
[`/ipv6 settings`](https://manual.mikrotik.com/docs/7.25/cli-reference/ipv6/settings/),
[`/ipv6 address`](https://manual.mikrotik.com/docs/7.25/cli-reference/ipv6/address/),
[`/ipv6 pool`](https://manual.mikrotik.com/docs/7.25/cli-reference/ipv6/pool/),
[CVE-2023-32154](https://mikrotik.com/supportsec/cve-2023-32154);
[VyOS `dhcpv6-options`](https://docs.vyos.io/en/latest/configuration/interfaces/ethernet.html),
[OpenWrt `dhcpv6`/odhcp6c](https://openwrt.org/docs/guide-user/network/ipv6/configuration),
[OPNsense](https://docs.opnsense.org/manual/interfaces.html), Cisco IOS-XE `ipv6 dhcp client pd`
\+ general prefix; RFCs: [RFC 9915](https://www.rfc-editor.org/rfc/rfc9915.html) (DHCPv6, STD 102,
jan/2026, obsoleta a [RFC 8415](https://datatracker.ietf.org/doc/rfc8415/) com a mesma numeração
de seções; errata [8415](https://errata.rfc-editor.org/rfc8415) e
[9915](https://errata.rfc-editor.org/rfc9915) — nenhuma muda o lado do cliente além do texto),
§§7.1–7.6, 11, 14.1, 15, 16, 18.2.1–18.2.13, 21.4–21.24; RFC 4861 (ND/RA), RFC 4862 (SLAAC),
RFC 4191, RFC 8106; [RFC 7084](https://www.rfc-editor.org/rfc/rfc7084.html) (CE router: W-3,
W-5, WPD-1..8) e [RFC 9096](https://www.rfc-editor.org/rfc/rfc9096.html) (WPD-9, WPD-10, L-15,
L-16); kernel [`ip-sysctl`](https://docs.kernel.org/networking/ip-sysctl.html) (`accept_ra` 0/1/2).

- **MikroTik:** `request` address/prefix/info, `pool-name` + `pool-prefix-length`,
  `prefix-hint` (`::/0` = nada), `add-default-route` (não; via o servidor),
  `default-route-distance`, `use-peer-dns`, `rapid-commit`, `accept-prefix-without-address`,
  `custom-duid`, `validate-server-duid`, `allow-reconfigure`; `/ipv6 address from-pool=`
  com o endereço como sufixo; `/ipv6 settings accept-router-advertisements`
  (no/yes/yes-if-forwarding-disabled, padrão o último) + `accept-router-advertisements-on`
  (lista); mudar o RA exige **reboot** para limpar o SLAAC; endereços do pool ficaram
  "deprecated" para sempre num bug do 7.23.3.
- **Outros:** VyOS põe o id da sub-rede (`sla-id`) e o host de cada LAN no próprio cliente;
  OpenWrt tem `norelease` por padrão, `reqaddress try/force`, `ip6hint` por LAN; OPNsense tem
  "Track Interface" + "Prefix ID"; Cisco tem o "general prefix" nomeado com o sufixo na LAN.
- **Adotado:** os nomes e padrões do RouterOS; o sufixo com id de sub-rede explícito e estável (o
  melhor do Cisco/VyOS/OPNsense, sem estado de alocação); sem Release ao parar (OpenWrt, RFC 9096);
  `auto` como padrão de RA (só na WAN declarada) — mais seguro que o `yes-if-forwarding-disabled`
  do RouterOS e sem reboot; o aprendido por RA visível com origem e validade; histórico e opções
  recebidas como na parte 1; servidores permitidos também por DUID e por MAC dentro do DUID;
  codec próprio (o `dhcproto` 0.15 v6 tem `panic` com Status Code curto e dessincroniza com
  Preference/Rapid Commit de tamanho errado — a pesquisa leu o código-fonte; ficaria atrás de
  outro saneador maior que o próprio codec).
- **Fora agora (viram gap):** `request=info` (stateless) e Information Refresh Time; Confirm/Rebind
  ao voltar o link (§18.2.12) e lembrar o lease (com o G4.7c); Decline após DAD falho; Reconfigure
  com RKAP; PD Exclude (RFC 6603); vários endereços/prefixos por IA; `pool-prefix-length` e pools
  estáticos (`ipv6.pool.add`); RA e servidor DHCPv6 na LAN a partir do pool (validades limitadas à
  do prefixo, L-13/L-16); rota de descarte do prefixo delegado (WPD-5); `prefix-address-lists`;
  `check-gateway` v6; gerenciar `forward` (hoje o kernel decide; mexer nele mudaria a máquina de
  desenvolvimento); RDNSS/DNSSL do RA para o DNS (G4.1).

## 15. Resiliência (G4.7c)

Três coisas que mantêm a WAN de pé quando o provedor falha ou o roteador reinicia.

### Concessão lembrada (INIT-REBOOT)

Toda concessão (cada ACK) é guardada **fora da config e das revisões**, no estado `dhcp-leases`
do armazenamento (`state-dhcp-leases.json` ao lado do `running.json`, gravado com temp + rename;
na memória nos testes e na GUI). Guarda-se o ACK inteiro, a interface, o MAC e a hora (relógio de
parede) em que veio. Quando o cliente começa de novo — reinício do daemon, cliente ou interface
reabilitados — e a interface e o MAC batem, o ACK é **decodificado e conferido outra vez** como se
tivesse acabado de chegar (o arquivo é entrada hostil: mesmo saneador do §5, hex com limite de
tamanho, entrada ruim ignorada) e os temporizadores andam para trás pela idade:

```text
 REBOOTING: REQUEST broadcast, ciaddr 0, opção 50 = endereço lembrado, sem opção 54 (§4.3.2)
   ACK  → sonda ARP → BOUND (sem DISCOVER/OFFER)
   NAK  → esquece a concessão → INIT (DISCOVER sem pedir endereço)            (§3.2 passo 3)
   3 REQUESTs a ~4 s sem resposta (~12 s):
     concessão ainda válida → sonda ARP → BOUND nela pelo resto do tempo     (§3.2, "MAY")
                              (T1/T2 já passados renovam na hora)
     vencida ou idade desconhecida → INIT, DISCOVER pedindo o mesmo endereço (§4.4.1)
```

- Sem relógio de parede confiável (idade negativa ou desconhecida) a concessão conta como
  vencida: o INIT-REBOOT ainda pode confirmá-la, mas ela nunca é usada sem servidor.
- `release` e `remove` esquecem a concessão; NAK também. Desabilitar não (é o caso de uso).
- `ip.dhcp-client.list` mostra `remembered` (o endereço guardado); o histórico ganha
  `rebooting` e um `bound` "no server answered: using the remembered lease…".
- Ao perder a concessão por expiração, o DISCOVER seguinte também pede o endereço antigo.

### Endereço de reserva

`fallback_address` (endereço/prefixo, ex. `192.168.100.2/24` para alcançar o modem) entra na
interface depois de `fallback_timeout` s (5–3600, padrão 30, como o `timeout` do dhcpcd) sem
concessão e sai no **mesmo apply** em que uma concessão chega. É dinâmico como a concessão
(flag `D`, comentário `fallback`, nunca na config), aparece em `ip.address.list`, e o `list` do
cliente mostra `fallback_active`. Limpar o campo com a reserva no ar a retira.

### `check_gateway`

`none` (padrão) | `arp` | `ping`, como o `check-gateway` do RouterOS (o do `/ip route`): uma
checagem a cada 10 s; sem resposta em 2 s conta uma falha; **2 falhas seguidas** = gateway fora;
a primeira resposta o traz de volta. O gateway checado é o da rota padrão da concessão (senão o da
primeira rota). Fora, as rotas da concessão por ele saem do data plane (as de outros gateways da
121 ficam) e aparecem em `ip.route.list` sem `A`, com o motivo — uma rota estática com distância
maior assume. `gateway_status` no `list`: `unchecked` / `up` / `down`; eventos `gateway` no
histórico.

- `arp`: a mesma sonda ARP do §2 (`DhcpPort::probe`/`conflict`), feita só fora do PROBING; o
  gateway responde a um pedido com remetente 0.0.0.0 como a qualquer outro.
- `ping`: eco ICMP pelo `Prober` das ferramentas (G6), pela interface (`SO_BINDTODEVICE`) com o
  endereço da concessão como origem.
- No lab, o roteador `100.64.N.1` responde ARP com o MAC do servidor; o knob `gateway_down` o cala.

### Testes (G4.7c)

| Onde | O quê |
|---|---|
| `proto-dhcp` (máquina) | INIT-REBOOT com os campos da RFC 2131 §4.3.2, ACK direto, NAK → DISCOVER sem opção 50, rede muda → reusa a concessão válida e depois renova/perde, vencida → DISCOVER com opção 50 após ~12 s, `restore_lease` com idade, sem relógio, lixo, truncado, não-ACK |
| `engine/tests/dhcp_resilience.rs` | reinício pelo mesmo armazenamento (INIT-REBOOT sem DISCOVER), rede muda após reinício, concessão vencida, NAK/release/remove esquecem, arquivo estragado ou hostil ignorado, reserva sobe e desce, check-gateway arp com rota reserva assumindo e voltando, ping, validação |
| `storage-fs` | estado ao lado da config, temp + rename, nomes que escapariam do diretório recusados |
| `ui` | Check Gateway / Fallback Address / Fallback Timeout na aba Advanced; Gateway Check e Remembered no Status |
| `corerouter-daemon/tests/netns_dhcp_resilience.rs` | daemon `--backend linux` num namespace: check-gateway ARP tira e devolve a rota padrão **do kernel** quando o gateway some do veth; daemon reiniciado manda REQUEST (INIT-REBOOT), nenhum DISCOVER, e volta com o mesmo endereço |

### Pesquisa (G4.7c)

- **RFC 2131** §3.2 (reusar endereço: REQUEST broadcast; NAK → INIT; sem resposta, "MAY" usar o
  anterior pelo resto da concessão), §4.3.2 (INIT-REBOOT: ciaddr 0, opção 50 MUST, opção 54 MUST
  NOT), §4.4.1 (opção 50 no DISCOVER), §4.4.2, §4.1 (retransmissão). Atualizada por 3396, 4361,
  5494, 6842; errata só editorial nessas seções (489, 7369, 8719). RFC 6842 (eco do client-id) e
  RFC 4436 (DNAv4: confirmar a rede por ARP unicast ao gateway lembrado) lidas; ficam para o G4.7d.
- **MikroTik v7**: `check-gateway` no `/ip dhcp-client` (arp/ping/bfd/none) sem efeito
  documentado na página; o `/ip route check-gateway` checa a cada 10 s e marca o gateway
  inacessível após 2 timeouts — adotado. Nenhuma concessão lembrada nem endereço de reserva
  documentados no cliente.
- **dhcpcd**: guarda o ACK cru (`/var/lib/dhcpcd/<if>.lease`, mtime = hora), `reboot` 5 s antes
  do DISCOVER, `lastlease` (usa a última se ninguém responde, só se válida), `fallback` e IPv4LL
  após `timeout` 30 s. **systemd-networkd**: `RequestAddress=` (opção 50 no DISCOVER), concessão
  em `/run` (não sobrevive ao boot), `KeepConfiguration=`. **VyOS/OPNsense**: `reject`, hooks;
  monitoramento de gateway do pfSense/OPNsense (dpinger: IP de monitoria separado, perda/latência)
  como ideia.
- **Adotado**: ACK cru re-conferido (dhcpcd), INIT-REBOOT + o "MAY" da §3.2 (o `lastlease` do
  dhcpcd, só pelo resto da concessão: nada de `lastleaseextend`, que viola a §3.7), opção 50 no
  DISCOVER após perder ou não confirmar (networkd), regra 10 s × 2 do RouterOS, reserva como o
  `fallback` do dhcpcd mas um endereço só e dinâmico. Melhor que eles: a concessão nunca vira
  revisão da config (rollback não a ressuscita), tudo visível no `list` e no histórico, a reserva
  e a troca de rota passam pelo mesmo apply transacional.

## Histórico de revisão

- 2026-10-22 — versão inicial (G4.7a).
- 2026-10-22 — seção Pesquisa (regra nova do AGENTS.md).
