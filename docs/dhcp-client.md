# Cliente DHCP (`/ip dhcp-client`)

Status: G4.7a (DHCPv4 estilo RouterOS + extras) feito. G4.7b (DHCPv6 com endereço, prefixo
delegado e aceitar RA) e G4.7c (endereço de reserva, checar gateway, concessão lembrada) abertos
em `docs/gaps.md`.

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
  para nós; G4.7c vai lembrá-lo). Só `release` manda DHCPRELEASE.
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

## Histórico de revisão

- 2026-10-22 — versão inicial (G4.7a).
- 2026-10-22 — seção Pesquisa (regra nova do AGENTS.md).
