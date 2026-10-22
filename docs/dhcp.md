# Servidor DHCP (`/ip dhcp-server`, `/ip pool`)

Status: **G4.2a** (servidor DHCPv4 completo), **G4.2b** (`/ip dhcp-relay`, opção 82 no servidor e
histórico de concessões, §11–§13) e **G4.2c** (servidor DHCPv6 com IA_NA e IA_PD, relay v6, §14)
feitos. O cliente DHCP
(WAN) está em `docs/dhcp-client.md`.

O roteador entrega endereços na LAN com os menus e nomes do RouterOS v7: pools, servidores,
redes, concessões fixas, opções, conjuntos de opções, matchers e alertas de servidor estranho. É
Rust puro sobre o `dhcproto`, sem Kea nem dnsmasq (decisão do usuário; a comparação está em
`docs/architecture.md`, "Servidor DHCP (G4.2)"). Os extras que só um servidor dentro do motor
permite: concessão → DNS (A + PTR) e → address-list do firewall, checagens contra erro do operador
antes do commit, estatísticas no `/metrics` e tudo por comando, transação, Safe Mode e MCP.

## 1. Comandos

| Comando | Faz |
|---|---|
| `ip.pool.add/set/remove/print` | pools: `name`, `ranges` (`10.0.0.10-10.0.0.200`, `10.0.0.0/24` ou um endereço, separados por vírgula), `next_pool`; o `print` traz tamanho, uso e as checagens |
| `ip.pool.used.print {pool?}` | quem tem cada endereço (o `/ip pool used`) |
| `ip.dhcp-server.add/set/remove/print` | servidores (veja §2); o `print` traz `status` (`running`, `disabled`, `invalid`, `starting`, `error`), onde escuta, concessões ativas e as checagens |
| `ip.dhcp-server.network.add/set/remove/print` | redes: `gateway`, `netmask`, `dns_server`, `dns_none`, `domain`, `ntp_server`, `wins_server`, `next_server`, `boot_file_name`, `dhcp_option`, `dhcp_option_set` e **`dns_zone`**; o `print` traz as checagens (os selos da GUI) |
| `ip.dhcp-server.lease.add/set/remove/print` | concessões fixas (config) e dinâmicas (estado), uma linha por endereço; `remove` de uma dinâmica a esquece |
| `ip.dhcp-server.lease.make-static {address}` | copia a dinâmica para a config (MAC, client id, servidor, nome) |
| `ip.dhcp-server.lease.release {address}` | encerra a concessão agora (DNS e listas saem) |
| `ip.dhcp-server.lease.block {address, block?}` | `block_access` (faz a fixa antes, se precisar) |
| `ip.dhcp-server.lease.check-status {address}` | sonda de novo um `conflict`/`declined`; sem resposta em 0,5 s, volta a ficar livre |
| `ip.dhcp-server.option.*`, `option-set.*`, `matcher.*` | opções na sintaxe do RouterOS (`'texto'`, `0x0a0b`, `s'…'`, `'10.0.0.1'`, `$(HOSTNAME)`, `$(CLIENT_MAC)`), conjuntos e o matcher do v7 (código, valor, `exact`/`substring`, `option_set`, `address_pool`) |
| `ip.dhcp-server.alert.add/set/remove/print/reset-alert` | alerta de servidor estranho por interface (`valid_server`, `alert_timeout`); o `print` lista os servidores ouvidos |
| `ip.dhcp-server.statistics.print/reset` | §6 |

Toda mudança passa pelas checagens (§5): um erro sobre o item recusa o comando apontando o
parâmetro; avisos voltam em `warnings`. A config é config de verdade (revisões, rollback, Safe
Mode); as concessões dinâmicas são estado de operação, como no RouterOS.

## 2. Servidor: propriedades e padrões

| Propriedade | Padrão | Significado |
|---|---|---|
| `name` | `dhcpN` | nome (as concessões e os matchers o usam) |
| `interface` | — | uma por servidor; não pode ser porta de bridge nem a própria VRF |
| `address_pool` | `static-only` | pool (e os `next_pool` dele); `static-only`: só concessões fixas |
| `lease_time` | `30m` (RouterOS v7) | 1 min a 1 ano; T1 = 0,5 e T2 = 0,875 dele (RFC 2131 §4.4.5) |
| `authoritative` | `yes` | `yes`: NAK para o que não pode dar; `no`: silêncio para broadcast desconhecido (renovação unicast ainda recebe resposta); `after-2sec-delay`/`after-10sec-delay`: silêncio até o `secs` do cliente chegar lá |
| `conflict_detection` | `yes` | sonda ARP antes de oferecer endereço novo (§4) |
| `always_broadcast` | `no` | responde em broadcast mesmo a quem aceita unicast |
| `server_address` | o da interface | origem e opção 54 |
| `relay` | — | atende só pedidos repassados por esse agente (`giaddr`); `255.255.255.255`: qualquer relay que outro servidor não atenda |
| `dhcp_option_set` | — | conjunto que todo cliente recebe |
| `address_lists` | — | listas do firewall onde o endereço entra enquanto ligado (RouterOS 7.17) |
| `client_mac_limit` | ilimitado | concessões que um MAC pode ter (client ids diferentes atrás do mesmo MAC) |
| `client_rate_limit` | 10/s | mensagens por segundo por cliente (MAC); acima disso o descarte é contado |

## 3. Como funciona

```text
proto-dhcp (L2, puro)            engine (L3)                       daemon / hal-linux
server::Server ── Effect ──▶ dhcp_server.rs: journal (fsync) ──▶ AF_PACKET + BPF, UDP 67, ARP
  request.rs (leitor próprio)     → respostas/sondas ao HAL         service/dhcp_server.rs:
  reply.rs (dhcproto)             → DNS (dns_dynamic_lease)          rodada a cada ≤ 5 ms
  leases.rs (tabela + diário)     → address-list (dinâmica)          (0 ms numa tempestade)
  checks.rs, plan.rs, stats.rs    → log (tópico dhcp)
```

- **`proto-dhcp/src/server/`**: o servidor sem socket, relógio nem disco. Recebe o que a interface
  ouviu e o tempo (ms monotônico e Unix), devolve `Effect`s: enviar, sondar, linha de diário,
  concessão ligada/encerrada, log. Pedidos são lidos por um leitor próprio (`request.rs`): o
  `dhcproto` 0.15 dá panic com bytes hostis (G4.7a). As respostas saem pelo `dhcproto`, com
  `chaddr` e `file` limitados antes (ele tem `assert!`) e a opção 82 escrita por nós (o `dhcproto`
  a escreve duas vezes quando vem como opção crua).
- **`engine/src/dhcp_server.rs`**: estado no `Session` (`s.ext_mut`); a cada rodada segue a config
  em vigor (o plano compilado), abre/fecha os sockets pelo HAL, lê, roda os temporizadores e
  aplica os efeitos na ordem: **diário primeiro** (uma escrita com `fdatasync` por rodada, antes
  de qualquer resposta: um ACK nunca sai sem a concessão estar no disco; *group commit*), depois
  respostas e sondas, DNS, listas e log.
- **`apps/corerouter-daemon/src/service/dhcp_server.rs`**: o serviço `dhcp-server` sob o
  supervisor (G0.10): heartbeat, `0.0.0.0:67 on <interface>`, erros de socket e de diário.
  Rodadas a cada 5 ms com o enlace quieto, sem pausa enquanto chegam mensagens. Sem daemon (GUI
  sozinha, testes) o relógio da sessão roda o servidor junto com o cliente DHCP.
- **`hal-linux/src/dhcp_server.rs`**: `AF_PACKET` com filtro BPF (UDP para 67, e de 67 para 68
  para o alerta), resposta a cliente sem endereço por quadro unicast ao MAC (RFC 2131 §4.1, sem
  entrada ARP), UDP 67 ligado à interface para relay e `ciaddr`, sonda ARP num socket `AF_PACKET`
  de ARP. Sem `unsafe`.
- **Laboratório**: atrás de cada porta do lab há quatro hosts simulados (`lab-laptop`,
  `lab-phone`, `lab-printer`, `lab-tv`, com vendor class), um "invasor" que responde ARP para
  todo endereço terminado em `.11` (a detecção de conflito o acha) e um servidor estranho em
  `192.0.2.250` (o alerta o acha). Assim a GUI, os testes e as capturas de tela mostram um servidor
  funcionando sem rede (`proto-dhcp/src/lab_hosts.rs`).

## 4. Regras de RFC aplicadas

| Regra | Onde |
|---|---|
| RFC 2131 §4.2: o cliente é o client id (61) quando há, senão `htype`+`chaddr`; RFC 4361 §6.3: fixa por MAC vale mesmo com client id | `request.rs` (`client_key`), `plan.rs` (`StaticPlan::matches`) |
| §4.3.1: ordem de escolha: fixa, concessão atual, endereço anterior, o pedido (50), o próximo nunca usado do pool (e `next_pool`), o livre há mais tempo | `server/mod.rs` (`choose`, `pick`) |
| §3.1 passo 2 / §2.2: sondar antes de oferecer (SHOULD); oferta estacionada até 500 ms (RouterOS ~0,5 s, Cisco 500 ms); quem responde vira `conflict` pelo tempo de concessão (RouterOS) e outro endereço é sondado (até 3 por DISCOVER); fixas e o próprio endereço do cliente não são sondados | `discover`, `probe_reply`, `tick_ms` |
| §3.1 passo 3: REQUEST para outro servidor libera a oferta; passo 4: NAK se não pode dar o oferecido | `request` |
| §4.3.2: SELECTING, INIT-REBOOT (rede errada: NAK; sem registro do cliente: silêncio, salvo `authoritative`), RENEWING/REBINDING | `request` |
| §4.3.3 DECLINE (`declined` pelo tempo de concessão), §4.3.4 RELEASE (o registro fica: afinidade), §4.3.5 INFORM (sem tempo de concessão nem `yiaddr`, unicast ao `ciaddr`) | `decline`, `release_msg`, `inform` |
| §4.1: para onde vai a resposta: `giaddr` → relay porta 67; NAK sem relay → broadcast; `ciaddr` → unicast; bit de broadcast → broadcast; senão unicast ao `chaddr`/`yiaddr` | `reply` |
| §4.3.2: NAK por relay com o bit de broadcast | `reply.rs` |
| Tabela 3: `hops`/`secs` zerados; 50, 55 e 57 nunca na resposta; 51 só em OFFER/ACK de REQUEST | `reply` |
| §4.4.5: T1 = 0,5 × concessão, T2 = 0,875 × concessão | `reply` |
| RFC 2132 §9.10: tamanho máximo do cliente (57, mínimo 576): sem caber, as opções não forçadas saem | `reply` |
| RFC 6842 §3: eco da opção 61 em OFFER/ACK/NAK | `reply`, `nak` |
| RFC 3046 §2.2: eco da opção 82 inteira, por último | `reply.rs` |
| RFC 4702 §4: resposta da opção 81 com S/O/N e a mesma codificação (E); §4.1: DNS só no ACK, nunca no DISCOVER; N = sem atualização; 81 vale mais que 12 | `fqdn_reply`, `ack` |
| RFC 4702 §5 / Kea: TTL dos registros = ⅓ da concessão, mínimo 600 s | `dns_ttl` |
| RFC 3396: opções longas divididas (o `dhcproto` faz); na leitura, partes juntadas | `reply.rs`, `v4::raw_options` |

Errata da RFC 2131: só editoriais verificadas (a 7177/7367 lembra que um servidor com vários
endereços aceita qualquer um deles como identificador: `ServerPlan::is_me` faz isso).

## 5. Checagens contra erro do operador

`proto-dhcp/src/server/checks.rs`, sobre a config candidata, em cada comando e no commit:

| Bloqueia (erro) | Avisa |
|---|---|
| pool que inclui o gateway, um endereço do roteador, o endereço de rede ou de broadcast | servidor numa interface com cara de WAN (cliente DHCP nela, lista `WAN`, rota padrão por ela) |
| pools sobrepostos | interface do servidor sem IPv4 |
| fixa no endereço do roteador; dois fixos no mesmo endereço ou para o mesmo cliente | pool fora da rede da interface |
| referência que não existe (pool, conjunto, opção, servidor, zona DNS primária) | rede sem servidor; gateway fora da rede |
| dois servidores na mesma interface (sem relay) | fixa fora de qualquer rede |
| opção com código do próprio servidor (51, 53, 54, 58, 59, 61, 82…) ou valor inválido | |

As checagens que passaram também voltam (`level: ok`): na GUI são os selos verdes do formulário
de rede (gateway, pool, servido, LAN, DNS).

## 6. Estatísticas e `/metrics`

`ip.dhcp-server.statistics.print`: concessões por estado, uso de cada pool (alerta a partir de
80 %), mensagens recebidas (DISCOVER, REQUEST, DECLINE, RELEASE, INFORM) e enviadas (OFFER, ACK,
NAK), ACK/s no último segundo e nos últimos 60 s com o pico, tempo de resposta p50/p99 (da
chegada à saída, incluindo gravar a concessão com `fdatasync` antes do ACK; a espera da sonda
ARP de uma oferta não conta), descartes por motivo (`malformed`, `bootp`, `no-server`,
`rate-limited`, `mac-limit`, `pool-exhausted`, `static-only`, `not-authoritative`, `other-server`,
`probing`, `unexpected`), sondas, conflitos e respostas de servidores estranhos. O mesmo vai no
`system.metrics` e no `/metrics`: `corerouter_dhcp_leases{state}`,
`corerouter_dhcp_pool_{size,used,offered}{pool}`, `corerouter_dhcp_{received,sent}_total{type}`,
`corerouter_dhcp_dropped_total{reason}`, `corerouter_dhcp_{probes,conflicts,rogue_replies}_total`,
`corerouter_dhcp_peak_acks_per_second` e o histograma `corerouter_dhcp_reply_seconds`.

## 7. Diário de concessões

Arquivo `journal-dhcp-leases.log` no diretório da config (`ConfigStorage::append_journal`),
uma linha JSON por mudança que precisa sobreviver (ligada, renovada, liberada, expirada,
conflito, esquecida). Ler é "a última linha de cada endereço vale"; uma linha cortada por uma
queda é pulada e contada. Compactação a cada hora ou quando o diário passa de 2× os registros
(+1024): o arquivo é reescrito com uma linha por registro vivo, num temporário com `fsync` e
`rename` atômico (o LFC do Kea sem processo à parte; o RouterOS grava a cada 5 min por padrão,
aqui é a cada rodada, com `fdatasync`). Ofertas não vão para o disco. Endereços livres lembram o
último cliente por 7 dias (afinidade; **estimado**).

## 8. GUI

- **IP › DHCP Server**: abas DHCP, Networks, Leases, Options, Option Sets, Matchers e Alerts. Em
  Leases, selos de resumo (bound, offered, static, conflict, blocked), uma linha por endereço com o
  host e os selos DNS/opt82, o motivo de um conflito no lugar do host, e os botões Make Static,
  Release, Block, Check Status e Statistics. O formulário de rede mostra as checagens como selos.
- **IP › DHCP Statistics**: KPIs (concessões ativas, ACK/s com pico, p99, descartados), barras de
  uso por pool (âmbar a partir de 80 %), mensagens, "por que não respondeu", sondas e o ACK/s do
  último minuto.
- **IP › Pool**: pools com o uso, e a aba Used Addresses.
- Selos em células de tabela: `chip::cell` (texto + selos), pintados pelo `table::show`.

## 9. Desempenho (medido)

AMD Ryzen AI MAX+ 395, build release, 2026-10-22, `cargo bench -p corerouter-proto-dhcp --bench
server_storm` (o servidor puro, com as linhas de diário serializadas como no engine):

| Tempestade | leases/s | por mensagem (p50 / p99, `--example storm`) |
|---|---|---|
| 1 000 clientes DORA, sem sonda | 214 k | — |
| 1 000 clientes, com sonda ARP (ofertas estacionadas) | 187 k | — |
| 10 000 clientes DORA, sem sonda | 188 k | 2,2 µs / 3,5 µs |
| 10 000 clientes, com sonda | 171 k | 2,2 µs / 4,6 µs |

O primeiro teste com sonda ficou em 20 k leases/s e p99 de 64 µs: achar uma retransmissão entre as
ofertas estacionadas era linear (O(n²) numa tempestade); com um conjunto, 171 k. No daemon o teto
é o disco: uma `fdatasync` por rodada (todas as concessões da rodada juntas), então uma
tempestade cabe em poucas escritas por segundo. A sonda de 0,5 s atrasa a oferta, não a vazão.

## 10. Diferenças do RouterOS e limites

- `add` já liga o servidor (o RouterOS também); alertas novos já vêm ligados (no RouterOS vêm
  desligados).
- `block_access` entrega o endereço sem gateway nem DNS (no RouterOS o bloqueio é por ARP
  `reply-only`, que ainda não temos).
- Sonda só ARP, só no enlace (pedido repassado por relay não é sondado: precisaria de ICMP; gap
  G4.2e).
- Sem `lease-script`, `use-radius`, filas (`rate-limit`, `insert-queue-before`), `add-arp`,
  BOOTP, `delay-threshold`, `$(NETWORK_GATEWAY)`, sobrecarga de opções (52) na leitura e opção 118.
- O `dhcproto` grava as opções em ordem de código, não na ordem da 55 (RFC 2132 §9.8 pede
  "tentar"); a 53 sai em ordem também (o RouterOS 7.4 passou a pô-la primeiro).
- Tempo de concessão pedido pelo cliente (51) não é atendido: vale o do servidor (a RFC permite).
- Sem alta disponibilidade (dois servidores com o mesmo pool): gap G4.2d.

## 11. Relay (`/ip dhcp-relay`, G4.2b)

| Propriedade | Padrão | Significado |
|---|---|---|
| `name` | `relayN` | |
| `interface` | — | onde estão os clientes; um relay por interface, e não onde um servidor do roteador já responde |
| `dhcp_server` | — | servidores (1..=8); cada pedido vai a todos, como no RouterOS |
| `local_address` | o da interface | o `giaddr`: para onde o servidor responde e por onde escolhe a rede |
| `add_relay_info` | `no` | acrescenta a opção 82: circuit id = o **nome da interface** (o RouterOS põe o MAC dela; o nome diz a porta), remote id = o MAC do cliente |
| `relay_info_remote_id` | — | remote id fixo no lugar do MAC |

Subida (RFC 1542 §4.1.1, RFC 2131 §4.1): `giaddr` posto quando zero (o de outro agente fica),
`hops` + 1, descartado a partir de 16; opção 82 por último e só se couber (RFC 3046 §2.1); um pedido
que já traz 82 não ganha outra. Descida (RFC 1542 §4.1.2, RFC 3046 §2.2): só respostas com o nosso
`giaddr`, a 82 sai antes do cliente ver, broadcast se o cliente pediu (ou NAK), senão unicast ao
`yiaddr`/`chaddr`. Se o servidor é o próprio roteador (um servidor com `relay` = o `giaddr`), a
conversa é em memória, sem socket: o lab funciona assim. Para servidores de fora, um socket UDP 67
sem interface (`hal-linux` `LinuxDhcpUplink`); os do servidor ficam presos às suas interfaces.
`ip.dhcp-relay.print` traz pedidos subidos, respostas descidas e descartes por motivo
(`malformed`, `hops`, `not-ours`, `send`, `no-uplink`). Checagens: interface e servidores
existentes, `local_address` do roteador, um servidor do roteador na mesma interface é erro (o
cliente teria duas respostas), servidor no mesmo enlace é aviso.

## 12. Opção 82 no servidor

- A concessão guarda a 82 (como chegou); `lease.print` mostra `agent_circuit_id` e
  `agent_remote_id` (texto quando imprimível, `0x…` senão: a RFC 3046 §3.1/§3.2 diz que são opacos).
- Concessão fixa por porta: `agent_circuit_id` e/ou `agent_remote_id` (RouterOS 7.21) no lugar de
  MAC/client id, ou junto (todos os que estiverem preenchidos têm de bater). Um endereço por porta
  de OLT ou switch, seja qual for o equipamento ligado.
- A renovação vem direto ao servidor, sem relay e sem 82 (RFC 2131 §4.4.5): o servidor reconhece o
  cliente pela concessão (o `ciaddr` e o client id) e usa a 82 guardada para casar a fixa. Também
  por isso uma renovação unicast acha o servidor da concessão, chegue por qual interface for.
- GUI: o host ganha um selo com a porta (circuit id), colorido por hash da porta.
- O alerta agora também manda um DISCOVER próprio por minuto (RouterOS), para achar servidores que
  só respondem por unicast.

## 13. Histórico de concessões

Cada vinculação vira uma entrada (endereço, MAC, client id, nome, servidor, circuit e remote id,
início e fim), aberta no ACK de um cliente novo, estendida a cada renovação e fechada quando a
concessão acaba. Diário próprio (`journal-dhcp-history.log`), mesmo esquema do de concessões
(§7); compactação diária descarta o que passou da retenção. Na volta do daemon, entradas abertas
cuja concessão não existe mais são fechadas no fim conhecido.

- `ip.dhcp-server.config.set {history_retention}`: padrão **1 ano** (os registros de conexão que o
  Marco Civil da Internet, art. 13, pede ao provedor); `0` desliga e apaga.
- `ip.dhcp-server.history.print {address?, mac?, at?, from?, to?, text?, limit?}`: `at` responde
  "quem tinha este IP neste instante" (`2026-10-03T14:02:00-03:00`, uma data ou segundos Unix);
  horários em UTC.
- `ip.dhcp-server.history.export {…}`: CSV (RFC 4180), até 10 000 linhas; a GUI copia para a área
  de transferência (aba History, Export CSV).
- Em memória até 500 000 entradas (**estimado** ~150 bytes cada); acima disso as mais antigas saem
  da memória (o disco guarda até a retenção).

## 14. DHCPv6 (`/ipv6 dhcp-server`, G4.2c)

| Comando | Faz |
|---|---|
| `ipv6.pool.add/set/remove/print` | pools configurados: `prefix` cortado em `prefix_length` (48..=64 para prefixos delegados, 128 para endereços); no máximo 2^20 prefixos por pool; o `ipv6.pool.list` da G4.7b continua mostrando os pools que o cliente DHCPv6 recebe |
| `ipv6.dhcp-server.add/set/remove/print` | `interface`, `address_pool` (IA_NA), `prefix_pool` (IA_PD), `lease_time` (vida válida, padrão 1 dia, **estimado**; a preferida é ⅔ dela), `preference` (255), `rapid_commit` (sim), `route_distance`, `relay` (link-address do relay), `dns_server`, `domain`, `dns_zone` (AAAA + PTR) |
| `ipv6.dhcp-server.binding.add/remove/print` | fixos por DUID (e IAID) com endereço e/ou prefixo; o `print` junta os dinâmicos; `remove` de um dinâmico o libera |
| `ipv6.dhcp-relay.add/remove/print` | relay v6: interface dos clientes, servidores (vazio: `ff05::1:3`), `link_address` |

RFC 9915 (ex-8415, que substituiu a 3315 e a 3633), por seção: §16 o que cada mensagem tem de ter
(Solicit sem Client Identifier ou com Server Identifier: descartado); §18.3.1 Solicit → Advertise
com Preference, ou Reply direto com Rapid Commit; §18.3.2 Request; §18.3.4 Renew (IA desconhecido:
NoBinding); §18.3.5 Rebind (endereço que não é do link: devolvido com vidas 0); §18.3.7 Release;
§18.3.8 Decline (endereço retido); §18.3.3 Confirm (Success ou NotOnLink); §18.3.6
Information-request; §21.4 T1 = 0,5 e T2 = 0,8 da vida preferida; §9/§19 Relay-Forw/Relay-Repl,
aninhados até o limite de 8 saltos, com Interface-Id. O servidor é puro como o v4
(`proto-dhcp/src/server6.rs`), com codec próprio (o do G4.7b) e diário próprio
(`journal-dhcp6-leases.log`).

- **Endereço (IA_NA):** um hash do cliente (DUID + IAID) escolhe o endereço no pool: o mesmo cliente
  recebe o mesmo endereço em qualquer roteador e depois de perder a tabela; 64 candidatos a partir
  do hash.
- **Prefixo (IA_PD):** o fixo, o que o cliente já tinha, a dica dele (§18.2.1), senão o próximo
  livre. Cada prefixo delegado ganha uma **rota** dinâmica (flag D) via o endereço de onde o cliente
  falou (o link-local dele ou o relay), pelo mesmo `Session::effective` dos clientes DHCP; volta
  depois de reiniciar (o diário).
- **DNS:** o nome da opção 39 (RFC 4704) dá AAAA e PTR (G4.1c-3), TTL ⅓ da vida, mínimo 600 s.
- **DUID do servidor:** DUID-LL do MAC da interface onde o pedido chegou.
- **Relay v6:** pedidos de clientes ouvidos na interface do relay viram Relay-Forw (link-address,
  peer-address, Interface-Id = nome da interface) para os servidores; a resposta Relay-Repl volta ao
  cliente. Servidor do próprio roteador: em memória, como no v4.
- **Transporte Linux:** UDP 547 por interface (`SO_BINDTODEVICE`), no grupo `ff02::1:2`; respostas ao
  link-local do cliente pela interface; o relay usa um socket 547 sem interface.
- **GUI:** IPv6 › DHCPv6 Server, abas Servers, Bindings (selos NA/PD, status, estático), Pools e Relays.
- **Fora (gap G4.2f):** reconfigure (RFC 9915 §18.3.11), opções arbitrárias por servidor, `prefix
  exclude` (RFC 6603), limite por cliente e estatísticas no `/metrics` como o v4, histórico v6.

## Pesquisa

**G4.2b.** RouterOS `/ip dhcp-relay` (`dhcp-server`, `local-address`, `add-relay-info` com circuit
= MAC da interface e remote = MAC do cliente, `relay-info-remote-id`, `delay-threshold`,
`dhcp-server-vrf`) e `agent-circuit-id`/`agent-remote-id` na concessão (7.21, hex desde 7.23);
Kea: sub-opções 1, 2, 5 (link-selection), 6, 11, 19 e reservas por `circuit-id`; RFC 3046 (§2.1:
por último, só se couber; §2.2: o servidor ecoa e o relay retira; §3.1/§3.2: opacos; §4: limite por
remote id), RFC 1542 §4.1 (hops, giaddr), RFC 2131 §4.1/§4.4.5. Marco Civil da Internet (Lei
12.965/2014), art. 13: registros de conexão por 1 ano. Melhorias: circuit id com o nome da
interface (legível) em vez do MAC; histórico com consulta "quem tinha às HH:MM" e CSV, que nem o
RouterOS nem o Kea trazem prontos; servidor e relay no mesmo roteador conversando em memória.

**G4.2c.** RouterOS `/ipv6 dhcp-server` (interface, `address-pool`, `prefix-pool`, `lease-time`,
`preference`, `rapid-commit`, `route-distance`, `binding` estáticos por DUID/IAID, rota automática
ao prefixo delegado) e `/ipv6 pool` (`prefix`, `prefix-length`); Kea DHCPv6 (pools e `pd-pools`
com `delegated-len`, reservas por DUID, `rapid-commit`); RFC 9915 (jan/2026, obsoleta a 8415, que
obsoletou a 3315 e a 3633), RFC 3646 (DNS), RFC 4704 (FQDN), RFC 6603 (exclude, fora). Melhorias:
endereço por hash do cliente (estável entre roteadores); prefixo dica honrado; relay e servidor no
mesmo roteador em memória; rota ao prefixo como entrada dinâmica do mesmo caminho de aplicação.

**Fontes.** RouterOS v7: <https://manual.mikrotik.com/docs/cli-reference/ip/dhcp-server/> (e
`/lease`, `/network`, `/option`, `/matcher`, `/alert`, `/config`),
<https://manual.mikrotik.com/docs/cli-reference/ip/pool/>, a página antiga
<https://help.mikrotik.com/docs/spaces/ROS/pages/24805500/DHCP> e os CHANGELOG 7.1–7.24
(<https://download.mikrotik.com/routeros/7.24/CHANGELOG>). Kea:
<https://kea.readthedocs.io/en/latest/arm/dhcp4-srv.html>, `lfc.html`, `lease-expiration.html` e o
hook ping-check (`doc/sphinx/arm/hooks-ping-check.rst`, código em `src/hooks/dhcp/ping_check`).
ISC dhcpd: <https://kb.isc.org/docs/isc-dhcp-44-manual-pages-dhcpdconf>. dnsmasq:
<https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html>. Junos: DHCP local server e
`show/clear system services dhcp conflict`. Cisco IOS-XE: `ip dhcp ping packets/timeout`,
`show ip dhcp conflict`, `ip dhcp database`. dora (BlueCat, Rust):
<https://github.com/bluecatengineering/dora> (só ideias). RFCs (texto do rfc-editor.org e errata):
2131 (§2.2, §3.1, §4.1, §4.2, §4.3.1–§4.3.5, Tabela 3, §4.4.5; atualizada pelas 3396, 4361, 5494,
6842), 2132 (§9.2–§9.14; errata 486), 3046 (§2.2, §3.1/§3.2, §4), 6842 §3, 4361 §6.3, 4702 (§4,
§4.1, §5), 3442, 3396; DHCPv6 para a G4.2c: 3315 → 8415 → 9915 (jan/2026), 3633 → 8415.

**Como o RouterOS faz.** Pool com `next-pool`; servidor `static-only` por padrão, `lease-time`
30 min, `authoritative=yes` (e os modos com atraso), `conflict-detection=yes` (ARP + ICMP, ~0,5 s,
o endereço fica `conflict` pelo tempo de concessão e outro é oferecido; fixas não são sondadas),
oferta segura por 120 s (7.16), `address-lists` (7.17), `add-dns-entries` (7.23, só A, TTL = concessão),
matcher genérico (7.4, `substring` em 7.16), opção 82 por último (7.19), status `waiting`,
`testing`, `offered`, `bound`, `conflict`, `declined`, `check-status`, `make-static`, alerta com
`valid-server` e `alert-timeout` 1 h, leases no disco a cada 5 min (`store-leases-disk`).

**Como os outros fazem.** Kea: memfile só de acréscimo + LFC (renomeações `.1/.2/.completed`,
seguro contra queda), ping-check que estaciona a oferta (100 ms, 1 eco; conflito vira lease
`declined`), `decline-probation-period` 1 dia, afinidade (`hold-reclaimed-time`),
`authoritative=false` por padrão, eco do client id, classes por vendor class. ISC dhcpd: ping 1 s,
`abandoned` 1 dia, arquivo só de acréscimo reescrito periodicamente. dnsmasq: ping por padrão,
`--dhcp-authoritative` reconstrói a base com os clientes, endereço por hash do MAC. Cisco: ping
500 ms × 2, tabela de conflitos até `clear`, base em flash/TFTP com `write-delay`. Junos: lista de
conflitos com o método (ping, ARP, DECLINE) até `clear`. dora: plugins com dependências, SQLite
como gargalo (~5 k leases/s), cache de renovação, limite por cliente com `governor`.

**O que adotamos.** Nomes, padrões e menus do RouterOS (inclusive `authoritative` com atraso,
`static-only`, oferta de 120 s, `conflict`/`declined` pelo tempo de concessão, matcher e alerta);
o diário só de acréscimo + compactação do Kea, dentro do processo e com `fdatasync` antes do ACK
(mais durável que os 5 min do RouterOS); oferta estacionada durante a sonda (Kea), mas tentando
outro endereço na mesma troca (RouterOS) em vez de esperar o cliente; reconstrução autoritativa
da base (dnsmasq); afinidade de endereço; índice em memória (a lição do dora).

**Melhorias além do RouterOS.** Concessão → DNS com A **e** PTR, TTL da RFC 4702 e opção 81
respondida; concessão → address-list com checagem de lockout; checagens contra erro do operador
antes do commit (selos verdes/âmbar na GUI); limite de mensagens por cliente e descartes contados
por motivo; estatísticas (p99, ACK/s com pico, uso de pool com alerta) também no `/metrics`;
laboratório com hosts simulados.

**Fora agora, e por quê.** Relay e opção 82 por porta, histórico de quem teve cada IP (Marco
Civil): G4.2b (feito, §11–§13). DHCPv6/PD: G4.2c. Alta disponibilidade (failover/HA como o Kea):
G4.2d. RADIUS, filas e `lease-script`: dependem de subsistemas que não existem. ICMP na sonda (para
relays) e limite de concessões por remote id: G4.2e.
