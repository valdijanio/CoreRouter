# DNS (G4.1)

O subsistema de DNS do CoreRouter é inteiro em Rust, sobre o **Hickory DNS** (decisão do usuário,
2026-10-22; veja `docs/architecture.md`, "DNS"). Ele vem em três partes, todas na mesma config
`/ip dns` e no mesmo cache:

| Parte | O quê | Estado |
|---|---|---|
| G4.1a | Resolvedor do próprio roteador: ping, MTU, MTR e o cliente NTP resolvem nomes por ele | feito |
| G4.1b | Encaminhador com cache para a LAN (`allow_remote_requests`), `/ip dns static`: base (cadeia de etapas) | feito |
| G4.1e | Statistics (contadores por etapa, por cliente, por tipo) e `allowed_from` com endereços dinâmicos | aberto |
| G4.1d | Adlist, Forwarders, DoT/DoH, GUI do `:resolve` | aberto |
| G4.1c | Zonas autoritativas (estilo BIND) com `hickory-server` | aberto |
| G4.1f | Validação DNSSEC no encaminhador | aberto |
| G4.1g | Benchmark do encaminhador contra Unbound e dnsmasq, com sockets | aberto |

## G4.1a — o resolvedor do roteador

**Problema.** Ping, MTR e o cliente NTP usavam o resolvedor do Linux do host
(`getaddrinfo` → `/etc/resolv.conf` → `127.0.0.53`, o systemd-resolved). Esse endereço não existe
no namespace de rede do roteador nem na imagem de produção: "failed to lookup address
information". O roteador já aprendia servidores DNS pelo DHCP e não os usava.

**Agora.**

```sh
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.set '{"servers":["1.1.1.1","2606:4700:4700::1111"]}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.get
corerouter-cli --connect 127.0.0.1:7979 run tool.ping.start '{"address":"uol.com.br","count":3}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.cache.print
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.cache.flush
```

| Comando | Parâmetros |
|---|---|
| `ip.dns.set` | `servers` (endereços IP, até 8), `allow_remote_requests` (aceito, vale na G4.1b), `cache_size` (KiB, 0 desliga), `cache_max_ttl_secs`, `query_server_timeout_ms`, `query_total_timeout_ms`, `max_udp_packet_size` |
| `ip.dns.get` | a config + `dynamic_servers` (DHCP `use_peer_dns`), `cache_used` (KiB), `resolver: router\|simulated` |
| `ip.dns.cache.print` | `name?`, `type?`; linhas `{name, type, kind, data, addresses, ttl, hits, server, stale}` (desde a G4.1b) |
| `ip.dns.cache.flush` | esvazia o cache; devolve quantas entradas saíram |

**Como funciona.**

- `crates/proto-dns` (L2, sem sockets, compila em wasm): mensagens com `hickory-proto`
  (`message.rs`), cache por TTL com orçamento em bytes (`cache.rs`) e o resolvedor com troca de
  servidor (`resolver.rs`), sobre um `Transport` que quem chama fornece.
- `apps/corerouter-daemon/src/service/dns.rs`: o transporte de verdade (UDP bloqueante com
  timeout, TCP quando a resposta vem truncada) e uma thread que copia, a cada segundo, a config
  em execução e os servidores do DHCP para o resolvedor. Uma consulta nunca pega o lock do
  `Session`. O resolvedor é registrado no `Session` (`Session::set_dns_backend`, estado por
  `ext_mut`). O engine o põe na frente do prober das ferramentas (`Session::tool_prober`).
- Sem daemon (lab headless, GUI sozinha, WASM, testes) não há resolvedor registrado: as
  ferramentas usam o resolvedor simulado do `SimProber`. No daemon, sem servidor configurado, o
  lab simulado também cai no resolvedor simulado. O prober do host (`--lab-ping host`, backend
  linux) não resolve nada sozinho: responde "no DNS server configured".
- Ordem: os servidores estáticos, depois os dinâmicos, sem repetir. Cada um espera até
  `query_server_timeout_ms` e a consulta inteira até `query_total_timeout_ms`. O servidor que
  respondeu por último é perguntado primeiro na próxima vez, como no RouterOS. SERVFAIL,
  REFUSED, silêncio ou resposta malformada passam para o próximo servidor. NXDOMAIN encerra a
  consulta, porque outro servidor diria o mesmo.
- O cliente NTP resolve os nomes de `system.ntp.client` pelo mesmo resolvedor. O syslog remoto só
  aceita endereço IP (como o `remote` do RouterOS), então não muda.

**Regras de RFC no código** (citadas onde estão implementadas):

| Regra | Onde |
|---|---|
| RFC 1035 §2.3.3: nomes comparados sem caixa; chave do cache em minúsculas | `message::parse_name`, `key_of` |
| RFC 1035 §2.3.4: nome de até 253 caracteres, rótulos de 1..=63 | `message::parse_name` |
| RFC 1035 §3.2.1: TTL zero não entra no cache | `cache::put` |
| RFC 1035 §4.1.1: RD ligado na consulta; RCODE 3 é NXDOMAIN | `message::query`, `parse_reply` |
| RFC 1035 §4.2.2: TCP com prefixo de 2 bytes de tamanho | `service/dns.rs` |
| RFC 1035 §6.2: exemplo SRI-NIC.ARPA (26.0.0.73, 10.0.0.51) vira teste | `message::tests::rfc1035_example_sri_nic` |
| RFC 2181 §5.2: o TTL da resposta é o menor da cadeia | `parse_reply` |
| RFC 2181 §5.4.1: registro fora da cadeia de CNAME é ignorado | `parse_reply`, teste `cname_chain…` |
| RFC 2181 §8: TTL com o bit mais alto ligado conta como zero | `ttl_of` |
| RFC 2308 §2.1/§2.2: NXDOMAIN e NODATA; NXDOMAIN vale para todos os tipos | `Outcome`, `Resolver::lookup` |
| RFC 2308 §5: TTL negativo = min(TTL do SOA, MINIMUM); sem SOA não guarda | `negative_ttl`, `cache::put` |
| RFC 5452 §9.1: resposta com outro id ou outra pergunta é ignorada (continua esperando) | `ReplyError::Mismatch`, transporte |
| RFC 5452 §9.2: id aleatório e porta de origem aleatória por consulta | `message::query`, `bind(0)` |
| RFC 6761 §6.3/§6.4: `localhost` é o loopback; `invalid` nunca existe; nenhum vai à rede | `special_use` |
| RFC 6891 §6.2.5: EDNS(0) anuncia `max_udp_packet_size` | `message::query` |
| RFC 7766 §5: resposta UDP truncada é refeita por TCP no mesmo servidor | `resolver::fetch` |

**Testes.** `proto-dns`: codec (exemplo da RFC 1035, CNAME, negativos, TTL enorme, respostas
alheias, truncamento, proptest com bytes hostis e respostas danificadas), cache (expiração, teto,
negativos, orçamento, flush) e resolvedor com transporte falso (failover, preferido, timeout
total, NXDOMAIN final, TCP, resposta forjada ignorada). Engine: comandos (sucesso, validação,
rollback), prober com o resolvedor registrado, `dynamic_servers` do DHCP do lab. Daemon:
servidor DNS local em UDP e TCP (cache, TCP no truncamento, servidor mudo pulado), serviço
seguindo a config, NTP resolvendo nomes pelo resolvedor. Namespace (`tests/netns_dns.rs`): um
servidor DNS de teste na porta 53 real de `127.0.0.2`, num namespace sem `resolv.conf`
utilizável. Sem servidor, o ping falha com a mensagem certa; com `ip.dns.set`, o ping resolve
`router.test`; o NXDOMAIN vai para o cache; o flush esvazia o cache.

**PTR e TXT (G6.3b).** O resolvedor também consulta PTR (nome de um endereço, RFC 1035 §3.5 /
RFC 3596 §2.5, seguindo CNAME como na delegação sem classe da RFC 2317) e TXT (as respostas da
Team Cymru para o ASN de um endereço), com o mesmo cache (`ip.dns.cache.print` mostra `type: PTR`
/ `TXT`, `kind: records`). Quem usa é o MTR (`docs/tools.md` §4.2), sem esperar: o daemon faz
essas consultas em threads próprias. Nomes e textos vindos da rede saem só com ASCII imprimível
(sem sequências de escape de terminal).

**Limites.** O roteador pergunta A, AAAA, PTR e TXT (o cache, desde a G4.1b, guarda qualquer tipo). `ip.dns.resolve` (o
`:resolve` do RouterOS) não existe ainda: um comando que espera a rede sob o lock do `Session`
travaria o plano de controle, então ele vai virar tarefa (G4.1d). Sem DoH/DoT, VRF nem servidores
dinâmicos do PPPoE e do DHCPv6 (G4.1d). Não há janela na GUI ainda (G4.1d).

## G4.1b — o encaminhador da LAN (parte 1, a base)

**Problema.** Os clientes da LAN precisam de um DNS no roteador (o DHCP anuncia o roteador como
servidor), com nomes locais (`nas.lan`), bloqueio de nomes e um cache que sobreviva a uma queda
do upstream. Sem virar resolvedor aberto: um encaminhador que responde a internet é um
amplificador de ataques de reflexão.

**Agora.**

```sh
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.set '{"servers":["1.1.1.1"],"allow_remote_requests":true}'
corerouter-cli --connect 127.0.0.1:7979 run interface.list.member.add '{"list":"LAN","interface":"bridge"}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.static.add '{"name":"nas.lan","address":"192.168.88.10"}'
dig @192.168.88.1 nas.lan            # da LAN
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.cache.print
```

No terminal: `/ip dns set allow-remote-requests=yes`, `/ip dns static add name=nas.lan
address=192.168.88.10`, `/ip dns static print`, `/ip dns cache print`, `/ip dns cache flush`. Na
GUI: IP › DNS (Settings, com os botões Static e Cache; Statistics, Adlist, Forwarders e Zones
aparecem desabilitados com a parte que os traz), IP › DNS Static e IP › DNS Cache.

| Comando | Parâmetros novos |
|---|---|
| `ip.dns.set` | `allow_remote_requests`, `allowed_from` (listas de interfaces e prefixos; padrão `LAN`), `max_queries_per_client` (consultas/s; padrão 200, 0 desliga), `server_selection` (`fastest` padrão, `sequential` do RouterOS), `serve_stale_secs` (RFC 8767; padrão 86400, 0 desliga), `max_concurrent_queries` (100), `max_concurrent_tcp_sessions` (20), `address_list_extra_time_secs` |
| `ip.dns.get` | + `allowed_networks` (o que `allowed_from` vale agora) e `upstream` (latência suavizada, respostas, falhas e se está fora, por servidor) |
| `ip.dns.static.add/set/remove/move/print` | `name` ou `regexp`, `type` (A, AAAA, CNAME, FWD, MX, NS, NXDOMAIN, SRV, TXT), `address`, `cname`, `forward_to`, `mx_*`, `ns`, `srv_*`, `text`, `ttl_secs` (padrão 86400), `match_subdomain`, `address_list`, `disabled`, `comment`, `place_before` |
| `ip.dns.cache.print` | `type?`; colunas `data`, `hits`, `stale` |

**A cadeia.** Cada consulta da LAN passa por etapas, uma por arquivo em
`crates/proto-dns/src/server/stage/`, na ordem do campo `order`:

| Ordem | Etapa | O que faz |
|---|---|---|
| 10 | `acl` | Fora de `allowed_from` (e do loopback): REFUSED. Nunca um resolvedor aberto. |
| 20 | `limit` | Balde de fichas por cliente (IPv6 por /64), rajada de 2× a taxa. Passou: UDP descartado (nada a refletir), TCP com REFUSED. |
| 25 | `special` | `localhost` e `.invalid` (RFC 6761) e ANY (RFC 8482: um HINFO só). |
| 30 | `adlist` | Vazia; a G4.1d entra aqui. |
| 40 | `static` | `/ip dns static` (abaixo). |
| 50 | `zones` | Vazia; a G4.1c entra aqui. |
| 60 | `cache` | O cache compartilhado com o resolvedor do roteador; responde na thread do socket. |
| 90 | `upstream` | O resolvedor da G4.1a (troca de servidor, TCP no truncamento, serve-stale); a única etapa que espera a rede: roda numa thread de trabalho. |

**Uma etapa nova** (Statistics, Adlist, Zones…) é só um arquivo `stage/<nome>.rs`:

```rust
pub(crate) const STAGE: Stage = Stage {
    name: "adlist",
    order: 30,          // a posição; deixe folga para as próximas
    handle,             // fn(&Forwarder, &mut Query, Option<&mut dyn Transport>) -> Step
    after: None,        // ou Some(fn(&Forwarder, &mut Query, &Reply)): vê toda resposta
};
```

- `handle` olha a `Query` (cliente, nome, tipo, a config em execução inteira em
  `q.config.config`) e devolve `Step::Next`, `Step::Reply(..)`, `Step::Drop` ou, se precisa da
  rede, `Step::Wait` (é chamada de novo numa thread de trabalho, com o transporte).
- Estado entre consultas: `f.state::<MeuTipo>()` (criado no primeiro uso). Config compilada
  (regexps, tabelas): `f.compiled(&q.config, MeuTipo::build)`, refeita a cada mudança de config.
- Efeitos fora do DNS (address list do firewall): `q.effects.push(Effect::…)`; o daemon aplica.
- Config própria: uma seção nova no modelo (`ip.dns_<algo>`), comandos em
  `engine/src/cmd/dns_<algo>.rs`; nada de editar `server/mod.rs`, `cmd/dns.rs` ou outra etapa.
- `server::tests::stages_are_in_order` lista a ordem esperada: acrescente o nome.

**Static** (RouterOS v7): entradas habilitadas, de cima para baixo, as de `regexp` antes das de
`name`. Um nome casa consigo mesmo e, com `match_subdomain`, com tudo abaixo dele. Decide a
primeira entrada que serve para a pergunta: uma do tipo perguntado (junto com as outras do mesmo
nome e tipo: duas A são dois endereços), um CNAME (seguido pelas estáticas de novo, depois cache
e upstream; laço de CNAMEs dá SERVFAIL), NXDOMAIN ou FWD (a consulta vai para `forward_to`). Uma
entrada de outro tipo não responde: AAAA de um nome que só tem A vai ao upstream, como no
RouterOS (o dnsmasq faz o mesmo desde a 2.86). PTR automático para as entradas A/AAAA. Com
`address_list`, os endereços respondidos entram nessa lista do firewall pelo TTL da resposta +
`address_list_extra_time_secs` (uma entrada já lá só é renovada com menos da metade do tempo).

**Daemon** (`service/dns_server.rs`, serviço `dns server`, opção `--dns-port`): sockets UDP/TCP
na porta 53, IPv4 e IPv6 separados; responde do endereço para o qual a consulta foi
(`IP_PKTINFO`/`IPV6_RECVPKTINFO`), senão um roteador com dois endereços na LAN responderia do
outro e o cliente descartaria. Abre e fecha os sockets conforme `allow_remote_requests`, sem
reiniciar. TCP com prefixo de tamanho, várias consultas por conexão, 10 s ociosa fecha.

**Regras de RFC no código:**

| Regra | Onde |
|---|---|
| RFC 1035 §4.1.1: FORMERR para mensagem malformada, NOTIMP para opcode desconhecido | `server::parse_request` |
| RFC 1035 §4.1.2: uma pergunta só | `Query::new` |
| RFC 1035 §2.3.3: a pergunta volta como o cliente escreveu | `server::encode` |
| RFC 1035 §4.2.1 e RFC 6891 §7: resposta UDP maior que o cliente aceita vai sem registros e com TC | `server::encode` |
| RFC 6891 §6.2.3: tamanho UDP do cliente, no mínimo 512, no máximo o nosso | `Query::new` |
| RFC 2308 §3: NXDOMAIN/NODATA levam o SOA na autoridade | `Answer::from_reply` |
| RFC 2181 §5.4.1: só a cadeia de CNAME e o tipo perguntado vão ao cache e ao cliente | `Answer::from_reply` |
| RFC 8767 §4/§5: resposta vencida servida com TTL 30 s, até `serve_stale_secs` depois | `cache::get_stale` |
| RFC 8482 §4.2: ANY respondido com um HINFO sintetizado | `stage/special.rs` |
| RFC 6761 §6.3/§6.4: `localhost` e `.invalid` nunca saem | `stage/special.rs` |
| RFC 7766 §6.2.3: conexão TCP ociosa fecha | `service/dns_server.rs` |
| RFC 1035 §3.3.14: TXT em strings de até 255 bytes | `stage/statics.rs` |

**Testes.** `proto-dns`: a cadeia de ponta a ponta com upstream falso (ACL → estático → cache →
upstream, REFUSED fora do `allowed_from`, limite por cliente, serve-stale com upstream fora,
regexp, `match_subdomain`, NXDOMAIN, FWD, CNAME em cadeia e em laço, PTR, TXT longo, address
list, truncamento UDP/EDNS/TCP, negativos com SOA, ANY, AXFR, classe CH, duas perguntas) e
proptest com bytes hostis e consultas danificadas; seleção do servidor mais rápido, serve-stale
e FWD no resolvedor. Engine: `ip.dns.static.*` (sucesso, validação, rollback), `ip.dns.set` com
os campos novos, address list. Shell: `/export` → `/import` de `/ip dns` e `/ip dns static`.
Daemon: o serviço com sockets reais (UDP e TCP, estático, cache, FWD + address list, liga e
desliga). Namespace (`tests/netns_dns_server.rs`): porta 53 de verdade, REFUSED para quem está
fora, resposta do endereço perguntado (dois endereços), PTR, TCP, serve-stale e limite por
cliente.

**Limites e o que fica para depois.** Sem validação DNSSEC: uma consulta com DO recebe a resposta
sem RRSIG, como no RouterOS (G4.1f). `allowed_from` com lista de interfaces usa os endereços
estáticos; os aprendidos por DHCP e os `from_pool` do IPv6 ficam para a G4.1e, junto com
Statistics. Grupos de forwarders, adlist e DoT/DoH: G4.1d. Zonas: G4.1c. Comparação de
desempenho com Unbound e dnsmasq com sockets de verdade: G4.1g. Consultas iguais em voo não são
juntadas (cada falta de cache pergunta ao upstream).

## Pesquisa

Fontes:

- MikroTik RouterOS v7, DNS: <https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS>
  (a página está marcada como congelada e aponta para <https://manual.mikrotik.com/>).
- dnsmasq: <https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html> (`--strict-order`,
  `--all-servers`, `--neg-ttl`, `--max-cache-ttl`, `--min-cache-ttl`).
- Unbound: <https://nlnetlabs.nl/documentation/unbound/unbound.conf/> (`cache-max-ttl` 86400,
  `cache-max-negative-ttl` 3600, `cache-min-ttl` 0).
- VyOS: <https://docs.vyos.io/en/latest/configuration/service/dns.html> (PowerDNS Recursor).
- RFCs: 1035 (§2.3.3, §2.3.4, §3.2.1, §4.1.1, §4.2.1, §4.2.2, §6.2), 2181 (§5.2, §5.4.1, §8),
  2308 (§2.1, §2.2, §5, §7.2), 5452 (§9.1, §9.2), 6761 (§6.3, §6.4), 6891 (§6.2.5), 7766 (§5).
  Errata: RFC 1035 EID 2130 (o TTL é sem sinal, §3.2.1 × §4.1.3; com a RFC 2181 §8 vale até
  2^31−1), EID 7587 e 6601 (editoriais); RFC 2308 EID 461 (§7.2: quem guarda a falha de
  servidor é o "resolver", por até 5 min); RFC 2181 sem errata verificada. "Updated by" da RFC
  2308: 4033–4035, 6604, 8020, 8499, 9499, 9520. Da RFC 1035 interessam aqui 2181, 2308, 4343
  (caixa), 5966/7766 (TCP), 6604 (RCODE com CNAME), 8767 (serve-stale) e 9619.

**Como o MikroTik faz.** `/ip dns` com `servers` (estáticos) e `dynamic-servers` (só leitura,
do DHCP/PPPoE `use-peer-dns`). Pergunta os servidores um a um, estáticos primeiro, e continua
usando o que respondeu. Padrões: `cache-size` 2048 KiB, `cache-max-ttl` 1 semana,
`query-server-timeout` 2 s, `query-total-timeout` 10 s, `max-udp-packet-size` 4096,
`allow-remote-requests` desligado, `max-concurrent-queries` 100, `max-concurrent-tcp-sessions`
20. Tem `cache-used` (KiB), `/ip dns cache` (respostas) e `/ip dns cache all` (todos os
registros), `/ip dns cache flush`, `/ip dns static` (com regexp, `match-subdomain`, FWD,
`address-list`), `use-doh-server` (um só), `vrf`, adlist e o repetidor de mDNS.

**Como os outros fazem.**

- **dnsmasq:** manda cada consulta a um servidor só, de preferência um que sabe estar no ar.
  `--strict-order` força a ordem do `resolv.conf` e `--all-servers` pergunta todos ao mesmo
  tempo. Cache contado em nomes (150 por padrão); `--neg-ttl` dá um TTL negativo quando a
  resposta vem sem SOA.
- **Unbound (OPNsense):** limita o TTL a 1 dia e o TTL negativo a 1 h. Tem `serve-expired`
  (RFC 8767) e `prefetch`, que renova antes de expirar.
- **VyOS (PowerDNS Recursor):** separa `system name-server`, o que o roteador usa, de
  `service dns forwarding`, o que ele serve. O forwarding só sobe com `listen-address` e
  `allow-from` definidos. `cache-size` 10000 entradas, `negative-ttl` 3600, `timeout` 1500 ms,
  `serve-stale-extension`, e o servidor pode vir do DHCP de uma interface (`dhcp <iface>`).

**O que adotamos.** Nomes, padrões e ordem de perguntas do RouterOS, com o servidor que
respondeu indo primeiro. Mensagens do `hickory-proto` sem runtime async, porque o daemon é por
threads. Teto de 1 h para o cache negativo (Unbound/VyOS; a RFC 2308 §5 sugere 1 a 3 h). A config
`/ip dns` é a mesma que o encaminhador e o servidor vão estender.

**Melhorias sobre o MikroTik.**

- `max_udp_packet_size` vem com **1232** e não 4096. É o valor do DNS Flag Day 2020: evita
  fragmentação IP, e um fragmento perdido parece servidor morto.
- **Segurança por padrão:** id e porta de origem aleatórios por consulta (RFC 5452), resposta
  com outra pergunta descartada, registros fora da cadeia de CNAME ignorados. Isso fecha o
  envenenamento de cache por glue estranho.
- `localhost` e `*.invalid` nunca vão à rede (RFC 6761).
- **Mensagens que dizem o que fazer:** "no DNS server configured: set one with ip.dns.set
  servers=… or a DHCP client with use_peer_dns", e o erro de cada servidor quando todos falham.
- A config recusa o que não funciona: servidor `0.0.0.0`, multicast ou broadcast; mais de 8
  servidores; `query_total_timeout` menor que o `query_server_timeout`.
- Uma consulta lenta não trava as outras: o lock cobre só o cache, nunca a rede.

**Fica para depois** (gaps novas no `docs/changes/G4.1a.md`):

- **G4.1b:** servir a LAN (`allow_remote_requests`) com o mesmo cache, `/ip dns static`, limites
  de concorrência e as outras classes de registro. Exige ACL por padrão, para não virar open
  resolver.
- **G4.1c:** servidor estilo BIND com `hickory-server`: zonas, transferência e DNSSEC, medido
  contra Unbound e Knot.
- **G4.1d:** janela IP › DNS na GUI, `ip.dns.resolve` como tarefa, DoH/DoT upstream, VRF,
  servidores dinâmicos do PPPoE e do DHCPv6, serve-stale (RFC 8767) e cache de falhas (RFC
  9520).

### Pesquisa da G4.1b

Fontes: MikroTik `/ip dns` e `/ip dns static`
(<https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS>); dnsmasq
(<https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html>: `--address`, `--server=/dom/`,
`--local-service`, `--dns-forward-max`); Unbound (`access-control`, `ip-ratelimit`,
`serve-expired`); Hickory DNS 0.26.3 (`hickory-proto`, `hickory-server`); RFCs 1035 (§2.3.3,
§3.3.14, §4.1.1, §4.1.2, §4.2.1, §4.2.2), 2181 (§5.2, §5.4.1, §8), 2308 (§2, §3, §5), 4033–4035
(DNSSEC: fica para a G4.1f), 5452 (§9), 6761, 6891 (§6.2.3, §7), 7766 (§6.2.3), 8482 (§4.2), 8767
(§4, §5).

- **MikroTik:** estáticas de cima para baixo, regexp antes de nome; uma estática de outro tipo
  não bloqueia o upstream; PTR automático para A/AAAA; `address-list` com
  `address-list-extra-time`; `max-concurrent-queries` 100, `max-concurrent-tcp-sessions` 20. Não
  tem ACL própria: a documentação manda restringir a porta 53 no firewall.
- **dnsmasq:** `--local-service` (padrão) só aceita sub-redes diretamente conectadas; `--address`
  e `--server` por domínio casam rótulos inteiros (como nosso `match_subdomain`);
  `--dns-forward-max` 150.
- **Unbound/OPNsense:** `access-control` recusa por padrão quem não está listado,
  `ip-ratelimit` por cliente, `serve-expired` (RFC 8767).
- **Hickory 0.26.3:** forwarder com cache, DNSSEC, DoT/DoH/DoQ, ACL, blocklist e métricas,
  embutível como biblioteca, mas exige tokio, não tem RRL, views, ECS, listar/limpar cache nem
  estatísticas no formato do RouterOS, e o README ainda diz "not recommended in production".

**O que adotamos.** Nomes e comportamento das estáticas do RouterOS; `hickory-proto` para as
mensagens e a nossa cadeia de etapas na frente, sem tokio.

**Melhorias sobre o MikroTik.** `allowed_from` com a lista `LAN` por padrão (nunca resolvedor
aberto, mesmo com o firewall vazio), com `allowed_networks` mostrando o que vale agora e um
aviso na GUI quando a lista não tem rede; limite por cliente que descarta em UDP; serve-stale
ligado (1 dia); servidor mais rápido medido, com os números no `ip.dns.get`; hits por entrada do
cache; resposta do endereço perguntado; ANY mínimo (RFC 8482); regexp em tempo linear (o crate
`regex` não faz backtracking: um padrão hostil não trava o DNS).
