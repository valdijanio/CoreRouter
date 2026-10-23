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
| `ip.dns.cache.print` | `name?`, `type?`, `limit?` (padrão 1000); linhas `{name, type, kind, data, addresses, ttl, hits, server, stale}` (desde a G4.1b) |
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
`:resolve` do RouterOS) é uma tarefa, porque um comando que espera a rede sob o lock do `Session`
travaria o plano de controle (G4.1d-3); DoH/DoT, adlist e forwarders também vieram na G4.1d. VRF
e servidores dinâmicos do PPPoE e do DHCPv6: G4.1j.

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
reiniciar. TCP com prefixo de tamanho, várias consultas por conexão, 10 s ociosa fecha; quem não
pode perguntar nada (fora de `allowed_from` e dos pares das zonas) é fechado no accept, cada origem
tem no máximo 1/4 das `max_concurrent_tcp_sessions`, uma mensagem tem 10 s do primeiro ao último
byte e a conexão não lê consulta nova depois de 2 min. UPDATE por UDP roda no thread `dns-update`.

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
estáticos; os aprendidos por DHCP e os `from_pool` do IPv6 entraram na G4.1e, junto com
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

## G4.1e — Statistics

**O que conta.** Uma etapa a mais na cadeia, `stage/statistics.rs` (ordem 100, só `after`): vê toda
resposta e todo descarte e conta, desde o último reset:

- consultas, UDP e TCP;
- **quem respondeu** (`answered`): `cache`, `static`, `upstream`, `stale` (RFC 8767), `refused`
  (fora do `allowed_from`), `limit` (acima de `max_queries_per_client`), `busy` (acima de
  `max_concurrent_queries`), `special` (RFC 6761/8880) e qualquer etapa nova pelo nome (adlist,
  zones), sem editar esta;
- códigos de resposta (`noerror`, `nxdomain`, `servfail`, `refused`, `dropped`…) e tipos
  perguntados (até 64 tipos; o resto em `other`);
- **por cliente**, os que mais perguntam, com quantas foram recusadas. A tabela guarda no máximo
  1024 clientes: cheia, o de menor contagem dá lugar ao novo (Space-Saving, Metwally et al.
  2005). O topo fica certo mesmo sob inundação de origens falsas, e cada contagem traz o erro
  máximo (`error`; a GUI mostra `≤N`);
- **por upstream**, as respostas que cada servidor deu aos clientes, junto com o SRTT e as falhas
  que o resolvedor já mede.

Para as `after` verem também os descartes, `Forwarder::done` passou a chamá-las antes de
descartar (`Query::dropped()` diz que foi descarte). É a única mudança em `server/mod.rs`, além
do `pub use` dos tipos.

**Comandos.** `ip.dns.statistics.print {top?}` (padrão 10 clientes, até 100) e
`ip.dns.statistics.reset`. Os contadores são estado de execução, não config: o reset não entra
na transação nem tem rollback, e um restart do daemon zera tudo. Sem daemon (lab virtual, WASM),
`print` mostra zeros com `resolver: simulated`.

```sh
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.statistics.print '{"top": 5}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.statistics.reset
```

**GUI.** O botão Statistics da janela IP › DNS abre **DNS Statistics** (`ui/src/dns_statistics.rs`):
total, UDP/TCP e acerto do cache no topo; "Answered by", "Response codes" e "Types" lado a lado;
tabelas "Top clients" e "Upstream servers". Um selo diz por que nada conta (`lab`, ou
`forwarder off` com Allow Remote Requests desligado).

**`allowed_from` com endereços dinâmicos.** `Session::dns_allowed_networks` calcula as redes
sobre a config efetiva: endereços estáticos das interfaces da lista, os aprendidos por cliente
DHCP (flag D) e os `from_pool` do IPv6 já resolvidos com o prefixo delegado. O serviço do
daemon recalcula a cada segundo e reconfigura o encaminhador quando muda (um lease novo ou um
prefixo novo liberam a LAN sem mexer na config). `ip.dns.get` mostra o mesmo em
`allowed_networks`.

**Custo, medido.** Um mutex e alguns mapas pequenos por consulta: +45 a +80 ns por consulta no
`benches/forwarder.rs` (cache quente 762 → 809 ns, estática 869 → 952 ns, falta de cache
2,16 → 2,39 µs). Números no `docs/perf.md`.

### Pesquisa

- **MikroTik RouterOS v7** (<https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS>): não
  há `/ip dns statistics`. Os únicos contadores são `match-count` e `name-count` do `/ip dns
  adlist` e o `cache-used`. Adotamos o estilo `print`/`reset` dos menus do RouterOS
  (`/interface print stats`, `reset-counters`).
- **Unbound** (`unbound-control stats`): `total.num.queries`, `num.cachehits`/`cachemiss`,
  `num.query.type.*`, `num.answer.rcode.*`, `num.query.tcp`, `num.query.ratelimited`,
  `unwanted.queries` (ACL), `num.expired` (serve-expired), histograma de tempo de resposta.
  Viraram `answered`, `rcodes`, `types`, `udp/tcp`, `limit`, `refused` e `stale`.
- **PowerDNS Recursor** (`rec_control get-all`, `top-remotes`, `top-queries`,
  `top-servfail-queries`): contadores por resultado e os "top" por amostragem num anel. Do
  `top-remotes` veio o "Top clients"; usamos Space-Saving no lugar do anel (memória fixa, topo
  exato para quem pergunta muito).
- **dnsmasq** (SIGUSR1 e `dig CHAOS TXT hits.bind misses.bind servers.bind`): por upstream,
  consultas mandadas e falhas. Daí a tabela "Upstream servers" com respostas, SRTT e falhas.

**Melhorias sobre o MikroTik.** A janela e o comando existem (no RouterOS só há o
`cache-used`); o topo de clientes com memória limitada mostra quem inunda o resolvedor; a
contagem por etapa mostra o efeito do `allowed_from`, do limite por cliente e do serve-stale; o
`allowed_from` acompanha DHCP e prefixo delegado sem o operador digitar a rede.

**Fica para depois (G4.1h).** Histograma de latência (Unbound), nomes mais perguntados e com
SERVFAIL/NXDOMAIN (PowerDNS `top-queries`), contagem de mensagens malformadas (hoje saem antes
da cadeia), contadores no `/metrics` do Prometheus e "visto há" por cliente.

## G4.1d — Adlist, Forwarders, DoT/DoH

Em PRs sequenciais: **G4.1d-1** adlist (este), **G4.1d-2** forwarders e upstream DoT/DoH,
**G4.1d-3** `ip.dns.resolve` como tarefa e cache de falhas (RFC 9520).

### Adlist (G4.1d-1)

**Problema.** Bloquear anúncios, rastreadores e malware para a LAN inteira (o que o Pi-hole e o
AdGuard Home fazem) com as listas públicas de sempre (StevenBlack, OISD, Hagezi…), que têm de
dezenas de milhares a mais de um milhão de nomes: muito para a config e para o `/ip dns static`
(limitado a 10 000 entradas).

**Agora.**

```sh
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.adlist.add '{"url":"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.adlist.add '{"file":"local.txt"}'   # de --adlist-dir
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.adlist.print    # state, name_count, match_count
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.adlist.reload
dig @192.168.88.1 ads.example        # 0.0.0.0
```

No terminal: `/ip dns adlist add url=…`, `/ip dns adlist print`, `/ip dns adlist reload`. Na GUI:
IP › DNS Adlist, ou o botão **Adlist** da janela DNS (o botão de uma parte nova acende sozinho
quando o painel `DNS <parte>` existe). A lista mostra fonte, estado, nomes, bloqueios, há quanto
tempo carregou e o comentário; o diálogo tem URL ou File, SSL Verify, Disabled, Comment, o estado e
as linhas puladas, com Reload e Remove.

| Comando | Parâmetros |
|---|---|
| `ip.dns.adlist.add/set` | `url` (`http://` ou `https://`) ou `file` (nome de arquivo em `--adlist-dir`), `ssl_verify` (padrão sim), `disabled`, `comment` |
| `ip.dns.adlist.remove` | `id` |
| `ip.dns.adlist.reload` | `id?` (sem: todas); baixa de novo em segundo plano |
| `ip.dns.adlist.print` | + `state` (`waiting`, `loading`, `loaded`, `failed`, `off`), `name_count`, `match_count`, `skipped`, `loaded_secs_ago`, `error` |

**Como funciona.**

- A config guarda só de onde vem cada lista (`ip.dns_adlist`, até 32). Os nomes ficam no daemon:
  o serviço `dns adlist` (`service/dns_adlist.rs`) baixa ou lê cada lista numa thread própria,
  nunca sob o lock do `Session`, e entrega o conjunto à etapa `adlist` (ordem 30, antes das
  estáticas) numa troca só. Uma consulta nunca espera um download.
- Carrega quando a lista entra ou muda, a cada **4 h** (como o RouterOS) e no `reload`. Falhou:
  mantém os nomes que tinha, mostra o erro e tenta de novo em 10 min. O contador de bloqueios
  continua entre recargas da mesma lista.
- **Formatos**, misturados no mesmo arquivo: hosts (`0.0.0.0 nome nome2`, qualquer endereço na
  frente, com ou sem zona `%lo0`), um domínio por linha, e o subconjunto Adblock de domínio inteiro
  `||nome^`. Comentários `#` e `!`. Os nomes da própria máquina (`localhost`, `ip6-*`,
  `broadcasthost`) e domínios de um rótulo só são ignorados; regras Adblock com caminho, `$opções`,
  `@@` ou curinga no meio contam como puladas (`skipped`), nunca meio entendidas.
- **O que casa:** linha de hosts ou de domínio bloqueia **aquele nome**; `||nome^` bloqueia o nome
  e **tudo abaixo dele** (como Pi-hole e AdGuard Home: as listas de hosts listam cada subdomínio
  que querem, e algumas listam um pai cujos outros subdomínios têm de continuar funcionando).
- **Resposta:** A → `0.0.0.0`, AAAA → `::`, outros tipos → NOERROR sem registros, TTL 10 s (o
  RouterOS responde 0.0.0.0; é o modo "NULL", padrão do Pi-hole). O cliente desiste na hora, em
  vez de tentar o próximo servidor como faria com um NXDOMAIN.
- **Liberar um nome** (allowlist, como no RouterOS 7.17): uma entrada estática `FWD` para ele;
  com `match_subdomain`, libera os subdomínios também.
- **Entrada hostil:** corpo até 64 MiB, linha até 4 KiB, cabeçalho HTTP até 16 KiB, 5
  redirecionamentos (nunca de https para http), 120 s por download, 2 000 000 nomes somando todas
  as listas (passou: guarda os primeiros e avisa no `error`); cada nome conferido pela RFC 1035
  §2.3.4 antes de entrar. `file` é só nome de arquivo (sem `/`, sem `..`, sem começar com `.`).
- **HTTPS:** cliente HTTP/1.1 próprio do daemon (`service/https.rs`) sobre rustls, com as raízes
  da Mozilla embutidas (`webpki-roots`), porque o roteador não tem loja de CAs nem resolvedor do
  sistema: o nome do servidor da lista é resolvido pelo próprio roteador (`/ip dns servers`).
  `ssl_verify=no` continua cifrando e conferindo a assinatura do handshake, só não confere o
  certificado.

**Testes.** `proto-dns`: parser (hosts, domínios, Adblock, comentários, linhas da máquina, zona
IPv6, teto de nomes, linha longa), proptest com texto qualquer e conjunto contra uma busca simples;
a etapa de ponta a ponta (A/AAAA/MX bloqueados, `||` com subdomínios, hosts exato, FWD libera,
contador, lista retirada). Engine: `ip.dns.adlist.*` (sucesso, validação, rollback, contagens e
reload vindos do carregador). Daemon: cliente HTTP (comprimento, chunked, até fechar, 404, laço de
redirecionamentos, cabeçalho enorme, corpo grande demais, TLS com e sem verificação contra um
servidor local com certificado autoassinado) e o carregador (URL e arquivo, desabilitar tira na
hora, reload mantém o contador, remover tira, teto de nomes somando listas). UI: o botão Adlist da
janela DNS abre a janela, contagens do carregador, novo pelo diálogo. Ao vivo: a lista do
StevenBlack (71 492 nomes) baixada por HTTPS, `dig` recebe 0.0.0.0 e `::`.

**Desempenho** (**medido**, AMD Ryzen AI MAX+ 395, build release, 2026-10-22, `cargo bench -p
corerouter-proto-dns --bench adlist`): 1 000 000 nomes lidos e montados em 230 ms, 31,8 MB no
conjunto; consulta 79 ns (nome listado), 82 ns (abaixo de um `||domínio^`), 105–120 ns (não
listado).

**Fica para depois** (G4.1i): recarga condicional (ETag/`If-Modified-Since`, como o "aplica só o
que mudou" do RouterOS), allowlist e regex próprias da adlist (o Pi-hole tem as duas), modo de
resposta configurável (NXDOMAIN, REFUSED, IP próprio) e envio de arquivos ao roteador (`/file`),
hoje um diretório do daemon (`--adlist-dir`).

### Forwarders e DoT/DoH (G4.1d-2)

**Problema.** Mandar um domínio (o da empresa, o da VPN) para outro grupo de servidores, e
cifrar o DNS que sai do roteador (o provedor e quem está no caminho veem cada nome perguntado).

**Agora.**

```sh
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.set '{"servers":["9.9.9.9"],"use_doh_server":"https://cloudflare-dns.com/dns-query"}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.forwarders.add '{"name":"corp","dns_servers":["10.0.0.53"],"doh_servers":["tls://10.0.0.54#dns.corp.example"]}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.static.add '{"name":"corp.example","type":"FWD","forward_to":"corp","match_subdomain":true}'
```

No terminal: `/ip dns set use-doh-server=… verify-doh-cert=yes`, `/ip dns forwarders add
name=corp dns-servers=10.0.0.53 doh-servers=tls://…`, `/ip dns static add … type=FWD
forward-to=corp`. Na GUI: os campos Use DoH Server e Verify DoH Certificate na janela DNS, e IP ›
DNS Forwarders (ou o botão **Forwarders**), com a coluna "Used By" (as estáticas que usam cada
grupo).

| Comando | Parâmetros |
|---|---|
| `ip.dns.set/get` | + `use_doh_server` (`https://host/path` DoH ou `tls://host[:porta][#nome]` DoT; vazio desliga), `verify_doh_cert` (padrão sim) |
| `ip.dns.forwarders.add/set` | `name`, `dns_servers` (até 8 IPs), `doh_servers` (até 4 URLs DoH/DoT), `verify_doh_cert` (padrão sim), `disabled`, `comment` |
| `ip.dns.forwarders.remove` | `id` (recusa se uma estática FWD ainda o usa) |
| `ip.dns.forwarders.print` | + `used_by` |
| `ip.dns.static.add/set` | `forward_to` aceita também o nome de um grupo (como o `forward-to` do RouterOS) |

**Como funciona.**

- `use_doh_server`: todas as consultas (do roteador e da LAN) vão ao servidor cifrado; os
  `servers` comuns só resolvem o nome dele, como no RouterOS. O nome também pode vir de uma
  estática A/AAAA (o RouterOS recomenda) ou ser um endereço (`https://1.1.1.1/dns-query`). Não
  há volta para o DNS comum quando o cifrado falha (RFC 8310 §5: o perfil estrito não cai para
  texto claro); o serve-stale continua valendo.
- Um grupo pode misturar servidores comuns e cifrados: os comuns primeiro, pela mesma regra
  `server_selection`, depois os cifrados. Grupo desabilitado ou apagado: a estática usa os
  servidores de sempre. Renomear um grupo leva as estáticas junto.
- **DoT** (RFC 7858): TLS na porta 853, cada mensagem com 2 bytes de tamanho (§3.3); o nome
  depois de `#` é o que o certificado tem de trazer (RFC 8310 §6.6, o `ip@853#nome` do Unbound);
  sem `#`, o próprio host.
- **DoH** (RFC 8484): `POST` com `application/dns-message` (§4.1), resposta conferida pelo tipo
  (§4.2), HTTP/1.1. Caminho padrão `/dns-query` (o exemplo da RFC).
- A consulta cifrada vai com id 0 (RFC 8484 §4.1) e é preenchida até múltiplo de 128 bytes com a
  opção Padding do EDNS(0) (RFC 7830, RFC 8467 §4.1): o tamanho não entrega o nome.
- **Conexões reaproveitadas** (RFC 7858 §3.4): até 4 ociosas por servidor, por 20 s; uma que o
  servidor fechou é refeita uma vez. Espera de no mínimo 5 s por servidor cifrado (o
  `doh-timeout` do RouterOS), dentro do `query_total_timeout_ms`.
- `verify_doh_cert` (padrão **sim**, o RouterOS usa não em `/ip dns`): cadeia até as raízes da
  Mozilla embutidas e o nome no subjectAltName (RFC 8310 §8.1). Desligado: continua cifrado, com
  qualquer certificado.

**Testes.** `proto-dns`: endereços DoH/DoT (portas, IPv6, `#nome`, recusas) com proptest de ida e
volta; consulta com id 0 e padding; resolvedor com `use_doh_server` por endereço, por nome
resolvido pelos servidores comuns, por estática, e o erro que diz o que fazer; grupo misto com
troca de servidor; transporte sem daemon recusa com a mensagem certa. Engine: `ip.dns.forwarders.*`
(sucesso, validação, rollback, renomear leva as estáticas, remover recusa se em uso), FWD para
grupo inexistente recusado, `use_doh_server` inválido recusado. Daemon: servidores DoT e DoH
locais com certificado autoassinado (recusado com verificação, aceito sem; três consultas numa
conexão só) e o resolvedor do roteador por eles. UI: campos DoH na janela DNS, botão Forwarders,
novo grupo pelo diálogo. Ao vivo: DoH no `cloudflare-dns.com` (nome resolvido pelo 9.9.9.9) e DoT
no Quad9 (`tls://9.9.9.9#dns.quad9.net`) por um grupo, com certificado verificado.

**Desempenho** (**medido**, 2026-10-22, release, cache vazio, 15 nomes populares pelo 1.1.1.1, RTT
~48 ms): UDP 48–51 ms, DoT 47–49 ms, DoH 49–53 ms por consulta. Com a conexão reaproveitada, o
TLS não acrescenta tempo perceptível.

**Fica para depois:** HTTP/2 no DoH (só se algum servidor recusar HTTP/1.1), várias consultas em
voo numa mesma conexão (pipelining, RFC 7858 §3.3), `dns_servers` de grupo por nome, e a coluna de
protocolo na tabela `upstream` do `ip.dns.get` (hoje o servidor cifrado aparece pelo endereço).

### `:resolve` e cache de falhas (G4.1d-3)

**Problema.** O operador quer perguntar um nome ao roteador ("o que o roteador responde para
x?") sem sair para outra máquina; e um nome que nenhum servidor consegue resolver (domínio
quebrado, servidor fora) não pode ser perguntado de novo a cada consulta de cada cliente.

**Agora.**

```sh
corerouter-cli --connect 127.0.0.1:7979 watch ip.dns.resolve '{"name":"example.com"}'
corerouter-cli --connect 127.0.0.1:7979 watch ip.dns.resolve '{"name":"1.1.1.1"}'                      # PTR
corerouter-cli --connect 127.0.0.1:7979 watch ip.dns.resolve '{"name":"example.com","type":"MX","server":"9.9.9.9"}'
```

No terminal: `/ip dns resolve example.com` ou `/ip dns resolve name=… type=MX` (sem atalho
global `resolve`: ele disputaria o Tab com `remove` em todo menu). Na GUI:
Tools › DNS Lookup (G6.6), que também abre pelo **Resolve…** da janela DNS Cache, já com o nome e o
tipo da entrada selecionada. A janela própria IP › DNS Resolve saiu: era um subconjunto do DNS
Lookup, e perguntar um nome é diagnóstico (Tools), não configuração (IP).

| Comando | Parâmetros |
|---|---|
| `ip.dns.resolve` | `name` (nome, ou endereço para o PTR), `type?` (A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA, HTTPS, SVCB; padrão A e AAAA, PTR para endereço), `server?` (só esse servidor, sem o cache) → `{id, task_id, types}`; eventos `{name, type, rcode, records, addresses, ttl, source, ms}` ou `{name, type, error}` |

**Como funciona.**

- É uma **tarefa** (`tool.task.poll`/`stop`), como ping e MTR: a espera pela rede acontece numa
  thread do runner, nunca sob o lock do `Session`. Sem runner (o lab no navegador), o comando
  fica desabilitado com o motivo. Sem daemon (o lab), A/AAAA vêm do resolvedor simulado
  (`source: simulated`).
- Sem `server`, a pergunta passa pelo resolvedor do roteador inteiro: cache, `use_doh_server` ou
  os servidores, serve-stale. Com `server`, vai só a ele, por UDP (TCP no truncamento), sem ler
  nem gravar o cache (o `:resolve server=` do RouterOS).
- O texto vindo da rede sai só com ASCII imprimível (sem sequências de escape de terminal).
- A ferramenta completa estilo `dig` (flags, seções, comparação, trace) é a G6.6
  (`tool.dns.query`, `docs/tools.md` §4.3), sobre `DnsBackend::exchange`.

**Cache de falhas (RFC 9520).** Quando nenhum servidor responde a um nome e tipo (SERVFAIL,
REFUSED, silêncio, resposta malformada, `query_total_timeout`), o par fica retido: por **5 s** na
primeira vez, dobrando a cada nova falha até **5 min** (§3.2: no mínimo 1 s, nunca mais de 5
min, recuo exponencial). Enquanto retido, a consulta falha na hora (SERVFAIL para a LAN, erro com
"asked again in N s, RFC 9520" para o roteador) ou recebe a resposta vencida do serve-stale
(RFC 8767). A chave é nome + tipo (§3.2 deixa a escolha à implementação); NXDOMAIN e NODATA são
respostas, não falhas (§2). Até 4096 pares; `ip.dns.cache.flush` esquece também as falhas. Os
limites de reenvio por servidor do §3.1 já valem: cada servidor é perguntado uma vez por consulta
(mais uma por TCP no truncamento).

**Testes.** `proto-dns`: a retenção (não pergunta durante, outro tipo é outra chave, 5 s → 10 s,
volta quando o servidor volta, flush esquece, NXDOMAIN não conta). Engine: `ip.dns.resolve` como
tarefa (desabilitado sem runner, eventos por tipo, erro de um tipo não derruba o outro, PTR para
endereço, `server` repassado, recusas de parâmetros, lab simulado). Daemon: registros, fonte
(servidor, depois `cache`) e `server` direto passando pelo cache. UI: **Resolve…** no DNS Cache
abre o Tools › DNS Lookup com a entrada selecionada.

**Fica para depois** (G4.1j): `vrf` em `/ip dns` (os servidores numa tabela de rotas), servidores
dinâmicos do PPPoE (`use-peer-dns`, quando houver cliente PPPoE) e do DHCPv6 / RA RDNSS em
`dynamic_servers`.

### Pesquisa da G4.1d

Fontes:

- MikroTik RouterOS v7, DNS (adlist, forwarders, DoH):
  <https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS>; changelogs 7.15–7.23
  (<https://upgrade.mikrotik.com/routeros/7.17/CHANGELOG> e os das outras versões).
- Pi-hole v6: <https://docs.pi-hole.net/ftldns/blockingmode/>,
  <https://docs.pi-hole.net/database/domain-database/>, o cron do gravity
  (<https://github.com/pi-hole/pi-hole/blob/master/advanced/Templates/pihole.cron>).
- AdGuard Home: <https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists>,
  <https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration> e o código
  (`internal/home/config.go`, `internal/filtering/rulelist/rulelist.go`).
- Unbound: <https://github.com/NLnetLabs/unbound/blob/master/doc/unbound.conf.rst>
  (`forward-tls-upstream`, `ip@853#nome`, `tls-cert-bundle`, padding); OPNsense:
  <https://docs.opnsense.org/manual/unbound.html> (DNSBL, DoT com "Verify CN").
- RFCs: 8484 (DoH: §4.1 id 0, §5.1 cache, §5.2 HTTP/2 recomendado, §6), 7858 (DoT: §3.1 porta
  853, §3.3 prefixo de 2 bytes, §3.4 reuso de conexão), 8310 (perfis estrito e oportunista, §5,
  §6.6, §8.1), 8467 (padding de 128 bytes, §4.1), 9520 (cache de falhas: §2, §3.1, §3.2: de 1 s a
  5 min, recuo exponencial). Errata: RFC 8484, três só "Reported" (§4.1 base64url, §3 server
  push, §10); RFC 7858, uma editorial "Held"; RFC 9520, uma editorial verificada (§7.2); RFC
  8310, nenhuma. "Updated by": a RFC 7858 pela 8310; a RFC 9520 atualiza 2308, 4035 e 4697.

**Como o MikroTik faz.** Adlist desde a 7.15: `url` ou `file`, `ssl-verify`, e só leitura
`name-count` e `match-count`; `reload` confere as listas e aplica só o que mudou; recarga a cada 4
h; listas de hosts; o nome bloqueado recebe 0.0.0.0; uma estática FWD libera um nome (7.17). Os
nomes moram no cache do DNS (aumentar `cache-size`; "max cache size reached" no log). Forwarders
desde a 7.17: `name`, `dns-servers` (IP ou nome), `doh-servers` (várias URLs), `verify-doh-cert`
(padrão **sim** aqui, **não** em `/ip dns`), round-robin; a estática `FWD` usa `forward-to=<nome>`.
`/ip dns` tem `use-doh-server` (uma URL), `verify-doh-cert`, `doh-max-server-connections` (5),
`doh-max-concurrent-queries` (50), `doh-timeout` (5 s); com DoH os `servers` só resolvem o nome
do servidor DoH, sem volta ao DNS comum. HTTP/2 no DoH só na 7.23 (ARM64/x86). Não tem DoT.

**Como os outros fazem.**

- **Pi-hole:** resposta "NULL" (0.0.0.0/::) por padrão; hosts e domínios casam o nome exato,
  `||nome^` casa os subdomínios; prioridade allow exato > allow regex > deny exato > listas >
  regex; gravity semanal.
- **AdGuard Home:** `||x^` casa subdomínios, linha de hosts não; `@@` libera; resposta 0.0.0.0/::
  (ou o IP da linha de hosts), TTL de bloqueio 10 s, listas a cada 24 h, até 256 MB por lista.
- **Unbound/OPNsense:** DNSBL de domínios, com campo separado para curingas; DoT por forwarder
  com nome do certificado (`ip@853#nome`), padding de 128 bytes ligado.

**O que adotamos (parte 3).** O `:resolve` do RouterOS (nome, tipo, `server`) como tarefa, que
não trava o plano de controle; da RFC 9520, o cache de falhas com 5 s iniciais, recuo
exponencial e teto de 5 min (o exemplo da própria RFC), por nome e tipo.

**O que adotamos (parte 2).** `/ip dns forwarders` com os nomes do RouterOS (`dns-servers`,
`doh-servers`, `verify-doh-cert` sim no grupo), a estática `FWD forward-to=<grupo>`,
`use-doh-server` substituindo os `servers` (que só resolvem o nome dele) e sem volta para texto
claro. Do Unbound/OPNsense: DoT com o nome do certificado (`#nome`) e padding de 128 bytes.

**Melhorias sobre o MikroTik (parte 2).** DoT além de DoH (o RouterOS não tem) na mesma sintaxe;
`verify_doh_cert` ligado por padrão também em `/ip dns`, com raízes embutidas; padding (RFC 8467)
e id 0; grupos que misturam servidores comuns e cifrados; "Used By" por grupo, remoção recusada
se em uso e renomear leva as estáticas; erro que diz como resolver o nome do servidor cifrado.

**O que adotamos (parte 1).** Nomes e comportamento do RouterOS (`url`, `file`, `ssl-verify`,
contadores, `reload`, 4 h, 0.0.0.0, FWD como allowlist); semântica de casamento e `::` para AAAA
do Pi-hole/AdGuard; TTL 10 s do AdGuard.

**Melhorias sobre o MikroTik.** `ssl_verify` ligado por padrão, com raízes embutidas (o RouterOS
confere contra `/certificate`, que vem vazio); listas fora do cache do DNS (uma lista grande não
expulsa as respostas do cache) num conjunto compacto medido; formatos de domínio e `||nome^`
além de hosts; `state`, `error`, `skipped` e "carregou há" por lista, para o operador saber por que
uma lista não bloqueia; um download falho mantém os nomes anteriores; teto de nomes somando as
listas, com aviso.

## G4.1c — Zonas

**Problema.** O RouterOS só tem `/ip dns static`: nomes soltos, sem SOA, sem delegação, sem
transferência. Um ISP precisa servir as próprias zonas (a reversa dos blocos, a zona dos
equipamentos, a da LAN de um cliente corporativo) e mantê-las em sincronia com outros servidores.
Hoje isso exige um BIND ao lado do roteador, com uma config paralela e outro ponto de falha.

**Agora (G4.1c-1).** Zonas autoritativas no próprio roteador, na mesma cadeia do encaminhador, por
comandos e transações:

```sh
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.set '{"allow_remote_requests":true}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.add '{"name":"example.com","allow_transfer":"192.0.2.0/24","notify":"192.0.2.2"}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.record.add '{"zone":"example.com","name":"www","address":"192.0.2.80"}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.record.add '{"zone":"example.com","type":"MX","target":"mail.example.com","priority":10}'
dig @192.168.88.1 www.example.com             # flag aa
dig +tcp @192.168.88.1 example.com AXFR       # de 192.0.2.0/24
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.add '{"name":"partner.example","type":"secondary","primaries":"192.0.2.53"}'
```

No terminal: `/ip dns zone add name=example.com`, `/ip dns zone record add zone=example.com
name=www address=192.0.2.80`, `/ip dns zone print`, `/export` e `/import` levam as zonas e os
registros. Na GUI, o botão Zones da janela IP › DNS abre **DNS Zones** (uma linha por zona: tipo,
serial, registros, estado), e daí **DNS Zone Records** e **DNS Zone File** (o arquivo de zona para
ler, copiar, editar e carregar de volta).

| Comando | Parâmetros |
|---|---|
| `ip.dns.zone.add/set` | `name`, `type` (`primary` padrão, `secondary`), `primary_ns` (MNAME, padrão `ns1.<zona>`), `admin` (RNAME: `noc@example.com` ou `noc.example.com`; padrão `hostmaster.<zona>`), `serial`, `serial_policy` (`date` padrão, `increment`, `unixtime`), `refresh_secs` 86400, `retry_secs` 7200, `expire_secs` 3600000, `minimum_secs` 3600 (TTL negativo), `ttl_secs` 3600 (padrão dos registros), `allow_transfer` (prefixos; vazio = ninguém), `notify` (endereços), `primaries` (secundária), `disabled`, `comment`. `set` aceita `id` ou o nome da zona |
| `ip.dns.zone.remove` | `id` ou nome; leva os registros junto |
| `ip.dns.zone.print` | a config + `records`, `status` (`running`, `loaded`, `not-loaded`, `disabled`, `config-only` sem daemon), `loaded_serial`, `refreshed_unix`, `next_refresh_unix`, `error` |
| `ip.dns.zone.record.add/set/remove/print` | `zone`, `name` (relativo: `@`, `www`, `*.dev`, `_sip._udp`; ou absoluto com ponto final), `type` (A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TXT), `address`, `target` (nome completo; `@` = a zona), `priority` (MX, SRV), `weight`, `port`, `text` (TXT; valor do CAA), `caa_flags`, `caa_tag`, `ttl_secs` (vazio = o da zona), `disabled`, `comment` |
| `ip.dns.zone.file.get` | `zone` → `text`: o arquivo de zona do que a zona serve (a secundária: a cópia transferida) |
| `ip.dns.zone.file.load` | `zone`, `text`: troca os registros da zona primária pelos do arquivo; SOA, `$TTL` e timers vêm dele |
| `ip.dns.zone.refresh` | `zone` (secundária): pergunta aos primários agora |

**O serial anda sozinho.** Todo comando que muda uma zona primária põe nela o próximo serial
depois do que está **em execução** (`serial_policy`), então todas as mudanças de uma transação
dividem um serial só, e o serial nunca volta (RFC 1982). `date` (o padrão, como o `DEFAULT` do
PowerDNS) é `AAAAMMDDnn`; passou de 99 mudanças num dia, invade o dia seguinte, ainda maior. Um
serial dado à mão, ou vindo de um `/export`, maior que o próximo, fica.

**A busca** (`crates/proto-dns/src/zone/`, etapa `zones`, ordem 50): a zona mais próxima que
contém o nome responde, pela RFC 1034 §4.3.2.

- Registros do tipo pedido, com AA; para NS, MX e SRV, os endereços dos alvos dentro da zona vão
  na seção adicional.
- CNAME: respondido, e o alvo procurado de novo nas nossas zonas; fora delas, segue pela cadeia
  (cache, upstream), com o CNAME na frente.
- Nome que existe sem o tipo: NODATA; nome que não existe: NXDOMAIN. Os dois levam o SOA na
  autoridade, com TTL = min(TTL, MINIMUM) (RFC 2308 §3).
- Curinga: só quando o nome não existe, a partir do encontro mais próximo (RFC 4592 §3.3.1). O
  dono da resposta é o nome perguntado. Um não terminal vazio existe e bloqueia o curinga.
- NS abaixo do ápice é delegação. Sem RD, a resposta é uma referência sem AA, com glue. Com RD, a
  pergunta vai às glue, como uma estática FWD (nós encaminhamos, não iteramos).
- Zona primária sem NS no ápice: o MNAME faz as vezes de NS.
- Secundária ainda não carregada, ou expirada: SERVFAIL.

**Transferências e NOTIFY** são atendidos antes da cadeia (`zone::xfr::intercept`, chamado pelo
`service/dns_server.rs`), com as ACLs próprias de cada zona, não o `allowed_from`. Assim, uma
secundária em outro lugar transfere, e um cliente da LAN não.

- **AXFR** (RFC 5936): só por TCP, para quem está em `allow_transfer`, que vem vazio (RFC 5936
  §5; o BIND passou a negar por padrão na 9.20). Zona alheia: NOTAUTH; ACL: REFUSED. A resposta
  vem em mensagens de ~16 KB, com o SOA no começo e no fim, a pergunta só na primeira e AA.
- **IXFR** (RFC 1995): um diário em memória guarda as mudanças de cada zona (até 64, ou duas
  vezes o tamanho da zona). Quem já tem o serial atual recebe só o SOA. Quem pede de um serial que
  o diário não alcança recebe a zona inteira no formato AXFR (§4). Por UDP, a resposta só vai se
  couber; senão vai o SOA, e o cliente refaz por TCP (§2).
- **NOTIFY recebido** (RFC 1996): só de um dos `primaries` da secundária (§3.10; outro: REFUSED).
  A resposta vem com AA (§4.7), e a secundária confere o SOA na hora (§3.11).
- **NOTIFY enviado:** a cada serial novo de uma primária, cada endereço de `notify` é avisado por
  UDP. Até 5 retransmissões (§3.6), com intervalo de 2, 4, 8, 16 e 32 s (a RFC sugere 60 s e
  permite backoff). NOTIMP ou outro erro encerra (§3.12). O erro aparece no `error` da zona.
- **Secundária** (serviço `dns zones` do daemon, `service/dns_zones.rs`): pede o SOA aos primários
  a cada REFRESH (RETRY depois de uma falha, e na hora com NOTIFY ou `ip.dns.zone.refresh`). Serial
  maior traz um IXFR, ou AXFR sem cópia ou se o IXFR falhar. Os timers vêm do SOA carregado,
  limitados como no BIND (refresh de 300 s a 4 semanas, retry de 60 s a 2 semanas). Sem refresh
  por EXPIRE, a cópia sai do ar. Uma transferência que falha mantém a cópia anterior (RFC 5936 §6).

**Arquivo de zona** (RFC 1035 §5, `zone/file.rs`): `$ORIGIN`, `$TTL`, `@`, dono herdado da linha
de cima, nomes relativos e absolutos, TTL e classe em qualquer ordem (TTL com unidades do BIND:
`1h30m`), parênteses, comentários e strings com `\"`, `\\`, `\X` e `\DDD`. Tipos: os dez acima.
Outro tipo é recusado com a linha, e `$INCLUDE` também: um texto importado nunca lê arquivo do
roteador. O parser é nosso. O do `hickory-proto` 0.26.3 decodifica `\DDD` errado e o `$INCLUDE`
dele lê qualquer caminho. Entrada hostil: até 8 MiB, tokens de 4 KiB, 50 000 registros, proptest
com bytes e texto hostis. A ida e volta TXT export → import está em proptest.

**Regras de RFC no código:**

| Regra | Onde |
|---|---|
| RFC 1034 §4.3.2: delegação, nome exato, CNAME, curinga, seção adicional | `ZoneData::lookup` |
| RFC 1034 §3.6.2 e RFC 2181 §10.1: CNAME não divide o nome, nem no ápice | `DnsZones::problem` |
| RFC 2181 §5: registro repetido é recusado | `DnsZones::problem` |
| RFC 2181 §8: TTL até 2^31−1 | `Zone::problem`, `ZoneRecord::problem`, `file::parse_ttl` |
| RFC 2308 §3/§4: NXDOMAIN e NODATA com o SOA, TTL = min(TTL, MINIMUM) | `ZoneData::negative_soa` |
| RFC 4592 §2.2.2/§3.3.1/§3.3.3: curinga do encontro mais próximo, não terminal vazio, dono = pergunta | `ZoneData::lookup` |
| RFC 4035 §3.1.4.1: DS no corte fica com o pai | `ZoneData::lookup` |
| RFC 1982 §3.1/§3.2: serial sempre maior, passo < 2^31 | `next_serial`, `serial_gt` |
| RFC 1912 §2.2: retry ≤ refresh, expire ≥ refresh + retry | `Zone::problem` |
| RFC 1035 §5: arquivo de zona | `zone/file.rs` |
| RFC 1035 §3.3.14: TXT em strings de até 255 bytes | `zone::chunks` |
| RFC 8659 §4.1: CAA com tag de letras e dígitos | `ZoneRecord::problem`, `zone::caa` |
| RFC 5936 §2.2, §2.2.1, §4.2, §5, §6: formato, AA, NOTAUTH, só TCP, ACL, cópia mantida | `zone/xfr.rs`, `service/dns_zones.rs` |
| RFC 1995 §2, §3, §4: IXFR, SOA do cliente, volta para AXFR, UDP só se couber | `xfr::serve`, `Transfer` |
| RFC 1996 §3.6, §3.7, §3.10–§3.12, §4.7 | `xfr::notify_*`, `service/dns_zones.rs` |
| RFC 1034 §4.3.5: secundária expira sem refresh | `service/dns_zones.rs` |

**Testes.** Modelo: validação (CNAME, duplicados, timers, nomes, CAA, secundária), serial (datas,
RFC 1982, volta do contador). `proto-dns`: busca (resposta, NODATA, NXDOMAIN, CNAME, curinga, não
terminal vazio, delegação com glue, DS, NS do MNAME), a cadeia de ponta a ponta com AA, referência
e encaminhamento às glue, secundária não carregada, AXFR (ACL, UDP, NOTAUTH, várias mensagens),
IXFR (diário, cliente aplicando, em dia, serial desconhecido, UDP), NOTIFY (aceito, recusado),
arquivo de zona (BIND, linhas com erro, unidades, `\DDD`) e proptests (texto e bytes hostis,
pacotes danificados, ida e volta de TXT). Engine: comandos (sucesso, validação, rollback, um
serial por transação). Shell: `/export` → `/import`. Daemon: dois daemons em loopback, primário e
secundário (AXFR inicial, mudança → NOTIFY → IXFR, estado no `print`, saída da config). Namespace
(`tests/netns_dns_zones.rs`): porta 53 de verdade, AA, NXDOMAIN com SOA, AXFR e IXFR pelo nosso
cliente e pelo `dig` (quando instalado), REFUSED para quem está fora, arquivo carregado por
comando. GUI: janelas e diálogos headless e screenshot nos temas claro e escuro.

**Desempenho (medido, `benches/zones.rs`).** Uma resposta de uma zona de 1000 registros custa
1,04 µs, o mesmo que um acerto de cache. Um NXDOMAIN com SOA custa 1,44 µs. Sem zonas, a etapa
não custa nada. Com 100 zonas configuradas, um nome de fora paga +0,3 µs (o detalhe está no
`docs/changes`).

**Por que a busca é nossa e não do `hickory-server`.** O `hickory-server` 0.26.3 não tem IXFR,
NOTIFY (enviado ou recebido), zona secundária nem ACL de IP para AXFR (só "todos", "ninguém" ou
TSIG). A busca dele é async (tokio). A cadeia é síncrona e compila em wasm. Por isso, nesta parte,
o Hickory entra pelo `hickory-proto` (mensagens, registros, codec), e a busca, as transferências e
o arquivo de zona são nossos (`docs/architecture.md`, "DNS"). O `hickory-server` volta na
assinatura DNSSEC (G4.1c-2), onde o `InMemoryZoneHandler::secure_zone_mut` (síncrono) monta
NSEC3 e RRSIG.

**Limites e o que fica para depois.**

- As zonas são servidas pelo mesmo servidor da LAN: só com `allow_remote_requests`, e as
  consultas só para quem está em `allowed_from`. Transferência e NOTIFY têm ACL própria. Modo só
  autoritativo para a internet, `allow_query` por zona e RRL: G4.1k.
- A cópia da secundária e o diário do IXFR ficam em memória: depois de um reinício, a secundária
  transfere de novo, e o primário responde IXFR com a zona inteira. NOTIFY só para `notify`
  (como o `notify explicit` do BIND), não para os NS da zona. Mais tipos de registro: G4.1l.
- Sem TSIG (G4.1c-3) e sem DNSSEC (G4.1c-2). Os benchmarks contra Unbound e Knot com sockets são
  a G4.1g.

### Pesquisa da G4.1c-1

Fontes, conferidas em 2026-10-22:

- MikroTik RouterOS v7, DNS: <https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS>
- BIND 9 ARM: <https://bind9.readthedocs.io/en/latest/reference.html> (`allow-transfer` negado por
  padrão desde a série 9.20, ISC #4728)
- Knot DNS: <https://www.knot-dns.cz/docs/latest/html/reference.html>
- PowerDNS:
  - <https://doc.powerdns.com/authoritative/settings.html>
  - <https://doc.powerdns.com/authoritative/domainmetadata.html>
  - <https://doc.powerdns.com/authoritative/dnsupdate.html>
- NSD: <https://nsd.docs.nlnetlabs.nl/en/latest/manpages/nsd.conf.html>
- VyOS: <https://docs.vyos.io/en/latest/configuration/service/dns.html>
- Junos `dns-proxy`
- RFCs:
  - 1034 §3.6.2, §4.2.1, §4.3.2, §4.3.5
  - 1035 §3.3.13, §3.3.14, §5
  - 1912 §2.2
  - 1982
  - 1995
  - 1996
  - 2181 §5, §8, §10.1, §10.3
  - 2308 §3, §4, §5
  - 4035 §3.1.4.1
  - 4592
  - 5936
  - 8659
- RIPE-203.
- Errata (<https://errata.rfc-editor.org/>), por RFC:
  - RFC 1995: 3197 (verificada: as respostas incrementais levam RRsets parciais, como o nosso
    diário) e 3196 (retida).
  - RFC 1996, 5936 e 1982: nenhuma.
  - RFC 2308: sete, todas editoriais.
  - RFC 2181: 6446 (rejeitada).
  - RFC 4592: 46 (retida) e 5119 (reportada: não sintetizar NSEC, importa na G4.1c-2).
  - RFC 8659: 5934 (editorial) e 7139 (retida).
- "Updated by": a RFC 1995 e a 5936 pela 9103 (XoT, transferência por TLS: fica de fora).

**Como o MikroTik faz.** Não faz. O `/ip dns static` tem A, AAAA, CNAME, FWD, MX, NS, NXDOMAIN,
SRV e TXT. Não tem SOA, PTR, CAA, zona, AXFR, IXFR nem NOTIFY.

**Como os outros fazem.**

- **BIND:**
  - `zone { type primary|secondary; }`, `allow-transfer` (negado desde a 9.20), `also-notify`.
  - `notify yes` avisa os NS da zona; `explicit` avisa só a lista.
  - `allow-notify` vale só para os primários.
  - `serial-update-method increment|unixtime|date`.
  - `ixfr-from-differences`; journal de até duas vezes a zona.
  - Timers do SOA limitados na secundária: refresh de 300 s a 4 semanas, retry de 500 s a 2
    semanas.
- **Knot:**
  - `serial-policy increment|unixtime|dateserial`, `zonefile-load difference`, journal.
  - ACL com ações `query`/`notify`/`transfer`/`update`.
- **PowerDNS:**
  - `allow-axfr-ips` padrão `127.0.0.0/8,::1`, metadados `ALSO-NOTIFY` e `ALLOW-AXFR-FROM`.
  - `SOA-EDIT-API DEFAULT`: `AAAAMMDD01` se for maior, senão +1.
  - A API cria a zona com os `nameservers`.
- **NSD:** `provide-xfr`, `notify` com `notify-retry`, `allow-notify` (quem não está na lista é
  descartado), `request-xfr` (IXFR por TCP com volta para AXFR).
- **VyOS:** `authoritative-domain` com registros (A, AAAA, CNAME, MX, NS, PTR, TXT, SPF, SRV,
  NAPTR), sem servir AXFR nem NOTIFY.
- **Junos:** `dns-proxy` só faz cache e views com encaminhamento.

**O que adotamos.**

- Tipos de zona e timers de RIPE-203 do BIND/Knot. O mínimo do SOA é 3600 e não os 2 dias do
  RIPE-203: desde a RFC 2308 o campo é o TTL negativo, e o §5 sugere 1 a 3 h.
- `allow_transfer` vazio por padrão (BIND 9.20, RFC 5936 §5).
- NOTIFY explícito, retransmitido como o NSD.
- Serial `date` (o `DEFAULT` do PowerDNS), legível pelo operador.
- IXFR com volta para AXFR, como o `request-xfr` do NSD.
- Timers da secundária limitados como no BIND.

**Melhorias sobre os outros.**

- O serial anda sozinho e uma transação inteira vira um serial só. No BIND, um `rndc reload` com
  o serial esquecido é o erro mais comum de quem edita zona à mão.
- Zonas, registros e transferências passam por comandos: `config.diff`, Safe Mode, rollback e MCP.
- A validação recusa antes do commit o que o BIND só avisa ao carregar: CNAME com outros dados,
  CNAME no ápice, registro duplicado, retry maior que refresh, expire curto, TXT com caractere de
  controle.
- O arquivo de zona é editável na GUI e volta como comando, sem `$INCLUDE`.
- O `print` mostra o estado de cada zona: serial carregado, último refresh, próximo refresh e o
  erro, em vez de só um log.
- A etapa `statistics` conta as respostas da etapa `zones`.

**Fica de fora, e por quê.**

- XoT (RFC 9103): exige TLS no servidor DNS.
- Views (split-horizon): G4.1k se for preciso.
- `$GENERATE` do BIND.
- Catalog zones (RFC 9432).
- Mais tipos de registro: G4.1l.

### G4.1c-2 — Assinatura DNSSEC

**Problema.** Uma zona sem assinatura pode ser falsificada no caminho (envenenamento de cache,
BGP sequestrado): o resolvedor do cliente não tem como saber. BIND, Knot e PowerDNS assinam
zonas; nenhum roteador da comparação assina (RouterOS nem valida). Quem quer DNSSEC hoje roda um
servidor à parte e cuida das chaves e das rotações à mão.

**Agora.**

```sh
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.set '{"id":"example.com","dnssec":true}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.print          # ds: o DS para o registro
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.dnssec.print   # chaves (nunca a privada)
dig +dnssec @192.168.88.1 www.example.com                              # RRSIG junto
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.dnssec.rollover '{"zone":"example.com","key":"zsk"}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.dnssec.rollover '{"zone":"example.com","key":"ksk"}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.dnssec.ds-published '{"zone":"example.com"}'
```

Na GUI, o diálogo da zona ganha DNSSEC, Algorithm e Signature Validity, e a seção "DNSSEC keys"
(papel, tag, estado com selo, o próximo passo, o DS com Copy DS e os botões Roll ZSK, Roll KSK e DS
Published).

| Comando | Parâmetros |
|---|---|
| `ip.dns.zone.add/set` | + `dnssec` (assina), `dnssec_algorithm` (`ecdsa-p256` padrão, `ed25519`), `signature_validity_secs` (padrão 14 dias, de 1 a 90) |
| `ip.dns.zone.print` | + `signed_serial`, `signatures_expire_unix`, `ds` (os DS das KSK, SHA-256), `signed` (secundária de zona assinada) |
| `ip.dns.zone.dnssec.print` | `{zone?}` → chaves: `role` (ksk/zsk), `algorithm`, `key_tag`, `state` (published/active/retired), `dnskey`, `ds`, `next` (o que acontece depois e quando) |
| `ip.dns.zone.dnssec.rollover` | `{zone, key: ksk\|zsk}` |
| `ip.dns.zone.dnssec.ds-published` | `{zone}`: o DS da KSK nova já está no pai |
| `ip.dns.zone.dnssec.forget` | `{zone}`: apaga as chaves de uma zona que não assina mais |

**As chaves ficam fora da config.** Como os usuários, elas não entram em revisão, `config.diff`
nem export: um `config.rollback` nunca pode levar embora uma chave cujo DS está no pai (a zona
ficaria "bogus" para todo resolvedor que valida), e a chave privada nunca aparece num diff. O
engine as guarda no estado operacional do armazenamento (`dnssec-keys`, arquivo 0600 ao lado da
config, o mesmo mecanismo das concessões do DHCP) e as muda na hora; o daemon as gera (ring) e
assina. Elas sobrevivem a reinícios (teste).

**O que é assinado** (`proto-dns/src/zone/dnssec/`, feature `dnssec`, ligada só pelo daemon:
engine, GUI e wasm não ligam o ring):

- KSK (flags 257) assina o conjunto DNSKEY; ZSK (256) assina o resto. ECDSA P-256 (13) por
  padrão, MUST para assinar pela RFC 8624/9904; Ed25519 (15), RECOMMENDED. Sem RSA (respostas
  maiores, assinatura lenta).
- Todo RRset autoritativo, inclusive o NS do ápice; o NS de uma delegação e a glue abaixo dela
  não (RFC 4035 §2.2). TTL único por RRset, o menor (RFC 2181 §5.2).
- NSEC3 (RFC 5155 §7.1): um por dono autoritativo e por não terminal vazio, SHA-1, 0 iteração
  extra, sem salt, sem opt-out (RFC 9276 §3.1: iterations 0 MUST, salt SHOULD NOT); TTL =
  min(TTL do SOA, MINIMUM) (RFC 9077); NSEC3PARAM no ápice. Delegação sem DS: bitmap só com NS,
  sem RRSIG.
- RRSIG com início uma hora antes (relógios desajustados) e validade de `signature_validity_secs`
  (RFC 6781 §4.4.2); assinado de novo quando falta metade, quando os dados mudam e quando as
  chaves mudam.
- Serial: a versão assinada tem serial próprio, sempre maior que o último assinado (guardado no
  estado, sobrevive a reinício) e que o da config: uma nova assinatura sem mudança de dados também
  sobe o serial, para as secundárias buscarem as assinaturas novas (como o `inline-signing` do
  BIND). Enquanto a nova versão é assinada, a anterior continua sendo servida.

**Respostas** (etapa `zones`): sem DO, nada de DNSSEC (RFC 4035 §3.1); o DNSKEY é dado comum e
vai para quem perguntar. Com DO (copiado na resposta, RFC 3225): os RRSIG do que responde (do
CNAME também), e no NXDOMAIN o SOA com RRSIG e a prova do encontro mais próximo (NSEC3 do encontro,
NSEC3 cobrindo o próximo mais próximo, NSEC3 cobrindo o curinga: RFC 5155 §7.2.2); NODATA com o
NSEC3 do nome (§7.2.3), curinga com o NSEC3 cobrindo o próximo mais próximo (§7.2.6), referência
para filho sem DS com o NSEC3 da delegação (§7.2.7). AXFR e IXFR levam a versão assinada; o diário
do IXFR e o NOTIFY seguem as versões assinadas. Uma secundária de zona assinada (nossa ou de
outro servidor) separa RRSIG e NSEC3 do que transferiu e responde DO do mesmo jeito.

**Rotação** (`engine/src/dnssec.rs`, tempos da RFC 7583, conferidos com relógio falso):

- Zona assinada sem chaves: o daemon gera uma KSK e uma ZSK, ativas. O DS (SHA-256, RFC 4509; o
  SHA-1 é MUST NOT desde a RFC 9905) aparece em `ip.dns.zone.print` e na GUI: o operador o leva ao
  registro.
- ZSK, pré-publicação (RFC 6781 §4.1.1.1): a nova é publicada no DNSKEY sem assinar; depois de
  Ipub = TTL do DNSKEY + 1 h de propagação ela passa a assinar e a antiga se aposenta; depois de
  Iret = maior TTL da zona + 1 h a antiga sai.
- KSK, assinatura dupla (§4.1.2): a nova assina o DNSKEY já junto com a antiga; o operador põe o
  DS novo no pai e diz `ds-published` (como o `rndc dnssec -checkds published` do BIND); a antiga
  se aposenta e sai depois do TTL do DS no pai (1 dia, `parent-ds-ttl` do BIND) + 1 h. Enquanto o
  operador não confirmar, as duas assinam (sem risco de quebrar).
- Trocar o algoritmo de uma zona com chaves é recusado (rotação de algoritmo: G4.1m); renomear
  também (o DS é do nome antigo).

**Regras de RFC no código:**

| Regra | Onde |
|---|---|
| RFC 4034 §2.1.1: flags 256/257 (SEP na KSK) | `dnssec/sign.rs::dnskey_of` |
| RFC 4034 §3.1.3 e RFC 6840 §6.3: rótulos do RRSIG sem o `*` | `sign.rs::rrsig` |
| RFC 4035 §2.2: delegação e glue sem assinatura; NS do ápice assinado | `sign.rs::sign` |
| RFC 4035 §3.1: DNSSEC só com DO; §3.1.1 RRSIG junto; §3.1.3 provas | `stage/zones.rs`, `dnssec::authenticate` |
| RFC 3225 §3: DO copiado na resposta | `server::encode` |
| RFC 5155 §7.1: NSEC3 por dono e não terminal vazio, NSEC3PARAM | `sign.rs::sign` |
| RFC 5155 §7.2.2/§7.2.3/§7.2.5/§7.2.6/§7.2.7: provas | `dnssec::authenticate` |
| RFC 5155 errata 3544: base32hex | `dnssec::base32hex` |
| RFC 9276 §3.1: 0 iterações, sem salt, sem opt-out | `sign.rs` (`ITERATIONS`) |
| RFC 9077: TTL do NSEC3 = min(SOA TTL, MINIMUM) | `sign.rs::sign` |
| RFC 2181 §5.2: um TTL por RRset | `sign.rs::sign` |
| RFC 8624/9904 §3.1: algoritmos 13 e 15; RFC 4509 e 9905: DS com SHA-256 | `sign.rs::generate` |
| RFC 6781 §4.1.1.1/§4.1.2, RFC 7583 §3: pré-publicação da ZSK, assinatura dupla da KSK, Ipub/Iret | `engine/src/dnssec.rs` |
| RFC 6781 §4.4.2: início no passado, renovação na metade da validade | `sign.rs`, `service/dns_zones.rs` |

**Testes.** `proto-dns` (feature `dnssec`): toda RRSIG verificada com o verificador do Hickory
(ECDSA e Ed25519), o que é e o que não é assinado, a cadeia NSEC3 (anel fechado, ordem, bitmaps,
parâmetros da RFC 9276, TTL), as provas da §7.2 (NXDOMAIN, NODATA, não terminal vazio, curinga,
referência, CNAME), zona assinada transferida e reindexada, estados das chaves, chave danificada,
a cadeia com e sem DO. Engine: ciclo de vida das chaves com relógio falso (chaves iniciais,
rotação de ZSK e de KSK, espera do DS, remoção), chaves sobrevivem a reinício, comandos. Daemon:
zona assinada com DO e sem DO, nova assinatura com serial maior, secundária servindo as
assinaturas e a mesma prova de NXDOMAIN. Namespace (`tests/netns_dns_dnssec.rs`): o `delv` do BIND,
um validador independente, com a KSK como âncora: resposta, SOA, DNSKEY, NXDOMAIN, NODATA, não
terminal vazio, curinga e CNAME "fully validated", e de novo depois de uma mudança. GUI: diálogo
com as chaves e o DS, o botão Roll ZSK chegando ao engine, screenshot.

**Desempenho (medido, `benches/dnssec.rs`).** Assinar uma zona de 1000 registros inteira (≈ 2000
assinaturas com o NSEC3): 24 ms com ECDSA P-256, 32 ms com Ed25519. Resposta assinada com DO:
1,56 µs; NXDOMAIN com a prova NSEC3 (hashes por consulta): 6,6 µs.

**Por que não o `hickory-server` aqui também.** O `InMemoryZoneHandler::secure_zone_mut` do
`hickory-server` 0.26.3 assina todo RRset, inclusive o NS de delegação e a glue (a RFC 4035 §2.2
proíbe), põe RRSIG no bitmap de delegações sem DS e não tem rotação de chaves. A criptografia é do
`hickory-proto` (DNSKEY, RRSIG, DS, hash NSEC3, ring); a cadeia, as provas e as rotações são nossas.

**Limites e o que fica para depois** (G4.1m): CDS/CDNSKEY (RFC 7344/8078/9615) e checagem
automática do DS no pai (o `checkds` do BIND, o `ksk-submission` do Knot); rotação automática por
idade (`zsk-lifetime`); rotação de algoritmo; NSEC como alternativa ao NSEC3; DS de zonas filhas
nos registros (delegação assinada).

#### Pesquisa da G4.1c-2

Fontes (conferidas em 2026-10-22): MikroTik `/ip dns` (sem DNSSEC nenhum, só DoH); BIND 9
`dnssec-policy` e o guia de DNSSEC (<https://bind9.readthedocs.io/en/latest/reference.html>,
<https://bind9.readthedocs.io/en/latest/dnssec-guide.html>); Knot `policy`
(<https://www.knot-dns.cz/docs/latest/html/reference.html>); PowerDNS
(<https://doc.powerdns.com/authoritative/dnssec/pdnsutil.html>,
<https://doc.powerdns.com/authoritative/dnssec/modes-of-operation.html>); VyOS, OPNsense
(plugin BIND), OpenWrt (pacote knot), pfSense; RFCs 3225, 4033, 4034, 4035, 4509, 5155, 6605,
6781 (§3.3, §4.1, §4.4.2), 6840 (§5.1, §5.11, §6.3), 7344, 7583, 8078, 8624 → 9904, 9077, 9276,
9615, 9905. Errata: RFC 4034 4552 (verificada) e 2681 (soma da key tag em 32 bits; o Hickory a
calcula assim), 1062; RFC 4035 5226 (§3.1.4.1), 8037 (retida); RFC 5155 3441, 3544 (base32hex),
4622, 4993; RFC 9276 7104 (editorial); RFC 6781 4844 (publicar o DNSKEY antes de mandar o DS);
RFC 7344 7997, RFC 8078 5049; RFC 8624 6227 e 8144 (rejeitadas); RFC 6840 8038 (retida).

**Como o MikroTik faz.** Não faz: nem valida nem assina.

**Como os outros fazem.** BIND `default`: uma CSK ECDSA P-256 sem prazo, NSEC (NSEC3 com
`nsec3param`, exemplo 0 iteração e sem salt), validade de 2 semanas renovada aos 5 dias,
`publish-safety`/`retire-safety` 1 h, `parent-ds-ttl` 1 dia, `inline-signing`, CDS/CDNSKEY,
`checkds` no pai, `rndc dnssec -checkds/-rollover/-status`. Knot: ECDSA P-256, KSK + ZSK
(`single-type-signing` desligado), `zsk-lifetime` 30 dias, KSK sem prazo, `rrsig-lifetime` 14
dias, NSEC3 desligado (0 iteração, sem salt quando ligado), `ksk-submission`. PowerDNS: uma CSK
ECDSA, NSEC por padrão, assinatura na hora com cache, janela semanal, `set-nsec3` padrão '1 0 0 -'
pela RFC 9276. VyOS, OPNsense e pfSense só validam; o OpenWrt assina só com Knot cru, sem tela.

**O que adotamos.** ECDSA P-256 como todos; KSK + ZSK como o Knot (o pedido da gap: a ZSK gira
sozinha sem tocar no registro, a KSK só quando o operador quer); NSEC3 com os parâmetros da RFC
9276 (pedido da gap; esconde os nomes da zona de quem caminha pelo NSEC); validade de 14 dias
como o Knot; DS só com SHA-256; a rotação da KSK espera a confirmação do DS como o `checkds`.

**Melhorias sobre os outros.** As chaves fora da config e do rollback (um rollback do BIND com
`dnssec-policy` não mexe nas chaves, mas um operador que restaura um backup de zona sim); o DS na
tela, com Copy, e o próximo passo de cada chave em palavras; a rotação da KSK nunca avança sem a
confirmação; o `delv` valida a zona inteira no teste de namespace; assinar a zona inteira custa
24 ms por 1000 registros.

**Fica de fora, e por quê.** CDS/CDNSKEY e a checagem do DS no pai (precisam consultar o pai pela
internet, com o resolvedor da G4.1f); NSEC (a gap pede NSEC3); rotação por idade e de algoritmo;
chave offline (`offline-ksk` do Knot): G4.1m.

### G4.1c-3 — Atualização dinâmica (RFC 2136 + TSIG) e DHCP → DNS

**Problema.** Os nomes dos equipamentos de uma LAN (o notebook, o telefone IP) vêm do DHCP e mudam
de endereço; ninguém os cadastra à mão. Os servidores de DHCP sérios (Kea com o dhcp-ddns, ISC
dhcpd) os publicam por RFC 2136 UPDATE assinado com TSIG; o RouterOS não aceita UPDATE (tem o
`add-dns-entries` do seu próprio DHCP e scripts de concessão). O servidor DHCP do CoreRouter (G4.2)
ainda não existe.

**Agora.**

```sh
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.tsig-key.add '{"name":"dhcp-ddns"}'      # devolve o secret (32 bytes aleatórios)
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.set '{"id":"lan.example","update_keys":"dhcp-ddns"}'
nsupdate -y hmac-sha256:dhcp-ddns:<secret> <<< $'server 192.168.88.1\nzone lan.example\nupdate add laptop.lan.example 600 A 192.168.88.77\nsend'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.zone.record.print '{"zone":"lan.example"}'   # D laptop A 192.168.88.77
```

Na GUI: IP › DNS TSIG Keys (New faz uma chave aleatória e mostra o secret uma vez, com Copy; Show
Secret mostra de novo), o diálogo da zona ganha Update Keys e Allow Update, e IP › DNS Zone Records
mostra os registros dinâmicos com `D` (Remove os tira).

| Comando | Parâmetros |
|---|---|
| `ip.dns.tsig-key.add/set/remove/print` | `name`, `algorithm` (`hmac-sha256` padrão, `hmac-sha384`, `hmac-sha512`), `secret` (base64, 16 a 256 bytes; ausente: 32 aleatórios), `comment`; `print show_secret=yes` mostra o secret (só grupo `full`), que o `print` normal e o `/export` escondem; o secret também não vai para o journal nem para o log, e abaixo do grupo `full` aparece como `***` no `state.inspect` e no `config.diff` |
| `ip.dns.zone.add/set` | + `update_keys` (chaves que podem atualizar), `allow_update` (de onde; sem `update_keys`, sem assinatura de lá) |
| `ip.dns.zone.record.print` | + as linhas `D` (dinâmicas): `dynamic`, `source` (quem pôs), `expires_unix` |
| `ip.dns.zone.dynamic.remove` / `.flush` | `{id}` / `{zone}` |
| `ip.dns.zone.file.get` | inclui os registros dinâmicos |

**Os registros dinâmicos ficam fora da config.** Como as chaves DNSSEC e as concessões do cliente
DHCP, ficam no estado operacional (`dns-dynamic`, salvo antes de responder ao UPDATE, RFC 2136 §3.5):
uma concessão não é revisão, um rollback não traz de volta o nome de uma concessão vencida e o
`config.diff` não se afoga neles. Um UPDATE nunca muda um registro configurado: apagar um nome
configurado só apaga os dinâmicos dele. Cada mudança sobe o serial servido (§3.6), também à frente
do serial da config, e o próximo serial da config passa dele; uma zona assinada é assinada de novo.

**Quem pode** (RFC 3007, §3.3): uma chave de `update_keys` (e, se houver, de `allow_update`); sem
chaves, sem assinatura só de `allow_update` (o `allow-update` do BIND, para uma LAN de confiança);
sem nenhum dos dois, REFUSED. Nada atualiza por padrão, como no BIND, no Knot e no PowerDNS.

**O que é checado** (`proto-dns/src/zone/update.rs`), antes de qualquer mudança:

- §3.1: a seção de zona é uma pergunta SOA de uma zona primária nossa (FORMERR, NOTAUTH).
- TSIG (RFC 8945 §5.2): a chave, depois o MAC (sem MAC truncado), depois o tempo (fudge de 300 s,
  §10) e nunca mais velho que a última mensagem da mesma chave (§5.2.3, contra repetição). BADKEY e
  BADSIG voltam sem assinatura, BADTIME assinado, todos com NOTAUTH; a resposta a um UPDATE
  assinado é assinada (§5.3). HMAC-SHA256/384/512 (§6: MD5 MUST NOT, SHA-1 NOT RECOMMENDED).
- §3.2: os pré-requisitos (nome em uso ou não, RRset existe ou não, RRset igual) contra o que a
  zona serve agora; YXDOMAIN, NXDOMAIN, YXRRSET, NXRRSET, NOTZONE.
- §3.4.1/§2.5: adicionar, apagar RRset, apagar nome, apagar registro; o SOA é nosso (ignorado);
  tipos que as zonas não guardam (SSHFP, DHCID…) são recusados; no máximo 100 mudanças por mensagem.
- Engine (`engine/src/dns_dynamic.rs`), tudo ou nada (§3.7): registro igual só troca o TTL; CNAME
  nunca se junta a outros dados nem outros dados a um CNAME (ignorado, §3.4.2.2 e errata 4469); o NS
  do ápice é nosso.

**DHCP → DNS (para a G4.2).** `Session::dns_dynamic_lease` põe o A/AAAA `host.<zona>` (trocando o
que uma concessão anterior do mesmo host pôs) e o PTR na zona reversa nossa que cobre o endereço,
com expiração no fim da concessão; `Session::dns_dynamic_release` os tira. Um host que é nome
configurado não é tomado (como o Kea, que não sobrescreve nome que não é dele). O servidor DHCP da
G4.2 chama essas duas funções (critério atualizado em `docs/gaps.md`); até lá, o Kea, o ISC dhcpd
ou qualquer servidor com DDNS já atualiza as zonas por UPDATE.

**Regras de RFC no código:**

| Regra | Onde |
|---|---|
| RFC 2136 §3.1/§3.1.1: uma pergunta SOA; NOTAUTH fora das nossas zonas | `update::read` |
| RFC 2136 §2.4/§3.2: pré-requisitos e seus códigos | `update::prerequisites` |
| RFC 2136 §2.5/§3.4.1: seção de atualização, varredura antes | `update::changes` |
| RFC 2136 §3.3 e RFC 3007 §2: permissão antes de tudo, nada por padrão | `update::read` |
| RFC 2136 §3.4.2.2 (errata 4469): conflito de CNAME ignorado; registro igual troca o TTL | `dns_dynamic::apply` |
| RFC 2136 §3.5: salvo antes da resposta; §3.6 serial sobe; §3.7 tudo ou nada | `Session::dns_dynamic_apply` |
| RFC 8945 §5.2/§5.3/§6/§10: ordem dos testes, erros, resposta assinada, algoritmos, fudge | `update::sign` |
| RFC 8945 §6: chave com pelo menos 16 bytes (`tsig-keygen` faz 32) | `dns_tsig::TsigKey::problem` |
| RFC 1035 §3.5 e RFC 3596 §2.5: nome reverso do PTR | `dns_dynamic::reverse_name` |

**Testes.** Modelo: chaves (base64, tamanho, algoritmos). `proto-dns`: permissão (sem chave, rede,
zona alheia, seção de zona), pré-requisitos da §2.4 um a um, seção de atualização (apagar RRset,
nome, registro; SOA ignorado; tipo desconhecido; NOTZONE), TSIG com o `TSigner` do Hickory (chave
certa com resposta assinada, BADSIG, BADKEY, BADTIME, repetição, rede fora de `allow_update`) e
proptests com bytes hostis e UPDATEs danificados. Engine: regras da §3.4.2, tudo ou nada, serial,
concessão com A + PTR, troca de endereço, nome configurado preservado, expiração, liberação,
reinício. Daemon: UPDATE assinado por UDP respondido na hora, chave errada sem efeito, concessão
com A e PTR e o fim dela. Namespace (`tests/netns_dns_ddns.rs`): o `nsupdate` do BIND com TSIG
(pré-requisito, YXDOMAIN, chave errada, PTR na reversa, delete). GUI: janela de chaves (New e Show
Secret), linha `D` removida, e o log/status da GUI nunca mostra um secret (`redact.rs`).

**Limites e o que fica para depois.** Sem DHCID/resolução de conflito da RFC 4703 (o Kea manda os
DHCID como TXT/DHCID; DHCID é recusado: use `ddns-conflict-resolution-mode no-check-without-dhcid`
no Kea); sem regras por nome/tipo como o `update-policy` do BIND; uma secundária não repassa UPDATE
ao primário; TSIG também para AXFR/NOTIFY: G4.1n.

#### Pesquisa da G4.1c-3

Fontes (conferidas em 2026-10-22): MikroTik `/ip dns` e DHCP server (`lease-script`,
`add-dns-entries` com sufixo `lan` e TTL da concessão,
<https://manual.mikrotik.com/docs/network-management/dhcp/server/>); Kea D2
(<https://kea.readthedocs.io/en/latest/arm/ddns.html>, `ddns-conflict-resolution-mode`, TTL 1/3 da
concessão com mínimo de 600 s); ISC dhcpd `ddns-update-style`; BIND `allow-update` ×
`update-policy`, journal; Knot ACL `action: update` com `update-type`/`update-owner`; PowerDNS
`dnsupdate`, `allow-dnsupdate-from`, `TSIG-ALLOW-DNSUPDATE` (IP e chave, os dois); dnsmasq
(`--domain`, `--dhcp-fqdn`) e OPNsense ("Register DHCP leases"); RFCs 2136 (§2.4, §2.5, §3.1–§3.8),
3007, 8945 (obsoleta 2845 e 4635), 4701, 4703, 2181, 1035 §3.5, 3596. Errata: RFC 2136 4469
(verificada, §3.4.2.2) e 2805 (retida); RFC 8945 7983 (editorial) e 9014 (rejeitada). "Updated by"
da RFC 2136: 3007, 4033, 4034, 4035.

**Como o MikroTik faz.** Sem UPDATE; o servidor DHCP põe um A dinâmico por concessão
(`add-dns-entries`, sem PTR) ou roda um script.

**Como os outros fazem.** Kea e ISC mandam UPDATE com TSIG (forward e reverse, DHCID para
conflitos), BIND/Knot/PowerDNS aceitam por chave ou endereço, com política por nome/tipo; dnsmasq
e OPNsense põem as concessões direto no DNS local.

**O que adotamos.** UPDATE com TSIG como o BIND/Knot/PowerDNS, chave por zona, nada por padrão, IP e
chave juntos como o PowerDNS; registros dinâmicos separados da config; e a função interna que o
nosso DHCP vai chamar, com A **e** PTR (o RouterOS só faz A).

**Melhorias.** O operador vê na lista de registros o que é dinâmico (`D`), quem pôs e quando vence,
e tira com Remove; um rollback nunca mexe neles; a chave TSIG nasce aleatória e o secret nunca
aparece no log, no `print` comum nem no export; o UPDATE de uma zona assinada sai assinado na hora.

**Fica de fora, e por quê.** DHCID/RFC 4703 e `update-policy` por nome (G4.1n); repassar UPDATE
de secundária ao primário (RFC 2136 §6, pouco usado); SIG(0) (quase ninguém usa).
