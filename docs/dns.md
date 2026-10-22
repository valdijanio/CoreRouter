# DNS (G4.1)

O subsistema de DNS do CoreRouter é inteiro em Rust, sobre o **Hickory DNS** (decisão do usuário,
2026-10-22; veja `docs/architecture.md`, "DNS"). Ele vem em três partes, todas na mesma config
`/ip dns` e no mesmo cache:

| Parte | O quê | Estado |
|---|---|---|
| G4.1a | Resolvedor do próprio roteador: ping, MTU, MTR e o cliente NTP resolvem nomes por ele | feito |
| G4.1b | Encaminhador com cache para a LAN (`allow_remote_requests`), `/ip dns static` | aberto |
| G4.1c | Servidor completo estilo BIND (zonas autoritativas, DNSSEC) com `hickory-server` | aberto |

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
| `ip.dns.cache.print` | `name?` (filtro por trecho); linhas `{name, type, kind, addresses, canonical, ttl, server}` |
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

**Limites.** A, AAAA, PTR e TXT só para o próprio roteador (o `cache all` com MX etc. fica para a G4.1b). `ip.dns.resolve` (o
`:resolve` do RouterOS) não existe ainda: um comando que espera a rede sob o lock do `Session`
travaria o plano de controle, então ele vai virar tarefa (G4.1d). Sem DoH/DoT, VRF nem servidores
dinâmicos do PPPoE e do DHCPv6 (G4.1d). Não há janela na GUI ainda (G4.1d).

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
