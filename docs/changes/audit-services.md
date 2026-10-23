id: audit-services

Auditoria dos serviços do daemon (supervisor, NTP, syslog remoto, métricas Prometheus), das
ferramentas ping/MTR/MTU e da descoberta de vizinhos (CRDP/LLDP/MNDP). Corrigido:

- **CRDP travava o lock da sessão por datagrama (alta).** Cada anúncio pegava o lock e varria a
  tabela de vizinhos clonando todas as chaves (~120 µs com a tabela cheia), sem limite de taxa:
  poucos milhares de pps paravam comandos, GUI, MCP e serviços. Agora a `NeighborTable` tem
  índices (idade por interface, contagem por interface), `record` diz se o vizinho é novo em
  O(log n) (`Session::hear_neighbor`), e o receptor CRDP aceita no máximo 200 anúncios/s (50 por
  origem) antes do lock. Testes: `recording_into_a_full_table_is_cheap`,
  `receive_rate_is_limited_per_second_and_per_source`; benchmark `neighbors` (abaixo).
- **Raspagem `/metrics` fazia netlink + ethtool por interface sob o lock (média).** Os contadores
  de erro/descarte vêm agora do próprio `poll` (`LinkState::errors`, `IFLA_STATS64`), a junção
  config × kernel é por mapa: uma raspagem custa um lock e um `poll`, como a doc prometia.
  Teste: `a_scrape_does_not_query_counters_per_interface`.
- **Ping/MTR acima de ~68 sondas/s mostravam perda falsa (média).** Com 8192 sondas recentes a
  tabela de enviadas era apagada inteira, inclusive as em voo. Agora só sai o que passou de
  120 s (no máximo uma varredura por segundo); a chave `u16` limita a tabela a 65 536. Teste:
  `a_full_sent_table_keeps_probes_in_flight`.
- **Tabela de vizinhos envenenada por 18 h (média).** A expulsão tirava a entrada que expira
  primeiro (sempre a legítima) e não havia teto por interface. Agora o hold aceito é no máximo
  14 400 s, cada interface guarda até 256 vizinhos e sai a entrada ouvida há mais tempo da mesma
  interface (ou da interface com mais entradas). Teste:
  `a_flood_on_one_port_does_not_evict_the_others`, `a_full_table_evicts_from_the_busiest_port`.
- **Cliente NTP dava panic com `min_poll > max_poll` vindo do disco (média).** `clamp` com
  mínimo acima do máximo; o supervisor desistia do serviço. `next_poll` normaliza os limites
  (6..=17, em ordem) e a validação da config inteira (`validate_all`, que também roda ao
  restaurar) aponta `min_poll`/`max_poll` fora da faixa, invertidos, mais de 8 servidores ou
  servidor inválido. Testes: `poll_interval_backs_off_and_resets`,
  `a_loaded_config_with_bad_poll_bounds_is_reported`.
- **Erros ICMP aceitos só por ident+seq (média).** Um host fora do caminho forjava "frag
  needed mtu=68" ou "unreachable" e mudava o resultado do MTU/MTR/ping. Agora o erro precisa
  citar uma sonda que ia para o mesmo destino (cabeçalho IP citado; na fila de erros do socket
  ping, o `msg_name`), o ident do socket raw é aleatório (`RandomState`) e "too big" abaixo de
  68/1280 não informa MTU. Teste: `an_icmp_error_must_quote_the_probe_destination`.
- **MNDP aceitava unicast de qualquer lugar (média).** O listener escuta em `0.0.0.0:5678`;
  agora só valem datagramas para 255.255.255.255, para o broadcast de uma sub-rede da interface
  de chegada ou para multicast IPv6 (destino lido do `IP_PKTINFO`). Teste:
  `mndp_takes_only_broadcast_and_link_multicast` (e o `netns_l2` confere o destino).
- **Listener CRDP da GUI com fila sem limite (média).** Com a GUI conectada (sem `poll`), cada
  anúncio da LAN se acumulava. Agora `sync_channel(MAX_HEARD)` com `try_send` (cheio: descarta).
  Teste: `the_queue_is_bounded_while_nobody_polls`.
- **Leitor lento segurava o endpoint de métricas (baixa).** Prazo total de 10 s para a resposta,
  escrita em blocos de 16 KB. Teste: `a_slow_reader_is_cut_off_at_the_deadline`.
- **`HostSocket::recv` girava sem fim sob enxurrada ICMP (baixa).** `drain` lê no máximo 256
  mensagens por vez; `recv` volta no prazo e a tarefa vê o stop. Teste:
  `draining_stops_after_its_budget`.
- **SNTP: atraso negativo sempre vencia e receive = 0 era aceito (baixa).** `check_reply`
  recusa receive zero e T3 < T2 (RFC 5905 §8); `poll_round` descarta amostra com atraso
  negativo. Testes: `replies_are_checked_like_rfc_4330_section_5`,
  `a_negative_round_trip_never_wins`.
- **Supervisor (baixa).** (a) falha ao criar a thread agora conta como falha e chega a `failed`
  depois da rajada; (b) um `restart` espera (até 2 s) as threads auxiliares da execução antiga
  soltarem os sockets antes de subir a nova. Testes: `spawn_failures_count_and_give_up`,
  `a_restart_waits_for_the_old_helpers`.
- **Syslog remoto (baixa).** O erro de uma ação apagada ou renomeada deixa de aparecer na linha
  do serviço, e um reinício do serviço continua de onde parou no log (eventos do período em
  backoff, como "falhou", também vão). Testes: `errors_of_removed_actions_are_forgotten`,
  `a_restart_resumes_where_the_last_run_stopped`.
- **NTP: rodada ignorava stop e heartbeat (baixa).** `poll_round` bate o heartbeat e confere o
  stop entre servidores. Teste: `a_round_stops_between_servers`.
- **`tool.ping.mtu` com `max_size=65535` (baixa).** O sentinela "nenhum falhou" saturava em
  65535 e aparecia como `smallest_failing`. Agora é `u32`. Teste:
  `a_clean_path_passes_at_the_maximum`.

Verificado e sem mudança: o achado "qualquer usuário consulta ou para tarefas de outro" já foi
corrigido pelo audit-persist (#123). `tool.dns.query` ser comando de consulta é igual a
`tool.ping.start`/`tool.mtr.start` (mesma permissão); falta uma política para ferramentas que
geram tráfego, que virou gap (abaixo). A porta `--metrics` (flag de linha de comando, só
loopback por padrão) continua sem `available_from`: é escolha explícita do operador.

Como testar: `cargo test -p corerouter-engine neighbors`, `cargo test -p corerouter-daemon
service::`, `cargo test -p corerouter-hal-linux icmp`, `cargo test -p corerouter-discovery`,
`cargo bench -p corerouter-engine --bench neighbors`.

| G0.10c | Política de ferramentas que geram tráfego | engine, model | Ping, MTR, Discover MTU e DNS Lookup são comandos de consulta, então um grupo só-leitura os roda; DNS Lookup com DoH/DoT abre TCP para qualquer host e porta (sondagem da rede interna a partir do roteador). Criar a política `test` do RouterOS (grupo de usuário) e exigir dela em `tool.*`, com teste de usuário só-leitura recusado | 3 h | aberto |
| G5.6 | Limite de taxa por interface na descoberta | discovery, daemon | O CRDP limita 200 anúncios/s no total e 50 por origem antes do lock, mas a interface só se conhece com a config (dentro do lock): uma enxurrada com origens forjadas numa porta ainda ocupa a cota global e atrasa anúncios legítimos das outras portas. Cota por interface (scope id do IPv6 sem lock; IPv4 por tabela de sub-redes copiada a cada segundo) e o mesmo para LLDP/MNDP | 2 h | aberto |

## perf

### audit-services: tabela de vizinhos por datagrama recebido (**medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release (`cargo bench`), 2026-10-22,
`cargo bench -p corerouter-engine --bench neighbors` (tabela cheia: 4096 entradas em 16
interfaces; inclui montar a entrada):

| caso | antes | depois |
|---|---|---|
| vizinho novo (expulsa um) | 121 µs | 0,84 µs |
| refresh de vizinho conhecido | 52 µs | 0,24 µs |

"Antes" é o caminho do receptor na `main`: varrer a tabela clonando chaves para saber se é novo
e depois `record` (outra varredura para expulsar). Com o lock da sessão ocupado ~120 µs por
datagrama, ~8 000 anúncios/s bastavam para segurá-lo o tempo todo; agora seriam ~1,2 M/s, e o
limite de 200/s corta antes disso.
