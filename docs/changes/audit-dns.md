id: audit-dns

Auditoria do DNS (resolvedor, encaminhador da LAN, zonas, transferências, UPDATE/TSIG, cliente
HTTP das adlists e do DoH). Corrigido, cada um com teste que falhava antes:

- **TCP/53 tomado por quem não pode perguntar nada, e por gotejamento** (alta). O accept dava
  vaga de `max_concurrent_tcp_sessions` a qualquer um antes do ACL, e o `TCP_IDLE` valia por
  `read()`: 20 conexões mandando um byte a cada 9 s seguravam o TCP da LAN (fallback do TC,
  AXFR, UPDATE) por dias. Agora o accept fecha quem não é o roteador, `allowed_from` nem um par
  que alguma zona nomeia (`zone::xfr::may_connect`: `allow_transfer`, `allow_update`,
  `primaries`; zona com TSIG sem `allow_update` aceita qualquer origem), cada origem fica com no
  máximo 1/4 das vagas, a mensagem tem 10 s do primeiro ao último byte (o buffer cresce com o
  que chega, o tamanho 65 535 sozinho não aloca nada) e a conexão não lê consulta nova depois
  de 2 min. Testes `who_may_connect`, `tcp_slots_survive_slow_and_greedy_peers`.
- **IXFR falsificado por UDP serializava a zona inteira no thread do listener** (média). Um IXFR
  de serial antigo vindo (forjado) de um endereço de `allow_transfer` copiava e codificava a zona
  toda (200 ms por pacote numa zona de 50 000 registros, build de debug, **medido**) só para
  descobrir que não cabia no UDP. Agora a contagem de registros decide antes (RFC 1995 §2: o SOA
  na hora). Teste `udp_ixfr_of_a_big_zone_is_the_soa_without_encoding_it`.
- **Despejo do cache O(n) por inserção, sob o lock do resolvedor** (média). Com o cache cheio,
  cada `put` varria o mapa duas vezes sob o mutex que todo acerto de cache também pega. Agora um
  índice por expiração (`BTreeSet`) despeja em O(log n). Teste
  `eviction_follows_the_expiry_index`; números em `## perf`.
- **Pré-requisitos do RFC 2136 checados fora do que aplica** (média, RFC 2136 §3.7). Dois UPDATEs
  "nome não está em uso" lidos antes de qualquer um aplicar passavam os dois. Agora o UPDATE
  guarda a versão dos registros dinâmicos que viu; `Session::dns_dynamic_update` só aplica se ela
  não mudou, senão o daemon confere os pré-requisitos de novo (`zone::update::recheck`) e tenta
  outra vez (YXDOMAIN no segundo). Testes `prerequisites_hold_when_the_update_applies`,
  `an_update_checked_against_old_records_waits`.
- **UPDATE por UDP esperava o lock da sessão e a gravação em disco no thread do listener**
  (média). Agora vai para o thread `dns-update` (fila de 64; cheia, descarta e o cliente
  repete). Teste `an_update_never_holds_up_queries`.
- **Cliente HTTP sem prazo de verdade** (média). O timeout do socket recomeçava a cada byte e o
  laço de trailers não tinha limite: um servidor de adlist lento segurava o thread por semanas e
  trailers sem fim, para sempre. Agora cada leitura espera só o que falta até o prazo, e no
  máximo 64 linhas de trailer. Testes `a_slow_server_never_outlives_the_deadline`,
  `endless_trailers_are_refused`.
- **EXPIRE da secundária sem piso** (média). `refresh 3600 expire 60` derrubava a cópia 60 s depois
  de cada checagem (SERVFAIL ~59 min por hora). Agora EXPIRE ≥ REFRESH + RETRY (RFC 1912 §2.2,
  como o BIND). Teste `expire_is_at_least_refresh_plus_retry`.
- **Tabela do limite por cliente varrida a cada pacote novo com ela cheia** (baixa). Agora no
  máximo uma varredura por segundo. Teste `a_full_table_is_swept_once_a_second`.
- **Janela do TSIG vinha do Fudge do cliente (até 18 h)** (baixa). Agora vale também o nosso
  limite de 300 s (RFC 8945 §5.2.3/§10), a mesma mensagem (mesmo Time Signed e MAC) é recusada
  como repetição, e um Time Signed menor que o Fudge é recusado antes do hickory (que subtrai sem
  checar e daria panic no build de debug). Teste `signed_updates_follow_rfc8945`.
- **`ip.dns.cache.print/flush` formatavam o cache inteiro sob o lock** (baixa). O flush conta sem
  formatar (`DnsBackend::cache_len`); o print filtra nome e tipo dentro do cache antes de formatar
  e para em `limit` (novo parâmetro, padrão 1000, máximo 100 000). Teste
  `cache_print_is_bounded_and_flush_does_not_format`.
- **Config antiga reconstruía as zonas para trás** (baixa). Uma consulta com o `ServerConfig`
  anterior que chegava depois do novo construído refazia as zonas velhas (diff invertido no
  diário do IXFR, NOTIFY com o serial antigo). Agora usa a config mais nova; os registros
  dinâmicos são relidos sob o lock. Teste `an_older_config_never_rolls_the_zones_back`. (A
  reconstrução de todas as zonas a cada mudança virou a G4.1p.)
- **Fila de efeitos sem limite** (baixa). Agora `sync_channel(4096)`; cheia, descarta (a próxima
  resposta acrescenta o endereço de novo). Teste `effects_queue_is_bounded`.
- **Redirect de adlist para dentro do roteador** (baixa, SSRF cego). Um redirect de um servidor
  de fora para loopback, rede privada, CGNAT, ULA ou link-local é recusado (uma lista que já
  estava dentro pode). Teste `redirects_inward_are_refused`.
- **Respostas perdidas em silêncio** (baixa). Transferência com mensagem que falha ao codificar
  vira SERVFAIL em vez de SOA … SOA incompleto (`xfr::whole`); falha ao criar o thread de uma
  consulta UDP responde SERVFAIL; resposta TCP acima de 64 KiB vira SERVFAIL.

Teste instável `answers_the_lan_over_udp_and_tcp` (saiu FLAKY num CI completo da `main`): o
upstream de teste tinha 300 ms de timeout e o cliente 500 ms; numa máquina carregada o resolvedor
perguntava duas vezes (contador do upstream em 2) ou o cliente desistia antes da resposta. Agora
3 s no upstream, 5 s no cliente para as respostas que dependem do upstream e 20 s no `wait`.

Conferido e sem mudança: o restante da lista "Checked, looks fine" do auditor (limites do parser,
TTLs, ACL antes do limite, NOTIFY só de primário, transferência de entrada limitada).

Ficou para depois:

| G4.1o | DNS: juntar consultas iguais em andamento no resolvedor | proto-dns, daemon | N clientes perguntando o mesmo nome fora do cache geram uma só consulta ao upstream (mapa `(nome, tipo, via)` em andamento; os seguidores esperam o resultado do líder até o próprio prazo), como o Unbound; teste com transporte que bloqueia: 10 resoluções simultâneas, 1 troca (RFC 5452 §5) | 3 h | aberto |
| G4.1p | DNS: reconstruir só as zonas que mudaram | proto-dns | Uma mudança de config ou um registro dinâmico (cada renovação de DDNS) reconstrói e compara só a zona afetada, fora do caminho da consulta, em vez de todas as primárias (até 100 000 registros) no primeiro thread de consulta que chega; benchmark de `zone::zones()` com 100 000 registros antes/depois | 4 h | aberto |
| G4.1q | DNS dinâmico: gravação incremental | engine, daemon | Cada UPDATE ou renovação de lease grava o JSON inteiro dos registros dinâmicos (até 20 000); um diário anexado com compactação periódica (como o journal do BIND) tira essa escrita do caminho de cada UPDATE; teste de recuperação depois de queda no meio | 4 h | aberto |

## perf

### audit-dns — cache do DNS cheio (2026-10-22, **medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release, criterion (`--warm-up-time 1 --measurement-time 3`),
`antes` = `origin/main` (dbbd394), depois = `stream/audit-dns`:

| benchmark | antes | depois |
|---|---|---|
| `dns_cache_put_full` (inserir num cache de 16 MiB cheio, ~60 000 entradas) | 298,9 µs | 0,611 µs (−99,8 %) |
| `dns_forward_cache_miss_full` (cadeia inteira, miss que despeja num cache de 8 MiB cheio) | 151,2 µs | 3,89 µs (−97,4 %) |
| `dns_forward_cache_hit_full` (acerto com o cache cheio) | 945 ns | 959 ns (ruído) |
| `dns_forward_cache_hit` (quente, cache pequeno) | 915 ns | 964 ns (ruído: `dns_query_encode`, código não tocado, variou o mesmo +5 %) |
| `dns_forward_cache_miss` (frio, upstream instantâneo, TTL 0) | 2,45 µs | 2,59 µs (ruído) |

Memória por entrada (uma resposta A, 200 000 entradas, RSS de `/proc/self/statm` antes e depois
num teste release): **690 bytes**. A estimativa que o cache usa contra o `cache_size` dava 352
(o `cache_size` permitia ~2× a memória configurada); com o índice por expiração e os overheads
corrigidos ela dá 672. Efeito: o mesmo `cache_size` guarda cerca de metade das entradas de
antes, mas agora corresponde à memória de verdade.
