# Log de consultas DNS (G4.1zd)

O log de consultas grava no disco do roteador as consultas que o encaminhador DNS da LAN respondeu
ou descartou. Para cada consulta ficam:

- a hora;
- o cliente;
- o nome, o tipo e o código de resposta;
- quem respondeu;
- o erro estendido (RFC 8914), quando há;
- o tempo de resposta.

Vem **desligado** e tem teto de espaço e de idade. Só liga com a ciência explícita do operador
sobre a lei.

- **Parte 1 (este PR):** o log persistente, os comandos `ip.dns.log.*` e a janela IP › DNS ›
  Query Log.
- **Parte 2:** a saída dnstap para coletores externos (seção "dnstap", no fim).

## Lei: por que desligado e com aviso

- **Marco Civil, art. 14.** Num provedor de conexão, guardar qual assinante perguntou qual nome, e
  quando, se parece com **registro de acesso a aplicação**. O Marco Civil da Internet (Lei
  12.965/2014) proíbe o provedor de conexão de guardar esse registro.
- **Marco Civil, art. 13.** Manda guardar só o registro de conexão, por um ano.
- **LGPD (Lei 13.709/2018).** O log é dado pessoal:
  - art. 6º III: guardar o mínimo necessário;
  - art. 16: eliminar ao fim do tratamento;
  - art. 18: o titular pode pedir a eliminação;
  - art. 46: segurança desde a concepção.
- **Decreto 8.771/2016, art. 13 §2º.** Pede reter o mínimo.

O usuário escolheu ter o log persistente sabendo disso. O roteador faz a escolha segura por
padrão:

| O quê | Como |
|---|---|
| Desligado | `ip.dns.log.set enabled=yes` só passa com `acknowledge=marco-civil-art14`, e a GUI pede a caixa "Li o aviso". O pedido fica no journal com o usuário e a hora. Ligar e desligar escrevem uma linha `dns,warning` no log do roteador |
| Cliente truncado | `client_address=truncated` por padrão: /24 no IPv4 e /56 no IPv6 (RFC 6235 §4.1.1). O AdGuard Home corta em /16 e /48; dá para escolher esses prefixos |
| Hash com sal que gira | `client_address=hashed`: SipHash-1-3 com chave de 128 bits do `getrandom`, só na RAM, trocada a cada `salt_rotation_hours` (24 h por padrão). Dentro do período, o mesmo cliente tem o mesmo valor. Depois da troca, nem o roteador liga o hash ao IP. Enquanto a chave existe, é **pseudônimo** (LGPD art. 13 §4º), não anônimo |
| Sem cliente | `client_address=none` |
| Teto e idade | `max_size_mib` (1024) dentro de 20 % do `/config`, e `max_age_hours` (24). Valem também com o log desligado |
| Apagar e exportar | `ip.dns.log.clear {all \| before \| older_than_secs \| client}`, que reescreve os segmentos, e `ip.dns.log.export {format: csv \| jsonl}`, que fica no journal com os filtros |
| Arquivos só do dono | pasta `0700`, arquivos `0600` |

O ext4 do `/config` não garante TRIM imediato: um bloco apagado só some da flash quando o disco o
reaproveita. O ⓘ "Apagar" diz isso.

## Pesquisa

### MikroTik RouterOS v7 (7.25)

- **Não há log de consultas nem dnstap.**
  - Só o tópico `dns` em `/system logging`, que vai para a memória, o disco (`disk-lines-per-file`
    1000, `disk-file-count` 2) ou o syslog.
  - A comunidade usa `dns,!packet` para não duplicar as linhas.
  - Fontes: [DNS](https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS),
    [logging action](https://manual.mikrotik.com/docs/7.25/cli-reference/system/logging/action/),
    [fórum](https://forum.mikrotik.com/t/dns-logging/103154).
- **Nomes que adotamos.** O menu `ip.dns.log` fica perto de `/ip dns`. Os rótulos seguem o estilo
  do RouterOS (`max-size`, `except-from`).

### Outros

| Projeto | Onde grava | Retenção | Privacidade | Fila cheia |
|---|---|---|---|---|
| [Pi-hole v6 FTL](https://docs.pi-hole.net/ftldns/configfile/) | SQLite em memória, gravado no disco a cada `DBinterval` (60 s) | `maxDBdays` 91 | `privacylevel` 0–3 (esconde domínios, depois clientes, depois desliga) | — |
| [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/querylog/qlog.go) | `querylog.json` (JSON por linha) mais um `.json.1` | `interval` 90 dias (entre 1× e 2×) | `anonymize_client_ip`: /16 e /48 ([http.go](https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/querylog/http.go)) | busca linear |
| [OPNsense](https://docs.opnsense.org/manual/reporting_unbound_dns.html) | módulo Python no Unbound → FIFO → DuckDB em lotes de 10 s ([logger.py](https://github.com/opnsense/core/blob/master/src/opnsense/scripts/unbound/logger.py)) | 7 dias fixos | — | `deque(100000)` descarta o mais velho **sem contar** |
| [Unbound](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html) | `log-queries`/`log-replies` em texto; dnstap | — | — | fila de 1 MiB por worker com mutex; descarta **sem contar** ([dtstream.c](https://github.com/NLnetLabs/unbound/blob/master/dnstap/dtstream.c)) |
| [BIND 9](https://bind9.readthedocs.io/en/latest/reference.html) | `querylog` num canal com `versions`/`size`; dnstap em arquivo ou unix | sem rotação por padrão | — | fstrm (8192, mpsc) |
| [PowerDNS Recursor](https://doc.powerdns.com/recursor/lua-config/protobuf.html) / [dnsdist](https://dnsdist.org/reference/dnstap.html) | protobuf e dnstap para coletor | — | `setProtobufMasks`; `ipEncryptKey` (ipcrypt) | **conta** (`queueFullDrops`) |
| [Knot Resolver](https://www.knot-resolver.cz/documentation/latest/config-logging-dnstap.html) | dnstap | — | — | — |

### Padrões e privacidade

- [RFC 8932](https://www.rfc-editor.org/rfc/rfc8932.html) §5.2.1 (DNS Privacy Service Best
  Practice): minimizar ou evitar a retenção; não dá prazo em número.
- [RFC 6235](https://www.rfc-editor.org/rfc/rfc6235.html) §4.1 (IP anonymization):
  - truncamento (§4.1.1);
  - permutação e hash com chave (§4.1.4).
- [draft-denis-ipcrypt](https://datatracker.ietf.org/doc/draft-denis-ipcrypt/): ainda não é RFC.
  Ficou como gap.
- dnstap: [dnstap.info](https://dnstap.info/),
  [dnstap.proto](https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto),
  [Frame Streams](https://github.com/farsightsec/fstrm/blob/master/fstrm/control.h).

### O que adotamos e o que fizemos melhor

- **Fila limitada por thread**, como o Unbound, mas **sem mutex compartilhado** (faixas como as
  estatísticas do G4.1h) e **com contador** de descartes, como o PowerDNS. O Unbound e o OPNsense
  descartam sem contar.
- **Teto em bytes**, que nenhum deles tem. A 20 mil consultas/s, os 91 dias do Pi-hole seriam
  ~1,9 TB.
- **Prévia antes de ligar**: GB por dia na taxa atual, horas que o teto guarda e desgaste do disco
  por ano.
- **Tudo é comando**: transação, Safe Mode, journal, MCP (`ip.dns.log.search` responde "o que o
  cliente X perguntou e por que falhou").

### Ficou de fora, e por quê

| O quê | Por quê |
|---|---|
| dnstap | é a parte 2, a pedido do usuário |
| Nível "só domínio registrável" (eTLD+1) | precisa da Public Suffix List, que não está no projeto; vira gap |
| Índice por cliente | com CGNAT, quase todo bloco de 10 s tem quase todo cliente (medido no sintético: os 4096 clientes em cada bloco de 65 mil): o índice não pula blocos |
| Filtro de Bloom de nomes por bloco | a busca por tempo e a decodificação a 12 milhões de consultas/s por núcleo bastam por ora; vira gap se a busca ficar lenta |
| Mensagens malformadas | voltam antes da cadeia e não entram no log; as estatísticas as contam |
| Consultas do próprio roteador | DNS Lookup e as ferramentas não entram no log |

## Desenho

```text
thread que responde ──Done.log (etapa querylog)──► daemon: hora + latência
   └─► Sink::push: buffer da faixa da thread (16 KiB) ──try_send──► canal (256 buffers)
                                                    cheio: descarta e conta
thread "dns-log" (a cada 200 ms): drena ─► anonimiza ─► bloco (65 536 consultas ou 10 s)
   └─► deflate ─► acrescenta ao segmento aberto (/config/dns-log/<1ª consulta ms>.crql)
       segmento: 1 h (ou max_age/4), ou 1/8 do teto; fdatasync a cada 60 s
       antes de gravar: teto e reserva livre da config (keep_free); senão, sai o segmento
       mais velho; sem espaço: descarta e conta
busca (ip.dns.log.search/export): cópia do índice sob o lock, leitura sem ele,
   até 8 blocos decodificados em paralelo, das mais novas para as mais antigas, com cursor
```

### Formato do arquivo

A especificação está em `crates/proto-dns/src/querylog/format.rs`.

- **Bloco.** Cabeçalho de 40 bytes:
  - magic `CRQL` e versão 1;
  - modo de anonimização e prefixos;
  - primeira e última consulta (unix ms);
  - quantidade de consultas e tamanhos;
  - CRC-32 do corpo.

  O corpo é deflate (RFC 1951). Nele, um nome ou um cliente é escrito por inteiro só na primeira
  vez em que aparece no bloco; depois vira um índice.
- **Índice.** São os próprios cabeçalhos: abrir um segmento lê 40 bytes por bloco.
- **Queda de energia.** Um bloco cortado ou com CRC errado encerra o arquivo ali, e o que veio
  antes continua legível.
- **Leitor.** Trata a entrada como hostil e nunca dá panic:
  - no máximo 2¹⁸ consultas por bloco;
  - corpo de até 16 MiB, antes e depois de comprimir;
  - o corpo descomprimido é lido até 1 byte além do anunciado, então nenhum tamanho do cabeçalho
    é tomado como verdade;
  - nomes de até 255 bytes, só ASCII imprimível.
- **Testes do leitor:** proptest (bytes hostis, blocos válidos com bytes trocados, com e sem o CRC
  refeito) e o alvo de fuzz `dns_query_log`, cujas sementes rodam em todo CI.

## Comandos

| Comando | O que faz |
|---|---|
| `ip.dns.log.set {enabled?, acknowledge?, client_address?, ipv4_prefix?, ipv6_prefix?, salt_rotation_hours?, max_size_mib?, max_age_hours?, exclude?, only_from?, except_from?}` | ajustes (journal) |
| `ip.dns.log.get` | ajustes, `writer` (arquivos, bytes, mais velha e mais nova, gravadas, descartadas, teto), `estimate` e `warnings` |
| `ip.dns.log.search {last_secs?, from?, to?, client?, name?, type?, rcode?, answered_by?, limit?, cursor?}` | uma página, das mais novas para as mais antigas, sem o lock do roteador; `next` continua |
| `ip.dns.log.export {format?: csv \| jsonl, …os mesmos filtros…, limit? ≤ 100 000}` | o texto; fica no journal |
| `ip.dns.log.clear {all? \| before? \| older_than_secs? \| client?}` | apaga e reescreve os segmentos (journal) |

No terminal, `/ip dns log print` mostra os ajustes (o `get`), como no RouterOS. A busca é
`search`, e não `print`, porque o `/export` monta o script a partir de todo `print`. O script leva
`/ip dns log set … acknowledge=marco-civil-art14` quando o log está ligado: importar liga de novo,
com a ciência que o operador deu, no journal de quem importou.

Filtros:

- **Cliente:** um endereço, uma rede ou `h:<hash>`. Um endereço acha a rede truncada que o contém.
- **Nome:** `*.example.com` acha o nome e tudo abaixo dele; outro texto acha os nomes que o
  contêm.

## Como testar

```sh
cargo run -p corerouter-daemon -- --config-dir /tmp/cr --control 7979 --dns-port 5353
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.set '{"allow_remote_requests":true,"servers":["1.1.1.1"]}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.log.set '{"enabled":true,"acknowledge":"marco-civil-art14"}'
dig @127.0.0.1 -p 5353 www.example.com           # várias; o bloco fecha em 10 s
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.log.search '{"limit":5}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.log.export '{"format":"csv","answered_by":"upstream"}'
corerouter-cli --connect 127.0.0.1:7979 run ip.dns.log.clear '{"client":"127.0.0.1"}'
cargo run -p corerouter-gui -- --connect 127.0.0.1:7979   # IP › DNS › Query Log
```

Testes:

- `cargo nextest run -p corerouter-proto-dns -p corerouter-engine -p corerouter-ui -E 'test(querylog) | test(dns_log) | test(dns_query_log)'`;
- `cargo test -p corerouter-daemon --bin corerouter-daemon dns_log`.

## Números

Todos **medidos**:

- **Máquina:** AMD Ryzen AI MAX+ 395, 32 threads, release, 2026-11-12, compartilhada com outras
  sessões (load 11–36).
- **Carga sintética:**
  - 200 mil nomes com Zipf s=1,0;
  - 4096 clientes (70 % CGNAT IPv4, 30 % IPv6);
  - A 45 %, AAAA 35 %, HTTPS 12 %;
  - 75 % de acerto no cache.

### Tamanho por consulta, por formato

Blocos de 65 536 consultas.

| Formato | Cru | deflate-1 | deflate-6 | zstd-fast (`ruzstd`) |
|---|---|---|---|---|
| texto (Unbound) | 85 B | 28,7 B | 21,7 B | 27,4 B |
| JSON (AdGuard) | 183 B | 33,4 B | 24,3 B | 33,6 B |
| **binário com tabelas por bloco** | **16,7 B** | **12,3 B** | 11,4 B | 13,9 B |

O deflate-1 do `miniz_oxide` (Rust puro, já no workspace) comprime melhor que o `ruzstd` no nível
"fastest" e custa metade. No laboratório (`dig` contra o daemon, nomes muito repetidos), o log
gravou **2,4–2,9 B por consulta**.

### Disco por dia e retenção

GB/dia = bytes por consulta × consultas/s × 86 400.

| Consultas/s | Binário deflate-1 | Texto cru | Retenção com 4 GiB |
|---|---|---|---|
| 100 | 0,11 GB | 0,74 GB | 40 dias |
| 1 000 | 1,06 GB | 7,4 GB | 4 dias |
| 20 000 | 21,3 GB | 147 GB | 4,9 h |
| 50 000 | 53,1 GB | 368 GB | 1,9 h |

Desgaste (**estimado**, com fator de escrita 1,2 para blocos sequenciais no ext4):

| Disco | Resistência | 20 mil/s | 50 mil/s |
|---|---|---|---|
| SSD TLC de 256 GB | ~150 TBW | ~16 anos | ~6,4 anos |
| eMMC de 8 GB | ~8–24 TB | 10 meses a 2,5 anos | 4–12 meses |

O texto cru a 50 mil/s gastaria um SSD de 256 GB em menos de um ano.

### Custo por consulta

Medido em `benches/querylog.rs` e `benches/statistics.rs`.

| Caso | Custo |
|---|---|
| Fila por consulta, `Mutex<Vec>`, 1 / 4 / 16 threads | 37 ns / 517 ns / **4,8 µs** |
| Fila por consulta, `sync_channel` com 16 threads | 4,5 µs |
| Buffer por thread e canal de buffers, 1 a 16 threads | **64–74 ns** por consulta |
| Escritor (decodificar, montar o bloco, deflate) | 11,4 ms por bloco de 65 536 = **174 ns por consulta**, ~5,7 milhões de consultas/s numa thread |

O servidor faz no máximo 1,12 milhão de consultas/s com 4 leitores (G3.9h): um escritor basta.

### Custo na cadeia real, contado em instruções

O tempo de parede não serviu: na máquina compartilhada, com load 11–36, o antes e depois alternado
de `benches/statistics.rs` variou ±30% entre rodadas, para os dois lados. A medida usada foram as
**instruções** contadas com `perf stat -e instructions:u`, exatas e iguais de uma execução para a
outra:

- laço fixo de consultas estáticas (o caminho mais barato da cadeia);
- perfil release do workspace (LTO thin, uma unidade de código);
- (5 milhões − 1 milhão) / 4 milhões, para tirar o custo de partida.

| Caso | Instruções por consulta | Diferença para a `main` |
|---|---|---|
| `main` | 14 011 | — |
| Branch, log desligado, `ip.dns_log` direto no `Ip` (primeira versão) | 14 314 | +303 (+2,2%) |
| Branch, log desligado, `ip.dns_log` num `CowArc` (versão final) | 14 058 | **+47 (+0,34%)** |

A primeira versão custava +2,2% com o log desligado. A bisseção achou a causa:

| Variante | Diferença para a `main` |
|---|---|
| uma etapa vazia na `main` | +7 |
| a branch sem a etapa | +31 |
| a branch com a etapa vazia | +244 |
| a branch com a etapa vazia, sem o campo `dns_log` no `Ip` | +18 |

O campo inline aumentava o `Ip` em ~100 bytes e, junto com a etapa a mais, mudava o código gerado
da cadeia. A glibc não era a causa: o resultado foi o mesmo com `tcache_count` 0 e 1000. A seção foi
para um `CowArc`, como `dns_static` e `dns_zones`.

Com o log **ligado**, mesmo laço, clientes CGNAT:

- a thread que responde faz +860 instruções por consulta (+5,6%): montar a entrada, um `Box`, e
  escrevê-la no buffer da faixa;
- o escritor, em outra thread, faz +1 300: decodificar, anonimizar, montar o bloco, deflate.

### Busca

Deflate-1, decodificando todas as consultas e filtrando por cliente: **12 milhões de consultas/s
com 1 thread e 77 milhões/s com 8**. Uma hora a 20 mil consultas/s (72 milhões) sai em ~1 s com 8
threads. Cada página olha no máximo 20 milhões de consultas (~1 s); acima disso volta `partial` e o
cursor continua.

## Desempenho e paralelismo

- **Trabalho por consulta:** um registro de ~40–60 B no buffer da própria faixa, O(1). Não cresce
  com o número de clientes nem com o tamanho do log.
- **Compartilhado:** só o canal limitado, com um `try_send` a cada ~300 consultas. Fila cheia:
  descarta e conta, nunca espera.
- **Escritor:** um só, a ~5,7 milhões de consultas/s, acima do máximo do servidor. Se virar
  gargalo, um escritor por leitor, cada um no seu segmento, e a busca intercala por tempo.
- **Busca:** até 8 blocos decodificados em paralelo (`thread::scope`, threads `dns-log-read`) e
  fora do lock do `Session`.
- **Clear:** reescreve fora do lock do escritor; só o segmento aberto é fechado antes.

## dnstap (parte 2)

O protobuf `dnstap.Dnstap` vai sobre Frame Streams:

- em socket unix ou TCP, handshake bidirecional: READY, ACCEPT, START e, no fim, STOP e FINISH;
- em arquivo, unidirecional: START, dados, STOP;
- content-type `protobuf:dnstap.Dnstap`.

Como vai ser feito:

- codificador próprio: o `dnstap.proto` é CC0, e o `prost` não está no `Cargo.lock`;
- o mesmo `Sink`, com um escritor por coletor que descarta e conta;
- a mesma anonimização;
- comandos `ip.dns.log.dnstap.*`;
- teste com o `dnstap` CLI ou o go-dnstap no laboratório.
