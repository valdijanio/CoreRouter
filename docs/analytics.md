# Analytics: métricas, logs, fluxos e NAT no ClickHouse (G4.4f)

**Padrão do projeto para "onde guardar métricas e logs por muito tempo":** o roteador **não** roda
banco de dados. Ele guarda só o histórico curto que precisa para as próprias telas (Log, gráficos
locais da G4.5) e **envia**, em lotes, para um **ClickHouse externo** que o operador mantém num
servidor dele. Vários roteadores mandam para o mesmo ClickHouse; cada linha leva o id do roteador.
O Grafana (ou o futuro módulo de Métricas avançado, G4.4g) consulta o ClickHouse.

```text
roteador ──(HTTP/HTTPS, INSERT … FORMAT JSONEachRow, gzip, em lotes)──▶ ClickHouse ◀── Grafana
   │  fila em memória (e em disco, opcional): reenvio com espera crescente, descarte contado
   └─ nunca bloqueia: um ClickHouse lento ou fora do ar não atrasa nenhum comando nem pacote
```

## 1. Instalar um ClickHouse de referência

Num servidor da operadora (não no roteador). Qualquer versão recente serve; testado com a 26.9.

### Docker

```sh
docker run -d --name clickhouse --restart unless-stopped \
  --ulimit nofile=262144:262144 \
  -p 8123:8123 -p 8443:8443 \
  -e CLICKHOUSE_USER=admin -e CLICKHOUSE_PASSWORD='troque-esta-senha' \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  -v clickhouse-data:/var/lib/clickhouse -v clickhouse-logs:/var/log/clickhouse-server \
  -v "$PWD/schema.sql:/docker-entrypoint-initdb.d/schema.sql:ro" \
  clickhouse/clickhouse-server
```

- Sem `CLICKHOUSE_USER`/`CLICKHOUSE_PASSWORD` a imagem não deixa o usuário `default` entrar pela
  rede. Não use `CLICKHOUSE_SKIP_USER_SETUP=1`.
- O `schema.sql` (seção 2) montado em `/docker-entrypoint-initdb.d/` cria as tabelas na primeira
  partida.
- TLS na 8443: monte um `config.d/` com `https_port` e o certificado (seção 5).

### Pacote (Debian/Ubuntu)

```sh
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/clickhouse.list
sudo apt-get update && sudo apt-get install -y clickhouse-server clickhouse-client
sudo systemctl enable --now clickhouse-server
clickhouse-client --multiquery < schema.sql
```

Para RPM: `https://packages.clickhouse.com/rpm/clickhouse.repo`.

### Usuários: o roteador só insere, o Grafana só lê

```sql
CREATE USER router IDENTIFIED BY 'senha-do-roteador' HOST IP '192.0.2.0/24';
GRANT INSERT ON corerouter.* TO router;
GRANT SELECT(name, database) ON system.tables TO router;   -- para o "Test Connection"

CREATE USER grafana IDENTIFIED BY 'senha-do-grafana' SETTINGS readonly = 1;
GRANT SELECT ON corerouter.* TO grafana;
```

## 2. Esquema SQL

O mesmo texto sai do roteador: `system.analytics.schema` (com `database` e os dias de cada
tabela: `metrics_days`, `logs_days`, `flows_days`, `nat_events_days`) e a aba **Schema** da
janela System › Analytics. Um teste confere que o bloco abaixo é igual ao que o roteador gera.

- **MergeTree, uma partição por dia, ordenada por roteador e tempo**: consultas "deste roteador,
  neste intervalo" leem só as partes certas; apagar um dia antigo é jogar fora uma partição.
- **TTL** com `ttl_only_drop_parts = 1`: o ClickHouse apaga partições inteiras, sem reescrever
  dados. Padrões: métricas 395 dias (um ano para trás mais o mês de comparação), logs 90,
  fluxos 30 (a tabela mais pesada), eventos de NAT 400 (o Marco Civil da Internet, Lei
  12.965/2014 art. 13, pede um ano dos registros de conexão; a folga cobre atraso de envio).
- **`non_replicated_deduplication_window`**: cada lote vai com um `insert_deduplication_token`;
  se a resposta de um INSERT se perde e o roteador reenvia, o ClickHouse reconhece o lote e não o
  grava duas vezes (o padrão do MergeTree sem réplica é não deduplicar).
- **`metrics`** é ordenada por `(router, name, time)`: a consulta típica é "esta métrica deste
  roteador ao longo do tempo".
- Endereços em colunas `IPv6`, com IPv4 mapeado (`::ffff:100.64.0.9`), como o Akvorado: uma
  coluna para as duas famílias.
- **`otel_logs`** é uma view com os nomes do modelo de logs do OpenTelemetry (`Timestamp`,
  `SeverityText`, `SeverityNumber`, `Body`, `ResourceAttributes`, `LogAttributes`), para os
  exploradores de log do Grafana e do ClickStack lerem sem configuração.

```sql
-- CoreRouter analytics (G4.4f): one database for every router.
CREATE DATABASE IF NOT EXISTS corerouter;

CREATE TABLE IF NOT EXISTS corerouter.metrics
(
    router  LowCardinality(String),
    time    DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    name    LowCardinality(String),
    labels  Map(LowCardinality(String), String),
    value   Float64 CODEC(Gorilla, ZSTD)
)
ENGINE = MergeTree
PARTITION BY toDate(time)
ORDER BY (router, name, time)
TTL toDateTime(time) + INTERVAL 395 DAY
SETTINGS ttl_only_drop_parts = 1, non_replicated_deduplication_window = 1000;

CREATE TABLE IF NOT EXISTS corerouter.logs
(
    router           LowCardinality(String),
    time             DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    seq              UInt64,
    severity         LowCardinality(String),
    severity_number  UInt8,
    priority         UInt8,
    topic            LowCardinality(String),
    topics           Array(LowCardinality(String)),
    origin           String,
    message          String CODEC(ZSTD),
    detail           String CODEC(ZSTD)
)
ENGINE = MergeTree
PARTITION BY toDate(time)
ORDER BY (router, time)
TTL toDateTime(time) + INTERVAL 90 DAY
SETTINGS ttl_only_drop_parts = 1, non_replicated_deduplication_window = 1000;

CREATE TABLE IF NOT EXISTS corerouter.flows
(
    router         LowCardinality(String),
    time           DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    time_start     DateTime64(3, 'UTC'),
    src_addr       IPv6,
    dst_addr       IPv6,
    src_port       UInt16,
    dst_port       UInt16,
    proto          UInt8,
    in_if          LowCardinality(String),
    out_if         LowCardinality(String),
    bytes          UInt64,
    packets        UInt64,
    tcp_flags      UInt8,
    sampling_rate  UInt32,
    nat_src_addr   IPv6,
    nat_src_port   UInt16
)
ENGINE = MergeTree
PARTITION BY toDate(time)
ORDER BY (router, time)
TTL toDateTime(time) + INTERVAL 30 DAY
SETTINGS ttl_only_drop_parts = 1, non_replicated_deduplication_window = 1000;

CREATE TABLE IF NOT EXISTS corerouter.nat_events
(
    router      LowCardinality(String),
    time        DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    event       LowCardinality(String),
    proto       UInt8,
    src_addr    IPv6,
    src_port    UInt16,
    nat_addr    IPv6,
    nat_port    UInt16,
    dst_addr    IPv6,
    dst_port    UInt16,
    port_start  UInt16,
    port_end    UInt16
)
ENGINE = MergeTree
PARTITION BY toDate(time)
ORDER BY (router, time)
TTL toDateTime(time) + INTERVAL 400 DAY
SETTINGS ttl_only_drop_parts = 1, non_replicated_deduplication_window = 1000;

CREATE VIEW IF NOT EXISTS corerouter.otel_logs AS
SELECT
    time                                   AS Timestamp,
    severity                               AS SeverityText,
    severity_number                        AS SeverityNumber,
    'corerouter'                           AS ServiceName,
    message                                AS Body,
    map('host.name', router)               AS ResourceAttributes,
    map('log.topic', topic, 'log.origin', origin, 'log.detail', detail) AS LogAttributes
FROM corerouter.logs;
```

### O que vai em cada tabela

| Tabela | Fonte hoje | Uma linha por |
|---|---|---|
| `metrics` | os contadores do `/metrics` (interfaces, comandos, commits, serviços, DHCP, Safe Mode…) a cada `metrics_interval`; e o histórico de tráfego local (G4.5, System › Graphing): a média e o máximo de cada minuto de `corerouter_system_{cpu,memory,conntrack}` e `corerouter_interface_{rx,tx}_{bps,pps}`, `…_errors`, `…_drops` (rótulo `interface`), sufixo `_max` para o máximo | amostra (nome + rótulos + valor) |
| `logs` | eventos do log do roteador (G4.6d) que uma regra manda para a ação `analytics` | evento |
| `flows` | Traffic Flow (G4.4b, IP › Traffic Flow ligado): os mesmos registros que ele manda por IPFIX; interfaces por nome | fluxo terminado |
| `nat_events` | blocos de portas do CGNAT no modo `blocks` (G2.3c, lidos do log): `block_alloc`/`block_release`; sessões NAT44 do Traffic Flow com eventos de NAT ligados: `session_create`/`session_delete` (RFC 8158 natEvent 4/5) | evento |

`logs`: `severity` é o nível do RouterOS (`debug`, `info`, `warning`, `error`, `critical`);
`severity_number` é o do OpenTelemetry (5, 9, 13, 17, 21); `priority` é a severidade do syslog
(RFC 5424: 7, 6, 4, 3, 2); `topic` é o primeiro tópico que não é nível; `detail` é o JSON
técnico do evento (comando, parâmetros com segredos mascarados, resultado), cortado em 4 KiB.

## 3. Configurar o roteador

Na GUI: **System › Analytics**. Pelo terminal ou MCP:

```sh
corerouter-cli run system.analytics.set '{"enabled": true, "url": "https://ch.isp.example:8443",
  "user": "router", "password": "senha-do-roteador", "router_id": "pop-centro-1"}'
# logs: regras que mandam eventos para a ação embutida "analytics"
corerouter-cli run system.logging.add '{"topics": ["info"], "action": "analytics"}'
corerouter-cli run system.logging.add '{"topics": ["warning"], "action": "analytics"}'
corerouter-cli run system.logging.add '{"topics": ["error"], "action": "analytics"}'
corerouter-cli run system.logging.add '{"topics": ["critical"], "action": "analytics"}'
corerouter-cli run system.analytics.test '{}'     # versão do servidor e tabelas que faltam
corerouter-cli run system.analytics.print '{}'    # estado, enviados, na fila, descartados, último erro
```

| Parâmetro | Padrão | O quê |
|---|---|---|
| `enabled` | `no` | liga a exportação (precisa de `url`) |
| `url` | — | `http(s)://servidor[:porta]` da interface HTTP (8123; 8443 com TLS) |
| `database` | `corerouter` | o banco das tabelas |
| `user`, `password` | `default`, — | login; a senha vai no cabeçalho `X-ClickHouse-Key`, nunca na URL |
| `certificate`, `private_key` | — | login por certificado (PEM; seção 5) |
| `ca_certificate`, `tls_verify` | —, `yes` | CA própria do servidor (vazio: raízes públicas); `no` cifra sem conferir |
| `router_id` | identidade | a coluna `router` |
| `metrics`, `logs`, `flows`, `nat_events` | `yes` | o que enviar |
| `metrics_interval` | 60 s | entre duas amostras de métricas (10–3600) |
| `batch_size` | 10 000 | linhas por INSERT, no máximo (100–1 000 000) |
| `flush_interval` | 10 s | quanto uma linha espera o lote encher (1–3600) |
| `queue_size` | 16 MiB | fila em memória (1–1024) |
| `disk_queue` | 0 | MiB em disco além da memória; precisa de `--analytics-spool <dir>` no daemon |
| `compression` | `gzip` | `gzip` ou `none` |

Os segredos (`password`, `private_key`) nunca voltam: `print` mostra `***`, o diário e o log
mostram `***`, e abaixo do grupo `full` nem o `inspect_state` os mostra.

## 4. Como o envio funciona

- **Lotes:** uma linha espera até o lote da sua tabela ter `batch_size` linhas ou `flush_interval`
  segundos; o lote é comprimido (gzip nível 1) ao fechar e guardado assim na fila. O ClickHouse
  recomenda pelo menos ~1000 linhas por INSERT e cerca de um INSERT por segundo; muitos INSERTs
  pequenos geram o erro *too many parts*. O roteador não usa `async_insert` (ele mesmo agrupa) e o
  manda desligado em cada pedido, assim como `wait_end_of_query=1`,
  `input_format_skip_unknown_fields=1` e `date_time_input_format=basic`: os padrões do servidor
  mudaram entre versões e o resultado não pode depender deles.
- **Resposta do servidor** (como fazem o Vector e o Fluent Bit):

  | Resposta | O que o roteador faz |
  |---|---|
  | 2xx | enviado |
  | 401, 403, 404 (senha, banco ou tabela faltando) | guarda e tenta de novo: o conserto do operador (senha, esquema) deixa passar |
  | 408, 429, 5xx (sobrecarga, *too many parts*), erro de rede | guarda e tenta de novo |
  | 400 e outros 4xx (linha que o servidor não aceita) | descarta o lote e conta: um lote ruim não trava a fila para sempre |

- **Reenvio:** a espera dobra a cada falha, de 1 s até 60 s, com 75–100 % de sorteio (roteadores
  que perderam o mesmo servidor não voltam todos juntos). O mesmo lote vai com o mesmo
  `insert_deduplication_token`.
- **Fila cheia:** quando a memória (`queue_size`) enche, o lote mais antigo vai para o disco (com
  `disk_queue` e `--analytics-spool`) ou é **descartado e contado** (`dropped_rows`, por tabela).
  Os mais novos ficam (como o `storage.total_limit_size` do Fluent Bit): depois de uma queda, o
  dado recente é o mais útil. O disco também tem teto; cheio, descarta o lote mais antigo dele. Nada
  disso bloqueia o roteador.
- **Disco:** os lotes no disco (`<dir>/<seq>-<id>-<tabela>-<linhas>-<compressão>.batch`, pasta
  0700) sobrevivem a um reinício do daemon e são enviados primeiro, na ordem. Ao parar, o daemon
  grava no disco o que estava na memória. Em flash, mantenha o `disk_queue` pequeno.
- **O log do roteador** guarda uma janela dos eventos recentes (1024); se mais do que isso
  acontecer entre duas leituras (a cada 250 ms), a diferença é contada como descartada, não
  escondida.

## 5. TLS e login por certificado

`https://` usa o rustls do projeto (sem OpenSSL). Para um servidor com CA própria, cole a CA em
`ca_certificate`. Para entrar por certificado em vez de senha:

```sql
CREATE USER router1 IDENTIFIED WITH ssl_certificate CN 'router1';
GRANT INSERT ON corerouter.* TO router1;
```

No servidor, `config.d/tls.xml` com `https_port` 8443, o certificado e, para pedir certificado do
cliente, `<verificationMode>relaxed</verificationMode>` e `<caConfig>` com a CA dos roteadores.
No roteador: `certificate` e `private_key` (PEM, X.509 v3) com `user` = `router1`; o roteador manda
`X-ClickHouse-SSL-Certificate-Auth: on`.

## 6. Consultar

```sql
-- Erros e avisos das últimas 24 h, por roteador
SELECT router, severity, count() FROM corerouter.logs
WHERE time > now() - INTERVAL 1 DAY AND severity_number >= 13
GROUP BY router, severity ORDER BY count() DESC;

-- Tráfego por interface em Mbit/s, média de cada minuto (histórico G4.5)
SELECT router, labels['interface'] AS iface, time, value / 1e6 AS mbps
FROM corerouter.metrics
WHERE name = 'corerouter_interface_rx_bps' AND time > now() - INTERVAL 1 DAY
ORDER BY time;

-- O mesmo a partir do contador do /metrics, de 5 em 5 minutos (contador → taxa)
SELECT router, labels['interface'] AS iface, toStartOfFiveMinutes(time) AS t,
       (max(value) - min(value)) * 8 / 300 / 1e6 AS mbps
FROM corerouter.metrics
WHERE name = 'corerouter_interface_receive_bytes_total' AND time > now() - INTERVAL 1 DAY
GROUP BY router, iface, t ORDER BY t;

-- Quem tinha 203.0.113.5:40312 às 14:02 de 3 de maio (CGNAT em blocos)
SELECT router, IPv6NumToString(src_addr) AS assinante, port_start, port_end, time, event
FROM corerouter.nat_events
WHERE nat_addr = toIPv6('::ffff:203.0.113.5') AND 40312 BETWEEN port_start AND port_end
  AND time <= '2027-05-03 14:02:00'
ORDER BY time DESC LIMIT 1;
```

(Na última, confira que o evento achado é `block_alloc`: um `block_release` antes do instante quer
dizer que o bloco já estava livre.)

## 7. Grafana

1. Instale o plugin oficial **ClickHouse** (`grafana-clickhouse-datasource`).
2. Fonte de dados: servidor do ClickHouse, protocolo **HTTP** (porta 8123, ou 8443 com TLS) ou
   nativo (9000/9440), usuário `grafana` (só leitura).
3. Painel de série temporal:

   ```sql
   SELECT $__timeInterval(time) AS t, labels['interface'] AS iface,
          (max(value) - min(value)) * 8 / $__interval_s AS bps
   FROM corerouter.metrics
   WHERE $__timeFilter(time) AND router = '${router}'
     AND name = 'corerouter_interface_receive_bytes_total'
   GROUP BY t, iface ORDER BY t
   ```

4. Logs: o explorador de logs do plugin reconhece a view `otel_logs`; ou um painel *Logs* com
   `SELECT time, severity, message FROM corerouter.logs WHERE $__timeFilter(time) ORDER BY time DESC`.
5. Variável `router`: `SELECT DISTINCT router FROM corerouter.logs`.

## 8. Testar com um ClickHouse de verdade

Os testes do exportador rodam sempre contra um servidor HTTP falso em Rust que confere o INSERT
(formato, cabeçalhos, gzip, token, reenvio, descarte). Contra um ClickHouse de verdade, sem root,
num diretório qualquer e numa porta alta:

```sh
mkdir -p /tmp/ch && cd /tmp/ch
cat > config.xml <<'EOF'
<clickhouse>
  <logger><level>warning</level><log>/tmp/ch/server.log</log><errorlog>/tmp/ch/err.log</errorlog></logger>
  <http_port>18123</http_port><tcp_port>19000</tcp_port><listen_host>127.0.0.1</listen_host>
  <path>/tmp/ch/data/</path><tmp_path>/tmp/ch/tmp/</tmp_path><user_files_path>/tmp/ch/files/</user_files_path>
  <users><default><password></password><networks><ip>127.0.0.1</ip></networks>
    <profile>default</profile><quota>default</quota><access_management>1</access_management></default></users>
  <profiles><default/></profiles><quotas><default/></quotas>
</clickhouse>
EOF
clickhouse server --config-file=/tmp/ch/config.xml &
COREROUTER_CLICKHOUSE_URL=http://127.0.0.1:18123 \
  cargo test -p corerouter-daemon --bin corerouter-daemon real_clickhouse
```

O teste cria um banco `corerouter_test_<pid>` com o esquema, envia logs, métricas, um fluxo e um
evento de NAT pelo exportador, confere as linhas (e a view `otel_logs`) e apaga o banco. O teste de
TLS e login por certificado usa `COREROUTER_CLICKHOUSE_TLS_URL`, `COREROUTER_CLICKHOUSE_CA`,
`_CERT`, `_KEY` e `_CERT_USER` (um servidor com `https_port` e um usuário `ssl_certificates`,
seção 5). A bateria de desempenho: `cargo test --release -p corerouter-daemon --bin
corerouter-daemon bench_analytics -- --ignored --nocapture`.

## 9. Desempenho

Resumo (**medido**, release, detalhes no `docs/perf.md`, G4.4f): ~510 000 linhas de log/s
codificadas e comprimidas num núcleo (≈ 1,9 µs de CPU por linha), ~665 000 linhas/s aceitas pelo
ClickHouse em lotes de 10 000; com o servidor fora do ar 10 minutos a 31 linhas/s, a fila guardou
19 000 linhas em 347 KB, nada se perdeu nem duplicou, e tudo foi enviado no primeiro reenvio
depois da volta (no máximo 60 s de espera).

## Pesquisa

Fontes consultadas (outubro de 2026):

- ClickHouse: [interface HTTP](https://clickhouse.com/docs/interfaces/http) (cabeçalhos
  `X-ClickHouse-User`/`-Key`, `Content-Encoding` do corpo, `X-ClickHouse-Exception-Code`,
  `wait_end_of_query`); [inserts em lote](https://clickhouse.com/docs/optimize/bulk-inserts) e
  [assíncronos](https://clickhouse.com/docs/optimize/asynchronous-inserts);
  [deduplicação em reenvios](https://clickhouse.com/docs/guides/developer/deduplicating-inserts-on-retries);
  [MergeTree, TTL e partições](https://clickhouse.com/docs/engines/table-engines/mergetree-family/mergetree);
  [codecs](https://clickhouse.com/docs/reference/statements/create/table/codec);
  [too many parts](https://clickhouse.com/docs/knowledgebase/exception-too-many-parts);
  [login por certificado](https://clickhouse.com/docs/guides/sre/ssl-user-auth);
  [esquema para observabilidade](https://clickhouse.com/docs/use-cases/observability/schema-design)
  e [ClickStack](https://clickhouse.com/docs/clickstack/ingesting-data/schemas);
  [códigos de erro → HTTP](https://github.com/ClickHouse/ClickHouse/blob/master/src/Server/HTTP/exceptionCodeToHTTPStatus.cpp).
- [Vector, sink clickhouse](https://vector.dev/docs/reference/configuration/sinks/clickhouse/):
  JSONEachRow, gzip por padrão, lote por bytes ou tempo, reenvio de 408/429/5xx, buffer em memória
  ou disco com `when_full`.
- Fluent Bit: [saída http](https://docs.fluentbit.io/manual/pipeline/outputs/http) com
  JSONEachRow, [reenvios](https://docs.fluentbit.io/manual/administration/scheduling-and-retries)
  e [buffer em disco](https://docs.fluentbit.io/manual/administration/buffering-and-storage)
  (`storage.total_limit_size` descarta os mais antigos).
- OpenTelemetry: [exportador ClickHouse do Collector](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/clickhouseexporter)
  (tabela `otel_logs`) e o [modelo de dados de logs](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
  (números de severidade).
- [Akvorado](https://github.com/akvorado/akvorado): fluxos no ClickHouse, endereços em `IPv6`,
  `SamplingRate`, colunas de NAT, tabelas agregadas (`flows_1m0s`, `flows_5m0s`, `flows_1h0m0s`)
  por views materializadas.
- [RFC 8158](https://www.rfc-editor.org/rfc/rfc8158.html): elementos IPFIX de log de NAT
  (`natEvent` 16/17 para alocação e liberação de bloco de portas).
- [Imagem Docker](https://hub.docker.com/r/clickhouse/clickhouse-server),
  [pacotes](https://clickhouse.com/docs/install/debian_ubuntu) e
  [Grafana](https://grafana.com/docs/plugins/grafana-clickhouse-datasource/latest/configure/).

**O MikroTik** não tem exportador para banco de dados: o RouterOS manda syslog (`/system logging
action target=remote`) e fluxos (`/ip traffic-flow`, NetFlow/IPFIX), e as métricas saem por SNMP,
pelo `/tool graphing` (guardado no próprio roteador) ou pelo The Dude. O que fazem os outros: o VyOS e o OPNsense
exportam por agentes (Telegraf, node_exporter), o Junos e o SR Linux por telemetria gNMI para um
coletor; quem guarda no ClickHouse é sempre um coletor à parte (Vector, Fluent Bit, OTel
Collector, Akvorado). **Adotamos** o que esses coletores fazem bem, dentro do roteador e sem
processo extra: JSONEachRow com gzip, lotes grandes, reenvio com espera crescente e sorteio, a
mesma classificação de respostas, fila com teto e descarte contado, disco opcional, token de
deduplicação (que eles não usam por padrão) e um esquema com nomes do OpenTelemetry na view.

Os fluxos e as sessões de NAT vêm do serviço do Traffic Flow (G4.4b), que entrega ao exportador os
mesmos registros que manda por IPFIX (`submit_records`); os blocos de portas, só pelo log, para
não chegarem duas vezes.

**Ficou de fora, como gaps:** a janela de Métricas avançado que consulta o ClickHouse (G4.4g); a
política por tabela quando a fila enche (bloquear para NAT, descartar o mais antigo para métricas)
e as tabelas agregadas por views materializadas, como o Akvorado (G4.4h); `RowBinary`/`ArrowStream`
só se o JSONEachRow virar gargalo (os números da seção 9 dizem que não).
