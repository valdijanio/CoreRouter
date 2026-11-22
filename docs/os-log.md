# OS Log — o log do sistema operacional (G4.8b)

A janela System › OS Log (e a aba OS Log de System › Resources, G4.8a) mostra o que o **Linux**
debaixo do roteador escreve: kernel (drivers de placa, pilha de rede, memória, discos), serviços e
logins. É diferente do **Log** do roteador (`log.print`, G4.6d), que é o que o próprio CoreRouter
fez.

## Como funciona

```text
/dev/kmsg ─┐  (non-blocking, 1 s)        ┌─ OsLogBook (engine, ext do Session)
           ├─ serviço os-log do daemon ──┤   anel de 20 000 linhas, repetições dobradas,
journalctl ┘  (cursor, 2 s, sem shell)   │   contagem por nível, estado das fontes
                                          └─ log.os.print {since, level, source, find, limit}
                                               └─ GUI (os_log.rs), CLI, MCP
```

- **Fontes** (`crates/hal-linux/src/oslog.rs`): `/dev/kmsg` lido direto (um `read` = um registro,
  `EAGAIN` = nada novo, `EPIPE` = o anel sobrescreveu, contado em `lost`); o journal do systemd
  por `journalctl -o json --output-fields=… --after-cursor=…` (primeira vez `-n 500`), sem shell,
  com teto de linhas e bytes, prazo de 5 s, o processo num grupo próprio, morto e colhido sempre.
  Com kmsg legível, as linhas `_TRANSPORT=kernel` do journal são puladas (senão viriam em dobro).
  Fonte que não dá para ler diz por quê (`unavailable: … dmesg_restrict … CAP_SYSLOG`,
  `journalctl not found`, `insufficient permissions`).
- **Hora das linhas do kernel:** hora do boot (relógio de parede menos `CLOCK_BOOTTIME`) mais o
  tempo do registro. **Medido** neste laptop com 11 dias ligado e várias suspensões: kmsg
  973 250 s, BOOTTIME 973 236 s, MONOTONIC 617 565 s — com MONOTONIC as linhas ficavam 4 dias no
  futuro. O teste `kmsg_reads_records_from_the_device` pega essa regressão.
- **Parsers** (`crates/hal/src/oslog.rs`, puros, também no WASM): entrada hostil — teto de 16 KiB
  por registro, mensagem cortada em 2048 caracteres, sem controle nem bidi, `\xNN` do kernel
  desfeito, UTF-8 inválido trocado, cursor só ASCII visível ≤ 512. Fixtures **sintéticas** no formato
  real (`crates/hal/tests/fixtures/oslog/`: campos do journal JSON, registros do kmsg com
  dicionário, linhas estranhas e truncadas), sem nenhum dado de máquina de verdade; um teste
  `#[ignore]` (`real_journal_parses`) lê o journal da máquina local à mão, fora do CI,
  proptest e o alvo de fuzz `oslog`.
- **Repetições** (`crates/engine/src/oslog.rs`): a chave é origem + unidade + severidade + a
  mensagem sem os números (um número que começa um token vira `#`; dentro de um nome fica:
  `ether1` ≠ `ether2`, `rx_missed 12` = `rx_missed 13`). Igual a uma dos últimos 10 min: a linha
  conta mais uma, guarda o texto mais novo e a hora mais antiga, e vai para o fim.
- **Catálogo** (`crates/engine/src/oslog_known.rs`): dados, não código — palavras (`all`, `any`),
  título, "O que significa" em português e ações (janela da GUI + o comando por trás). 16
  entradas: anel da placa cheio, placa parou de transmitir, LACP sem parceiro, link caiu/subiu,
  conntrack cheio, tabela de vizinhos cheia, SYN flood, martian, OOM, erro de disco, MCE, CPU
  quente, lockup/hung task, segfault, login recusado, "callbacks suppressed". As que custam
  tráfego ou hardware (`alert`) vão uma vez por linha nova (não por repetição, nem do backlog
  com mais de 5 min) para o Log do roteador como `system,error`/`system,warning`, onde as regras de
  `/system logging` (syslog remoto) as pegam.
- **Laboratório:** `Hal::os_log` (padrão: nenhum) dá as linhas inventadas do lab virtual; o
  daemon com `--backend virtual` deixa o lab responder (`--os-log host` lê a máquina de verdade,
  só leitura); com `--backend linux` o padrão é `host`.

## Pesquisa

Fontes (2026-10-24; "lida" = aberta e conferida nesta rodada):

- **MikroTik RouterOS v7, `/log` e `/system logging`**
  (https://help.mikrotik.com/docs/spaces/ROS/pages/328094/Log, lida): cada linha tem tópicos
  (`dhcp`, `firewall`, `system`…) e os tópicos genéricos `info`, `debug`, `warning`, `error`,
  `critical` fazem o papel de nível; `/log print where topics~…`, `follow`, buffers em memória,
  disco, e-mail e syslog remoto (severidade da RFC 3164 só no envio). A página não trata de
  repetições nem de explicação, e o log do kernel do Linux do RouterOS não é exposto (só a
  facilidade `kern` do syslog remoto). É o ponto onde dá para ser melhor.
- **RFC 5424 §6.2.1** (https://www.rfc-editor.org/rfc/rfc5424#section-6.2.1): as oito
  severidades 0–7 (a errata em rfc-editor.org/errata não foi relida nesta rodada; a tabela é a
  mesma da RFC 3164). O kernel e o syslog usam os mesmos números (`LOG_EMERG`…`LOG_DEBUG`), e o
  `log.os.print {level}` aceita os nomes da RFC e os curtos do syslog (`err`, `crit`, `emerg`).
- **Kernel, `Documentation/ABI/testing/dev-kmsg`**
  (https://www.kernel.org/doc/Documentation/ABI/testing/dev-kmsg, lida): cabeçalho
  `prioridade,seq,usec,flag` separado por vírgulas, `;` e o texto; linhas que começam com espaço
  são `KEY=valor` (`SUBSYSTEM=`, `DEVICE=`); bytes não imprimíveis e a própria `\` em `\xNN`;
  `read()` dá `EPIPE` quando registros foram sobrescritos e a posição pula para o próximo. O
  documento chama o tempo de "monotonic"; na prática (medido abaixo) ele segue `CLOCK_BOOTTIME`.
  `kernel.dmesg_restrict` e `CAP_SYSLOG`: `Documentation/admin-guide/sysctl/kernel.rst`.
- **systemd, formatos de exportação do journal** (https://systemd.io/JOURNAL_EXPORT_FORMATS/,
  `journalctl(1)`): JSON uma entrada por linha; campo não UTF-8 vem como lista de bytes; campo
  repetido vem como lista; `__CURSOR`, `__REALTIME_TIMESTAMP`, `--after-cursor`,
  `--output-fields`.
- **Cockpit, página Logs** (https://cockpit-project.org/guide/latest/api-logs-html e as notas
  das versões 219 e 222, lidas): filtro de prioridade (padrão `err`, `*` = todas), filtro por
  unidade (`service=sshd`), `since:` e `boot:` para intervalo de tempo e boot anterior, botão de
  pausa, detalhe da entrada. Adotado: filtro por prioridade, busca, pausa, detalhe com unidade e
  boot; intervalo de tempo virou gap (G4.8bc).
- **Juniper Junos, `show log messages`** (pelo conhecimento do comportamento, link não relido nesta rodada) (https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-log.html):
  `| match`, `| last N`, e o "last message repeated N times" do syslog. Adotado: a repetição
  contada, mas numa linha só (com primeira e última hora) em vez de uma linha extra.
- **OPNsense/pfSense** (pelo conhecimento, não relido: System › Log Files › General/Kernel, filtro de texto e de nível) e
  **VyOS** (`show log kernel`, `show log tail`): o log do sistema separado do de firewall;
  nenhum explica a mensagem.

O que adotamos e o que propomos além:

- Níveis da RFC 5424 em três selos (error 0–3, warning 4, info 5–7) com contagem, origem em
  selos (kernel, services, auth), busca por texto/unidade/dispositivo/PID.
- **Repetições numa linha só** com "repetido 37× em 9 min" (nenhum dos outros dobra por padrão).
- **Mensagens conhecidas com "O que significa" e botão para a janela que resolve** — Tuning da
  porta (anel/IRQ), gráfico, Interfaces, Services, Firewall, Resources. Ninguém faz isso; é o
  que o operador de ISP vindo do MikroTik mais sente falta quando o kernel reclama.
- Alerta no Log do roteador (e daí no syslog remoto) para as que custam tráfego/hardware.
- Fonte indisponível diz por quê, em vez de lista vazia.
- Fica de fora (gaps): leitor de journal em Rust puro (G4.8ba), saída de processos externos
  supervisionados (G4.8bb), filtro por intervalo de tempo e exportação (G4.8bc), explicações do
  catálogo em inglês (G4.8bd).

## Desempenho (**medido**, 2026-10-24, AMD Ryzen AI Max+ 395, Linux 7.0)

| O quê | Resultado |
|---|---|
| Anel do engine: 100 000 linhas (metade repetida) | 339 ns/linha (release); `since` de 500 linhas: 1,5 µs |
| GUI: 100 000 linhas em respostas de 2000, 20 000 guardadas | 1,4 s para tomar tudo (debug); **2,6 ms por quadro** (debug, virtualizado); refiltrar 20 000: 14 ms (debug, só quando filtro ou linhas mudam) |
| `journalctl --after-cursor` (journal de 2,0 GB) | ≤ 10 ms por chamada, a cada 2 s; backfill de 500 linhas: 60 ms; pico de RSS do processo 46 MB |
