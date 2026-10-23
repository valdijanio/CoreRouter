# Desempenho e memória: números de referência

Resumo dos números **medidos** na auditoria de outubro de 2026 (`docs/audit-2026-10.md`), para
comparar versões futuras: se um número destes piorar, é regressão. O detalhe de cada medida
(comando do benchmark, base usada, ressalvas) está em `docs/perf.md`; esta página é o painel.

**Máquina:** AMD Ryzen AI MAX+ 395 (32 CPUs lógicas), 62 GiB, NVMe, Linux 7.0.0-38-generic.
**Build:** release, benchmarks criterion (`cargo xtask bench`). **Datas:** 2026-10-22/23.
"Antes" é a `main` imediatamente anterior a cada PR da auditoria; "depois" é o código com ele.

## Motor: commit, validação e comandos

| Medida | Benchmark | Antes | Depois | PR |
|---|---|---|---|---|
| Validar 3000 regras de firewall | `engine_scale/validate_all/filter_rules/3000` | 562 ms | 0,22 ms | #125 |
| Commit com 3000 regras de firewall | `engine_scale/commit/filter_rules/3000` | 584 ms | 2,07 ms | #125, #130 |
| Validar 10 000 rotas | `engine_scale/validate_all/routes/10000` | 48,2 ms | 1,21 ms | #125 |
| Commit com 10 000 rotas | `engine_scale/commit/routes/10000` | 380 ms | 6,29 ms | #130 |
| Commit com 10 000 endereços | `engine_scale/commit/addresses/10000` | 288 ms | 3,46 ms | #130 |
| Commit com 20 000 entradas de address-list | `engine_scale/commit/address_lists/20000` | 347 ms | 6,60 ms | #130 |
| Commit gravando no disco (fsync, 64 revisões, 10 000 rotas) | `storage_fs/commit/routes_history64/10000` | 396 ms | 11,0 ms | #130 |
| Listar 10 000 rotas | `engine_scale/ip.route.list/10000` | 64,6 ms | 14,0 ms | #125 |
| `ip.address.add` | `engine_execute/ip.address.add` | 29,6 µs | 19,9 µs | #130 |
| `ip.firewall.filter.add` | `engine_execute/ip.firewall.filter.add` | 38,0 µs | 26,8 µs | #130 |
| `ip.address.list` | `engine_execute/ip.address.list` | 1,39 µs | 0,223 µs | #130 |
| Parâmetro recusado | `engine_execute/rejected_param` | 1,21 µs | 0,815 µs | #130 |

## Import no daemon real (ponta a ponta, CLI)

| Import | Antes | Depois | PR |
|---|---|---|---|
| 20 000 entradas de address-list | 22,8 s | 0,54 s | #130, #131 |
| 10 000 rotas | 18,3 s | 0,17 s | #130, #131 |
| 4000 regras de filtro | 1,02 s | 0,06 s | #130, #131 |
| Commit com a config grande (p50 / máx.) | 110 / 297 ms | 36 / 55 ms | #130, #131 |

## Aplicação no kernel (netns)

| Medida | Benchmark | Antes | Depois | PR |
|---|---|---|---|---|
| Remover 1000 endereços | `hal_linux_apply/addresses_remove/1000` | 260 ms | 31,6 ms | #125 |

## DHCP

| Medida | Benchmark | Antes | Depois | PR |
|---|---|---|---|---|
| Rodada de tempestade (128 + 128, histórico, DNS, address-list) | `engine_dhcp_round/mem` | 220,7 ms | 14,1 ms | #124 |
| Idem, gravando no disco (fsync) | `engine_dhcp_round/fsync` | 844 ms | 8,1 ms | #124 |
| 1000 DISCOVER com o pool esgotado | `dhcp_attack/exhausted_pool_random_mac/16k` | 18,4 ms | 1,95 ms | #124 |
| 200 DORA com 65 536 concessões fixas | `dhcp_attack/statics_dora/65536` | 351 ms | 3,05 ms | #124 |
| 100 vinculações com o histórico no teto | `dhcp_attack/history_open_at_cap/500k` | 520 ms | 14,1 ms | #124 |
| 100 SOLICIT com o pool de PD (2^16) esgotado | `dhcp6_attack/solicit_pd_exhausted/65536` | 639 ms | 0,052 ms | #124 |

Tempo com o estado travado por rodada de tempestade: de 220–844 ms para 8–14 ms; o DHCP segura o
lock no máximo ~20 ms por rodada.

## DNS

| Medida | Benchmark | Antes | Depois | PR |
|---|---|---|---|---|
| Gravar no cache cheio (16 MiB) | `dns_cache_put_full` | 298,9 µs | 0,611 µs | #127 |
| Consulta fria com o cache cheio (8 MiB) | `dns_forward_cache_miss_full` | 151,2 µs | 3,89 µs | #127 |
| Consulta respondida pelo cache | `dns_forward_cache_hit` | 915 ns | 964 ns (ruído) | #127 |

## Canal de controle

| Medida | Benchmark | Antes | Depois | PR |
|---|---|---|---|---|
| `ping` por TCP | `control/tcp/ping` | 8,20 µs | 8,13 µs | #122 |
| `interface.list` por TLS | `control/tls/interface.list` | 55,3 µs | 51,0 µs | #122 |

Sob carga (`control_load/tcp/interface.list/N`, depois do #130):

| Conexões | Vazão | p50 | p99 |
|---|---|---|---|
| 1 | 17,6 mil/s | 51,6 µs | 113 µs |
| 4 | 61,5 mil/s | 62,6 µs | 106 µs |
| 16 (máximo) | 77,1 mil/s | 201 µs | 578 µs |

## Descoberta de vizinhos

| Medida | Benchmark | Antes | Depois | PR |
|---|---|---|---|---|
| Vizinho novo com a tabela cheia (4096) | `neighbors` | 121 µs | 0,84 µs | #126 |
| Refresh de vizinho conhecido | `neighbors` | 52 µs | 0,24 µs | #126 |

## GUI (um quadro)

| Quadro | Antes | Depois | PR |
|---|---|---|---|
| 10 000 endereços | 208 ms | 16,1 ms | #129 |
| 10 000 endereços, todos selecionados | 15,15 s | 28,0 ms | #129 |
| 5000 regras com sombreadas | 155 ms | 21,0 ms | #129 |
| Terminal com 5000 linhas | 8,47 ms | 0,090 ms | #129 |

## Memória do daemon

Daemon release com `--backend virtual`, carga acumulada passo a passo, memória residente (VmRSS,
`/proc/<pid>/status`). **Medido antes do #130**, que mudou o histórico de revisões (agora um
arquivo por revisão): os valores com histórico grande devem estar abaixo disto, a medir de novo.

| Estado (acumulado) | RSS | Pico |
|---|---|---|
| Ocioso | 10,8 MiB | |
| + 4000 regras de filtro | 47 MiB | |
| + 20 000 entradas de address-list | 137 MiB | |
| + 10 000 rotas | 150 MiB | 257 MiB |
| + 10 000 concessões DHCP fixas | 244 MiB | |
| + cache DNS com 50 000 nomes | 289 MiB | 354 MiB |

Memória por entrada no cache DNS (200 mil respostas A): **672 B** por entrada (a estimativa interna
dizia 352 B e foi corrigida no #127).

Tetos de memória que a auditoria pôs (entradas hostis não crescem sem limite): ofertas e
vinculações do DHCPv6 em 131 072 registros, ofertas somem após 120 s; histórico de concessões com
teto; cache DNS pelo orçamento em bytes configurado; tabela de vizinhos da descoberta em 4096.

## Como medir de novo

- Benchmarks: `cargo xtask bench` (todos) ou `cargo bench -p <crate> --bench <nome>`; para
  antes/depois, `--save-baseline antes` na `main` e `--baseline antes` na branch.
- Ponta a ponta e import: `apps/corerouter-daemon/tests/e2e.rs`.
- Novo número entra pela seção `## perf` do `docs/changes/<id>.md` do PR (vai para
  `docs/perf.md`); atualize esta página quando um número de referência mudar.
