id: audit-perf

Desempenho do caminho de commit e de `Session::execute`, e o canal de controle sob carga.
Resolve G1.23. Números na seção `## perf` (antes = `main` c5db148, mesma máquina).

Corrigido:

- **Alto — todo commit regravava o histórico inteiro** (G1.23). A gravação serializava a
  running e as até 64 revisões (até 32 MiB) e fazia fsync disso a cada comando: com 10 000 rotas
  um commit levava ~0,4 s. Agora o backend com arquivos de revisão (`FileStorage` e
  `MemoryStorage`, `ConfigStorage::revision_files`) guarda cada revisão num arquivo próprio
  (`rev-<n>.json`, `persist::encode_revision`), escrito uma vez pelo commit que a criou e
  apagado quando sai do histórico; o slot (`running.json`/`.prev`) guarda só a running e a
  revisão mais nova, no mesmo formato de antes (versões anteriores leem o arquivo, com
  histórico de uma entrada). O commit serializa a config uma vez (`persist::encode_config`, que
  também mede o limite de tamanho) e o texto é emendado no slot e no arquivo da revisão. Ordem
  da gravação: arquivos que faltam (temp + fsync + rename) → slot (como antes: temp, fsync,
  rotação, fsync do diretório, que torna os renames dos arquivos duráveis) → apagar os que saíram
  do histórico. Boot: os arquivos mais antigos que o slot completam o histórico; um ilegível ou
  com outro número custa só aquela revisão (`storage.boot_errors`); um mais novo que o slot
  (gravação interrompida, ou volta ao `previous`) é ignorado e reescrito pelo próximo commit;
  `rev-*.json.tmp` é apagado ao abrir. Arquivo de versão anterior (histórico inteiro no slot)
  carrega e migra no primeiro commit. O limite de 32 MiB vale para a soma dos arquivos de
  revisão. Testes `a_commit_writes_its_revision_not_the_whole_history` (o slot tinha 22 cópias
  da config, agora 2), `the_history_survives_a_reboot_and_old_files_are_deleted`,
  `an_unreadable_revision_file_costs_that_revision_only`,
  `a_file_with_the_whole_history_from_an_older_build_loads_and_moves_to_files`,
  `a_revision_file_newer_than_the_slot_is_replaced`, `safe_mode_saves_nothing_of_its_revisions`
  (`crates/engine/tests/history_files.rs`), `revisions_are_files_of_their_own` e
  `revision_names_are_strict` (storage-fs), `spliced_running_file_is_the_one_revision_file` e
  `revision_files_round_trip_and_are_checked` (model). Bench novo
  `storage_fs/commit/routes_history64/*` (arquivo de verdade, fsync, 64 revisões):
  396 → 11,0 ms com 10 000 rotas.
- **Médio — `/import` era quadrático** (achado nesta auditoria). Cada passo de um batch
  atômico copiava o candidate inteiro como ponto de rollback, mas um passo que falha desfaz o
  batch inteiro pela cópia do próprio batch. Dentro de um batch atômico os passos não copiam
  mais. Bench novo `engine_scale/import/address_lists/5000`: 423 → 61 ms.
- **Médio — consultas copiavam a config** (`store.candidate().clone()` em todo `execute`). Só
  comandos de ação (`journal`) copiam agora; teste `queries_leave_the_candidate_alone` roda toda
  consulta do registro sobre um candidate sujo e confere que nada muda.
- **Médio — `cmd::find` varria o registro duas vezes por `execute`** e `doc_keys` reanalisava o
  `params` em toda chamada. Índice por id (`OnceLock<HashMap>`, montado uma vez, com as chaves
  já analisadas); `execute` procura uma vez. `ip.address.list`: 1,39 µs → 0,22 µs.
- **Baixo — commit copiava a config duas vezes para o plano de dados** (`effective(..)
  .into_owned()` mesmo sem nada de DHCP para acrescentar): agora só copia quando o DHCP
  acrescenta algo.
- **Baixo — journal com `Vec::remove(0)`** a cada comando depois de 1024: agora apara em blocos
  de 256 (`journal()` continua mostrando as 1024 mais novas).

Verificado e mantido:

- `is_dirty` compara a config inteira (1,6 µs na config do lab, **medido**; O(config) com 10 000
  rotas) e `ConfigStore::commit` copia a candidate duas vezes; junto com o ponto de rollback por
  comando de ação é o que resta do custo por comando proporcional à config. Tirar isso pede
  `Arc`/cópia na escrita no `ConfigStore`: vira a gap G0.16.
- `engine_execute/virtual_lab_new` (3,42 µs na tabela; 8,0 µs na `main` → 7,4 µs): não é um bug, a `Config` do lab
  cresceu (clonar 1,1 µs, comparar 1,6 µs, aplicar no lab virtual 2,2 µs, **medido**), e o
  `ConfigStore::new` a copia duas vezes. Fica com a G0.16.
- `rejected_param` 1,21 → 0,81 µs com o índice; o resto é a sugestão "did you mean".
- Canal de controle sob carga (bench novo `control_load/tcp/interface.list/{1,4,16}`): escala de
  18 mil para 77 mil pedidos/s com 16 conexões; com 16 o p50 sobe para 0,2 ms porque cada
  `interface.list` passa ~9 µs com o lock da sessão (uma sessão, um lock, por desenho). Não há
  gargalo além desse. 32 conexões não cabem: `MAX_CONNECTIONS` = 16 por endpoint, de propósito.

| G0.16 | Comando sem cópia da config inteira | model (`store`), engine (`session.rs`) | Todo comando de ação clona a candidate (ponto de rollback), compara candidate × running (`is_dirty`, duas vezes num commit) e o commit a copia mais duas vezes (running e histórico): com 10 000 rotas um `interface.set` gasta ~6 ms nisso (**estimado** a partir de `engine_scale/commit/routes/10000` = 6,6 ms). Guardar running e revisões como `Arc<Config>` (revisão = contador de referência), marcar a candidate como tocada em `candidate_mut` e pular a comparação quando não foi; bench `engine_scale/commit/routes/10000` < 2 ms e `engine_execute/virtual_lab_new` < 5 µs | 6 h | aberto |

Como testar: `cargo test -p corerouter-engine --test history_files --test query_purity`,
`cargo test -p corerouter-storage-fs`, `cargo bench -p corerouter-storage-fs --bench commit`,
`cargo bench -p corerouter-engine --bench scale -- 'commit|import'`,
`cargo bench -p corerouter-control --bench load`.

## perf

### audit-perf — commit, execute e canal de controle sob carga

Máquina A: AMD Ryzen AI MAX+ 395 (32 CPUs lógicas), Linux 7.0.0-38-generic; build release
(bench); 2026-10-22. Todos **medidos**; antes = `main` c5db148 (mesmo bench, código da `main`).

| Benchmark | Antes | Depois |
|---|---|---|
| `storage_fs/commit/routes_history64/1000` (arquivo, fsync, 64 revisões) | 23,7 ms | 4,47 ms |
| `storage_fs/commit/routes_history64/10000` | 396 ms | 11,0 ms |
| `engine_scale/commit/filter_rules/3000` | 51,2 ms | 2,07 ms |
| `engine_scale/commit/routes/1000` | 17,6 ms | 0,65 ms |
| `engine_scale/commit/routes/10000` | 380 ms | 6,29 ms |
| `engine_scale/commit/addresses/10000` | 288 ms | 3,46 ms |
| `engine_scale/commit/address_lists/20000` | 347 ms | 6,60 ms |
| `engine_scale/import/address_lists/1000` (batch atômico) | 19,1 ms | 3,65 ms |
| `engine_scale/import/address_lists/5000` | 423 ms | 60,8 ms |
| `engine_execute/interface.list` | 10,3 µs | 8,15 µs |
| `engine_execute/ip.address.list` | 1,39 µs | 0,223 µs |
| `engine_execute/ip.address.add` | 29,6 µs | 19,9 µs |
| `engine_execute/ip.firewall.filter.add` | 38,0 µs | 26,8 µs |
| `engine_execute/rejected_param` | 1,21 µs | 0,815 µs |
| `engine_execute/virtual_lab_new` | 8,04 µs | 7,36 µs |

Canal de controle sob carga (`control_load/tcp/interface.list/N`, bench novo, TCP com token
local, N conexões pedindo sem parar; latência de cada pedido):

| Conexões | Vazão | p50 | p99 |
|---|---|---|---|
| 1 | 17,6 mil/s | 51,6 µs | 113 µs |
| 4 | 61,5 mil/s | 62,6 µs | 106 µs |
| 16 (`MAX_CONNECTIONS`) | 77,1 mil/s | 201 µs | 578 µs |

A vazão satura em ~77 mil pedidos/s (~13 µs cada, o tempo com o lock da sessão).
