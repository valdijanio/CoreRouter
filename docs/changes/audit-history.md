id: audit-history
history: G0.20 criado (histórico em memória como diferenças: boot e RAM com config grande)

Histórico de revisões em disco como diferenças, não cópias inteiras (auditoria de 2026-10-23).

- **Só 6 das 64 revisões sobreviviam ao reboot com config de 5 MiB (3 com 10 MiB)** — severidade
  média (a running nunca se perdia; o `config.rollback` para trás depois de um reboot, sim).
  Causa: desde o G1.23 cada revisão é um arquivo `rev-<n>.json` com a config inteira, e a soma
  cabe em 32 MiB (`SAVE_BUDGET_BYTES`). Correção: o arquivo da revisão `k` guarda a diferença
  estrutural para a revisão `k+1` (delta reverso; `base` + `delta` no lugar de `config`); a mais
  nova não tem arquivo, o slot a guarda inteira. Módulo novo `model::json_delta` (objetos por
  chave, listas por `id` em trechos copiados + itens novos, listas sem id por prefixo/sufixo;
  `diff_text` compara os textos JSON que o commit já tem sem montar as árvores; `apply_owned`
  move as partes mantidas). `engine::history_files` grava a diferença do penúltimo no commit e
  percorre a cadeia do slot para trás no boot. Testes:
  `all_64_revisions_of_a_big_config_survive_a_reboot` (config de ~750 KB, 64 commits, reboot com
  as 64 iguais às da memória e rollback exato para a mais velha; na `main` falha com 19 revisões
  não salvas), `a_crash_between_the_steps_of_a_save_loses_only_that_revision` (storage que falha
  na gravação do arquivo de revisão, do slot ou na remoção: só a revisão em voo se perde, e os
  commits seguintes continuam), `a_broken_revision_file_costs_it_and_the_older_ones_only`,
  `a_difference_that_does_not_fit_its_base_is_refused` (trecho fora da lista, base errada, base
  mais velha, delta que não dá uma `Config`), `full_copy_revision_files_from_g1_23_load_and_become_differences`,
  `a_file_with_the_whole_history_from_an_older_build_loads_and_moves_to_files`,
  `a_revision_file_newer_than_the_slot_is_replaced`; em `json_delta`, proptest de ida e volta
  (`apply(diff(a, b)) == b`, `diff_text == diff`) e de lixo (`apply` nunca entra em pânico),
  entradas hostis (trecho fora, trechos sobrepostos, profundidade > 64) e a troca de um item numa
  lista de 65 536 em menos de 200 bytes.

Propriedades de segurança mantidas do G1.23: ordem arquivos novos → slot → apagar; arquivo da
revisão do slot ou mais novo é ignorado no boot e reescrito; `.tmp` limpo ao abrir; histórico
inteiro no slot (antes do G1.23) e arquivos com cópia inteira (G1.23) carregam e migram no próximo
commit. Muda: um arquivo ilegível no meio custa ele **e os mais velhos** (dependem dele), relatado
em `storage.boot_errors` como `revisions a..b: N left out`; o boot pelo slot `previous` não perde
nada. Uma versão anterior lendo o diretório novo (downgrade) carrega a running e acusa as revisões
antigas como ilegíveis. Escolha e números em `docs/architecture.md` (Persistência).

Como testar: `cargo test -p corerouter-engine --test history_files`; `cargo test -p
corerouter-model json_delta`; `cargo bench -p corerouter-storage-fs --bench commit -- history64`
(imprime quantas revisões o reboot restaura e os bytes em disco).

| G0.20 | Histórico em memória como diferenças | model, engine | Hoje a memória guarda 64 `Config` inteiras (64 × a config) e o boot monta as 64 a partir dos deltas (~1,2–1,5 s com 5–10 MiB, **medido**); guardar as revisões antigas como diferenças (as do disco) e montar a config só em `config.rollback`/`config.history.diff`; boot com 64 revisões de 10 MiB abaixo de 400 ms e RAM do histórico perto do tamanho dos deltas, com bench | 6 h | aberto |

## perf

### audit-history: histórico de 64 revisões com config grande (2026-10-23, **medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release, `cargo bench -p corerouter-storage-fs --bench
commit` (`storage_fs/history64/*`, novo): `FileStorage` em disco de verdade (fsync) sob o tmp do
target, 64 revisões, commit pequeno (`interface.set` comment). Config de 5 MiB = 4000 regras de
filtro, 20 000 entradas de address-list, 10 000 rotas, 10 000 leases estáticos; 10 MiB = 4000
regras, 65 536 entradas, 30 000 rotas. Antes = `main` (cópia inteira por revisão); depois =
diferença para a revisão seguinte.

| medida | 5 MiB antes | 5 MiB depois | 10 MiB antes | 10 MiB depois |
|---|---|---|---|---|
| revisões restauradas no reboot | 6 de 64 | 64 de 64 | 3 de 64 | 64 de 64 |
| bytes em disco (total) | 50,9 MiB | 20,4 MiB | 68,1 MiB | 38,9 MiB |
| bytes nos arquivos de revisão | ~30 MiB (6 cópias) | 0,01 MiB (63 deltas) | ~29 MiB (3 cópias) | 0,01 MiB |
| commit (mediana) | 39,8 ms | 47,4 ms (49,0 na 2ª rodada) | 70,1 ms | 85,8 ms (104,7, rodada ruidosa) |
| boot (`Session::with_storage`) | 265 ms | 1,46 s | 329 ms | 1,21 s |
| `storage_fs/commit/routes_history64/10000` | 11,6 ms | 15,5 ms | | |

O commit fica ~7–16 ms mais caro (comparar os textos das duas configs) e grava menos (2× a config
no slot, antes 3×). O boot cresce com o número de revisões montadas (~20 ms cada com 5 MiB):
restaura 64 em vez de 3–6; G0.20 trata disso.
