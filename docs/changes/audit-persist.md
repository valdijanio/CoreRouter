id: audit-persist

Auditoria do núcleo do engine (persistência, Safe Mode, transações, journal, import, script do
terminal). Cada correção tem um teste que falhava na `main` antes dela.

Corrigido:

- **Crítico — config grande fazia o roteador subir em branco** (#1). O arquivo guardava a running
  e as 64 revisões completas em JSON indentado, sem limite; com ~4000 entradas de address-list
  comentadas passava dos 64 MiB que a leitura aceita, as duas cópias iam para quarentena e o boot
  voltava às portas descobertas, sem endereço nem firewall. Agora o JSON é compacto, a gravação
  fica abaixo de 32 MiB (`persist::encode_bounded` deixa de fora as revisões mais antigas, nunca
  a running; `storage.revisions_not_saved` mostra quantas), um commit cuja config sozinha passaria
  de ~15 MiB é recusado com o motivo e a leitura aceita até 256 MiB (arquivos de versões
  anteriores ainda carregam). Testes: `a_big_config_with_a_full_history_still_boots`,
  `bounded_encoding_leaves_the_oldest_revisions_out`, `encoded_len_is_exact`.
- **Alto — segredos TSIG no journal, no log e para o grupo `read`** (#3). `secret` (e `psk`,
  `private_key`, `passphrase`, para o que vier) entrou em `SECRET_KEYS`: some do journal, da
  mensagem e do detalhe do log (e portanto do syslog remoto), inclusive o secret gerado no
  resultado do `add`. Abaixo do grupo `full`, `state.inspect` e `config.diff` mostram `***`, e
  `ip.dns.tsig-key.print show_secret` exige `full` (como a política `sensitive` do RouterOS).
  Nenhum outro parâmetro secreto existe hoje na `main` (DHCP, relay e DHCPv6 não têm chave).
  Teste: `tsig_secrets_stay_out_of_the_journal_the_log_and_read_accounts`.
- **Médio — journal sem limite** (#4): parâmetros guardados inteiros (16 MiB × 1024 entradas).
  Agora limitados como o detalhe do log (2 KiB) e o erro a 512 bytes. Teste:
  `journal_entries_are_bounded`.
- **Médio — `config.commit`/`config.mode.set` dentro de batch atômico** (#5) comitava de verdade e
  um passo seguinte com erro deixava diferença escondida no candidate. O batch atômico agora
  recusa `config.commit`, `config.discard`, `config.mode.set` e `config.safe-mode.*` antes de rodar
  qualquer passo. Teste: `an_atomic_batch_refuses_transaction_control_steps`.
- **Médio — commit fora do guarda de panic** (#6): um panic no validador ou no plano de dados
  deixava a edição no candidate para o próximo comando comitar. O commit do `execute`, o do batch,
  o desfazer do Safe Mode e o `tick` inteiro rodam no `guard`. Teste:
  `a_panic_while_committing_leaves_nothing_pending`.
- **Médio — prazo do Safe Mode no relógio de parede** (#7): `Hal::monotonic_secs` (novo, padrão
  `None`; o `hal-linux` usa `CLOCK_MONOTONIC`) conduz o prazo; um passo do NTP não dispara nem
  desarma mais o Safe Mode. Teste: `the_deadline_follows_the_monotonic_clock`. O resto dos prazos
  por relógio de parede virou a gap G0.13.
- **Médio — falha ao aplicar a config restaurada no boot** (#8) só ia para o log; kernel e
  `running` divergiam para sempre. Agora `storage.boot_apply_error` mostra o motivo, o `tick`
  tenta de novo a config inteira a cada segundo e o próximo commit aplica tudo a partir do vazio.
  Testes: `a_failed_boot_apply_is_reported_and_retried`,
  `a_commit_after_a_failed_boot_apply_applies_everything`.
- **Médio — `/import` de um `/export` com mais de 256 comandos** (#9) era recusado. `MAX_BATCH`
  subiu para 32 768 (cobre qualquer script de 1 MiB). Testes: `an_atomic_batch_takes_a_big_import`,
  `a_big_export_imports_back`.
- **Baixo — lockout só olhava o firewall** (#10): remover ou desativar o endereço da sessão de
  gerência, ou desativar a interface dele, agora é lockout; e cada lado da comparação usa a
  interface que tem o endereço naquela config (mover o endereço atrás de `in-interface` é pego).
  Teste: `removing_the_management_address_or_its_interface_is_a_lockout`.
- **Baixo — contadores de id atrasados num arquivo editado** (#11): o `decode` acerta cada
  `next_*` para o maior id da sua lista e renumera ids duplicados (`persist::repair_ids`). Testes:
  `a_counter_behind_its_items_is_repaired_on_load`, `counters_behind_their_items_are_repaired`.
- **Baixo — `tool.task.stop`/`poll` sem dono** (#12): só quem iniciou a tarefa (mesma conta) ou o
  grupo `write` para cima. Teste: `only_the_owner_or_a_writer_stops_or_polls_a_task`.
- **Baixo — Safe Mode desfeito em modo transacional** (#13) descartava edições pendentes dizendo
  "nothing to undo"; agora `last` diz quantas foram descartadas. Teste:
  `cancel_says_when_it_drops_pending_edits`.
- **Baixo — caracteres de controle na mensagem do log** (#14): viram espaço (linha forjada, ESC).
  Teste: `log_messages_carry_no_control_characters`.
- **Baixo — script terminado em `\`** (#15) perdia o último comando em silêncio; agora é erro com o
  número da linha. Teste: `a_script_ending_in_a_continuation_is_refused`.
- **Baixo — storage-fs** (#16): cada quarentena ganha seu arquivo (`.corrupt`, `.corrupt.1`, …) e
  `state-*.tmp`/`journal-*.tmp` de gravação interrompida são apagados no `open`. Testes:
  `every_quarantine_keeps_its_own_copy`,
  `stale_temp_files_of_state_and_journals_are_removed_on_open`.

Verificado e falso:

- #2 (mudar usuários em Safe Mode gravava a config não confirmada): `user.add/set/remove` já são
  recusados em Safe Mode desde o G0.3 (`not_in_safe_mode`). Mesmo assim o `save()` agora grava o
  store da entrada sempre que o Safe Mode está ativo (defesa em profundidade; teste
  `a_save_in_safe_mode_writes_the_entry_config`, e `user_changes_wait_for_the_end_of_safe_mode`
  documenta a recusa).
- Em #1, "regras de firewall sem limite" não procede (`MAX_RULES` = 4096 por tabela); as
  address-lists (65 536) e o DNS estático bastam para o problema.

Como testar: `cargo test -p corerouter-engine -p corerouter-model -p corerouter-shell -p
corerouter-storage-fs`. No daemon, `state.inspect` mostra `storage.boot_apply_error` e
`storage.revisions_not_saved`.

| G0.13 | Prazos no relógio monotônico (fora o Safe Mode) | engine, control | Abandono de tarefas (`tasks.rs`), timeouts de address-list dinâmica, ociosidade de login e expiração de leases por `Hal::monotonic_secs` em vez de `now_unix`; teste com passo de NTP para frente e para trás em cada um | 3 h | aberto |
| G0.14 | Validação do firewall O(n²) no commit | firewall | `rule_issues` clona a tabela inteira por regra: com 3000 regras cada commit (mesmo um `system.identity.set`) leva 0,87 s em release (**medido**); validar em O(n log n) (grafo de chains montado uma vez), bench `commit_with_n_rules` antes/depois, < 50 ms com 4096 regras | 3 h | aberto |

## perf

### audit-persist: tamanho do arquivo de config e latência de commit (2026-10-22, **medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release, `cargo test --release -p corerouter-engine
--test persistence a_big_config_with_a_full_history_still_boots`.

| Medida | Antes | Depois |
|---|---|---|
| Uma cópia da config (4000 entradas de address-list com comentário de 200 caracteres) | 1,47 MB (indentado) | 1,16 MB (compacto, −21%) |
| Arquivo com a running + 65 revisões | ~97 MB (recusado no boot: limite 64 MiB) | 32,4 MB (27 revisões mais novas; boot ok) |
| Teste inteiro (4000 adds, 65 commits, gravação, boot) | — | 1,1 s |
| Commit de `system.identity.set` com 3000 regras de filtro | 0,87 s (`validate_all` → `corerouter_firewall::validate`) | igual (gap G0.14) |
