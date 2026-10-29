id: fix-test-ceiling-journal

Dois testes da camada rápida passavam do teto de 10 s no runner do GitHub e reprovavam PRs que
nem tocavam no motor (o #406): `config_journal::the_shutdown_checkpoint_loses_no_journal_line`
(10,12 s) e o proptest `the_journal_saves_what_the_slot_would` (10,03 s). O caso de 1100 commits
do primeiro virou `slow_the_shutdown_checkpoint_loses_no_journal_line_after_1100_commits` (a
camada rápida fica com 3 e 40); o proptest passa a respeitar o `PROPTEST_CASES` (32 na camada
rápida), com no máximo os 48 de antes no lote e no noturno.
