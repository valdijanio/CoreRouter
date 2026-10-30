id: fix-journal-proptest-ceiling

O proptest `config_journal::the_journal_saves_what_the_slot_would` passou do teto de 10 s da
camada rápida no runner do GitHub (11,7 s com 32 casos, **medido**, run 40982891327) depois que o
journal passou a cobrir todas as seções de roteamento (#483), e tirava da fila PRs que nem tocam
no motor (#486). A camada rápida (`PROPTEST_CASES=32`) roda 12 casos; o lote e o noturno seguem
com até 48.
