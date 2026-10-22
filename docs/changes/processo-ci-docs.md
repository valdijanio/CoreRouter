id: processo

PR que só mexe em `docs/` roda só `cargo xtask docs` no CI (job `changes` decide; os 3 checks
exigidos passam do mesmo jeito): o PR de fold de cada lote da fila custava um CI inteiro (~3 min)
para mudar só `.md`, e num lote de 1 PR dobrava o tempo. Lote, `main` e `workflow_dispatch`
continuam com o CI completo.
