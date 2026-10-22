id: processo

Fila de entrada resolve sozinha os conflitos só nos documentos do fold (`docs/log.md`,
`docs/gaps-history.md`, `docs/perf.md`: entradas dos dois lados; `docs/gaps.md`: a mesma gap
fica uma vez, a do PR). Eles vinham de uma branch que guardou o fold de uma rodada anterior da
fila, que parou no meio: o #62 ficou fora de dois lotes por isso. Um PR que o GitHub marca em
conflito só nesses documentos recebe a `main` na própria branch antes do lote (o squash é do
GitHub, que não vê a resolução do lote). Testado na branch do #62.
