id: processo

O `docs/perf.md` passa a ser consolidado pela fila, como o log: medições novas vão na seção
`## perf` do `docs/changes/<id>.md`, e `cargo xtask docs fold` as acrescenta no fim do
`perf.md`. Achado da bateria da fila de entrada: o #49 e o #50 acrescentaram no fim do `perf.md`
e o segundo parou na fila com conflito real. `xtask/src/changes.rs` ganhou a struct `Docs` (os
quatro documentos do fold) e testes da seção nova.
