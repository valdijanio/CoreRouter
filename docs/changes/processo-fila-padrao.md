id: processo

Fila de entrada como o padrão do mercado (pesquisa: merge queue do GitHub, Rust/bors rollups,
Trunk, towncrier, changesets): lote vermelho faz bisseção (~log2 N CIs para isolar quem
quebra, em vez de N no um por um) e o fold dos `docs/changes/` é periódico (`--fold` ou 10
pendentes), não um PR extra por lote; `cargo xtask docs pending` mostra os status de gap ainda
não consolidados, e as sessões o leem junto com o `gaps.md`.
