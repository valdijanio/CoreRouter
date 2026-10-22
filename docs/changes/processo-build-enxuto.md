id: processo

Perfil de build enxuto: `debug = "line-tables-only"` no código do workspace e sem debuginfo nas
dependências (`[profile.dev]`). Uma `cargo xtask ci` do zero numa pasta de build nova (o que
cada sessão em paralelo faz) caiu de 15 GB e 163 s para 6,6 GB e 135 s (**medido**, 32 núcleos):
com 63 GB livres, cabiam 4 sessões; agora cabem 9. Achado da bateria de 10 features da fila de
entrada. Backtraces e mensagens de panic continuam com arquivo e linha.
