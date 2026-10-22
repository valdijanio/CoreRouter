id: processo

Push na `main` que só mexe em `docs/` (o fold de cada lote) também roda só `cargo xtask docs` no
CI, comparando com o commit anterior; antes rodava o completo e enfileirava atrás do run do lote.
