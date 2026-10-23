id: processo

i18n: traduções de janela nova em `crates/ui/src/i18n/auto/<escopo>_<idioma>.rs`, registradas
pelo `build.rs` (sem editar as listas do `i18n/mod.rs`), com rótulos procurados primeiro no escopo
da janela (`i18n::tr_in`). O `i18n/mod.rs` era o ponto quente da rodada de 2026-10-23: todo PR com
tela acrescentava linhas nas mesmas listas (a fila só conseguia integrar um por lote), e a mesma
palavra em inglês com traduções diferentes em janelas diferentes ("Checks", "Last") reprovava o
lote. O registro antigo continua valendo (mudança aditiva); `AGENTS.md` e `docs/ui-style.md`
explicam o caminho novo.
