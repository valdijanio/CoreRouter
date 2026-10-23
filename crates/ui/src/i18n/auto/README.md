# Catálogos registrados sozinhos

Uma janela nova põe aqui as suas traduções, sem editar lista nenhuma:
`<escopo>_<idioma>.rs` (`traffic_flow_pt.rs`, `traffic_flow_en.rs`), com as constantes que
precisar, ordenadas pela chave:

```rust
pub(super) const LABELS: &[(&str, &str)] = &[("Last", "Últimos")];      // só em _pt
pub(super) const HELP: &[(&str, &str)] = &[("traffic_flow.timeout", "…")]; // em _en e _pt
pub(super) const TEMPLATES: &[(&str, &str)] = &[];
```

O `build.rs` do crate as registra. Na janela, use `i18n::tr_in("traffic_flow", lang, "Last")`:
o catálogo do escopo vem primeiro, então a mesma palavra em inglês pode ter outra tradução em
outra janela. As explicações (`HELP`) usam chaves com o escopo na frente e valem em qualquer
lugar (`i18n::explain`). Detalhes em `docs/ui-style.md`, "Idioma".
