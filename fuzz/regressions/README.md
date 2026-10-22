# Regressões de fuzzing

Uma entrada que já derrubou um alvo vai para `regressions/<alvo>/<nome-que-diga-o-bug>`; os
testes `crates/*/tests/fuzz.rs` a reexecutam em todo `cargo xtask ci`. Veja `docs/fuzzing.md`.
