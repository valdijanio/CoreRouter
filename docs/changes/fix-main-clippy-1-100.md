id: fix-main-clippy-1-100

O Rust 1.100.0 (stable de 2026-11-12) chegou ao CI, que segue o `stable` do `rust-toolchain.toml`,
e o clippy novo passou a reprovar `needless_range_loop` em cinco laços de testes do PPPoE do
daemon (`pppoe_bng_tests.rs`, `pppoe_ha_tests.rs`, `pppoe_routes_tests.rs`). Isso reprovava o
`lint` de todo PR e ia reprovar a `main`. Os laços passam a usar `iter().enumerate()`. Sai
também a dependência `thiserror` do `proto-syslog`, sem uso, que o cargo 1.100 passou a avisar.
Conferido com `RUSTUP_TOOLCHAIN=1.100.0 cargo xtask ci --only fmt,clippy,wasm` e com os 40
testes de PPPoE alterados. Nas máquinas ainda com o 1.99, o `--affected` local não via o erro:
quem atualizar o `stable` (`rustup update stable`) passa a ver o mesmo que o CI.
