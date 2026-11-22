# Objeto XDP pré-compilado

`corerouter-xdp.o` é o programa deste crate compilado para `bpfel-unknown-none`; o `hal-linux`
o embute (`include_bytes!`), e assim o workspace estável compila e carrega o XDP sem nightly nem
`bpf-linker`. `corerouter-xdp.sources` guarda o SHA-256 das fontes de que ele saiu e o do próprio
objeto: o passo `ebpf-check` do `cargo xtask ci` falha se alguém mudar as fontes sem recompilar.

Recompilar: `cargo xtask ebpf` (precisa do nightly fixado em `../rust-toolchain.toml`, com
`rust-src`, e do `bpf-linker`; veja `docs/xdp.md`) e fazer commit dos dois arquivos.
