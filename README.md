# CoreRouter

Sistema de roteamento carrier-grade em Rust: um motor de comandos transacional (candidate/running,
commit, rollback), GUI estilo WinBox/WebFig em egui (nativo e navegador via WASM), CLI e servidor
MCP para agentes. Status: **esqueleto v0.1.0** — o motor arquitetural funciona sobre um
backend virtual; o data plane real está em `docs/gaps.md`.

```sh
cargo xtask ci                                   # fmt, clippy sem panic, testes, camadas, wasm
cargo run -p corerouter-gui -- --control 7979    # GUI (virtual lab) + canal de controle
cargo run -p corerouter-cli -- list              # comandos disponíveis
cargo run -p corerouter-cli -- run ip.address.add '{"address":"10.0.0.1/24","interface":"ether1"}'
claude mcp add corerouter -- corerouter-cli mcp  # MCP
```

Web: `trunk serve apps/corerouter-gui/index.html`.

Leia primeiro: [AGENTS.md](AGENTS.md), [docs/architecture.md](docs/architecture.md),
[docs/gaps.md](docs/gaps.md), [docs/mcp.md](docs/mcp.md),
[docs/control-protocol.md](docs/control-protocol.md).

Licença: ainda não definida (G0.1).
