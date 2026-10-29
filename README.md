# CoreRouter

Sistema de roteamento carrier-grade em Rust: um motor de comandos transacional (candidate/running,
commit, rollback), GUI estilo WinBox/WebFig em egui (nativo e navegador via WASM), CLI e servidor
MCP para agentes. Status: **esqueleto v0.1.0** — o motor arquitetural funciona sobre um
backend virtual; o data plane real está em `docs/gaps.md`.

```sh
cargo xtask ci                                   # fmt, clippy sem panic, testes, camadas, wasm
cargo run -p corerouter-gui -- --control 7979    # GUI (virtual lab) + canal de controle
cargo run -p corerouter-daemon -- --control 7979 --config-dir /tmp/cr   # roteador (lab virtual persistente)
cargo run -p corerouter-gui -- --connect 127.0.0.1:7979                 # GUI gerenciando o daemon
cargo run -p corerouter-cli -- list              # comandos disponíveis
cargo run -p corerouter-cli -- run ip.address.add '{"address":"10.0.0.1/24","interface":"ether1"}'
claude mcp add corerouter -- corerouter-cli mcp  # MCP
```

Instalar o gerenciador (GUI + CLI) no Debian/Ubuntu e abrir pelo menu, como o WinBox:
`cargo xtask package gui` gera `target/package/corerouter-gui_<versão>_amd64.deb`; instale com
`sudo apt install ./target/package/corerouter-gui_*.deb`. Links `corerouter://10.0.0.1` abrem
a GUI já conectando. Detalhes em [docs/install-gui.md](docs/install-gui.md).

Web (requer `cargo install trunk --locked`): `cd apps/corerouter-gui && trunk build`, depois
`cargo run -p corerouter-daemon -- --ws 7980 --web-root apps/corerouter-gui/dist` e abra
http://127.0.0.1:7980 (a GUI servida pelo roteador, como o WebFig). Só a demo no navegador:
`trunk serve` e abra http://127.0.0.1:8080/?lab.

Primeiro acesso (como o RouterOS 7): o daemon cria o usuário `admin` **sem senha**. Entre como
`admin` com a senha vazia a partir da própria máquina (GUI em `127.0.0.1`, ou
`corerouter-cli shell`); a GUI e o terminal pedem para definir uma senha logo ao entrar ("Not
now" pula). Enquanto o `admin` estiver sem senha, todo login pela rede (`--listen`,
`--ws-listen`) é recusado. Esqueceu a senha? `corerouter-daemon --reset-admin-password` volta
ao estado sem senha. Detalhes em [docs/control-protocol.md](docs/control-protocol.md).

Leia primeiro: [AGENTS.md](AGENTS.md), [docs/architecture.md](docs/architecture.md),
[docs/gaps.md](docs/gaps.md), [docs/mcp.md](docs/mcp.md),
[docs/control-protocol.md](docs/control-protocol.md).

Licença: [GNU AGPL-3.0-or-later](LICENSE). Quem distribuir uma versão modificada, ou oferecê-la como serviço pela rede, precisa publicar o código-fonte dela.
