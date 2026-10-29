id: processo
history: G1.6r criado (enviar só o que mudou no `os push`)

Build rápido da imagem (`cargo xtask os build|push`):

- **Uma pasta de build por checkout fora do repositório.** Buildroot, `O=`, ccache, targets do
  cargo, GUI web, pastas dos testes no QEMU e a chave de assinatura vão para
  `/srv/build/os-out/<checkout>-<hash>` (`$COREROUTER_OS_OUT` muda; sem `/srv/build`, `os/out`).
  `cargo xtask os out-dir` mostra a pasta.
- **Chave preservada.** Um checkout cujo `os/out/keys` já tem chave continua usando o `os/out`
  até migrar, e o build avisa. Com `$COREROUTER_OS_OUT` numa pasta sem chave, o build para e diz
  o que copiar. O roteiro de migração está em `docs/os-image.md`, "Onde fica o build".
- **Um build por pasta**, garantido por um `flock` em `<out>/.build.lock`.
- **`make all` com `-j` de topo automático:** núcleos/4, no máximo um por 4 GiB livres, no
  mínimo 2, mais `-l<núcleos>`. `--top-jobs`/`--jobs` continuam valendo.
- **GUI web num target próprio** (`<out>/web-target`). No mesmo `cargo-target` que o daemon,
  cada build invalidava os artefatos de host do outro.
- **CLI do `push` em `<out>/cli-target`**, com perfil rápido (sem LTO, 16 unidades,
  incremental). O `ab-test --scenario push` usa a mesma CLI.
- `RUSTC` fixado ao lado do cargo da toolchain: sem `RUSTUP_TOOLCHAIN`, o `rust-toolchain` do
  crate `dhcproto` (1.90) trocava o compilador no meio do build.
- O `check_needed` compara caminhos canônicos, então um out acessado por symlink funciona.

**Medido** (2026-10-29, Ryzen AI Max+ 395, 32 threads, outras sessões rodando):

- uma linha no daemon + `os build --only crpkg`: **889 → 213 s**;
- CLI do `push`: 223 → 66 s com target novo e 144 → 3,2 s depois de mudar o engine;
- build completo com ccache: 1063 → 1010 s; o caminho crítico é `host-protobuf` → FRR, serial.

`boot-test` (KVM) e `ab-test --scenario push` passaram com a imagem nova: envio a 83 MiB/s,
B confirmado em 18,3 s.

| G1.6r | `os push`: enviar só o que mudou | xtask, `os/` | No ciclo de teste, quando só o Rust mudou: (1) não refazer `wasm-bindgen` + `wasm-opt` da GUI sem mudança no `.wasm` (57 s de 213 s, **medido**); (2) um perfil do daemon sem LTO para o ciclo de teste, marcado no pacote como não-produção (~100 s do cargo release, **medido**); (3) avaliar enviar só o binário do daemon (pacote delta assinado) em vez do rootfs inteiro; medir antes e depois | 4 h | aberto |

## perf

### Build rápido da imagem (processo, 2026-10-29)

**Medido** em 2026-10-29, AMD Ryzen AI Max+ 395 (32 threads), 62 GiB, NVMe, build release, com
5–6 outras sessões compilando (carga 20–90). Cada lado numa cópia própria do out em
`/srv/build` (ccache do checkout principal, downloads em cache).

| Situação | Antes | Depois |
|---|---|---|
| `os build` completo, out vazio só com ccache | 1063 s (`make all` 838 s, serial) | 1010 s (`make all` 800 s, `-j6 -l32`) |
| Uma linha no daemon, `os build --only crpkg` | 889 s (GUI 331 + `make all` 497; 126 + 97 crates recompilados) | 213 s (GUI 60 s, 0 crates; `make all` 139 s) |
| CLI do `push`, target novo | 223 s | 66 s |
| CLI do `push`, uma linha no engine | 144 s | 3,2 s |

O paralelismo médio entre pacotes no build completo foi 2,1× (1714 s de pacotes em 802 s). A
corrente `host-protobuf` (309 s) → `protobuf-c` → FRR → kernel do instalador limita o `-j` de
topo.
