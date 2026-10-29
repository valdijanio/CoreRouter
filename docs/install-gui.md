# Instalar o gerenciador (GUI + CLI) — G0.28

Como o WinBox: instala uma vez, abre pelo ícone do menu e gerencia qualquer CoreRouter, local
ou remoto por TLS. O pacote `corerouter-gui` traz a GUI **e** a CLI (`corerouter-cli`).

## Gerar e instalar (Debian, Ubuntu)

```sh
cargo xtask package gui                     # build `dist` (release sem símbolos) + .deb
sudo apt install ./target/package/corerouter-gui_*.deb
```

Com `CARGO_TARGET_DIR` definido, o `.deb` sai em `$CARGO_TARGET_DIR/package/` (ou na pasta
de `--out <dir>`). `--no-build` empacota os binários que já estão em `<target>/dist`. O
`apt` instala as dependências que faltarem. Remover: `sudo apt remove corerouter-gui`.

Depois de instalado:

- **Menu → Rede → CoreRouter** abre a tela de conexão: Neighbors (CRDP), Saved, Virtual lab.
- No terminal: `corerouter-gui`, `corerouter-cli shell`, `corerouter-cli mcp` etc.
- **Links `corerouter://`** (numa página, num e-mail, num chamado) abrem a GUI já conectando:

| Link | Conecta em |
|---|---|
| `corerouter://10.0.0.1` | `tls://10.0.0.1:8729` (porta TLS padrão) |
| `corerouter://noc@router.lan:9000` | `tls://router.lan:9000` como `noc` |
| `corerouter://[2001:db8::1]` | `tls://[2001:db8::1]:8729` |
| `corerouter://127.0.0.1:7979` | canal local `127.0.0.1:7979` com o token local |

O link só diz **onde** conectar; o caminho é o mesmo do botão Connect. Um roteador visto pela
primeira vez pergunta pelo certificado antes de mandar qualquer coisa; a senha vem do chaveiro
(se foi lembrada para aquele endereço), nunca do link nem de `$COREROUTER_PASSWORD`. O texto é
tratado como hostil: só `[usuário@]host[:porta]`, até 300 bytes, sem caminho, query,
`%`-encoding nem senha (`usuário:senha@` é recusado). `corerouter-gui corerouter://…` no
terminal faz o mesmo.

## O que o pacote instala

| Caminho | O quê |
|---|---|
| `/usr/bin/corerouter-gui`, `/usr/bin/corerouter-cli` | binários (perfil `dist`; o commit aparece em `server.info` e na barra da GUI) |
| `/usr/share/applications/corerouter-gui.desktop` | entrada do menu, categoria Network; `MimeType=x-scheme-handler/corerouter` |
| `/usr/share/icons/hicolor/{16…512}/apps/corerouter-gui.png`, `scalable/…svg` | ícone desenhado por código (`xtask/src/package/icon.rs`) |
| `/usr/share/doc/corerouter-gui/` | `copyright`, `changelog.gz` |

O nome `corerouter-gui.desktop` é o `app_id` da janela (Wayland) e o `StartupWMClass` (X11):
assim o painel mostra o ícone certo na janela aberta. Os caches de menu e de ícones são
atualizados pelos gatilhos do dpkg (`desktop-file-utils`, `hicolor-icon-theme`); o pacote não
tem scripts de instalação.

**Versão:** `<versão do workspace>+<commits>.g<commit>`, ex. `0.1.0+1520.g7a6041d`. O número de
commits cresce na `main`, então um pacote novo sempre é "upgrade" do anterior.

**Dependências** (conferidas com `ldd` a cada empacotamento: biblioteca nova sem pacote
conhecido faz o `package` falhar):

- `Depends`: `libc6 (>= glibc mais nova pedida pelos binários)` — é a glibc da máquina que
  compilou (Ubuntu 24.04 dá `>= 2.39`, **medido**); para instalar em distribuições mais velhas,
  gere o pacote nelas, `libgcc-s1`, e o que o winit/wgpu
  abrem por `dlopen` e sem o qual a janela não abre: `libxkbcommon0`,
  `libwayland-client0 | libx11-6`, `libvulkan1 | libegl1`;
- `Recommends`: o resto que eles abrem (nomes achados no binário): Vulkan e drivers Mesa, EGL e
  `libwayland-egl1`, e os extras do X11 (`libx11-xcb1`, `libxcursor1`, `libxi6`,
  `libxkbcommon-x11-0`);
- `Suggests`: um chaveiro do Secret Service (senhas lembradas).

Tamanho (**medido**, 2026-10-28, commit `7a6041d`): `.deb` de 34 MB; instalado, 79 MB (GUI
55 MB, CLI 24 MB, perfil `dist`).

## Conferir sem instalar

```sh
dpkg-deb --info target/package/corerouter-gui_*.deb
dpkg-deb --contents target/package/corerouter-gui_*.deb
```

O teste `dpkg_reads_the_package_and_installs_it_into_a_scratch_root` (xtask) instala e remove
um pacote gerado pelo mesmo código num diretório descartável, sem root (`dpkg --root
--force-not-root`).

## Pesquisa (resumo)

- **WinBox 4 (MikroTik):** binário único por sistema; no Linux um `.zip` com o executável e uma
  pasta de recursos, sem pacote oficial nem entrada de menu (quem quer menu escreve o `.desktop`
  à mão; existem pacotes da comunidade no AUR, Flathub e Snap). Não registra esquema de URL.
- **Outros:** VyOS, OPNsense/pfSense e Ubiquiti não têm gerenciador de desktop (gerência por
  web/SSH; UniFi tem app próprio); ferramentas de rede de desktop no Debian (Remmina, Wireshark)
  seguem o padrão `.desktop` + ícone hicolor + `x-scheme-handler` (Remmina abre `rdp://`,
  `vnc://`).
- **Padrões:** freedesktop Desktop Entry (`Exec=… %u` para um URL, `MimeType=x-scheme-handler/…`,
  categoria principal `Network` + `RemoteAccess`), Icon Theme (hicolor, tamanhos fixos +
  `scalable`), Debian Policy (`/usr/share/doc/<pacote>/copyright`, `md5sums`, arquivos de root).
- **Ferramenta:** `cargo-deb` resolveria, mas traz dezenas de crates para o xtask e lê
  metadados próprios no `Cargo.toml`; `dpkg-deb --build` precisa do `dpkg` e de `fakeroot`
  para os arquivos serem de root. O `.deb` é um `ar` com dois `tar.gz` — cerca de 100 linhas
  em Rust, reproduzível (mtime = hora do commit) e sem ferramenta externa; o `dpkg-deb`, quando
  existe, só confere.

## Depois

AppImage (G0.28b), instalador do Windows (G0.28c) e `.dmg` do macOS (G0.28d) estão em
`docs/gaps.md`. Publicar binários (GitHub Releases, repositório apt) é decisão do dono do
projeto.
