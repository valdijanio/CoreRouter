# CoreRouter — instruções para agentes

CoreRouter é um sistema operacional de roteador carrier-grade (interfaces/VLANs, firewall, CGNAT,
OSPF, BGP, MPLS, DNS, DHCP) 100% Rust, com GUI estilo WinBox/WebFig em egui (nativo + WASM),
CLI e servidor MCP. Alvo de qualidade: um operador de ISP confia nele em produção.

Este arquivo é idêntico a `CLAUDE.md` (`cargo xtask agents-sync` falha se divergirem).

## Comece toda sessão aqui

1. Leia `ROADMAP.md` e `docs/gaps.md` (lista ranqueada). Sem tarefa do usuário, pegue o primeiro
   item `aberto` de `docs/gaps.md` que não esteja `em andamento`.
2. Se existir, leia `plan/STATUS.md` (pasta local, fora do git) e a tarefa em `plan/`.
3. Leia `docs/architecture.md` antes de criar crate ou mexer em camadas.
4. Ciclo por tarefa: orientar → planejar → implementar + testar → verificar → registrar → commit.
   Pare e pergunte só para: licença, publicação, segredos, remotos novos, aplicar config em
   kernel/hardware real.

## Inegociáveis (cada um com o motivo e o que o impõe)

- **Tudo é comando.** Comportamento novo = `CommandSpec` em `crates/engine/src/cmd/<área>.rs`
  com `cmd!` + teste. UI, CLI, canal de controle e MCP só chamam `Session::execute(id, params)`.
  Motivo: um caminho só para validar, registrar no journal e fazer rollback. Imposto por revisão
  e pelos testes do registro (`ids_are_unique_and_well_formed`, `every_params_doc_parses`).
- **O `params` é contrato.** Formato `{chave: tipo, opcional?: tipo} → resultado`. O engine
  rejeita chave não declarada (com "did you mean") e chave obrigatória ausente. Mudou o
  parâmetro, mudou o doc — senão o comando quebra.
- **Nunca dar panic em produção.** Um panic derruba o plano de controle de um roteador = queda de
  rede. Sem `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`, nem
  indexação `v[i]`/`map["k"]` mutável. Use `?`, `.get(i)`, `let … else`, `ok_or_else`.
  `clippy` em `deny` + `cargo xtask ci`. Testes podem usar `unwrap` (`clippy.toml`).
- **Entradas são hostis.** Pacotes, arquivos de config, parâmetros de comando, linhas do canal de
  controle e mensagens MCP. Limite tamanhos, valide antes de mutar, mensagens de erro truncam a
  entrada. Parser novo = proptest/fuzz (veja `crates/engine/tests/command_sweep.rs`).
- **Camadas.** L0 model → L1 hal → L2 proto-* → L3 engine → L4 control/mcp → L5 ui → L6 apps → L7
  xtask. Dependência só para baixo; egui/eframe/winit/wgpu só em L5+; crates de plataforma
  (`hal-linux`, `hal-frr`, `dataplane-ebpf`) só nas apps. Imposto por `cargo xtask layers`.
  Crate novo precisa entrar na tabela `LAYERS` de `xtask/src/layers.rs`.
- **UI fina.** Painéis leem estado por comandos de consulta e agem com `CoreRouterUi::run(id,
  params)`. Nenhuma regra de negócio em `crates/ui`.
- **Só Rust.** Nada de JS/TS escrito à mão (o `index.html` do trunk é a exceção).
- **Nunca quebrar o WASM.** model, hal, engine, ui e gui compilam para `wasm32-unknown-unknown`.
  Não use `std::time::SystemTime::now`, threads ou `std::net` nessas camadas (o relógio vem do
  `Hal::now_unix`). Imposto por `cargo xtask wasm`.
- **`unsafe` proibido**, exceto no futuro crate isolado `dataplane-ebpf` (programas XDP), com
  revisão humana e comentário `SAFETY:` por bloco.
- **Kernel real só com pedido explícito.** O padrão é `--backend virtual`. Nunca rode
  `--backend linux` como root nem altere interfaces da máquina de desenvolvimento (veja "Acesso
  root e testes de rede").

## Rodar e olhar

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo run -p corerouter-cli -- list ip.                 # comandos e assinaturas
cargo run -p corerouter-cli -- run interface.list
cargo run -p corerouter-daemon -- --control 7979        # daemon (virtual lab)
cargo run -p corerouter-gui -- --control 7979           # GUI + canal de controle
cargo run -p corerouter-cli -- --connect 127.0.0.1:7979 run ip.address.add '{"address":"10.0.0.1/24","interface":"ether1"}'
cargo run -p corerouter-cli -- --connect 127.0.0.1:7979 screenshot /tmp/ui.png   # depois abra o PNG
```

Mudou UI? Rode a GUI com `--control`, tire `screenshot` e **olhe o PNG** antes de dizer que está
pronto. Sem display, use o teste headless de `crates/ui` (`every_window_renders_headless`).
MCP: `claude mcp add corerouter -- corerouter-cli mcp` (detalhes em `docs/mcp.md`).

## Verificação

- Antes de cada commit: `cargo xtask ci` (fmt, clippy -D warnings, test, layers, agents-sync,
  wasm). Ele para no primeiro FAIL; não faça commit com FAIL.
- Comando novo: teste de sucesso, de erro de validação e de rollback; o `command_sweep` cobre
  params lixo automaticamente.
- Um id de tarefa por commit: `G1.2: hal-linux aplica endereços via rtnetlink`.

## Integração: sempre por Pull Request

Nada entra na `main` sem PR com o CI verde. O repositório é privado no plano gratuito, então o
GitHub não impõe isso: esta regra impõe.

1. Trabalhe numa branch `stream/<id>-<slug>`, nunca na `main`. Nunca faça commit nem push na `main`.
2. Antes de cada commit: `cargo xtask ci`.
3. Ao terminar: `git push -u origin <branch>` e
   `gh pr create --base main --title "<id>: <resumo>"`. O corpo do PR diz o que mudou, como
   testar (comandos ou cliques) e o id da gap.
4. O workflow `ci` (`.github/workflows/ci.yml`) roda no PR. Vermelho? Leia o log
   (`gh run view --log-failed`), corrija na mesma branch e faça push de novo.
5. O merge é do usuário (**Squash and merge**: um commit por gap na `main`). Agente só faz merge
   com pedido explícito do usuário naquela conversa.
6. Depois do merge, apague a branch local e a remota.

## Acesso root e testes de rede

- Agentes **nunca** rodam `sudo`. Não há senha no ambiente, e isso é intencional: um erro com
  root derruba a rede da máquina de desenvolvimento.
- Testes que precisam de `CAP_NET_ADMIN` (netlink, VLAN, bridge, nftables) rodam num network
  namespace descartável, sem root:
  `unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux`. Dentro dele só
  existe uma interface `lo`; crie interfaces `dummy`/`veth` no próprio teste. Nada vaza para o host.
- Precisa de root de verdade (FRR instalado no host, XDP numa NIC física, imagem Buildroot,
  `setcap`)? Pare e entregue ao usuário o comando exato e o motivo; ele roda no terminal dele.
  Nunca proponha `sudo` sem senha (NOPASSWD) amplo.

## Agentes em paralelo

- `CARGO_TARGET_DIR=target-<seu-id>` próprio (o diretório `target-*` está no `.gitignore`);
  apague-o ao terminar (~10–30 GB).
- Edite só os crates da sua tarefa (a coluna "crates" de `docs/gaps.md`). Precisa mexer em
  `crates/model` ou `crates/engine/src/session.rs`? São compartilhados: mudanças pequenas,
  aditivas, e avise no PR.
- Marque o item como `em andamento (<branch>)` em `docs/gaps.md` no primeiro commit.
- Branch: `stream/<id-da-gap>-<slug>`, ex. `stream/G1.2-netlink-addresses`.

## Progresso

- Ao terminar: atualize o status em `docs/gaps.md`, o log de `ROADMAP.md` e, se a arquitetura
  mudou, `docs/architecture.md` — no mesmo PR.
- Notas e estimativas erram para baixo; marque cada número como **medido** ou **estimado**.
- Documento tocado ganha linha no histórico de revisão no fim do arquivo.
