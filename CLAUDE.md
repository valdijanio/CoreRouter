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
4. Ciclo por tarefa: orientar → **pesquisar** → planejar → implementar + testar → verificar →
   registrar → commit. Pare e pergunte só para: licença, publicação, segredos, remotos novos,
   aplicar config em kernel/hardware real.

## Pesquisa antes de implementar (obrigatória em toda feature nova)

Nenhuma feature nova começa pelo código. Comece por `scripts/research.sh "<menu ou termo>"`, que
imprime os links de busca já montados de todas as fontes de `docs/research-sources.md` (MikroTik,
outros roteadores, RFCs, kernel, crates). Antes de planejar:

1. **MikroTik RouterOS v7 primeiro.** Leia a documentação oficial da versão estável mais recente
   (help.mikrotik.com) sobre a feature, se existir: nomes de menus, parâmetros, padrões, flags,
   comportamento em casos de borda e o que mudou nas versões 7.x. Ela é a referência de
   comportamento e de nomes do CoreRouter (o usuário opera MikroTik).
2. **Outros roteadores e projetos, para ideias.** Veja como pelo menos dois destes resolvem o mesmo
   problema: VyOS, Juniper Junos, Cisco IOS-XE/NX-OS, Nokia SR Linux, Arista EOS, OPNsense/pfSense,
   OpenWrt, FRR, Ubiquiti EdgeOS/UniFi e as RFCs/padrões envolvidos. Procure o que eles fazem
   melhor que o MikroTik.
3. **A RFC original quando a feature fala um protocolo** (DHCP, LLDP, BGP, OSPF, IPv6/RA, NAT…),
   ou quando a documentação do MikroTik é vaga, contraditória ou não cobre um caso de borda
   (tempos, retransmissão, pacote malformado, interoperabilidade). Leia a cadeia completa: a RFC
   base, as que a atualizam ("Updated by"/"Obsoleted by", no Datatracker) e a errata
   (rfc-editor.org/errata). Siga os "MUST/SHOULD" (RFC 2119). Cite a seção no código e no teste
   que implementa a regra (`// RFC 2131 §4.4.5: T1 = 0,5 × lease`) e transforme os exemplos de
   pacote da RFC em testes quando houver.
4. **Proponha o que pode ser melhor.** Em cima da ideia principal: o que simplifica a operação, o
   que evita erro do operador (lockout, conflito, regra inútil), diagnóstico, segurança por
   padrão, e o que o nosso motor (tudo é comando, transações, Safe Mode, MCP) permite que os outros
   não permitem. Separe "entra agora" de "vira gap depois".
5. **Registre a pesquisa no corpo do PR**, seção `## Pesquisa`: links das fontes (inclusive as
   RFCs e seções consultadas), como o MikroTik faz, como os outros fazem, o que adotamos, as
   melhorias propostas e o que ficou de fora e por quê. Feature grande (novo
   subsistema/protocolo) ganha também `docs/<feature>.md` com essa seção.
6. **Sem copiar.** Use a documentação para entender comportamento e nomes; escreva texto e código
   próprios (o projeto é AGPL). Formatos proprietários sem especificação (MNDP, RoMON, WinBox)
   não são clonados — veja a decisão do G5 em `docs/gaps.md`.

Quando um humano pede uma feature, mostre a ele esse resumo (MikroTik, outros, melhorias
propostas) **antes** de implementar e deixe-o escolher o escopo.

## Desempenho e escolha de implementação (Rust puro × ferramenta externa)

Decisões de desempenho se tomam com números, não com preferência.

- **Meça caminhos quentes antes e depois:** encaminhamento/filtragem de pacotes, aplicar
  milhares de regras/rotas/endereços no kernel, o canal de controle, codecs e parsers de
  protocolo, ferramentas (ping/MTR). Use os benchmarks do workspace (`cargo xtask bench`,
  criterion) e registre o resultado em `docs/perf.md` marcado como **medido** (máquina, build
  release, data). PR que toca caminho quente traz a seção "Desempenho" com antes/depois:
  `cargo xtask bench --save-baseline antes` na `main`, `cargo xtask bench --baseline antes` na
  branch (a coluna "change" do resumo é o antes/depois). Benchmark novo = `benches/<nome>.rs`
  (criterion, `harness = false`) no crate dono do código; alvo `netns_*` roda num namespace sem
  root. Detalhes em `docs/perf.md`.
- **O CI não reprova por benchmark** (máquinas compartilhadas variam). Só entram travas folgadas
  contra regressões grandes, como o teste de latência do canal de controle.
- **Orquestrar algo externo (FRR, `nft`, accel-ppp…) ou escrever em Rust puro:** compare com
  números (vazão/pps, latência, memória, tempo para aplicar N itens) **e** com o que não é número
  (maturidade e interoperabilidade do protocolo, risco de bug, superfície de segurança, esforço
  de manutenção).
  - **Rust puro ganha** quando é mensuravelmente melhor, ou quando elimina um processo externo e
    um ponto de falha sem perder correção, ou quando o externo não serve (sem API
    transacional, sem dados estruturados).
  - **O externo fica** quando correção e interoperabilidade pesam mais que desempenho — o caso
    típico é um protocolo de roteamento maduro (BGP/OSPF no FRR). O gargalo de um roteador
    raramente é o plano de controle.
  - **Rust puro costuma ganhar** no caminho de dados (XDP, G2.5), em codecs/parsers, no motor e
    na aplicação em lote via netlink.
- **Registre a decisão** em `docs/architecture.md`: o que foi comparado, os números e o porquê,
  para poder ser revista com dados depois.

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
cargo run -p corerouter-gui -- --connect 127.0.0.1:7979 --control 7990   # GUI gerenciando o daemon
cargo run -p corerouter-cli -- --connect 127.0.0.1:7979 run ip.address.add '{"address":"10.0.0.1/24","interface":"ether1"}'
cargo run -p corerouter-cli -- --connect 127.0.0.1:7979 screenshot /tmp/ui.png   # depois abra o PNG
cargo run -p corerouter-daemon -- --config-dir /tmp/cr --listen 127.0.0.1:8729   # TLS + login
cargo run -p corerouter-cli -- --connect tls://127.0.0.1:8729 --user admin inspect
```

Autenticação (G0.3/G0.3b): na primeira vez o daemon cria `admin` **sem senha** (RouterOS 7):
entra com senha vazia só de `127.0.0.1`, a GUI e o terminal pedem para definir uma ("Not now"
pula), e todo login pela rede é recusado até lá (`--reset-admin-password` volta a deixar o
`admin` sem senha). CLI, MCP e GUI em `127.0.0.1` entram sem senha com
o **token local** que o daemon grava em `control-<porta>.token` (só o mesmo usuário do sistema
lê; `$COREROUTER_RUNTIME_DIR` muda a pasta, `--token-file` o arquivo). Fora do loopback é sempre
TLS + `--user` (senha por prompt ou `$COREROUTER_PASSWORD`); o certificado é confirmado no
primeiro uso e fica em `~/.config/corerouter/known_hosts`. Detalhes em `docs/control-protocol.md`.

Mudou UI? Rode a GUI com `--control`, tire `screenshot` e **olhe o PNG** antes de dizer que está
pronto. Sem display, use o teste headless de `crates/ui` (`every_window_renders_headless`).
MCP: `claude mcp add corerouter -- corerouter-cli mcp` (detalhes em `docs/mcp.md`).

## Verificação

- Antes de cada commit: `cargo xtask ci` (fmt, clippy -D warnings, test, bench-check, netns,
  layers, agents-sync, wasm). Ele para no primeiro FAIL; não faça commit com FAIL.
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
   testar (comandos ou cliques), o id da gap e, em feature nova, a seção `## Pesquisa` (veja
   "Pesquisa antes de implementar").
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

- Ao terminar, no mesmo PR:
  - atualize **só a linha do seu item** em `docs/gaps.md` (status, critério) — nunca reescreva
    linhas de outros itens;
  - acrescente **no fim** de `docs/log.md` uma entrada `- AAAA-MM-DD — <id>: …` (o que entrou,
    como testar, números medidos);
  - acrescente **no fim** de `docs/gaps-history.md` uma linha se você criou, redefiniu ou mudou o
    status de um item;
  - se a arquitetura mudou, atualize `docs/architecture.md`.
- `docs/log.md` e `docs/gaps-history.md` são **só de acrescentar** e usam `merge=union`
  (`.gitattributes`): o git junta as entradas de PRs paralelos sem conflito. Por isso, só
  acrescente no fim; nunca edite, reordene ou apague entradas antigas.
- Não crie seções de "histórico de revisão" no fim de outros documentos (geram conflito entre PRs
  paralelos); o histórico do projeto é o `docs/log.md`.
- Notas e estimativas erram para baixo; marque cada número como **medido** ou **estimado**.
