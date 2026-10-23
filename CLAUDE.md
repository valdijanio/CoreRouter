# CoreRouter — instruções para agentes

CoreRouter é um sistema operacional de roteador carrier-grade (interfaces/VLANs, firewall, CGNAT,
OSPF, BGP, MPLS, DNS, DHCP) 100% Rust, com GUI estilo WinBox/WebFig em egui (nativo + WASM),
CLI e servidor MCP. Alvo de qualidade: um operador de ISP confia nele em produção.

Este arquivo é idêntico a `CLAUDE.md` (`cargo xtask agents-sync` falha se divergirem).

## Comece toda sessão aqui

1. Leia `ROADMAP.md`, `docs/gaps.md` (lista ranqueada) e a saída de `cargo xtask docs pending`
   (status de gap que a fila ainda não consolidou no `gaps.md`). Sem tarefa do usuário, pegue o primeiro
   item `aberto` de `docs/gaps.md` (sessões em paralelo recebem o id no brief da sessão principal).
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

### Todo pedido, feature ou correção: o que mostrar antes de implementar

Vale para pedido de feature nova, melhoria de tela e correção de bug. Antes do código, entregue
ao usuário, nesta ordem (pule o que não cabe no pedido e diga que pulou):

1. **O que existe hoje:** como o código, a tela e os comandos se comportam agora e onde moram
   (arquivo e linha); num bug, a causa reproduzida, não a suposta.
2. **Os padrões do projeto que se aplicam:** `docs/ui-style.md` (selos, tabelas, padrão de
   janela de lista e de modal), comandos (`cmd!`, `params`), i18n (rótulos em inglês,
   explicações em português, ⓘ), tabelas centrais (menu, ícones). O pedido segue o padrão; se o
   padrão não serve, diga por quê e proponha mudar o padrão, não abrir exceção.
3. **Mockup** quando o pedido mexe em tela: uma ou mais opções lado a lado, com a recomendada
   marcada, para o usuário escolher.
4. **Como deve funcionar pela norma:** a RFC e as atualizações e errata quando há protocolo; a
   documentação do MikroTik v7 e de pelo menos dois outros (seção "Pesquisa antes de
   implementar").
5. **Extras:** ideias que o usuário não pediu e que fariam diferença (operação, diagnóstico,
   segurança por padrão, o que o motor permite: transação, Safe Mode, MCP).
6. **Riscos do próprio pedido:** o que ele pode quebrar ou piorar (lockout, desempenho,
   compatibilidade, dado perdido, conflito com outra sessão), e como evitar.

Só depois da escolha do usuário o trabalho começa. O mesmo resumo vai no corpo do PR (seção
`## Pesquisa` e, quando houver, `## Extras e riscos`).

## Desempenho e escolha de implementação (Rust puro × ferramenta externa)

Decisões de desempenho se tomam com números, não com preferência.

- **Meça caminhos quentes antes e depois:** encaminhamento/filtragem de pacotes, aplicar
  milhares de regras/rotas/endereços no kernel, o canal de controle, codecs e parsers de
  protocolo, ferramentas (ping/MTR). Use os benchmarks do workspace (`cargo xtask bench`,
  criterion) e registre o resultado na seção `## perf` do seu `docs/changes/<id>.md` (a fila o acrescenta ao `docs/perf.md`; não edite o `perf.md` à mão) marcado como **medido** (máquina, build
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
  com `cmd!` + teste (área nova = arquivo novo; o `build.rs` do engine a registra). UI, CLI, canal de controle e MCP só chamam `Session::execute(id, params)`.
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
  params)`. Nenhuma regra de negócio em `crates/ui`. Visual: siga `docs/ui-style.md` — selos (chips) e
  selos coloridos por hash de chave (AS, VLAN, VRF) com `crates/ui/src/chip.rs`, nunca texto entre
  colchetes nem cores ad hoc; tabelas com uma linha por item e seleção por clique.
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
pronto.

**Binários sempre atuais:** depois de cada lote, a fila de entrada (`scripts/land.sh`) leva o
checkout principal para a `main` nova e recompila daemon, GUI e CLI (só se ele estiver na `main`
e sem alterações; `LAND_REBUILD=0` desliga). Quem já está rodando não é reiniciado: a barra da GUI
mostra "daemon <commit> ≠ GUI <commit>" quando o daemon foi compilado de outro commit
(`server.info` traz o `commit`, crate `corerouter-buildinfo`). Sem display, use o teste headless de `crates/ui` (`every_window_renders_headless`).
MCP: `claude mcp add corerouter -- corerouter-cli mcp` (detalhes em `docs/mcp.md`).

## Verificação

- Antes de cada commit: `cargo xtask ci` (fmt, clippy -D warnings, test, bench-check, netns,
  docs, layers, agents-sync, wasm). Ele para no primeiro FAIL; não faça commit com FAIL. O passo
  `test` usa o `cargo nextest` quando instalado (`cargo install --locked cargo-nextest`; metade do
  tempo, **medido**). Teste que falha e passa ao repetir sai como FLAKY/"flaky netns test" e não
  reprova: corrija-o depois (teste instável trava a fila; foram quatro em 2026-10-22).
- **Portão em duas camadas:** `cargo xtask ci --fast` (sem `netns` e `bench-check`) é o do PR;
  o completo roda localmente, no lote da fila de entrada e na `main`.
- Comando novo: teste de sucesso, de erro de validação e de rollback; o `command_sweep` cobre
  params lixo automaticamente.
- Um id de tarefa por commit: `G1.2: hal-linux aplica endereços via rtnetlink`.

## Integração: sempre por Pull Request, pela fila de entrada

Nada entra na `main` sem PR com o CI verde. A proteção da `main` no GitHub impõe isso: PR
obrigatório, os três checks do `ci` no próprio PR, vale para admin, sem force-push. A
combinação dos PRs com a `main` é testada pela fila (abaixo). Quem faz o merge é a **fila de entrada** da sessão principal. O usuário aprova ao pedir a rodada
de features; daí a fila integra sozinha (ele pode pedir para ser consultado antes de um lote).
Sessões de feature não fazem merge nem ligam auto-merge.

1. Trabalhe numa branch `stream/<id>-<slug>`, nunca na `main`. Nunca faça commit nem push na `main`.
2. Antes de cada commit: `cargo xtask ci`.
3. Ao terminar: `git fetch origin && git merge origin/main` (merge, nunca rebase/force-push numa
   branch com PR), `cargo xtask ci` de novo, `git push -u origin <branch>` e
   `gh pr create --base main --title "<id>: <resumo>"`. O corpo do PR diz o que mudou, como
   testar (comandos ou cliques), o id da gap e, em feature nova, a seção `## Pesquisa` (veja
   "Pesquisa antes de implementar").
4. Abra o PR com o rótulo **`fila`** (`gh pr create … --label fila`): é ele que a fila contínua
   (`scripts/land.sh --watch`) procura. Com o PR aberto, **pare** e diga no relato "pronto para a fila: #<n>" (o `cargo xtask ci`
   local completo já passou; não espere o CI do GitHub). Não ligue `gh pr merge --auto` nem
   faça merge. O CI do PR roda o portão rápido (`cargo xtask ci --fast`); se ele ou a fila
   acusarem erro, a sessão principal avisa e você corrige na mesma branch.

### Fila de entrada (sessão principal)

Enquanto houver sessões trabalhando, a sessão principal deixa rodando a **fila contínua**
`scripts/land.sh --watch`: ela pega sozinha os PRs com o rótulo `fila` e, enquanto um lote roda o
CI, já testa os PRs novos num lote especulativo montado em cima dele (lote verde: o especulativo
entra logo depois, sem esperar outro CI; vermelho: é descartado). O resultado de cada CI vem dos
runs do Actions, não dos check-runs (o GitHub já deixou um check-run preso em "in_progress").
`scripts/land.sh --batch <pr>...` integra uma lista na hora:

- **Lote:** junta a `main` e todos os PRs numa branch temporária, confere os `docs/changes/` e
  roda **um** CI completo nessa combinação, que é o que a `main` vai ser: o "sozinho passa,
  junto quebra" aparece aqui. Verde: squash de cada PR em ordem, sem esperar mais CI. Um PR que
  conflita de verdade fica de fora (a sessão dona resolve); conflito só nos documentos do fold
  ou de **PR empilhado** a fila resolve sozinha (abaixo). Um CI por lote (~4–6 min de ponta a ponta, **medido**).
- **Lote vermelho:** bisseção — a fila divide ao meio e testa cada metade, até isolar quem quebra
  (~log₂ N CIs); os outros entram, quem quebra fica de fora para a sessão dona corrigir.
- **Fold periódico:** os `docs/changes/` são consolidados em log, gaps, histórico e perf só com
  `scripts/land.sh --fold` ou quando há 10 pendentes (como o towncrier/changesets, que
  consolidam no release) — não um PR extra por lote. Até lá, `cargo xtask docs pending` mostra
  o que falta consolidar.

A fila para no primeiro problema e diz qual PR e por quê:

- **conflito real com a `main`**: a sessão dona resolve na branch (`git merge origin/main`,
  `cargo xtask ci`, push) e o PR volta para a próxima rodada;
- **CI vermelho depois do merge da `main`**: idem; a quebra é de integração, quem conhece o código
  corrige;
- **`docs/changes` inválido**: corrija o arquivo (`cargo xtask docs` diz o que está errado).

A fila envia commits na branch do PR (merge da `main`, fold). Antes de enviar mais trabalho num
PR aberto, faça `git pull` (merge) da própria branch. Nunca force-push.

### `main` vermelha é prioridade zero

O CI roda na `main` após cada merge. Se falhar, o workflow `main-red` abre (ou atualiza) a issue
**"main quebrada"** com o link do log e a fecha sozinho quando a `main` voltar a ficar verde.
Enquanto ela estiver aberta: a próxima sessão que vir a issue (ou a sessão principal) corrige numa
branch `stream/fix-main-<slug>` ou reverte o PR culpado (`git revert` num PR), antes de qualquer
outra tarefa. Não acumule PRs em cima de uma `main` quebrada.

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
  apague-o ao terminar (~7 GB depois de uma `cargo xtask ci`, **medido**).
- Edite só os crates da sua tarefa (a coluna "crates" de `docs/gaps.md`). Precisa mexer em
  `crates/model` ou `crates/engine/src/session.rs`? São compartilhados: mudanças pequenas,
  aditivas, e avise no PR.
- Branch: `stream/<id-da-gap>-<slug>`, ex. `stream/G1.2-netlink-addresses`.
- **Ids de gap vêm do brief ou da `main`.** Nunca invente um id: confira `docs/gaps.md` na
  `origin/main` atualizada antes de registrar um item novo (já houve colisão de G1.20).
- **Não abra outras sessões por conta própria.** Trabalho extra que você descobrir vira uma gap
  nova no seu `docs/changes/<id>.md` e uma sugestão no seu relato; quem decide abrir sessão é o usuário ou a sessão
  principal (sessões não planejadas mexem nos mesmos arquivos e geram conflito).
- **PRs pequenos e focados**: entram mais rápido e reduzem a janela de conflito. Feature grande
  vira vários PRs sequenciais, um por sessão.
- **Pode empilhar.** A parte seguinte pode sair da branch da anterior (`git switch -c
  stream/<id>-c stream/<id>-b`), sem esperar a fila. Quando a anterior entra por squash, a
  seguinte passa a trazer as mudanças dela duas vezes e o GitHub acusa conflito; a fila resolve
  sozinha: se, em cada arquivo em conflito, a `main` tem exatamente o que o PR pai tinha, ela fica
  com o lado do PR (pai + o que ele mudou), dá push na branch e segue. Arquivo que não bate com o
  pai é conflito de verdade e volta para a sessão dona.
- **Arquivo novo em vez de lista compartilhada.** Os registros que todo PR editava (e onde PRs
  paralelos conflitavam) agora são gerados a partir dos arquivos:
  - área de comandos nova: `crates/engine/src/cmd/<área>.rs` com `COMMANDS` — o `build.rs` do
    engine a registra; **não edite** `cmd/mod.rs`;
  - janela nova na GUI: um **painel** `crates/ui/src/<feature>.rs` com
    `pub(crate) const PANEL: Panel` (veja `crates/ui/src/panel.rs`: estado próprio, consultas,
    respostas, diálogos); **não edite** `ui/src/lib.rs` nem `ui/src/windows.rs`. Os itens de cada
    grupo do menu ficam em ordem alfabética (como no WinBox); grupo novo é uma linha em `MENU`;
  - testes de UI de uma feature: `crates/ui/src/tests/<feature>.rs` (descoberto), não no fim do
    `mod tests` do `lib.rs`;
  - teste em namespace: `tests/netns<nome>.rs` em qualquer pacote — o `cargo xtask netns`
    descobre; não há lista para editar;
  - módulo novo no engine, no model ou no mcp: só o arquivo `src/<nome>.rs` (ou
    `src/<nome>/mod.rs`) — o `build.rs` gera os `pub mod` (`build-support/root_modules.rs`);
    **não edite** a lista do `lib.rs`. Atributo do módulo vai dentro dele (`#![doc(hidden)]`).
    Não acrescente `pub use` na raiz: use o caminho (`corerouter_model::bonding::BondMode`);
  - estado de execução de uma feature no `Session`: `s.ext_mut::<SeuTipo>()` /
    `s.ext::<SeuTipo>()` (`crates/engine/src/ext.rs`); **não acrescente campo** ao `Session`;
  - serviço novo no daemon (thread de rede, opção de linha de comando): um arquivo
    `apps/corerouter-daemon/src/service/<nome>.rs` com `pub(crate) const SERVICE: Service`
    (opções e `start`); **não edite** o `main.rs` do daemon;
  - módulo do kernel que o CI completo precisa carregar: um arquivo
    `ci/kernel-modules/<módulo>` com a variável que ele liga; **não edite** o `ci.yml`.
  Medido na rodada de 7 agentes (2026-10-22): 5 de 6 conflitos eram linha acrescentada no fim
  dessas listas; listas geradas zeraram os conflitos na simulação (`docs/perf.md`).
- **Pontos quentes que restam** (`crates/hal/src/lib.rs`, `crates/model/src/config.rs`):
  mudanças mínimas e aditivas; prefira arquivos novos no seu módulo.

## Progresso

- Ao terminar, no mesmo PR, grave **um arquivo só seu**: `docs/changes/<id>.md` (ou
  `<id>-<slug>.md` se a gap tiver mais de um PR). Formato em `docs/changes/README.md`:
  - `status:` o texto novo da coluna Status da sua linha em `docs/gaps.md`;
  - `history:` uma linha para `docs/gaps-history.md`, se você criou, redefiniu ou mudou o status
    de um item;
  - o corpo é a entrada de `docs/log.md`: o que entrou, como testar, números (**medido** ou
    **estimado**);
  - linhas de tabela `| G… |` no corpo são gaps novas (id conferido na `origin/main`).
- **Não edite** `docs/log.md`, `docs/gaps-history.md` nem a coluna Status de `docs/gaps.md`: a
  fila de entrada consolida os arquivos de `docs/changes/` (`cargo xtask docs fold`) um PR por
  vez, logo antes do merge, e nada conflita. `cargo xtask ci` confere o formato (passo `docs`).
- Mudou o critério ou o texto de um item de `docs/gaps.md`, ou a arquitetura? Edite
  `docs/gaps.md` (só a linha do item) ou `docs/architecture.md` direto; são mudanças raras.
- Não crie seções de "histórico de revisão" no fim de outros documentos (geram conflito entre PRs
  paralelos); o histórico do projeto é o `docs/log.md`.
- Notas e estimativas erram para baixo; marque cada número como **medido** ou **estimado**.
