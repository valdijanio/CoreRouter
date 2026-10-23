# CoreRouter — log

Gerado pela fila de entrada: cada PR grava `docs/changes/<id>.md` e `cargo xtask docs fold`
acrescenta a entrada aqui, no fim, logo antes do merge (formato em `docs/changes/README.md`).
**Não edite à mão.** Uma entrada = um item `- AAAA-MM-DD — <id>: …` (pode ter linhas de
continuação indentadas).

- 2026-10-21 — v0.1.0: workspace em 8 camadas, `Session::execute` com 14 comandos
  (interface, ip address, BGP instance, identity, config commit/rollback/diff/mode), guard de
  panic, modos immediate/transactional, canal de controle, MCP stdio (5 tools + aliases), GUI egui
  estilo WinBox (nativo + wasm, `ui.screenshot`), `cargo xtask ci`.

- 2026-10-21 — G0.2: `.github/workflows/ci.yml` — em push/PR para `main`, `cargo xtask ci` em
  ubuntu-latest (toolchain do `rust-toolchain.toml`, deps de sistema do eframe, rust-cache) e
  build de gui/cli/daemon em macOS e Windows. Actions fixadas por SHA. Validado só localmente
  (`cargo xtask ci`); primeira execução no GitHub fica para o push.

- 2026-10-21 — G1.1: `interface.vlan.add`, `interface.bridge.add`, `interface.bridge.port.add`/
  `remove`/`list`, `interface.loopback.add`, `interface.remove` (21 comandos no total). Porta de
  bridge é o campo `Interface.bridge` (uma bridge por porta por construção). Validação: VLAN com
  pai existente, par (pai, vlan_id) único, MTU ≤ MTU do pai, sem ciclo; `interface.remove` recusa
  porta física e diz o que remover antes (endereço, VLAN filha, porta de bridge). Janela
  Interfaces com coluna Info, remover por linha e formulários VLAN/bridge/loopback/porta. 15
  testes novos no engine + 1 na UI; screenshot conferido. Bonding virou G1.8.

- 2026-10-21 — G0.6: persistência da config. `model::persist` (de)serializa running + histórico
  em JSON versionado (`format_version` 1, limite de 64 MiB, invariantes conferidas: revisões
  crescentes, running = última revisão). Trait `ConfigStorage` no engine (slots current/previous +
  quarentena) com `MemoryStorage` (GUI, wasm, testes); crate novo `corerouter-storage-fs` (L4):
  `running.json` / `running.json.prev`, escrita temp + fsync + rename + fsync do diretório, modo
  0600. `Session::with_storage` restaura o slot legível mais novo, salva após cada commit e expõe
  `storage` no `state.inspect`; falha ao salvar não desfaz o commit (log + `last_error`).
  `corerouter-daemon --config-dir <dir>` (padrão `/config` só com `--backend linux`). 24 testes
  novos (3 proptest). Teste manual: endereço sobreviveu a reinício do daemon.

- 2026-10-21 — G1.2: `LinuxHal::apply` aplica no kernel via `rtnetlink` 0.23 (tokio
  current-thread encapsulado no `hal-linux`): links up/down e MTU, VLAN 802.1Q, bridge + portas,
  loopback (`dummy`) e endereços IPv4/IPv6. Plano puro `from` → `to` em ordem segura (11 testes
  unitários); executor lê o kernel antes de cada passo e, se um falha, desfaz os anteriores.
  Só toca interfaces do config; não descobre o `lo`; não apaga link de tipo diferente do config.
  4 testes de integração em network namespace sem root (`cargo xtask netns`, novo passo do
  `cargo xtask ci`; `skip` onde `unshare` sem root é proibido). Na CI do GitHub o workflow
  libera user namespaces (`sysctl kernel.apparmor_restrict_unprivileged_userns=0`).

- 2026-10-21 — G1.9: tabelas estilo WinBox em `crates/ui/src/table.rs`, reutilizáveis: seleção
  da linha inteira (clique, Ctrl, Shift, espaço vazio limpa, Ctrl+A, ↑/↓), filtro Find (Ctrl+F),
  atalhos do WinBox v3/v4 conferidos em help.mikrotik.com (Delete, Ctrl+E/D/M; Enter abre),
  menus de contexto na linha e no espaço vazio. Janela Interfaces (`interfaces.rs`): barra
  +/−/✓/✗/comentário com ícones desenhados (a fonte do egui não tem ✓/✗) e motivo no tooltip
  quando desabilitado; "Add VLAN on <if>", "Add to Bridge ▸"; duplo clique abre a janela
  flutuante "Interface <nome>" (MTU, comment, disabled; pai/VLAN id; portas da bridge; OK/Cancel/
  Apply/Disable/Remove); diálogos New VLAN/Bridge/Loopback (Apply vira a janela da interface
  criada) substituem os formulários fixos do rodapé. Addresses usa a mesma tabela. Só `crates/ui`;
  nenhum comando novo. 4 testes headless dirigidos por eventos sintéticos + 3 de seleção;
  conferido na GUI real (xdotool + `screenshot`).

- 2026-10-21 — G0.4: a GUI gerencia um `corerouter-daemon` (antes só rodava um lab em memória,
  e o que se fazia nela sumia ao fechar). `crates/ui` ganhou o trait `Backend` (`submit` →
  `RequestId`, `poll`, `link`) sobre os métodos do canal de controle; `CoreRouterUi::run`
  continua a única porta de ação, mas o resultado chega num frame seguinte (diálogos esperam a
  resposta com os botões desabilitados; refresh um por vez; resposta atrasada não sobrescreve
  uma mais nova). `Local` mantém o comportamento antigo e os testes headless. Nativo:
  `corerouter-gui --connect HOST:PORT` (thread + reconexão a cada 2 s; "connecting…/
  disconnected" na barra superior, erro na de status; `--control` repassa ao daemon e mantém
  `ui.screenshot`). Web: `corerouter-daemon --ws <porta>` (`control::ws`, `tungstenite` 0.30
  síncrono) com lista de `Origin` (padrão: só a origem da própria porta), `--ws-origin`,
  `--web-root dist` (GUI servida pelo daemon, modelo WebFig); GUI wasm com `web_sys::WebSocket`
  (`?connect=`, `?lab`, ou mesma origem). Sem autenticação/TLS (G0.3): só loopback, dito no log.
  16 testes novos (WS com Origin aceito/recusado, limites, arquivos estáticos; backend remoto
  contra servidor real em `127.0.0.1:0` e queda de conexão; UI com respostas fora de ordem e
  link caindo). Teste manual (**medido**): ether3 desabilitada e ether5 comentada pela GUI
  nativa sobreviveram a reinício de GUI e daemon (revisão 2 restaurada); a GUI reconectou
  sozinha; pela GUI web servida com `--web-root`, ether3 reabilitada (revisão 3); página de
  outra origem recusada (403) até `--ws-origin`.

- 2026-10-21 — G1.10 + G1.11: comentários inline e tema claro/escuro (só `crates/ui` e
  `apps/corerouter-gui`; nenhum comando novo). A tabela reutilizável ganhou a coluna
  `table::comment()` e o item marcável "Inline Comments" nos menus de contexto: ligado, a coluna
  some e o comentário vira uma faixa acima do item (como o "Comment Type: header" do WinBox v4,
  conferido em manual.mikrotik.com, e a linha `;;;` do terminal), com fundo sutil azul, barra e
  ícone de balão desenhados e texto em itálico; a faixa e a linha formam um item só (clique,
  Shift/Ctrl, menu), duplo clique na faixa abre o diálogo Comment, e o Find continua casando o
  comentário. Barra superior: seletor Sistema/Claro/Escuro à direita (função própria, `top_bar`
  intocado). Preferências da janela (`CoreRouterUi::prefs`/`apply_prefs`, JSON) salvas pelo
  eframe com a feature `persistence` (arquivo em `~/.local/share/corerouter-gui` via
  `app_id`, para não cair na pasta de config de um daemon; `localStorage` na web); entrada
  hostil ignorada. Ícones da barra com tons próprios para o tema claro. 4 testes novos (2
  headless dirigidos por eventos, 2 de preferências). Teste manual (**medido**): daemon com
  `--config-dir` + GUI `--connect`, comentários em ether2/ether5, Inline Comments e tema
  claro ligados pela GUI real (xdotool), screenshots nos dois temas conferidos; GUI fechada e
  reaberta voltou em tema claro com os comentários inline.

- 2026-10-21 — G1.5: rotas estáticas e VRF básico. Modelo: `ip.routes` (`RouteEntry` com
  `dst_address` IPv4/IPv6 incluindo `0.0.0.0/0` e `::/0`, `gateway` IP / interface /
  `ip%interface`, `distance` 1..=255, `routing_table`, ids `*N`); VRF = interface tipo `vrf`
  com tabela do kernel própria (1000+) e `Interface.vrf` nos membros. `model::route::reach`
  decide se uma rota vale agora (ativa / inativa / inválida) e é usado pela validação, pelas
  flags de `ip.route.list` (X A D C S; conectadas derivadas dos endereços como `ADC`) e pelo
  `hal-linux`, então engine e kernel não divergem. Comandos: `ip.route.add/set/remove/list`,
  `ip.vrf.add/set/remove/list`; recusa gateway fora de rede conectada da tabela, famílias
  trocadas, bits de host no destino, rota duplicada ou de mesma distância (ECMP fica para
  depois), endereço do próprio roteador, link-local sem interface; remover endereço/interface
  de que uma rota depende é recusado com o comando a usar. `hal-linux`: ops `AddRoute`/
  `DelRoute` (distance → métrica, proto static) e link `vrf`; o kernel apaga rotas de link que
  desce, é recriado, muda de VRF ou perde o último IPv4, e apaga IPv6 de link que desce
  (`keep_addr_on_down=0`, achado no teste de netns) — o plano remove e recoloca isso
  explicitamente para o desfazer funcionar. UI: janela IP › Routes no padrão G1.9 (seleção,
  +/−/✓/✗/Comment, menu de contexto, duplo clique "Route <dst>", "New Route" com Apply que
  vira a janela da rota; gateway "10.0.0.1 reachable ether1"). 30 testes novos (13 de
  comandos, 7 de modelo, 5 de plano, 3 em netns sem root — o de VRF pula com aviso se o kernel
  não tem `vrf`, como o runner do GitHub —, 2 headless de UI).
  Teste manual (**medido**): daemon `--config-dir` + GUI `--connect`; rota padrão criada pelo
  "New Route" (revisão 3), backup distance 10 e `::/0` pela CLI; daemon e GUI reiniciados →
  revisão 5 restaurada com as 3 rotas e flags iguais. Fora do escopo: ECMP, blackhole,
  pref-src, criar VRF pela GUI.
- 2026-10-21 — G1.13: VRF pela GUI (só `crates/ui`; nenhum comando novo). Janela IP › VRF
  (`crates/ui/src/vrf.rs`) na tabela reutilizável do G1.9 sobre `ip.vrf.list`, consultado no
  refresh (`Field::Vrfs`): flag X, nome, tabela do kernel, membros e comentário; toolbar,
  menus, atalhos e comentários inline como em Routes. "New VRF" pede nome e marca os membros
  numa lista de caixas que deixa de fora VRFs, portas de bridge e membros de outra VRF (uma
  bridge entra inteira); Apply cria e abre "VRF <nome>", que edita membros (`ip.vrf.set`
  troca a lista inteira), comentário e Disabled e tem Disable/Remove. Recusas do engine
  (nome `main`, VRF com endereço ou rota) aparecem no diálogo ou no log. Num kernel sem VRF
  (G1.14), + e "Add VRF…" ficam cinza com o motivo no tooltip: a UI consulta `engine.list`
  pelo backend no refresh (`Field::Commands`, `CoreRouterUi::command_allowed`), sem detectar
  nada por conta própria, e funciona igual na GUI remota. 3 testes headless dirigidos por
  eventos sintéticos (um com HAL sem VRF).

- 2026-10-21 — G5.2 (Parte 1): LLDP e escuta passiva de MNDP. `crates/proto-lldp` (L2): codec
  puro de LLDPDU do IEEE 802.1AB (Chassis ID, Port ID, TTL, End, Port/System Description,
  System Name, Capabilities, Management Address; TLVs desconhecidos e de organização guardados
  crus), validação de recepção do 9.2.7.7. `crates/proto-mndp` (L2): **só decodificação** do
  anúncio MikroTik (UDP 5678), escrito a partir do dissector do Wireshark e do manual da
  MikroTik (fontes no topo do crate); o CoreRouter nunca anuncia MNDP. `hal-linux::l2`:
  `LldpIo` (socket `AF_PACKET` por porta, EtherType 0x88CC para 01:80:C2:00:00:0E, envio a cada
  30 s via `due`/`send`, recepção não bloqueante, `allmulticast` ligado e restaurado por
  rtnetlink) e `MndpListener` (IPv4 + IPv6, `IP_PKTINFO` para a interface de chegada), sem
  `unsafe` (`socket2` + `sockaddr_ll` vindo do `getifaddrs` do `nix`). Testes: proptest nos
  dois codecs (1024 casos por propriedade) e `tests/netns_l2.rs` em namespace sem root (LLDP
  entre as pontas de um veth nos dois sentidos, MNDP com a interface certa); `cargo xtask netns`
  agora roda cada binário de teste no seu próprio namespace; os dois codecs entram no passo
  wasm. Integração com a tabela de vizinhos do G5.1 (`ip.neighbor.list` com protocol=lldp/mndp)
  fica para um segundo PR, depois do G5.1. Detalhes em `docs/lldp-mndp.md`.

- 2026-10-21 — G1.12: maximizar e restaurar as janelas internas, estilo WinBox. Todas as janelas
  flutuantes (as do menu e os diálogos de interface) passam por um wrapper único,
  `crates/ui/src/float.rs` (`Floats::show`): a barra de título continua a do egui (▼, arrastar, ✕) e
  ganha, na mesma camada da janela, o botão □/❐ ao lado do ✕ (desenhado; a fonte não tem os
  glifos) e uma faixa só de clique sobre o título — o arraste ainda chega ao egui, o duplo clique
  maximiza em vez de recolher, o botão direito abre Maximize/Restore. Maximizada = `fixed_rect` da
  área central a cada frame (acompanha o redimensionamento) e o corpo ocupa a área toda (o egui
  dimensiona a janela pelo conteúdo). Restaurar usa `fixed_rect` sem `constrain` por um frame (com
  `current_pos` o arraste da barra do egui desfaz a posição; com `constrain` o tamanho maximizado do
  frame anterior empurra a janela para o canto) e corrige o tamanho pedido por até 3 frames, porque
  o conteúdo pode ficar uns px abaixo do pedido (Interfaces: 5 px, **medido**). Recolhida, guarda o
  tamanho expandido. Estado só da UI, não passa pelo engine. 6 testes headless (maximizar ocupa a
  área, restaurar devolve o retângulo, duplo clique, menu, redimensionar a área, arrastar/recolher,
  janela de propriedades); conferido na GUI real (xdotool + `screenshot`).

- 2026-10-22 — G1.14: kernel sem VRF. `Hal::features() -> Features { vrf }` (aditivo, padrão
  "tudo"; `VirtualHal` diz sim). `LinuxHal` sonda uma vez, na primeira consulta, criando um link
  `vrf` descartável (`crvrf<pid>`, tabela fora da faixa do engine; nome ocupado é pulado, só o
  link criado pela sonda é apagado) e guarda o resultado; sonda indecisa (sem `CAP_NET_ADMIN`)
  assume sim e registra o motivo. `ip.vrf.add` ganha `enabled`: sem VRF, fica desabilitado com
  "this kernel has no VRF support (CONFIG_NET_VRF / module vrf)" (menus e `list_commands`
  mostram o motivo); criar link `vrf` com EOPNOTSUPP no `apply` dá o mesmo texto (o rollback já
  era limpo). `Session::hal()` (leitura, `pub(crate)`) é a única mudança em `session.rs`. CI: o
  job Linux roda `sudo modprobe vrf` (com `linux-modules-extra-$(uname -r)` como plano B) e
  `COREROUTER_REQUIRE_VRF=1`, que faz `vrf_routes_live_in_their_own_table` falhar em vez de
  pular e transforma o `skip` do passo netns do xtask em FAIL. Testes: 2 de engine (HAL falso
  sem VRF; lab virtual), 2 unitários do mapeamento de erro/veredito da sonda, 1 em netns (sonda
  = `ip link add … type vrf`, sem sobras). Rodando de verdade, o teste de VRF mostrou uma corrida
  do G1.5: ele e `static_routes_and_link_state` punham `0.0.0.0/0` métrica 1 na `main` do mesmo
  namespace em paralelo (EEXIST em ~1 de 5 rodadas, **medido**); a rota da `main` no teste de VRF
  passou a distance 5 (40 rodadas seguidas limpas, **medido**). `xtask netns` sem `--quiet`, para o
  log da CI listar cada teste.

- 2026-10-22 — G1.4: Safe Mode com a semântica do RouterOS (help.mikrotik.com, "Configuration
  Management"). `config.safe-mode.enter {timeout_secs?}` (10..=86400; o dono de novo re-arma o
  prazo), `exit {force?}` (confirma e salva), `cancel {force?}` (desfaz); `safe_mode` no resumo
  do `state.inspect`. Módulo `engine::safe_mode`: guarda a `Config` da entrada; mudanças de
  qualquer cliente ficam pendentes (revisão `[safe mode]`, não salva); undo = config da entrada
  commitada como revisão nova. Dono por conexão: `Caller` + `Session::execute_as`/`hang_up`;
  `control` dá um id por conexão TCP/WS e avisa quando ela fecha. Relógio: `Session::tick`,
  chamado a cada 1 s por `control::spawn_clock` (daemon e GUI em lab). Segundo `enter` recusado
  com dono e "since <UTC> (N s ago)". GUI: botão na barra superior, vermelho com contagem m:ss
  quando é seu, "Safe Mode: <dono>" quando é de outro; clique direito com timeouts, desfazer e
  release/undo forçado. 13 testes novos (9 de integração no engine + 1 do formato UTC, 2 no
  canal TCP/WS, 1 na UI). Teste manual (**medido**): daemon `--config-dir` + GUI `--connect`, Safe Mode 5 min
  pelo clique direito, ether2 desabilitada (diretório de config continuou vazio), GUI morta com
  `kill` → daemon logou o undo e ether2 voltou habilitada (revisão 2 "safe mode undo: the
  owner's connection closed"). Esforço do agente ~2 h (**estimado**).

- 2026-10-22 — G5.1: descoberta de vizinhos com protocolo próprio, o CRDP (`docs/discovery.md`):
  UDP 7979, `ff02::1` por interface + broadcast IPv4 dirigido, anúncio a cada 30 s, hold 4 ×
  intervalo (120 s), despedida com hold 0; cabeçalho `CRDP`/versão, 13 TLVs (node id, hold,
  identity, versão, plataforma, placa, uptime, interface, MAC, IPv4, IPv6, portas de controle e
  WebSocket), datagrama ≤ 1232 bytes, TLV desconhecido ignorado. Codec puro em
  `crates/proto-discovery` (L2, proptest: decode nunca dá panic, ida e volta, bytes trocados);
  runtime em `crates/discovery` (L4, std + `socket2`): `Agent` do daemon (só anuncia e escuta,
  nunca responde) e `Listener` passivo da GUI. Model: `NeighborEntry`/`NeighborProtocol` (estado
  operacional, nunca salvo) e `ip.neighbor_discovery` (config: padrão ligado e **sem
  interfaces**, porque ainda não há listas LAN/WAN). Engine: tabela de vizinhos (máx. 4096,
  expiração por hold), `Session::record_neighbor`/`expire_neighbors` (ponto de entrada do G5.2),
  `ip.neighbor.list`, `ip.neighbor.discovery.set`/`.get`; `interface.remove` tira a interface da
  lista. Daemon: `--discovery-port`, `--no-discovery`, node id em `<config-dir>/node-id`. UI:
  janela IP › Neighbors (tabela + configurações) e tela de conexão estilo WinBox 4
  (`crates/ui/src/connect.rs`): Connect to/Login/Password/Group/Comment, Save to list, Connect,
  Virtual lab; abas Neighbors/Saved com Find; clique preenche, duplo clique conecta; login e
  senha desabilitados até o G0.3 e nenhuma senha gravada. GUI nativa sem `--connect` abre nela e
  escuta CRDP (vizinho na própria máquina vira `127.0.0.1:<porta>`); web mostra o
  `ip.neighbor.list` do daemon que serviu a página. 37 testes novos, entre eles dois daemons em
  namespaces sem root que se veem em `ip.neighbor.list` por IPv6 puro e por IPv4+IPv6, e se
  esquecem na hora com a despedida (`cargo xtask netns`, ~9 s **medido**). Teste manual num netns
  descartável: dois daemons (7979 e 7981) e a GUI; a aba Neighbors mostrou os dois, o duplo
  clique conectou e IP › Neighbors listou o outro roteador (screenshots conferidos).

- 2026-10-22 — G1.15: teclado nos diálogos e janelas internas, no padrão Windows/macOS/GNOME/WinBox.
  Um lugar só: `crates/ui/src/dialog.rs` (tipo comum de diálogo: `Status` com erro/pendências,
  `Footer` com OK/Cancel/Apply + botões extras, `Form` que dá a cada campo de texto um id com o nome
  do parâmetro do comando) e `Floats::keys` em `float.rs`. Enter = OK (fecha só quando o engine
  aceita; recusa mantém aberto, mostra o erro e põe o cursor no campo de `parameter '<x>'`),
  Ctrl+Enter = Apply, Esc = Cancel sem perguntar; com resposta pendente (backend remoto, G0.4) o OK
  vira "Saving…" e nada reaplica. "•" no título com alterações não salvas — "●" (U+25CF) não existe
  nas fontes do egui e virava um quadrado (**medido** no screenshot). Listas: Esc limpa o Find, depois
  a seleção, depois fecha. Roteamento: as teclas vão à janela que tem o foco ou, sem foco, à de cima
  ainda aberta (o egui mantém janelas fechadas na ordem de camadas; usar `top_layer_id` engolia o Esc
  logo depois de fechar um diálogo — achado no teste manual); popup/combo aberto no início do frame
  fica com Esc/Enter; Enter com foco num botão/checkbox é do widget. De quebra, Enter na tabela (G1.9)
  limpava a seleção antes de abrir as propriedades (o egui transforma Enter num clique do widget com
  foco, e o fundo da tabela tem o id do foco): o fundo agora só aceita clique de ponteiro. 14 testes
  novos (11 headless com eventos sintéticos, inclusive backend que segura a resposta e os diálogos
  de VRF do G1.13; 3 unitários); Esc em camadas também em VRF e Neighbors (G5.1).
  Teste manual (**medido**): `corerouter-daemon --control --config-dir <tmp>` + `corerouter-gui
  --connect`, xdotool + `screenshot`: Enter na tabela abre, "•" ao editar, MTU 10 + Enter mostra o erro
  com o cursor no MTU, Ctrl+Enter aplica 9000 e fica aberto, Esc descarta, Esc em camadas na lista.
  Esforço do agente ~3 h (**estimado**).

- 2026-10-22 — G1.16: ações indisponíveis ficam cinza com o motivo. Motivo real: GUI nova `--connect`
  num daemon iniciado antes do Safe Mode; o clique dava "unknown command 'config.safe-mode.enter'" na
  barra de status. Agora um ponto só (`crates/ui/src/avail.rs`, `CoreRouterUi::can`) responde, por
  comando, a partir de `engine.list` + `server.info` + estado do link (G0.4): ausente no daemon
  ("this router (corerouter X) has no <id>: its daemon is older than this GUI …; update or restart
  it"), `enabled=false` (o `disabledReason` do engine, ex. "no pending changes") ou `connecting…`/
  `disconnected` (mesmo texto do indicador). Lista ainda não carregada com o link de pé não bloqueia.
  Usado em todas as ações: barras +/−/✓/✗/Comment, menus de contexto, botões dos diálogos (via
  `Footer::ok` e `extra` do `dialog.rs` do G1.15: OK/Apply/Enable/Disable/Remove, Add Port, −),
  barra superior (Safe Mode sem menu quando cinza, Commit, Discard), modo de commit, Rollback, Add/Apply
  das janelas simples, Apply do Neighbors. Motivo da UI (seleção, porta física) combina com o do
  roteador, o do roteador primeiro. `CoreRouterUi::run` confere de novo: atalho de tabela, Enter/
  Ctrl+Enter de diálogo ou clique numa ação indisponível não envia nada (o motivo vai para o log e,
  num diálogo, para o erro dele). Nenhuma lista fixa de comandos na UI. 8 testes novos (3 unitários
  do `Avail`; 5 headless com um daemon falso: sem `config.safe-mode.*`, comando desabilitado pelo
  engine, link caído com teclas, comando ausente em barra/menu, OK de diálogo cinza com Enter);
  conferido que falham com o `check` neutralizado. Teste manual (**medido**): daemon compilado de
  `6fbab48` (worktree temporária, `CARGO_TARGET_DIR` próprio) + GUI deste branch `--connect`
  `--control`, xdotool para o hover e `screenshot`: Safe Mode cinza com o tooltip de versão.
  Esforço do agente ~3 h (**estimado**).
- 2026-10-22 — G5.2 (Parte 2): LLDP e MNDP na tabela de vizinhos. Com `--backend linux` o daemon
  (`apps/corerouter-daemon/src/link_discovery.rs`, uma thread) envia LLDP nas interfaces da
  descoberta a cada `interval_secs` com TTL 4 × (System Name = identity, System Description =
  `CoreRouter <versão>`, Chassis ID = node id do CRDP, Port ID = nome, Port Description =
  comentário, Management Address = endereços da interface), reenvia logo quando o conteúdo muda
  e manda TTL 0 quando a interface sai; recebe LLDP e escuta MNDP (UDP 5678, **nunca**
  anunciado) e grava `lldp`/`mndp` com `record_neighbor`. Sem `CAP_NET_RAW` o LLDP fica
  desligado com um aviso claro e o daemon segue (conferido com `setpriv`). `hal-linux`:
  `LldpIo::set_interval`/`ifindex`. Testes: 7 unitários de mapeamento e
  `tests/netns_l2.rs` (dois daemons linux em namespaces, veth ×2; crdp + lldp com o mesmo
  node id, filtro por protocolo, MNDP sintético, interface sem descoberta não grava, TTL 0
  apaga; ~14 s **medido**); helpers dos testes netns do daemon em `tests/common`.

- 2026-10-22 — G5.4: no lab virtual a descoberta CRDP usa o loopback do host. Antes, um
  `corerouter-daemon` virtual anunciava pelas interfaces **reais** com o nome das portas do lab
  (`ether1` não existe no host) e, sem interfaces por padrão, não anunciava nada: a aba Neighbors
  da GUI ficava vazia. Agora `corerouter_discovery::Transport::Loopback` (padrão de
  `--backend virtual`; `--discovery-transport interfaces|loopback` troca) manda um broadcast para
  `127.255.255.255:7979` por porta virtual ativa, de um socket ligado a `127.0.0.1` — nada sai da
  máquina, nada lê `/proc/net/if_inet6` — e só ouve origem loopback. Portas de mesmo nome de todos
  os labs do computador estão no mesmo fio: o vizinho entra na porta com o nome do TLV de
  interface, se ela existe, está habilitada e tem descoberta. Lab novo (config não restaurada)
  roda `ip.neighbor.discovery.set {"interfaces": ["ether1"]}` ao subir, pelo `Session::execute`.
  `--backend linux` inalterado, e passa a descartar origem loopback (é o fio dos labs). O teste
  em namespace do G5.1 roda labs sobre veths e agora pede `--discovery-transport interfaces`.
  4 testes novos: dois labs e o `Listener` da GUI se veem pelo loopback sem namespace nem root
  (`127.0.0.1:7979`/`:7981`), portas de nomes diferentes não se veem, o transporte de interfaces
  ignora o fio do lab, e o mapeamento de porta (unitário). Teste manual (**medido**): dois
  daemons virtuais (`--control 7981`/`7983`, a 7979 estava ocupada por outro daemon) se listaram
  em `ip.neighbor.list` em `ether1`, e a `corerouter-gui --control 7990` sem `--connect` mostrou
  os dois na aba Neighbors como `127.0.0.1 (this machine)` (screenshot conferido).
  No mesmo PR, a pedido do usuário: (a) o lab não tenta mais broadcast de endereços que só existem
  na config (sumiu o `WARN cannot broadcast from 10.0.0.1 on ether1`); no linux o aviso sai uma vez
  por problema (teste com logger que captura); (b) o `Listener` da GUI cacheava para sempre "não é
  local" — a tabela de interfaces era lida antes de a veth existir (releitura a cada 10 s) e o
  bind no link-local falha porque o datagrama chega com o escopo da outra ponta; o duplo clique ia
  para `[fe80::…%2]:7981` e era recusado. Agora "não" vale 2 s, a tabela é relida (≤ 1×/s) e
  endereço tentativo conta como local. Teste em netns (`netns_local`: GUI antes do enlace) falhou
  antes da correção e passa 5/5 depois (**medido**); (c) vizinho de outra máquina fica cinza com o
  motivo (G0.3) e o duplo clique explica em vez de tentar (teste headless); Connect continua
  tentando o endereço do campo. Teste manual em netns descartável: daemon local + daemon num
  namespace filho + GUI — local "(this machine)", remoto cinza com a dica (screenshot conferido).
  Esforço do agente ~3 h (**estimado**).
- 2026-10-22 — G1.17: cores dos comentários nas tabelas. Pedido do usuário a partir de um print: a
  `ether5` desativada (flag X, linha cinza) tinha o comentário no mesmo azul do item ativo, e a coluna
  Comment (Inline Comments desligado) usava texto comum. Agora `table::comment_style(visuals,
  disabled, selected)` é o único lugar dessas cores: ativo no azul de destaque do G1.10, desativado
  (o mesmo `Row::dimmed` da linha) em cinza escuro na faixa, barra, ícone e texto, selecionado na
  cor de texto da seleção. A coluna Comment ganha o balão e o itálico da faixa, com as mesmas cores.
  Vale para Interfaces, Addresses, Routes e VRF sem mudar as janelas. 1 teste headless novo (inline e
  coluna × claro e escuro, ativo/desativado/selecionado, contraste do cinza com o fundo). Teste manual
  (**medido**): daemon de lab `--config-dir <tmp>` + `corerouter-gui --connect --control` com as
  preferências num `XDG_DATA_HOME` descartável, `ether4` "queimou" ativa e `ether5` desativada
  comentada, `screenshot` nos quatro casos conferido. Esforço do agente ~1 h (**estimado**).
- 2026-10-22 — G5.5: o `corerouter-daemon` se despede ao encerrar. SIGINT/SIGTERM chegam pelo
  `signal_hook::flag::register` (o handler só marca um `AtomicBool`, lido a cada 50 ms; mesmo
  caminho no unix e no Windows — o iterador do `signal-hook` só existe no unix e quebrou o build
  do Windows na primeira versão do PR; sem `unsafe` no workspace, sem runtime async; `ctrlc` com
  `termination` também serviria, mas não distingue os sinais no log). Ao receber: `corerouter_control::Shutdown` fecha
  as portas de controle e WebSocket (`serve_until`/`spawn_ws_until`; conexões abertas seguem até o
  fim do processo); `Agent::shutdown` acorda o emissor (agora dorme num canal, não num `sleep`) e
  manda `hold 0` em toda interface onde anunciava, também o loopback do lab; `LinkDiscovery`
  manda o LLDPDU TTL 0; prazo total 1 s; depois a sessão fica travada até o `exit(0)` (commit em
  curso termina, nenhum novo começa a salvar). Safe Mode ativo: só um aviso no log; não salvo,
  então reinicia na config de antes (G1.4). Segundo sinal: sai na hora com 130. `drop` do `Agent`
  também se despede. A GUI nativa já tirava o vizinho ao ouvir `hold 0` (`Listener::poll`); teste
  novo confirma com o `Listener`. Testes: dois daemons de lab reais (processos), SIGTERM e SIGINT
  num deles — o outro o esquece em ~50 ms (**medido**, exigido ≤ 2 s, hold de 4 s) e o processo sai
  com 0 e loga `shutting down: sent CRDP goodbye on 1 interface(s)`; `Agent::shutdown` com lab e
  `Listener`; `Shutdown` fecha as duas portas. Esforço do agente ~1,5 h (**estimado**).

- 2026-10-22 — G1.18: o backend linux descobre links pelo mesmo rtnetlink que aplica (antes lia
  sysfs, que num `unshare --net` mostra o host: o daemon listava `docker0`/`br-*` e falhava em
  `eth0`). Tipos do kernel (`veth`, `bridge`, `loopback`, …) e política de posse: portas físicas,
  veth com par no namespace e o que o CoreRouter criou são gerenciados; o resto aparece em
  `interface.list` com `managed: false` e o motivo, nunca recebe apply e recusa comandos.
  `--manage`/`--unmanaged` no daemon. Seed copia o admin state (boot no-op). G1.7 feito junto.
  Esforço do agente ~2 h (**estimado**).
- 2026-10-22 — G0.3: autenticação, usuários/grupos e TLS. **Engine**: `model::users` (contas
  salvas no `running.json`, fora das revisões: `config.rollback` não restaura senha), comandos
  `user.add/set/remove/list/active.list`, `auth::required_group` (consulta `read`, ação `write`,
  `user.*` `full`) checado em `execute`/`inspect` com o grupo atual do `Principal` do `Caller`,
  `engine.list` por chamador (botões cinza do G1.16), Argon2id com sal do SO, journal com
  `***`, sem lock-out do último `full`, recusa em Safe Mode. **Controle**: `auth::Gate` (token de
  256 bits guardado como SHA-256, comparação em tempo constante, 30 min ocioso/12 h, falhas por
  IP e por usuário: 3 livres, 250 ms dobrando até 8 s, bloqueio com 20 em 15 min, resposta única
  `invalid user or password` com verificação falsa para usuário inexistente), token local em
  arquivo 0600 (CLI/MCP do mesmo usuário do sistema sem senha; outro usuário da máquina precisa
  logar), `Endpoint` loopback ou TLS (`rustls`+`ring`, certificado `rcgen` em `--config-dir`,
  chave 0600, impressão digital no log), `known_hosts` + `dial` (TOFU: primeira vez pergunta,
  igual passa, mudou recusa antes de enviar nada). **Daemon**: `admin` com senha aleatória
  impressa uma vez, `--reset-admin-password`, `--listen`, `--ws-listen` (wss, origem
  `https://`+`Host`), `--token-file`. **CLI/MCP**: `--user` (prompt sem eco ou
  `$COREROUTER_PASSWORD`), `--fingerprint`. **GUI**: Login/Password de verdade, diálogo de
  certificado novo, "Remember password" só com keyring do SO (`keyring`, zbus puro; na web
  nunca), `user: X (grupo)` na barra, re-login automático quando o token expira, proxy
  `--control` com a sessão da janela; vizinhos CRDP com porta TLS (TLV 14/15) conectáveis.
  Testes novos: engine (grupos, máscara, rollback × contas, lock-out, logins), controle (login
  certo/errado, força bruta, expiração, token local, proptest dos params de login, TLS ponta a
  ponta com TOFU nas três situações, texto puro na porta TLS), daemon (processo real: admin
  impresso uma vez, TLS + login, certificado igual após reinício, token local recusado no TLS,
  reset), CLI/MCP pelo token local, GUI (re-login, senha errada para de tentar, tela de
  conexão). Teste manual (**medido**): namespace sem root com `dummy` 10.77.0.1, daemon
  `--listen 10.77.0.1:8729`, GUI por esse IP: diálogo com a mesma impressão do log, admin
  `(full)` com `+` ativo, usuário `noc` `(read)` com `+` e Safe Mode cinza; nenhuma senha nos
  logs. Esforço do agente ~6 h (**estimado**).

- 2026-10-22 — G0.8: terminal com a sintaxe da CLI do RouterOS, **gerado do registro** (crate novo
  `corerouter-shell`, L4, puro e wasm). Menu = prefixo do id, `list`/`get`→`print`, chaves em
  kebab-case, tipos lidos do doc `params` (bool `yes/no`, número, lista `a,b`, enum para o Tab);
  nenhuma tabela por comando (teste percorre `cmd::all()`). Contexto (`/ip address`, `..`, `/`,
  `/ip/address`), abreviação com "did you mean", `?`/F1, Tab (menus, comandos, parâmetros, valores
  de enum, interfaces, ids), `print` com legenda de flags, `;;;`, `where` (and/or, `!`, `=`, `!=`,
  `~`, `<`, `>`), `detail`, `as-json`, `count-only`, `proplist`, itens por número da última
  `print` (vários → batch atômico) ou `*id`. `/export` determinístico em ordem de dependências,
  segredos nunca em claro; `/import file=` e colar = um `engine.batch` atômico (ida e volta
  testada). Ctrl+X Safe Mode, `<SAFE>` no prompt, `/quit` mantém e Ctrl+D desfaz (conferido na doc
  da MikroTik). Front ends: janela "New Terminal" na GUI (várias, histórico, Tab clicável, cópia,
  tema, maximizar) e `corerouter-cli shell` (`rustyline`, histórico persistente sem segredos,
  modo não interativo por pipe). Engine ganhou `system.identity.get`. Tudo por `engine.*` e
  `state.inspect`: permissões, Safe Mode e journal valem igual. SSH (`--ssh`, `russh`) fica para um
  segundo PR, depois do G0.3. Testes: 16 unitários + 14 de integração no shell (2 proptest), 3
  headless na UI; manual: daemon de lab + CLI `--connect` + GUI `--connect` com screenshot.
  Depois do primeiro retorno do usuário (`ping 8.8.8.8` → "bad command name"): metadados
  `alias`/`positional`/`task` no `CommandSpec` (construtores `const`), atalhos em qualquer menu,
  valor posicional, tarefas acompanhadas ao vivo por `tool.task.poll` com Ctrl+C →
  `tool.task.stop` (testado com roteador simulado; o ping real liga-se sozinho), e menos
  requisições: ação = 3 (era ~12), `print` = 1. Esforço do agente ~8 h no total (**estimado**).
- 2026-10-22 — G2.1a: firewall base no modelo do RouterOS (`docs/firewall.md`). Modelo em
  `model::firewall` (tabelas, chains nativas e próprias, matchers em sintaxe RouterOS com `!`,
  ações, seções, IPv4+IPv6 numa lista com `family`) e `model::interface_list` (LAN/WAN padrão).
  Crate novo `corerouter-firewall` (L1 puro: validação + render nftables + grafo de jumps), usado
  pelo engine, pelo `VirtualHal` e pelo `hal-linux` — L1 porque o `hal-linux` não pode depender de
  L2. 27 comandos (`ip.firewall.{filter,nat,mangle}.*`, `address-list.*`, `interface.list.*`,
  `.member.*`); erros apontam o parâmetro. Aplicação: tabela `inet corerouter` trocada inteira por
  `nft -f -` (um lote netlink, atômico), antes do plano netlink e desfeita se ele falhar; entradas
  dinâmicas (timeout) são estado operacional e sobrevivem à troca. Testes: 7 do render/validador
  (golden `full.nft`, carregado também num kernel real), 9 de comandos (sucesso, validação,
  rollback por recusa do data plane e por `config.rollback`, move/place_before, laços, dinâmicas
  com expiração), 1 em netns (aplica, troca, recusa sem mudar nada, preserva tabela de outro
  dono), 6 headless da GUI (seções, cores, diálogo com abas, erro no campo, ▲ e arrastar,
  atalhos, abas de listas). Teste manual: daemon de lab + `corerouter-gui --connect`, regras
  pela CLI, janela e diálogo conferidos em screenshot (repetido depois do merge com G0.3, logado
  pelo token local, arrastando uma regra). Com o terminal do G0.8: `/export` → `/import` do firewall
  testado (listas padrão LAN/WAN viram `set`, `passthrough=no` não se perde, chains próprias e `!`
  digitados no terminal). Esforço do agente ~7 h (**estimado**).

- 2026-10-22 — G6.1 + G6.2: Tools › Ping. Engine ganha tarefas em segundo plano (`tasks.rs`:
  `tool.task.list/poll/stop`, jobs nas threads de um `Runner` que o app instala —
  `control::ThreadRunner` —, anel de 1024 eventos, ≤ 8 rodando, abandono em 60 s, nada no
  journal) e as ferramentas puras em `tools/` (ping com N destinos, MTU por busca binária com DF,
  estatísticas com jitter RFC 3550 e percentis, texto estilo RouterOS). `Hal::prober()` (L1,
  `probe.rs`): `hal-linux::icmp` com ping socket ou raw (`CAP_NET_RAW`), sem `unsafe`
  (socket2 + nix para fila de erros/cmsg/poll + rustix para `IP_MTU_DISCOVER`); `VirtualHal`
  com rede simulada determinística (`sim.rs`) ou a do host (`--lab-ping`). GUI: janela Tools ›
  Ping com `egui_plot` 0.38 (linha da egui 0.37), alertas, histograma, CSV (`ui::Export`,
  salvo pelo app: arquivo nativo, download na web). CLI `watch`, MCP `run_task`; terminal do
  G0.8 usa `alias("ping")`/`positional`/`task`. Testes: 4 em netns com ICMP real (veth e um
  roteador com MTU 1400 em namespaces aninhados), jobs na rede simulada com relógio falso,
  headless da janela. Sem tempos medidos de produção; esforço do agente ~6 h (**estimado**).
  MTR (G6.3) vai no PR seguinte.

- 2026-10-22 — G6.3: MTR. `tool.mtr.start` (rodadas com um probe por TTL, corta no destino ou
  no "unreachable", estatísticas por salto: perda, último/média/melhor/pior/desvio, até 4
  endereços), janela Tools › MTR com tabela ao vivo e barra da média, alias `mtr` no terminal,
  tabela no CLI `watch`. Rede simulada agora perde pacotes só a partir do enlace com perda e o
  jitter cresce com o salto (o MTR do lab mostra onde a perda começa). Esforço do agente ~1,5 h
  (**estimado**).

- 2026-10-22 — G6.5: ferramentas no terminal como no RouterOS. `ping 8.8.8.8`, `/ping`,
  `/tool ping 8.8.8.8 count=5 size=1400`, `/tool ping address=…`, `traceroute`/`mtr`.
  Genérico, sem o shell conhecer o ping: `alias` aceita vários nomes (`"traceroute,mtr"`), um
  menu com o nome de um alias roda o comando dele quando o que vem depois não é nome do menu,
  e `tool.task.poll {text: true}` devolve `header`/`lines`/`summary_lines` renderizados pelo
  engine (`tools::text`). Esforço do agente ~1 h (**estimado**).

- 2026-10-22 — G0.3b: primeiro acesso estilo RouterOS 7, a pedido do usuário (no lugar da senha
  aleatória impressa do G0.3). `admin` nasce **sem senha** (`password_hash: None`, estado
  explícito; `user.list` mostra `no_password`), criado por `Session::bootstrap_admin` na partida
  do daemon; `--reset-admin-password` volta a esse estado. `control::auth::Gate`: senha vazia só
  de loopback, e todo login de endereço não-loopback é recusado enquanto houver conta `full` sem
  senha (`--listen` fora do loopback sobe com aviso). `auth.login`/`auth.whoami` dizem
  `no_password`. GUI (nativa e web): diálogo "Set a password for admin" com "Not now" logo após
  entrar e aviso clicável na barra superior (`ui::first_login`); terminal (`corerouter-shell`,
  CLI e New Terminal) pergunta a senha sem eco e fora do histórico. Definir é o `user.set` normal;
  quem define continua logado. Testes: modelo, engine, `Gate` (loopback × rede), daemon de ponta
  a ponta, terminal, GUI headless (clique em "Not now", aviso aparece e some). Esforço do agente
  ~3 h (**estimado**).

- 2026-10-22 — G0.3c: tela de conexão sem beco sem saída, a pedido do usuário (daemon rodando como
  root num network namespace e a GUI como o usuário: o token local era ilegível e a tela parava
  numa mensagem sobre token; e uma GUI nova num daemon antigo mostrava `unknown method
  'auth.whoami'`). Login vem com `admin`; em loopback a GUI sonda `server.info`, tenta o token
  local e cai para Login/Password; erro = uma frase (`ui::connect::explain`) com o técnico em
  "Details". Roteador anterior ao G0.3 (sem `auth` no `server.info`) é nomeado e, só em loopback,
  "Connect anyway" com aviso `old router: no login` na barra (decisão: esse daemon já aceita
  qualquer processo local, então conectar não reduz a segurança; pela rede ele nem tem TLS). Testes:
  headless (Login preenchido, "Details", "Connect anyway", aviso na barra) e com servidores de
  controle de teste (token legível, ilegível, recusado; senha errada; daemon antigo falso). Manual
  **medido**: daemon com o token em 000, daemon de 6fbab48 e token legível, com screenshots. Esforço
  do agente ~2 h (**estimado**).

- 2026-10-22 — G1.19: abas do diálogo de interface (parte 1, só leitura), a pedido do usuário.
  Engine: `interface.ethernet.monitor`, `interface.hardware`, `interface.stats` (consultas, no
  terminal pelo registro), "não suportado" como `available: false` + motivo, e `link_watch`
  anotando a hora das subidas/quedas a cada `tick`/`interface.list`. HAL: tipos em `hal::nic` e
  três métodos aditivos com padrão "não suportado"; `VirtualHal` simulado e determinístico.
  `hal-linux`: cliente genetlink síncrono próprio (`genl.rs`, socket do `netlink-sys`, codec puro
  com proptest) para as famílias `ethtool` (link modes/info/state, pause, features, rings,
  channels, grupos de estatística padrão) e `devlink` (firmware), rtnetlink para MAC de fábrica,
  MTU, filas, dispositivo pai, portadora e stats64, sysfs do dispositivo e `pci.ids` (parser
  puro com proptest); nada de ioctl. GUI: abas General/Status/Hardware/Traffic/Statistics no
  "Interface <nome>" (`ui::iface_tabs`), gráfico bps/pps com `egui_plot`, "Zero view" só na
  janela. Testes: engine, netns com veth (4), headless (2), unitários; conferido na placa Wi-Fi
  da máquina (só leitura: offloads batem com `ethtool -k`) e por screenshots no Xvfb. G1.20
  (Ethernet configurável, SFP/DOM, teste de cabo) registrado. Esforço do agente ~5 h
  (**estimado**).

- 2026-10-22 — G4.7a: cliente DHCPv4 na WAN, estilo `/ip dhcp-client` do RouterOS, a pedido do
  usuário (a porta real eno1 não pegava IP sozinha). `ip.dhcp-client.add/set/remove/list/renew/
  release/options/history` (add-default-route yes/no/special-classless, distância, tabela/VRF,
  use-peer-dns/ntp, host-name, client-id, vendor-class, opções extras na sintaxe do RouterOS,
  servidores permitidos por IP/MAC). Máquina de estados pura em `proto-dhcp` (T1/T2, backoff,
  NAK, DECLINE por ARP) rodando em `Session::dhcp_service` a cada 250 ms (`control::spawn_clock`);
  endereço e rotas como entradas dinâmicas (flag D) que o HAL vê junto da config em todo apply;
  `hal-linux::dhcp` sem unsafe (`AF_PACKET` + BPF, UDP 68, ARP); servidor simulado no lab;
  janela IP › DHCP Client com abas DHCP/Status/Advanced/Options e histórico no Log. O proptest
  achou dois `panic` no `dhcproto` 0.15 com pacotes malformados; o decode agora passa por um
  saneador. Testes: 32 no `proto-dhcp`, 15 de integração no engine, netns com daemon real e
  servidor DHCP em Rust (concessão + rotas no kernel em ~3 s **medido**), UI headless, terminal.

- 2026-10-22 — G1.20: abas do diálogo de interface (parte 2), a pedido do usuário.
  `interface.ethernet.set` (autonegociação, velocidade/duplex forçados, modos anunciados com nomes
  do kernel ou do RouterOS 7.12+, controle de fluxo on/off/auto, offloads, `reset`) validado contra
  o que a porta diz antes de aplicar; na config (`Interface::ethernet`), journal, histórico,
  rollback e Safe Mode. Porta de gerência (a do IP do cliente remoto, via VLAN/bridge/VRF): mudança
  de link e teste de cabo pedem Safe Mode ou `force`. SFP/SFP+/QSFP: `hal::sff` decodifica
  SFF-8472/8636 (calibração externa, checksums, limites do módulo) com proptest e 4 dumps reais
  publicados; `interface.ethernet.monitor` ganha `sfp` (identidade, DOM, níveis, alertas);
  `engine::dom_watch` registra só as travessias de limite (e insere/remove), a cada monitor e a
  cada 30 s. Teste de cabo como tarefa (G6.1), resultado por par e `cable-pairs` do RouterOS.
  `hal-linux`: `LINKMODES_SET`/`PAUSE_SET`/`FEATURES_SET` com retrato da porta antes da primeira
  mudança (tirar da config restaura), `MODULE_EEPROM_GET`, `CABLE_TEST_ACT` + notificação do grupo
  `monitor`; tudo ou nada no `apply`. `VirtualHal`: ether8 vira gaiola SFP+ com módulo e DOM, teste
  de cabo com um par em curto no ether7. GUI: abas Ethernet (form + offloads + "Cable Test" +
  "Reset to Port Defaults", cinza com o motivo) e SFP (DOM colorido por nível, `SFP ⚠` na aba).
  Testes: codec SFF (dumps reais + proptest), parser da notificação de cabo (proptest), engine
  (sucesso, validação, rollback, Safe Mode e queda da conexão, plataforma sem ethtool, tarefa),
  netns sem root com veth (offloads aplicados e restaurados no kernel; link/pause/EEPROM/cabo pelo
  caminho "não suportado"), headless das abas; screenshots conferidos. Fora: LED (ioctl), `/export`
  de `/interface ethernet`, FEC. Esforço do agente ~5 h (**estimado**).
- 2026-10-22 — G0.9: `cargo xtask bench` (criterion 0.8 como dev-dependency, sem plots/rayon).
  Um build de todos os `benches/` e um resumo legível (mediana, IC 95%, tempo por item, variação
  contra a rodada anterior ou `--baseline <nome>`; `--save-baseline`, `--quick`, `--markdown`
  para o `docs/perf.md`). 31 benchmarks: canal de controle (TCP e TLS, `ping` e
  `interface.list`), `Session::execute` (list/add/filter add/erro), `VirtualHal::apply` e
  `LinuxHal::apply` de 100/1000 endereços, rotas e regras (o do kernel num namespace sem root,
  `netns_*`, pulado com aviso onde não dá), codecs DHCPv4/LLDP/CRDP/MNDP. Números **medidos**
  (Ryzen AI MAX+ 395, release): `ping` 7,4 µs (TLS 8,3 µs), `ip.address.add` 16 µs, netlink
  ~20 µs por endereço/rota, `nft -f` ~20 ms fixos + ~13 µs/regra, decode DHCP 0,57 µs. Passo
  `bench-check` no `cargo xtask ci` (+10,5 s **medido**): roda cada benchmark uma vez em debug.
  Como testar: `cargo xtask bench --quick`; `cargo xtask bench-check`.
- 2026-10-22 — G2.1b: firewall seguro e fácil (`docs/firewall.md` §6–§11). **Lockout:** o canal
  de controle dá ao `Caller` o `Link` da conexão; todo commit que mexe no firewall passa os pacotes
  dela (estabelecido em input, resposta em output, login novo em input e em dstnat) pelo firewall
  atual e pelo candidato (`firewall::eval`) e recusa o que os cortaria, salvo `force` ou Safe
  Mode; na GUI a recusa vira a janela "This change would lock you out" (Safe Mode e aplicar /
  aplicar mesmo assim / cancelar). **Sombras:** `firewall::shadow` por inclusão de matchers
  (`shadowed_by` e flag `S`; linha na cor de aviso). **Defaults** (`ip.firewall.defaults.apply`,
  estilo `defconf` do RouterOS com IPv6 e `lo`), **5 modelos** (`ip.firewall.template.*`:
  redirecionar porta, bloquear endereço, força bruta em estágios, limitar ping, gerência só da
  LAN), **zonas** (`ip.firewall.zone.*`: matriz de→para gerando um bloco marcado `Z`, edição
  manual dele recusada, `detach` devolve as regras). Para a força bruta: ação
  `add-src/dst-to-address-list` (o kernel não insere em set de intervalos pelo caminho dos
  pacotes, então a lista ganha um set `ad*` e a regra que a casa vira duas disjuntas) e matcher
  `limit`. **Descrição** em português por regra (`firewall::describe`) e cores por ação com
  contraste ≥ 4,5:1 nos dois temas. Testes: 7 unitários do crate firewall (avaliador, sombras,
  descrição), golden atualizado, 1 netns novo (um SYN enche o set dinâmico, a troca preserva, a
  regra conta), 13 do engine (lockout com conexão simulada em 8 situações, sombras, defaults,
  modelos, zonas), 1 do canal de controle real (lockout por `lo` e `force`), 7 headless da GUI
  (descrição/sombra, botões cinza nas regras Z, assistentes, matriz nos dois temas, contraste,
  janela de lockout e cancelamento que volta ao assistente). Teste manual: daemon de lab +
  `corerouter-gui --connect` num Xvfb isolado; defaults, modelos, zonas e o aviso de lockout
  (bloquear 127.0.0.1 pela própria GUI → janela → Safe Mode e aplicar) conferidos em screenshot.
  Esforço do agente ~6 h (**estimado**).
- 2026-10-22 — processo: proteção da main sem "branch atualizada" (strict=false) para dar vazão; workflow `main-red` abre/fecha a issue "main quebrada" quando o CI da main falha/volta; AGENTS.md: trazer a main antes do PR, main vermelha é prioridade zero, ids de gap só do brief/main, sessões não abrem sessões, PRs pequenos, pontos quentes com mudanças mínimas. Medido antes: CI de PR mediana 2,0 min, 1,6 execuções por PR.
- 2026-10-22 — G4.7b: cliente DHCPv6 estilo `/ipv6 dhcp-client` do RouterOS (RFC 9915): IA_NA +
  IA_PD, Rapid Commit, retransmissão da §15, limite de taxa da §14.1, NoBinding/NotOnLink,
  validades por binding, sem Release ao parar; codec próprio (`proto-dhcp::v6`; o `dhcproto` v6
  dá panic com bytes hostis). Prefixo delegado vira pool; `ip.address.add address=::1/64
  from_pool=pd` numera a LAN e renumera com o prefixo. `ipv6.settings` decide o `accept_ra` de
  cada interface (padrão `auto`: só onde há cliente DHCPv6) e o hal-linux limpa na hora o que o
  kernel aprendeu por RA onde ele deixa de valer (o caso do endereço do provedor na `eno1`).
  Endereços/rotas de RA e DHCPv6 com flag D e origem nas listas; janelas IPv6 › DHCPv6 Client,
  Pool e Settings; terminal `/ipv6 …`. Testes: 26 novos no `proto-dhcp` (codec + máquina com
  relógio simulado + proptest), 10 de integração no engine, netns com daemon real, servidor
  DHCPv6 e RAs em Rust (teste inteiro em ~4,3 s **medido**), UI headless e terminal. Como testar:
  `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p
  corerouter-daemon --test netns_dhcp6`; no lab, `ipv6.dhcp-client.add interface=ether1
  request=address,prefix pool_name=pd` e IPv6 › IPv6 Pool.
- 2026-10-22 — processo: workflow `pr-sync` (`scripts/pr-sync.sh`): a cada push na `main`, os PRs
  com auto-merge que o GitHub marca CONFLICTING recebem o merge de verdade da `main` (o GitHub
  ignora o `merge=union` e marcava conflito só por causa de `docs/log.md`/`docs/gaps-history.md`);
  merge limpo → push do bot e `ci` disparado por `workflow_dispatch` (push com GITHUB_TOKEN não
  dispara workflows); conflito real → comentário com os arquivos e rótulo `conflito`, sem push.
  O `ci` ganhou `workflow_dispatch`. Testado localmente com repositório e `gh` falsos (union limpo
  enviado, conflito real só comentado). Observado antes: com o merge do #37, #40/#41/#42 viraram
  CONFLICTING no GitHub e o merge local do #40 saiu limpo.
- 2026-10-22 — G1.21: hierarquia das janelas internas, a pedido do usuário (com um diálogo aberto,
  clicar na lista o mandava para trás, e pedir os detalhes de novo não o trazia de volta). Um lugar
  só, `Floats` em `crates/ui/src/float.rs`: relação filho→pai por janela (`Floats::adopt`, ligada
  por `dialog::Head::parent`, que cada família de diálogos preenche com a sua lista: Interfaces,
  Routes, VRF, Firewall com os assistentes do G2.1b, Interface List). Modelo das janelas *owned* do Windows / *transient-for*
  do GTK: o filho fica sempre acima do pai (o egui só sabe "subir" um conjunto mantendo a ordem
  relativa, então ao subir o pai os descendentes sobem no mesmo frame, e uma janela pedida no frame
  em que a família sobe sobe no seguinte), e o teclado vai à janela *ativa* (a clicada, pedida ou
  aberta por último), que pode estar sob os próprios filhos. Pedir de novo (`Status::bring_to_front`,
  `Floats::raise`): sobe, toma o foco e pisca a borda por ~0,6 s. Filho abre abaixo do cabeçalho
  da tabela do pai e a 30 % da largura dele (48–240 px), em cascata de 24 px: a primeira tentativa (36, 44) cobria o "+" da lista e
  quebrou um teste do VRF, e (48, 92) cobria o meio das linhas com o diálogo maior do G1.19 (dois
  testes que clicavam no centro da linha); agora os nomes das outras linhas ficam clicáveis
  (**medido**). Fechar o pai: filhos limpos fecham junto (`Floats::close_family`/`take_close`);
  com alterações, `egui::Modal` "Close <pai>?" (Close All / Cancel / Esc). Extras: marca na linha
  cuja janela está aberta (`TableState::open`, clique traz a janela) e Ctrl+Tab / Ctrl+F6 (atalho do
  WinBox) com Shift ao contrário; no navegador o Ctrl+Tab é da aba, o Ctrl+F6 fica. 8 testes headless
  novos; conferido na GUI real num Xvfb próprio (screenshots). Esforço do agente ~3 h (**estimado**).
- 2026-10-22 — processo: os pontos quentes que todo PR editava viram registros gerados a partir dos
  arquivos (medido nos 40 commits anteriores: `ui/src/lib.rs` em 23, `xtask/src/main.rs` em 13,
  `ui/src/windows.rs` em 13, `engine/src/cmd/mod.rs` em 10). `crates/engine/build.rs` registra
  cada `src/cmd/<área>.rs` (áreas em ordem de nome de arquivo); `crates/ui/build.rs` declara os
  módulos de `src/`, os testes de `src/tests/` e os **painéis** (`ui/src/panel.rs`: janela com
  estado, consultas, respostas e diálogos próprios, `Win::Panel(id)`, menu alfabético por grupo);
  `cargo xtask netns` descobre `tests/netns*.rs`. IP › DHCP Client e as janelas IPv6 viraram
  painéis. Regras em AGENTS.md ("Arquivo novo em vez de lista compartilhada").
- 2026-10-22 — processo (pr-sync): o rótulo `conflito` sai na próxima execução em que o PR não
  conflitar mais, inclusive quando a sessão dona resolveu à mão (antes só saía quando o próprio
  pr-sync fazia o merge). Rótulos pela API REST (`gh pr edit --add-label/--remove-label` falha no
  gh 2.45 por causa dos Projects clássicos, e o erro era engolido). Sem aviso de conflito quando a
  branch andou durante o merge (no #42 o comentário listou um conflito que já tinha sido resolvido
  17 s antes). Testado com `DRY_RUN=1` num clone descartável, com e sem o rótulo.

- 2026-10-22 — processo: Fila de entrada e arquivos de mudança por PR, no lugar do merge automático + `pr-sync`. Cada PR
  grava `docs/changes/<id>.md` (log, status da gap, histórico, gaps novas) em vez de editar
  `docs/log.md`, `docs/gaps-history.md` e a coluna Status de `docs/gaps.md`; `cargo xtask docs`
  confere o formato no CI e `cargo xtask docs fold` consolida. As sessões não ligam mais o
  auto-merge: a sessão principal pergunta ao usuário por lote ("N features prontas — subir?") e
  roda `scripts/land.sh`, que integra um PR por vez (traz a `main`, faz o fold, envia, espera o CI
  do PR e faz o squash). A proteção da `main` volta a exigir branch atualizada, então o CI de cada
  PR roda sobre a `main` em que ele vai entrar: "sozinho passa, junto quebra" (como o `from_pool` e
  o `Head.parent` em 2026-10-22) para no PR, não na `main`. Saem o workflow `pr-sync` e o
  `scripts/pr-sync.sh`; o #46 foi fechado sem merge. Números do dia (**medido**): 46 PRs, 86 runs
  de CI nos PRs e 46 na `main`.

- 2026-10-22 — processo: CI mais rápido, com números em `docs/perf.md` ("CI e build"). O job `xtask ci (linux)` chegou a
  775 s num PR (**medido**): 416 s só para carregar o módulo `vrf` instalando o
  `linux-modules-extra` inteiro. Agora o `vrf.ko` sai do `.deb` baixado (cai na instalação
  completa se o `insmod` falhar); sem debuginfo no CI (cache de ~2,5 GB, 70 s para restaurar);
  `cargo nextest` no passo `test` do `cargo xtask ci` quando instalado (`COREROUTER_NEXTEST=0`
  força o `cargo test`), com `cargo test --doc` só se algum comentário de documentação tiver
  código Rust. Localmente os testes caíram de 29,7 s para 14,3 s (**medido**). `sccache` medido e
  descartado (0% de acerto entre pastas de build; build nova já leva 27 s).
  Também corrige um teste instável que derrubou o CI deste PR: no `netns_icmp`, o primeiro ping
  IPv6 logo depois de o laboratório subir pode voltar "unreachable" enquanto o roteador resolve o
  host; os testes que esperam eco agora tentam de novo (`ask_echo`) antes de reprovar.

- 2026-10-22 — processo: Mais tempo tirado do CI (números em `docs/perf.md`, "CI e build"). Os testes em namespace
  (`cargo xtask netns`) compilam todos os binários num `cargo test --no-run` e rodam os 11 ao mesmo
  tempo, cada um no seu user + network namespace descartável, como antes, com a saída agrupada
  por binário: de 33–36 s para ~9 s nesta máquina (**medido**, 32 núcleos, build pronto). No CI,
  os pacotes do `apt` vêm de cache (`awalsh128/cache-apt-pkgs-action`, fixado por SHA), sem o
  `apt-get update` que variava de 14 s a 114 s; o passo do `vrf` só atualiza a lista de pacotes
  quando precisa baixar o módulo.

- 2026-10-22 — processo: Perfil de build enxuto: `debug = "line-tables-only"` no código do workspace e sem debuginfo nas
  dependências (`[profile.dev]`). Uma `cargo xtask ci` do zero numa pasta de build nova (o que
  cada sessão em paralelo faz) caiu de 15 GB e 163 s para 6,6 GB e 135 s (**medido**, 32 núcleos):
  com 63 GB livres, cabiam 4 sessões; agora cabem 9. Achado da bateria de 10 features da fila de
  entrada. Backtraces e mensagens de panic continuam com arquivo e linha.

- 2026-10-22 — processo: O `docs/perf.md` passa a ser consolidado pela fila, como o log: medições novas vão na seção
  `## perf` do `docs/changes/<id>.md`, e `cargo xtask docs fold` as acrescenta no fim do
  `perf.md`. Achado da bateria da fila de entrada: o #49 e o #50 acrescentaram no fim do `perf.md`
  e o segundo parou na fila com conflito real. `xtask/src/changes.rs` ganhou a struct `Docs` (os
  quatro documentos do fold) e testes da seção nova.

- 2026-10-22 — G0.8: Terminal (pedido do usuário): `print` cabe na largura do terminal e `/export` exporta a matriz de
  zonas. Um `print` largo (`/ip dhcp-client print`, `/ip firewall filter print`) esticava a janela
  Terminal da GUI até a linha mais longa (no teste, de 760 para 3246 px): agora o shell recebe a
  largura (`Shell::set_width`; GUI pela largura visível da janela, CLI pela do terminal) e mostra
  as colunas que cabem, como o RouterOS, com uma última linha "N more columns (…): print detail,
  or print proplist=…"; `proplist` explícito sai inteiro; linha comprida rola para o lado. No
  `/export`, a matriz de zonas saía como "# set: from is not exported" e as regras que ela gera
  saíam como regras soltas em `/ip firewall filter` (no `/import`, duplicadas e desligadas da
  matriz): agora sai `/ip firewall zone set from=… to=… action=…` por célula e as regras geradas
  ficam de fora (regra genérica: uma linha com `<menu irmão>=true` foi gerada por esse menu). Testes:
  ida e volta export → import → export da matriz, tabela com largura, janela que não cresce.

- 2026-10-22 — processo: Bateria da fila de entrada (pedido do usuário): 10 features sintéticas (`scripts/bench-queue/`)
  de ponta a ponta numa base descartável (`bench/queue`), com um conflito de texto, uma quebra
  "sozinho passa, junto quebra", uma gap nova e uma mudança de status de propósito. Resultado: a
  fila integrou as 10, parou nas duas quebras (conflito em 3 s; CI vermelho em 57 s, antes da
  base) e voltou depois da correção da dona (5 s e 10 s). Achados corrigidos aqui: o teste de
  latência do canal de controle reprovava PR bom sob carga (agora o pedido mais rápido de 40, 20 ms);
  o download do `linux-modules-extra` para o `vrf` chegou a 82 kB/s (10 min) — o `vrf.ko` fica no
  cache do Actions por versão do kernel, o download tem teto de 2 min e, se estourar, o CI segue
  sem o teste de VRF com aviso. Achados já entregues em outros PRs: perfil de build enxuto (#50) e
  `docs/perf.md` pela fila (#51).

- 2026-10-22 — processo: Teste de latência do canal de controle (`a_persistent_connection_answers_in_milliseconds`) sem
  falso negativo sob carga: na bateria de 10 features, com 10 `cargo xtask ci` ao mesmo tempo, a
  mediana de 40 pedidos passou dos 5 ms e reprovou um PR bom. Agora vale o pedido mais rápido dos
  40, com limite de 20 ms: o atraso de Nagle (~40 ms) atinge todo pedido e continua reprovando; a
  carga só atrasa alguns.

- 2026-10-22 — processo: Teste `failure_rolls_back_every_done_step` (netns) sem falso negativo: a comparação dos
  endereços ignora o estado `tentative` do DAD do IPv6, transitório logo depois de o link subir
  (reprovou o CI do PR da bateria).

- 2026-10-22 — processo: Fila de entrada em lote (`scripts/land.sh --batch`), a pedido do usuário: um CI para a
  combinação de todos os PRs prontos, não um por PR. A fila junta a `main` e os PRs numa branch
  temporária, faz o fold e roda o CI (`workflow_dispatch`); verde, faz o squash de cada PR em
  ordem sem esperar mais CI (a `main` termina igual à combinação testada) e um PR do fold;
  vermelho, cai no modo um por um para achar o culpado; um PR que conflita com o lote fica de
  fora. A proteção da `main` deixa de exigir branch atualizada (o lote testa a combinação). Com 7
  PRs: ~2,5 min de CI em vez de ~17 min (7 × ~2,5 min, **estimado** pela bateria).

- 2026-10-22 — processo: Integração mais rápida, depois da rodada de 7 agentes (do primeiro PR pronto, 45 min sem nenhum
  entrar): portão em duas camadas e teste instável que não trava a fila. No PR, `cargo xtask ci
  --fast` (sem os testes contra o kernel e o `bench-check`); no lote da fila de entrada
  (`workflow_dispatch`), no modo um por um (a fila dispara o completo no commit que vai entrar) e
  na `main`, o completo. `nextest --retries 1` e, no passo `netns`, o binário que falha roda de
  novo sozinho num namespace novo: passar na segunda vez é instável (aviso no CI), não falha. As
  sessões ficam "prontas para a fila" ao abrir o PR, sem esperar o CI do GitHub. Motivo: quatro
  testes instáveis em 2026-10-22 (latência, ping IPv6, DAD, `netns_l2`), cada um travando a fila
  por 5–10 min.

- 2026-10-22 — G0.7: MCP, parte 1: o servidor declara `resources`, `prompts` e `completions` no `initialize`.
  Resources `corerouter://state`, `corerouter://commands`, `corerouter://diff` e os templates
  `corerouter://command/{id}` e `corerouter://state/{path}` (JSON, mesmas permissões das tools;
  inexistente → `-32002` com `data.uri` e sugestão de id). Prompts `configure_address` (endereço
  + rota numa transação revisada, Safe Mode se for a gerência), `review_and_commit` (embute estado
  e diff, explica riscos, commit só com o "sim") e `diagnose_connectivity` (rota, interface, ping,
  MTR, sem mudar nada); argumento inválido → `-32602`. `completion/complete` sugere ids de
  comando, caminhos de estado e interfaces. Como testar: `cargo test -p corerouter-mcp` (6 testes
  de protocolo novos + proptest de params hostis) ou, no Claude Code com
  `claude mcp add corerouter -- corerouter-cli mcp`, `@corerouter:corerouter://state` e
  `/mcp__corerouter__review_and_commit`. Detalhes em `docs/mcp.md`.
- 2026-10-22 — G1.3: Drift, parte 1: `config.drift.list` diz onde o kernel não tem mais o que a config em execução
  (mais o que os clientes DHCP instalaram) pôs lá — link virtual apagado, porta derrubada, MTU
  trocado, porta tirada da bridge/VRF, endereço apagado ou a mais, rota estática apagada ou a mais
  num link gerenciado. Endereço que o kernel fez sozinho (SLAAC, link-local IPv6), rota de outro
  protocolo e link de outro programa não são drift. `config.drift.reconcile` põe de volta (tudo ou
  nada por rodada, até 3 rodadas enquanto houver progresso: entrar numa VRF derruba IPv6, que a
  rodada seguinte recoloca), não muda a config nem a revisão e fica no journal; porta física que
  sumiu fica como `fixable: false`. Se a conexão de quem chama chega por um endereço fora da config,
  o reconcile recusa removê-lo (diz para `ip.address.add` ou `force: true`), como o lockout do
  firewall. O motor fica em `corerouter_hal::drift` (o que a config põe no kernel, `diff`,
  `repaired`); o hal-linux lê endereços (`IFA_F_PERMANENT`) e rotas `proto static` por rtnetlink e
  gera os ops de reparo (`plan::repair`, na ordem do `plan`); o lab virtual guarda um "kernel" que
  o teste altera (`VirtualHal::kernel()`).

  Testar: `cargo test -p corerouter-engine --test drift` (lab: cada tipo de drift, porta sumida,
  candidate não conta, proteção da conexão, params inválidos);
  `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_drift`
  (kernel real: `ip addr del`, `ip link del` da VLAN, `ip link set nomaster`, MTU, rota a mais →
  drift visto e reconciliado, conferido com `ip`). Na mão: daemon `--backend linux` num namespace,
  `ip addr del …`, depois `corerouter-cli run config.drift.list` e `config.drift.reconcile`.

- 2026-10-22 — G4.4: Prometheus, parte 1: `corerouter-daemon --metrics 9100` serve `/metrics` no formato de texto do
  Prometheus 0.0.4 (`text/plain; version=0.0.4`) em 127.0.0.1:9100; `--metrics 0.0.0.0:9100` (ou
  `[::]:9100`) abre para a rede com um aviso no log (sem login, como o node_exporter). Cada scrape
  roda a consulta nova `system.metrics` (tudo é comando: CLI e MCP leem os mesmos números), que
  traz por interface (config + links da plataforma, inclusive não gerenciados) bytes, pacotes,
  erros, descartes, `running`, `disabled` e quedas de link vistas pelo motor, e os contadores do
  motor desde o início: comandos de mudança e consultas por resultado, ids desconhecidos, commits
  aplicados e recusados, revisão e Safe Mode. O daemon renderiza com nomes no estilo
  netdev/netclass do node_exporter (`corerouter_interface_receive_bytes_total{interface="ether1"}`,
  `corerouter_interface_up`, `corerouter_interface_info{type,managed}`,
  `corerouter_commands_total{kind,result}`, `corerouter_commits_total{result}`,
  `corerouter_config_revision`, `corerouter_safe_mode`, `corerouter_build_info`,
  `corerouter_scrape_duration_seconds`); contador que a plataforma não tem não gera amostra (nunca
  um zero inventado). Servidor HTTP mínimo em `std`: só `GET`/`HEAD` de `/metrics` e `/` (405 com
  `Allow`, 404, 400), uma conexão por vez, cabeçalho limitado a 8 KiB e 2 s no total, escrita com
  5 s de timeout; valores de label escapados (`\`, `"`, quebra de linha) e truncados em 128
  caracteres. Contadores do motor em `crates/engine/src/metrics.rs` (dois incrementos em
  `session.rs`: `execute` e o commit).
  Testar: `cargo run -p corerouter-daemon -- --metrics 9100` e `curl -s 127.0.0.1:9100/metrics`;
  `cargo run -p corerouter-cli -- run system.metrics`. Testes: `crates/engine/tests/metrics.rs`,
  unitários do formato em `apps/corerouter-daemon/src/metrics.rs` (regras do formato: HELP/TYPE
  uma vez antes das amostras, famílias sem intercalar, `_total` só em counter, série sem repetir) e
  `apps/corerouter-daemon/tests/metrics.rs` (daemon real: scrape, contador sobe depois de um
  `ip.address.add`, HEAD/POST/404, pedido de 64 KiB cortado). Custo de um scrape no laboratório
  virtual com 8 portas: uma consulta à plataforma por interface (`counters`) sob o lock da sessão,
  **estimado** abaixo de 1 ms; no linux cada interface abre o ethtool, então com centenas de
  interfaces o scrape pesa (vira medição no G4.4c).

- 2026-10-22 — G4.7c: Cliente DHCP, parte 3 (resiliência). Cada ACK é lembrado no estado `dhcp-leases` do
  armazenamento (`state-dhcp-leases.json`, fora da config e das revisões; `ConfigStorage` ganhou
  `load_state`/`save_state` com padrão vazio). Ao recomeçar (daemon reiniciado, cliente ou
  interface reabilitados) o cliente faz INIT-REBOOT: REQUEST broadcast com a opção 50 e sem a 54;
  ACK → bound sem DISCOVER; NAK → esquece e descobre; ~12 s sem resposta → usa a concessão
  lembrada pelo resto do tempo (RFC 2131 §3.2) ou, vencida, DISCOVER pedindo o mesmo endereço.
  `fallback_address` sobe após `fallback_timeout` s sem concessão (padrão 30) e sai no mesmo apply
  em que uma chega. `check_gateway` (none/arp/ping) checa o gateway a cada 10 s; após 2 falhas as
  rotas por ele saem do data plane (inativas em `ip.route.list`; a de distância maior assume) e
  voltam na primeira resposta. O `list` mostra `gateway_status`, `fallback_active` e `remembered`;
  na GUI, campos novos nas abas Advanced e Status. Desenho e pesquisa em `docs/dhcp-client.md` §15.

  Testar: `cargo test -p corerouter-engine --test dhcp_resilience`, `cargo test -p
  corerouter-proto-dhcp client`; netns: `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user
  --net -- cargo test -p corerouter-daemon --test netns_dhcp_resilience` (check-gateway tira a rota
  padrão do kernel e a devolve; o daemon reiniciado manda REQUEST e nenhum DISCOVER; ~25 s,
  **medido**). Lab: `ip.dhcp-client.add {"interface":"ether1","check_gateway":"arp","fallback_address":"192.168.100.2/24"}`.

- 2026-10-22 — G1.8: Bonding (`/interface bonding` do RouterOS v7). Comandos `interface.bonding.add {name, slaves, mode, primary?, transmit_hash_policy?, lacp_rate?, mii_interval?, min_links?, mtu?, comment?}`, `interface.bonding.set` (troca slaves e parâmetros) e `interface.bonding.list`; `interface.remove` apaga o bond e solta os slaves. Os 7 modos do Linux com os nomes do RouterOS (`802.3ad`, `active-backup`, `balance-rr`, `balance-xor`, `broadcast`, `balance-tlb`, `balance-alb`; `lacp` também vale). O modo é obrigatório (o padrão `balance-rr` do RouterOS embaralha a ordem dos pacotes e precisa de LAG estático no switch). Slave só pode ser porta ethernet sem endereço, cliente DHCP/DHCPv6, VLAN, bridge, VRF nem outro bond; o erro diz o que tirar e onde pôr (no bond). Recusa o que não teria efeito: `primary` fora de active-backup/tlb/alb ou fora dos slaves, `transmit_hash_policy` em modo que não faz hash, `lacp_rate` fora do 802.3ad, `min_links` maior que o número de slaves (o bond nunca subiria). O MTU do bond vale para os slaves (como no kernel); `interface.set mtu` num slave é recusado. A validação do commit (`validate.rs`) é a rede para config carregada e modo transacional. No modelo, `InterfaceKind::Bonding` e `Interface.bond` (o slave aponta para o bond, como a porta de bridge, então ninguém é slave de dois). `hal-linux` cria o `bond` via rtnetlink (mudar um parâmetro recria o bond, com os slaves soltos antes e de volta depois), baixa o link antes de escravizar ("Device can not be enslaved while up") e reaplica o estado admin depois de entrar/sair de um bond; o undo de um apply que falhou devolve slaves e estado. Janela Interfaces › Bonding (painel `crates/ui/src/bonding.rs`, tabela G1.9, diálogo com os slaves em caixas de seleção e os campos do modo escolhido).

  Como testar: `cargo test -p corerouter-engine --test bonding`; `cargo test -p corerouter-hal-linux --lib plan`; `cargo xtask netns` (inclui `tests/netns_bond.rs`; sem o módulo `bonding` o teste pula, e o CI o carrega e exige com `COREROUTER_REQUIRE_BOND=1`); `cargo test -p corerouter-ui bonding`. Na mão: `corerouter-cli run interface.bonding.add '{"name":"bond1","slaves":["ether1","ether2"],"mode":"802.3ad"}'` e Interfaces › Bonding na GUI.

- 2026-10-22 — G4.6: NTP e syslog remoto, parte 1. Comandos estilo RouterOS: `system.ntp.client.set/get`
  (`enabled`, `servers` com IP ou nome DNS, `min_poll`/`max_poll` 6..17 — o RouterOS aceita 3, mas a
  RFC 4330 §5 proíbe perguntar mais de uma vez por minuto; habilitar sem servidor é recusado) e
  `system.logging.action.add/set/remove/list` (alvo remoto: `remote`, `remote_port` 514,
  `src_address`, `syslog_facility` padrão `daemon`, `syslog_severity` padrão `auto`) +
  `system.logging.add/set/remove/list` (`topics` com `!` para excluir, como no RouterOS; tópicos
  conferidos contra uma lista fixa, então um erro de digitação não cria regra inútil; ação em uso
  não pode ser removida). Crates novos L2 puros: `proto-ntp` (pacote SNTPv4, checagens da RFC 4330 §5,
  Kiss-o'-Death da RFC 5905 §7.4, offset/atraso da §8, eras de 2036) e `proto-syslog` (RFC 5424 §6,
  só encode, campos do cabeçalho saneados e corte em 1180 bytes na fronteira UTF-8, RFC 5426 §3.2),
  os dois com proptest. No daemon: thread do cliente SNTP (pergunta a todos os servidores, fica com o
  menor atraso, intervalo dobra até `max_poll`, DENY/RSTR descartam o servidor, RATE vai ao
  `max_poll`; status `stopped`/`waiting`/`synchronized` com servidor, estrato, offset e atraso em
  `system.ntp.client.get`) e thread de syslog remoto (mudanças de config `system,info` + tópico da
  área, comandos que falharam `…,error`, sincronizou/perdeu NTP `ntp,info`/`ntp,warning`; nunca
  envia segurando o lock da sessão). O cliente **não acerta o relógio** ainda: registra um aviso se o
  offset passar de 1 s (G4.6b).

  Como testar: `cargo test -p corerouter-proto-ntp -p corerouter-proto-syslog`, `cargo test -p
  corerouter-engine --test ntp_logging`, `cargo test -p corerouter-daemon --bins ntp remote_log`
  (servidor SNTP e coletor syslog de teste em 127.0.0.1). À mão:
  `corerouter-daemon --control 7466 --no-discovery`, depois `corerouter-cli --connect
  127.0.0.1:7466 run system.ntp.client.set '{"enabled":true,"servers":["pool.ntp.org","time.cloudflare.com"]}'`
  e `run system.ntp.client.get`: **medido** em 2026-10-22, `synchronized` com time.cloudflare.com
  (estrato 3, atraso 44,6 ms, offset −5,5 ms) em menos de 6 s; com
  `system.logging.action.add {"name":"lab","remote":"127.0.0.1","remote_port":15514}` e
  `system.logging.add {"topics":"info","action":"lab"}` um `nc -ul 15514` recebe
  `<30>1 2026-10-22T14:36:13.366151Z CoreRouter corerouter 11354 system - system.logging.add …`.

- 2026-10-22 — processo: Fila de entrada resolve sozinha os conflitos só nos documentos do fold (`docs/log.md`,
  `docs/gaps-history.md`, `docs/perf.md`: entradas dos dois lados; `docs/gaps.md`: a mesma gap
  fica uma vez, a do PR). Eles vinham de uma branch que guardou o fold de uma rodada anterior da
  fila, que parou no meio: o #62 ficou fora de dois lotes por isso. Um PR que o GitHub marca em
  conflito só nesses documentos recebe a `main` na própria branch antes do lote (o squash é do
  GitHub, que não vê a resolução do lote). Testado na branch do #62.

- 2026-10-22 — G0.5: Fuzzing das três entradas hostis do plano de controle. Cada uma tem um oráculo de bytes →
  `Result` (`corerouter_engine::fuzz::config_file`, `corerouter_control::fuzz::{wire,
  control_line}`, `corerouter_mcp::fuzz::messages`) que roda de dois jeitos: proptest com semente
  fixa em `crates/{engine,control,mcp}/tests/fuzz.rs` (entra no `cargo xtask ci`, ~2 s, **medido**;
  `COREROUTER_FUZZ_CASES=N` faz a rodada longa sem nightly) e libFuzzer no crate `fuzz/` (fora do
  workspace; `cargo +nightly fuzz run -s none <alvo>`). O arquivo de config não só decodifica: o
  roteador dá boot a partir dele e responde a todas as consultas, e salvar → ler → salvar é ponto
  fixo. Pânico capturado pelo guarda do motor também conta como falha (hook de pânico por thread).
  Sementes em `fuzz/seeds/`, dicionário `fuzz/json.dict`; crash achado vai para
  `fuzz/regressions/<alvo>/` e a CI o reexecuta. Como testar: `cargo test -p corerouter-engine -p
  corerouter-control -p corerouter-mcp --test fuzz`; rodada longa em `docs/fuzzing.md`.

  Rodada de 10 min por alvo com libFuzzer (`-s none`, `json.dict`, 4 alvos em paralelo, Ryzen AI
  Max+ 395, 2026-10-22), **medido**: nenhum crash, nenhum pânico capturado. `config_file` 1,9 M
  execuções (cobertura 4545 arestas), `wire` 81 M (104), `control_line` 14,8 M (4720),
  `mcp_messages` 4,6 M (3802). Rodada aleatória sem nightly, também limpa: 3 000 configs mutadas
  (~90 % decodificam e dão boot), 5 000 casos por teste do canal de controle, 20 000 sessões MCP.
  Nada a corrigir nos alvos; um bug achado no próprio oráculo do `wire` (entrada só `\r`) foi
  corrigido antes da rodada.

- 2026-10-22 — processo: Pontos quentes que sobravam viram arquivos (pedido do usuário, depois da rodada de 7 agentes):
  os `pub mod` do engine, do model e do mcp são gerados de `src/` (`build-support/root_modules.rs`);
  estado de execução de feature no `Session` por tipo (`s.ext_mut::<T>()`, `crates/engine/src/ext.rs`)
  em vez de campo novo; serviços do daemon em `apps/corerouter-daemon/src/service/<nome>.rs` com
  `SERVICE` (opções de linha de comando e `start`) — NTP, syslog remoto e métricas migrados, o
  `main.rs` não muda mais por serviço; módulos do kernel do CI em `ci/kernel-modules/<módulo>`.
  De quebra, duas falhas de pasta de build compartilhada entre worktrees: o `xtask` acha a raiz do
  workspace a partir do diretório atual (não do `CARGO_MANIFEST_DIR` do build), e os geradores
  vigiam `src/` por caminho absoluto (senão reaproveitavam a lista de outra worktree).

- 2026-10-22 — processo: A fila faz o squash com o título do PR (`--subject "<título> (#n)"`): o #79 entrou na `main`
  como "wip hotspots", a mensagem do primeiro commit da branch.

- 2026-10-22 — processo: PR que só mexe em `docs/` roda só `cargo xtask docs` no CI (job `changes` decide; os 3 checks
  exigidos passam do mesmo jeito): o PR de fold de cada lote da fila custava um CI inteiro (~3 min)
  para mudar só `.md`, e num lote de 1 PR dobrava o tempo. Lote, `main` e `workflow_dispatch`
  continuam com o CI completo.

- 2026-10-22 — processo: Push na `main` que só mexe em `docs/` (o fold de cada lote) também roda só `cargo xtask docs` no
  CI, comparando com o commit anterior; antes rodava o completo e enfileirava atrás do run do lote.

- 2026-10-22 — processo: Fila de entrada como o padrão do mercado (pesquisa: merge queue do GitHub, Rust/bors rollups,
  Trunk, towncrier, changesets): lote vermelho faz bisseção (~log2 N CIs para isolar quem
  quebra, em vez de N no um por um) e o fold dos `docs/changes/` é periódico (`--fold` ou 10
  pendentes), não um PR extra por lote; `cargo xtask docs pending` mostra os status de gap ainda
  não consolidados, e as sessões o leem junto com o `gaps.md`.

- 2026-10-22 — G0.5c: MCP: lotes JSON-RPC recusados. A revisão 2025-06-18 do MCP (a única que o servidor negocia)
  removeu o batching; até aqui o servidor aceitava arrays de até 64 mensagens. Agora um array na
  linha, vazio ou não, recebe **um** objeto de erro `-32600` com `id: null` (JSON-RPC 2.0 §6: lote
  não aceito → uma Response só, não um array) e uma mensagem que diz para mandar uma mensagem por
  linha; nenhum item do array é executado, então um lote nunca aplica pela metade. O
  `MAX_BATCH` saiu; o oráculo de fuzz (`corerouter_mcp::fuzz`) passa a exigir que toda resposta
  seja um objeto, e o proptest `sessions_never_break` continua mandando arrays. `docs/mcp.md`
  explica o comportamento e aponta a tool `command_batch` (atômica) para várias mudanças.
  Testar: `cargo test -p corerouter-mcp` (`batch_items_never_run_and_the_server_keeps_serving`
  confere que um `ip.address.add` dentro de um lote não roda e que o servidor segue atendendo;
  `every_batch_is_refused_with_one_object` cobre arrays de 0 a 79 itens).

- 2026-10-22 — G0.8: `/export` com a matriz de zonas vazia não escreve nada (saía "# set: from is not exported"):
  uma configuração cuja lista de itens está vazia não tem linha a exportar. Visto pelo usuário
  no roteador real; o #64 só cobria a matriz com células.

- 2026-10-22 — G0.8b: Terminal como o do RouterOS: linha comprida quebra, nada de barra horizontal. **GUI**
  (`crates/ui/src/terminal.rs`): a saída rola só na vertical; uma linha mais larga que a janela
  quebra na largura visível (depois do último espaço da linha, se houver) e quebra de novo quando a
  janela muda de tamanho, inclusive o que já está na tela; as linhas de continuação começam com um
  `↳ ` discreto. A quebra é só de exibição: a saída guarda a linha original, Copy All copia as
  originais e um plugin do egui (`UnwrapCopy`, no `output_hook`) tira as quebras de exibição do texto
  de uma seleção copiada. A janela não estica (`wide_print_does_not_stretch_the_window` segue
  passando). **Foco**: um clique em qualquer lugar da janela (na saída, não só na linha de
  comando) devolve o foco ao campo de entrada, como no xterm, no PuTTY e no WinBox; arrastar para
  selecionar mantém a seleção para copiar e não rouba o foco no meio do arrasto, e a próxima tecla
  depois da seleção vai para a linha de comando; o menu de contexto (Copy All, Clear) continua.
  **`/export`** (`crates/shell/src/export.rs`): comando mais largo que o terminal quebra
  com ` \` no fim e as linhas seguintes recuadas 4 espaços, entre argumentos (nunca dentro de um
  valor entre aspas; argumento maior que a linha fica sozinho); largura = a do terminal
  (`Shell::set_width`: janela da GUI, `rustyline` da CLI), 80 sem terminal; `file=` sempre em 80,
  para o arquivo não depender da janela. **`/export terse`**: uma linha por item com o menu na
  frente, sem quebra (script, grep); `compact` aceito (padrão do RouterOS), `verbose` e
  `show-sensitive` recusados com o motivo (antes viravam nome de arquivo); Tab completa `terse`.
  As linhas de continuação são coloridas como argumentos. Tabelas do `print` continuam como
  estavam. Como testar: `cargo run -p corerouter-gui -- --control 7979`, New Terminal, um comando
  comprido e `/ip dhcp-client export` (estreite a janela e repita); na CLI,
  `corerouter-cli shell` e `/export`, `/export terse`. Testes: unidade da quebra (aspas, valor
  maior que a largura, recuo, linhas curtas intactas) e do `terse`; ida e volta export quebrado em
  48 colunas → colar → export igual, e `terse` → colar → export igual (`crates/shell/tests/terminal.rs`);
  headless da GUI (quebra, re-quebra ao estreitar arrastando o canto, nada desenhado além da borda,
  janela não estica, clique na saída foca a entrada, arrasto preserva a seleção e a tecla seguinte vai para a entrada, quebra/desquebra exata, plugin de cópia, glifo `↳` na fonte mono); screenshots
  em `docs/changes/G0.8b-screenshots/`.

- 2026-10-22 — G1.8d: Bonding: mudar parâmetros sem recriar o bond. O planejador (`hal-linux/src/plan.rs`) ganhou `bond_in_place` e a op `SetBond`: `mii_interval`, `min_links`, `transmit_hash_policy` e `primary` vão para o bond existente num `RTM_NEWLINK` sem `NLM_F_CREATE` só com os `IFLA_BOND_*` que mudam (o `bond_changelink` do kernel; o `RTM_SETLINK` ignora o `IFLA_LINKINFO`). Nada de soltar slaves, apagar o link nem reinstalar endereços e rotas; o undo de um apply que falhou devolve os valores antigos. `primary` vazio vai como ifindex 0, que o kernel entende como "sem primary". Só o que o modo usa conta (hash fora de 802.3ad/balance-xor/balance-tlb, `primary` fora de active-backup/tlb/alb e `lacp_rate` fora do 802.3ad não geram op). Ainda recriam, porque o kernel recusa no bond vivo (`drivers/net/bonding/bond_options.c`): o modo (`BOND_OPTFLAG_NOSLAVES | BOND_OPTFLAG_IFDOWN`, "the bond device has slaves") e o `lacp_rate` (`BOND_OPTFLAG_IFDOWN`, "the bond is up"), conferido no Linux 7.0 (**medido**). Como testar: `cargo test -p corerouter-hal-linux --lib plan` e `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_bond` (`live_settings_change_without_recreating_the_bond` prova que o ifindex não muda, que os slaves ficam e que o rollback desfaz).

- 2026-10-22 — G4.1a: Resolvedor DNS do próprio roteador (`/ip dns`). Ping, MTR e o cliente NTP resolviam nomes pelo
  resolvedor do Linux do host (`/etc/resolv.conf` → `127.0.0.53`), que não existe no namespace do
  roteador nem na imagem: "failed to lookup address information". Agora há um resolvedor próprio:
  `crates/proto-dns` (L2, sem sockets) com mensagens `hickory-proto`, cache por TTL com orçamento
  em KiB e troca de servidor, e um serviço do daemon (`service/dns.rs`) com UDP/TCP bloqueantes e
  uma thread que segue a config. Comandos `ip.dns.set` (servers, allow_remote_requests aceito para
  a G4.1b, cache_size, cache_max_ttl_secs, query_server_timeout_ms, query_total_timeout_ms,
  max_udp_packet_size), `ip.dns.get` (+ `dynamic_servers` do DHCP `use_peer_dns`, `cache_used`,
  `resolver`), `ip.dns.cache.print` e `ip.dns.cache.flush`. Config em `ip.dns` do modelo
  (`corerouter_model::dns`); o resolvedor é registrado no `Session` por `ext_mut`. O prober do host
  deixou de chamar `getaddrinfo`. No lab sem daemon, e no daemon sem servidor configurado, o
  resolvedor simulado do `SimProber` continua valendo. Regras de RFC 1035/2181/2308/5452/6761/7766
  citadas no código e nos testes. Os padrões seguem o RouterOS, exceto `max_udp_packet_size`, que
  é 1232 (DNS Flag Day 2020), e o teto de 1 h para o cache negativo. Decisão "DNS inteiro em
  Hickory DNS" registrada em `docs/architecture.md`.
  Como testar: `cargo run -p corerouter-daemon -- --control 7979`, depois
  `corerouter-cli --connect 127.0.0.1:7979 run ip.dns.set '{"servers":["1.1.1.1"]}'`,
  `run tool.ping.start '{"address":"uol.com.br","count":3}'` e `run ip.dns.cache.print`. Testes:
  `proto-dns` (codec com o exemplo SRI-NIC.ARPA da RFC 1035 §6.2, CNAME, negativos, proptest;
  cache; failover com transporte falso), engine (comandos, prober, `dynamic_servers` do DHCP),
  daemon (servidor DNS local UDP/TCP, NTP por nome) e `tests/netns_dns.rs` (servidor DNS na porta
  53 de um namespace sem resolv.conf: ping resolve `router.test`, NXDOMAIN em cache, flush).

- 2026-10-22 — G4.1b: Encaminhador DNS da LAN, parte 1 (a base). Com `ip.dns.set allow_remote_requests=yes` o daemon
  atende UDP e TCP 53 (serviço `dns server`, `service/dns_server.rs`, opção `--dns-port`) com o
  mesmo resolvedor e o mesmo cache do G4.1a: as consultas do roteador e as da LAN dividem o
  cache, que agora guarda qualquer tipo de registro, positivo e negativo, com hits por entrada.
  Cada consulta passa por uma cadeia de etapas em `crates/proto-dns/src/server/stage/`, um
  arquivo por etapa, achadas pelo `build.rs` e ordenadas pelo `order`:
  `acl → limit → special → adlist (vazia) → static → zones (vazia) → cache → upstream`. As
  próximas partes (Statistics, Adlist/Forwarders/DoT-DoH, Zones) entram como arquivos novos nessa
  cadeia; o passo a passo está em `docs/dns.md`, "Uma etapa nova". Sem tokio: a thread do socket
  responde o que não precisa de rede, e cada falta de cache ganha uma thread (no máximo
  `max_concurrent_queries`, depois SERVFAIL). Resposta sai do endereço perguntado
  (`IP_PKTINFO`/`IPV6_RECVPKTINFO`, pelo `nix`).

  Config nova em `ip.dns.set`: `allowed_from` (listas de interfaces e prefixos; padrão `LAN`:
  nunca resolvedor aberto, REFUSED para quem está fora; `ip.dns.get` mostra `allowed_networks`),
  `max_queries_per_client` (balde de fichas por cliente, IPv6 por /64; UDP excedente
  descartado), `server_selection` (`fastest`, que mede a latência e põe um servidor que falhou no
  fim por 1 min, ou `sequential` do RouterOS; `ip.dns.get` mostra `upstream` com latência,
  respostas e falhas), `serve_stale_secs` (RFC 8767, 1 dia por padrão, TTL 30 s),
  `max_concurrent_queries`, `max_concurrent_tcp_sessions`, `address_list_extra_time_secs`.
  `/ip dns static` (`ip.dns.static.add/set/remove/move/print`, área nova `cmd/dns_static.rs`,
  seção `ip.dns_static` do modelo): A, AAAA, CNAME, FWD, MX, NS, NXDOMAIN, SRV, TXT, `regexp`
  (crate `regex`, tempo linear), `match_subdomain`, `address_list`, `ttl_secs`, `disabled`,
  `comment`, ordem de cima para baixo com regexp antes de nome, PTR automático para A/AAAA.
  `ip.dns.cache.print` ganhou `type`, `data`, `hits` e `stale`. Também: ANY com um HINFO (RFC
  8482), `localhost`/`.invalid` (RFC 6761), AXFR e classe não-IN recusados, FORMERR para lixo,
  truncamento UDP pelo EDNS do cliente. GUI: IP › DNS (Settings com os botões Static e Cache;
  Statistics, Adlist, Forwarders e Zones desabilitados com "Coming soon" e a gap), IP › DNS Static
  (tabela + diálogo) e IP › DNS Cache (Flush Cache), painéis em `crates/ui/src/dns.rs`; o
  espaço reservado `Win::Dns` saiu de `windows.rs`. Terminal e `/export` saem do registro:
  `/ip dns static add …` vai e volta.

  Como testar: `cargo run -p corerouter-daemon -- --control 7979 --dns-port 5353`, depois
  `corerouter-cli --connect 127.0.0.1:7979 run ip.dns.set '{"servers":["1.1.1.1"],"allow_remote_requests":true}'`,
  `run ip.dns.static.add '{"name":"nas.lan","address":"192.168.88.10"}'`,
  `dig @127.0.0.1 -p 5353 nas.lan`, `dig @127.0.0.1 -p 5353 uol.com.br MX` e
  `run ip.dns.cache.print`. Testes: `proto-dns` (cadeia ponta a ponta com upstream falso,
  proptest de pacotes hostis, cache com serve-stale e hits, resolvedor com servidor mais rápido e
  FWD), engine (`ip.dns.static.*`, `ip.dns.set`, address list), shell (`/export` ida e volta),
  daemon (sockets reais) e `tests/netns_dns_server.rs` (porta 53 num namespace: REFUSED fora do
  `allowed_from`, resposta do endereço perguntado, PTR, TCP, serve-stale, limite por cliente).
  Conferido também com `dig` contra um dnsmasq de upstream no namespace, e screenshot da GUI.

- 2026-10-22 — G4.4c: `/metrics` como serviço da config, no estilo de `/ip service` do RouterOS. Comandos novos
  `ip.service.metrics.set {enabled?, address?, port?, available_from?}` e
  `ip.service.metrics.get` (config + `status: stopped|listening|error`, `listening`,
  `last_error`, `requests`, `refused`). Padrão: desligado, `127.0.0.1:9100` (a porta do
  node_exporter e do VyOS). O daemon segue a config em execução numa thread (`metrics-service`):
  um commit abre, muda de porta ou fecha o listener em até 1 s, sem reiniciar; porta ocupada vira
  `status: error` com o motivo e é tentada de novo a cada segundo. Cliente fora de
  `available_from` é desconectado sem resposta e contado em `refused` (como o `address` do
  `/ip service`; IPv4 mapeado em `::ffff:` casa como IPv4). `set` avisa (`warning`) quando o
  endpoint, que não tem login, fica aberto para a rede sem `available_from`. A opção `--metrics`
  continua igual, como um listener fora da config. Config em `system.metrics` do modelo
  (`corerouter_model::metrics`); estado de execução no `Session` por `ext_mut::<MetricsStatus>()`.
  Como testar: `cargo run -p corerouter-daemon -- --control 7979`, depois
  `corerouter-cli --connect 127.0.0.1:7979 run ip.service.metrics.set '{"enabled":true}'`,
  `curl -s 127.0.0.1:9100/metrics` e `run ip.service.metrics.get`. Testes: engine
  (`cmd::metrics_service`: sucesso, validação, aviso, rollback, status) e daemon
  (`service::metrics`: abre, move, recusa por `available_from`, fecha; porta ocupada → erro →
  recupera). O id do comando é `ip.service.metrics.*` (e não `system.metrics.set`, como dizia o
  critério): `system.metrics` já é a consulta dos contadores, e um menu `/system metrics` no
  terminal a esconderia; `/ip service metrics set port=9273` segue o `/ip service` do RouterOS e
  abre espaço para os outros serviços do daemon (`ip.service.<nome>`).

- 2026-10-22 — G4.6d: Log do sistema, parte 1. Todo evento passa por `Session::log_event` (engine, `logging.rs`): número,
  hora do relógio da sessão (`Hal::now_unix`/`tick`), tópicos RouterOS, **origem** (`daemon` ou
  conta + canal: `admin · GUI`, `local · terminal`, `… · MCP`, `… · CLI`, pelo `via` que cada
  cliente manda em `engine.execute`/`engine.batch` e o `Caller` guarda), **mensagem em português**
  ("Ping para uol.com.br iniciado (tarefa 1)", "NTP Client ligado: servidores pool.ntp.org, poll
  6–10", "NTP: não foi possível resolver pool.ntp.org", "Falhou: /ip address add address=bad … —
  motivo") e **detalhe técnico** (comando, parâmetros com segredos mascarados, resultado ou erro,
  revisão criada). Fontes: journal de comandos, cliente DHCPv4/v6 (histórico traduzido; `searching`
  e `offered` são `debug`), NTP só na mudança de estado ou de erro (sem repetir a cada poll) e o
  aviso de relógio do daemon, ferramentas (início e fim de Ping/MTR/MTU/teste de cabo com quem
  pediu; falha como `tool,warning`). A ação embutida `memory` guarda as últimas `memory_lines`
  (padrão 1000, 1..65535, `system.logging.action.set {name: memory, memory_lines}`); as regras
  padrão `info`, `error`, `warning`, `critical` → `memory` vêm em toda config nova (ids `*1`–`*4`,
  marcadas `default` para o `/export` fazer `set`). O syslog remoto (G4.6) lê o mesmo log
  (`Session::log_since`). Comandos `log.print {topics?, level?, since?, find?, limit?}` (o terminal
  ganha `/log print`) e `log.clear`. Janela Log nova (painel `ui/src/system_log.rs`; a antiga, que
  mostrava o journal da GUI em JSON, saiu): Hora (HH:MM:SS, data se não for o dia da linha mais
  nova, data/hora completa UTC no tooltip), Tópicos, Origem, Mensagem com cor por nível;
  Legível/Técnico, filtro de tópico, "Só avisos e erros", busca, Pausar, Limpar; pede só as
  linhas depois da última (`since`) e recomeça se o roteador reiniciou. A janela System › Logging
  mostra a ação `memory` (só o número de linhas muda; não se remove). Tópicos novos: `tool` e
  `dns` (ponto de ligação do resolvedor da G4.1a, que estava em outra sessão).

  Como testar: `cargo run -p corerouter-daemon -- --control 7980`, `corerouter-cli --connect
  127.0.0.1:7980 run system.ntp.client.set '{"enabled":true,"servers":["pool.ntp.invalid"]}'`,
  `… run tool.ping.start '{"address":"uol.com.br","count":3}'`, `… run log.print '{"level":"warning"}'`;
  GUI `--connect 127.0.0.1:7980`, menu Log. Testes: `cmd/log.rs`, `logging.rs`, `tasks.rs`,
  `tests/ntp_logging.rs`, `ui/src/tests/system_log.rs`, `ui/src/tests/logging.rs`.

  Limites: hora em UTC (não há fuso horário); configs salvas antes desta mudança com regras de
  `/system logging` não ganham as regras padrão (só as configs sem a seção); no terminal, a
  mensagem longa sai das colunas do `/log print` (use `proplist=date,origin,message` ou `print
  detail`; G4.6h).

- 2026-10-22 — G4.6e: GUI de NTP e log remoto, dois painéis novos em `crates/ui` (nenhuma edição em `lib.rs`/`windows.rs`;
  o `build.rs` os achou e o menu System os lista em ordem alfabética):

  - **System › NTP Client** (`ntp_client.rs`): formulário Enabled / Servers (um por linha) / Min Poll /
    Max Poll com Apply e Revert; o formulário intocado acompanha o roteador, a edição não aplicada fica
    (marcada com "•") e a recusa do engine aparece embaixo. Status lido de `system.ntp.client.get` a cada
    atualização: Status colorido (synchronized/waiting/stopped), Synced Server (nome e endereço), Stratum,
    System Offset, Round Trip, Last Sync (UTC) e Next Poll, e o último erro.
  - **System › Logging** (`logging.rs`): abas Rules (Topics, Prefix, Action) e Actions (Name, Type,
    Remote Address/Port, Src. Address, Facility, Severity, Comment), cada uma uma tabela G1.9 (barra,
    menus, atalhos, busca); diálogos New/Properties para regra e ação. Na regra, os tópicos válidos são
    botões (clique inclui, botão direito exclui com `!`) e Action é uma lista das ações existentes; o
    engine continua sendo quem valida (tópico inexistente e remover ação em uso voltam como erro no
    diálogo).

  Testar: `cargo test -p corerouter-ui -- ntp logging` (6 testes headless: status ao vivo vindo do daemon,
  Apply/erro/Revert do NTP, editar/desabilitar/criar regra com tópico inválido, editar ação, remoção
  recusada de ação em uso, nova ação; as listas de tópicos e facilities da UI conferidas contra o
  `corerouter-model`). Na GUI: `cargo run -p corerouter-gui -- --control 7979`, menu System › NTP Client
  e System › Logging.

- 2026-10-22 — G6.3b: MTR/traceroute com nome, ASN e rótulos MPLS por salto, para operador de ISP. `tool.mtr.start`
  ganha `use_dns` (padrão ligado, como o `mtr`) e `as_lookup` (padrão desligado, como o `-z`);
  no terminal `/tool traceroute 8.8.8.8 use-dns=no as-lookup=yes`. O resolvedor do roteador
  (G4.1a) passa a consultar PTR (`in-addr.arpa`/`ip6.arpa`, RFC 1035 §3.5 / RFC 3596 §2.5, CNAME
  da RFC 2317) e TXT (Team Cymru: `origin.asn.cymru.com`, `origin6`, `AS<n>.asn.cymru.com`) no
  mesmo cache (`QType::Ptr/Txt`, `CachedData::Records` no modelo). As consultas não atrasam a
  medição: o `Prober` ganhou `reverse_name`/`origin_as` que respondem `Pending` ou `Done`; no
  daemon elas rodam em 4 threads com fila limitada (256) e respostas guardadas 5 min; o MTR
  pergunta de novo a cada volta e, com `count`, espera até 3 s no fim. Endereços RFC 1918, ULA,
  CGNAT (RFC 6598), link-local e loopback são marcados (`scope`) e nunca consultados (RFC 6598 §4,
  RFC 6303 §3). Rótulos MPLS: codec puro `crates/hal/src/icmp_ext.rs` (extensões ICMP da RFC 4884
  com o modo §5.5 para remetentes antigos, objeto MPLS Label Stack da RFC 4950), lido pelo
  `hal-linux` nas respostas Time Exceeded/Unreachable do raw socket (o ping socket não vê as
  extensões). Lab: o `SimProber` dá roteadores privado (1º salto), CGNAT (2º) e públicos
  `198.19.<salto>.x` com nomes `*.sim-transit.example`, AS64500/64510/64999 e rótulos MPLS
  sintéticos. Janela Tools › MTR: caixas Use DNS e AS lookup, nome em cima e IP embaixo (menor),
  colunas ASN e MPLS (screenshot em `docs/changes/G6.3b-screenshots/`). Terminal: `nome (IP)
  [private]`, coluna ASN e linha `MPLS L=… TC=… S=… TTL=…` por rótulo.
  Como testar: `cargo run -p corerouter-gui`, Virtual lab, Tools › MTR, marque AS lookup, endereço
  `198.51.100.20`, Enter. Testes: `proto-dns` (PTR/TXT com o exemplo da RFC 1035 §3.5 e da RFC
  3596 §2.5, CNAME da RFC 2317, respostas da Team Cymru, proptest de texto hostil, cache de PTR e
  ASN no resolvedor), `hal` (codec com o exemplo da RFC 4950 §3, comprimentos por família, §5.5,
  checksum zero, objetos desconhecidos, proptest de bytes hostis e ida e volta), `hal-linux`
  (Time Exceeded com rótulo no raw socket), engine (classificação privado/CGNAT, nomes que chegam
  depois sem travar e nome que nunca chega, comando e texto do terminal), daemon (consultas sem
  espera contra um servidor DNS local), shell (`use-dns=no as-lookup=yes`) e headless da janela
  (nome aparece depois; IP na hora).

- 2026-10-22 — G6.3d: Ajustes do MTR pedidos pelo usuário: o selo do AS não repete o número quando o registro não tem
  nome (`AS262901 AS262901` → `AS262901`; a Team Cymru devolve o próprio número como nome); clique
  numa linha seleciona o hop (destaque atrás do texto; clique de novo desmarca; clique direito: Copy
  address / Copy host); Enter no endereço inicia o MTR e, rodando, um endereço novo reinicia com ele.
  Os selos saem do MTR para `crates/ui/src/chip.rs` (tons neutro/âmbar/azul e paleta por hash de
  chave), com o padrão em `docs/ui-style.md` e no AGENTS.md ("UI fina"). Fila contínua: consolida os
  `docs/changes/` quando fica ociosa depois de integrar (antes só ao terminar).

- 2026-10-22 — G6.3d: Janela Tools › MTR, acabamento visual (só `crates/ui/src/mtr.rs`). Uma linha por salto, todas da
  mesma altura: o host é o nome (DNS reverso) ou o IP enquanto não há nome, cortado com "…" acima
  de 40 caracteres; nome completo, endereços, rótulos e avisos vão no tooltip. Ao lado do host,
  selos pequenos arredondados no lugar do texto entre colchetes: `privada` (neutro, com borda),
  `CGNAT` (âmbar) e `MPLS 85260` (azul; a coluna MPLS saiu). A coluna ASN virou **Network**: o AS
  é uma pílula `AS7162 UOL` (primeira palavra do nome; completo e prefixo no tooltip) com cor tirada
  de uma paleta de 8 tons por hash de Fibonacci do número, então todos os saltos de um AS têm a
  mesma cor e números consecutivos nunca coincidem; se dois ASs vizinhos no caminho caem no mesmo
  tom, o segundo pega o tom seguinte (a troca de operadora sempre aparece). Cada tom tem tinta
  escura no tema claro e clara no escuro, fundo lavado da mesma cor. Salto sem resposta: `sem
  resposta` apagado, números `–`, perda em vermelho. Terminal sem mudança.
  Como testar: `cargo run -p corerouter-gui`, Virtual lab, Tools › MTR, marque AS lookup, endereço
  `198.51.100.20`, Enter; troque o tema no canto superior direito. Testes headless em
  `crates/ui/src/tests/mtr_look.rs` (selos sem colchetes, "sem resposta", altura das linhas
  uniforme nos dois temas, cor do AS estável e distinta para consecutivos e vizinhos de caminho).

- 2026-10-22 — processo: Binários sempre atuais: a fila de entrada leva o checkout principal para a `main` nova e
  recompila daemon, GUI e CLI depois de cada lote (só na `main` e sem alterações; `LAND_REBUILD=0`
  desliga). Crate novo `corerouter-buildinfo` (L0) com o commit do build: o `server.info` o informa
  e a barra da GUI avisa "daemon <commit> ≠ GUI <commit>" quando o daemon rodando é de outro build
  (o usuário testou correções contra um daemon velho). O `plan/hw-lab.sh` local também recompila
  antes de subir o daemon, a GUI e o terminal.

- 2026-10-22 — processo: AGENTS.md e template de PR descrevem a fila como ela é: o usuário aprova ao pedir a rodada e a
  fila contínua (`--watch`, rótulo `fila`) integra sozinha, com o resultado do CI lido dos runs do
  Actions. Números das rodadas no `docs/perf.md`.

- 2026-10-22 — processo: Fila contínua (`scripts/land.sh --watch`): pega sozinha os PRs com o rótulo `fila` (as
  sessões o põem no `gh pr create`), sem esperar a sessão principal reagir; e lote especulativo:
  enquanto um lote roda o CI, os PRs que ficam prontos são testados num lote montado em cima
  dele; verde, entram logo depois, sem outro CI; vermelho, o especulativo é descartado e o lote
  passa pela bisseção. PR que ficou de fora volta sozinho quando a branch muda. Simulado: lote
  verde com um PR chegando no meio entra um passo depois; lote vermelho cai na bisseção.

- 2026-10-22 — G0.10: Supervisor de serviços do daemon: cada serviço de `apps/corerouter-daemon/src/service/` (dns-resolver, dns-server, ntp-client, remote-logging, metrics) roda numa thread do supervisor, que o reinicia quando termina, devolve erro ou dá panic (`catch_unwind`), esperando 1 s, 2 s, 4 s… até 60 s; com 5 falhas em 60 s ele fica `failed`, com linha `critical` no log. Cada serviço informa heartbeat, portas em escuta, último evento ou erro, threads e o motivo de estar ocioso pela config (`disabled`); o `dns-server` depende do `dns-resolver`. Comandos novos em `crates/engine/src/cmd/system_service.rs`: `system.service.print` e `system.service.start|stop|restart|reset-failures {name}` (o `stop` dura até o boot e não muda a config; o `control` é protegido e explica por quê). Janela System › Services (`crates/ui/src/services.rs`): botões, selos de resumo, tabela com selo de estado e de alcance (`all`, `LAN`, `local`, `public`), detalhe com o comando que liga o serviço, dependência, política, heartbeat, threads e as últimas linhas do tópico no log. Selos `GREEN` e `RED` novos em `chip.rs` (docs/ui-style.md). Interface `Service` nova documentada no topo de `service/mod.rs` e em `docs/architecture.md`.

  Como testar: `cargo run -p corerouter-daemon -- --control 7979`, depois `corerouter-cli --connect 127.0.0.1:7979 run system.service.print`, `run system.service.stop '{"name":"ntp-client"}'` e `run system.service.start '{"name":"ntp-client"}'`; na GUI (`--connect 127.0.0.1:7979`), System › Services. Com `--metrics 9100`, `curl 127.0.0.1:9100/metrics | grep service`. Testes: `cargo test -p corerouter-daemon supervisor` (falha → espera → failed → reset; panic contido; stop/start/restart; dependência), `cargo test -p corerouter-engine system_service`, `cargo test -p corerouter-ui services`.

- 2026-10-22 — G4.1c: Zonas DNS autoritativas, estilo BIND, na cadeia do encaminhador. Config `ip.dns_zones` (modelo
  `crates/model/src/dns_zone.rs`): zona primária (SOA a partir dos campos da zona, serial
  `date`/`increment`/`unixtime` que anda sozinho, um serial novo por transação) ou secundária
  (`primaries`). Comandos `ip.dns.zone.add/set/remove/print`, `ip.dns.zone.record.add/set/remove/print`,
  `ip.dns.zone.file.get/load` (arquivo de zona RFC 1035, parser próprio com proptest; `$INCLUDE`
  recusado) e `ip.dns.zone.refresh`. A etapa `zones` (`proto-dns/src/zone/`) responde com AA pela
  RFC 1034 §4.3.2: curingas (RFC 4592), não terminais vazios (NODATA), delegação com glue
  (referência sem RD; com RD, encaminha às glue), CNAME seguido, NXDOMAIN/NODATA com o SOA (RFC
  2308 §3), seção adicional para NS/MX/SRV. AXFR (RFC 5936, só TCP, `allow_transfer`, NOTAUTH
  para zona alheia), IXFR com diário em memória (RFC 1995; sem histórico, a zona inteira; por UDP
  só se couber) e NOTIFY recebido de `primaries` são atendidos antes da cadeia; o serviço do daemon
  `dns zones` manda NOTIFY (RFC 1996 §3.6, 5 retransmissões com intervalo crescente) e mantém as
  secundárias (SOA a cada refresh, IXFR com volta para AXFR, expira em `expire`). Janela IP › DNS ›
  Zones (DNS Zones, DNS Zone Records, DNS Zone File). Testar: `corerouter-daemon --control 7979
  --dns-port 5353`, `ip.dns.set allow_remote_requests=yes`, `ip.dns.zone.add
  '{"name":"example.com","allow_transfer":"127.0.0.0/8"}'`, `ip.dns.zone.record.add
  '{"zone":"example.com","name":"www","address":"192.0.2.80"}'`, `dig -p 5353 @127.0.0.1
  www.example.com` (flag `aa`) e `dig +tcp -p 5353 @127.0.0.1 example.com AXFR`. Custo **medido**:
  nenhum para quem não tem zonas; 1,04 µs por resposta de uma zona de 1000 registros.

- 2026-10-22 — G4.1d: DNS adlist (`/ip dns adlist`, RouterOS v7): listas de bloqueio por URL (`http`/`https`) ou arquivo
  (`--adlist-dir`), em formato hosts, um domínio por linha ou `||nome^`; o nome listado recebe
  0.0.0.0 / `::` (TTL 10 s), `||nome^` vale para os subdomínios, uma estática FWD libera um nome.
  O daemon baixa e monta as listas fora do lock do `Session` (cliente HTTP/1.1 próprio sobre rustls
  com as raízes Mozilla embutidas, nomes pelo resolvedor do roteador), recarrega a cada 4 h e no
  `ip.dns.adlist.reload`, e mostra estado, nomes, bloqueios e erro em `ip.dns.adlist.print` e na
  janela IP › DNS Adlist (aberta pelo botão Adlist da janela DNS). Como testar: `corerouter-cli run
  ip.dns.adlist.add '{"url":"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"}'`,
  `ip.dns.adlist.print` e `dig @<roteador> <nome da lista>`. Ao vivo (**medido**): a lista do
  StevenBlack, 71 492 nomes, baixada e aplicada em menos de 10 s. Detalhes em `docs/dns.md`.

- 2026-10-22 — G4.1d: DNS forwarders e upstream cifrado: `/ip dns forwarders` (RouterOS 7.17: grupos com `dns_servers`,
  `doh_servers` e `verify_doh_cert`), a estática FWD com `forward_to=<grupo>`, e `ip.dns.set
  use_doh_server` com DoH (`https://…`, RFC 8484) ou DoT (`tls://host#nome`, RFC 7858; o RouterOS
  não tem), certificado verificado contra as raízes Mozilla por padrão, consulta com id 0 e padding
  de 128 bytes (RFC 8467), conexões reaproveitadas, sem volta para texto claro. O nome do servidor
  cifrado vem de uma estática ou dos `servers` comuns. Janela IP › DNS Forwarders e campos DoH na
  janela DNS. Como testar: `ip.dns.set '{"use_doh_server":"https://cloudflare-dns.com/dns-query"}'`
  e `dig @<roteador> example.org`; grupo: `ip.dns.forwarders.add '{"name":"q9","doh_servers":["tls://9.9.9.9#dns.quad9.net"]}'`
  e `ip.dns.static.add '{"name":"wikipedia.org","type":"FWD","forward_to":"q9","match_subdomain":true}'`.
  Ao vivo (**medido**): Cloudflare DoH e Quad9 DoT respondendo com certificado verificado. Detalhes em
  `docs/dns.md`.

- 2026-10-22 — G4.1d: DNS `:resolve` e cache de falhas: `ip.dns.resolve {name, type?, server?}` (RouterOS `:resolve`;
  `/ip dns resolve` no terminal) roda como tarefa, sem esperar a rede sob o lock do `Session`, e mostra por
  tipo a resposta, a fonte (cache, stale, servidor), o TTL e o tempo; endereço vira PTR; `server`
  pergunta só a ele, sem o cache. Janela IP › DNS Resolve (também pelo **Resolve…** do DNS Cache).
  O resolvedor guarda as falhas (RFC 9520): um nome e tipo que nenhum servidor respondeu não é
  perguntado de novo por 5 s, dobrando até 5 min; nesse tempo responde SERVFAIL ou a resposta
  vencida (RFC 8767). Como testar: `corerouter-cli --connect 127.0.0.1:7979 watch ip.dns.resolve
  '{"name":"example.com"}'`; na GUI, IP › DNS Resolve. Detalhes em `docs/dns.md`.

- 2026-10-22 — G4.1e: Estatísticas do encaminhador DNS da LAN. Etapa nova `crates/proto-dns/src/server/stage/statistics.rs`
  (só `after`, ordem 100) conta consultas UDP/TCP, quem respondeu (cache, static, upstream,
  stale, refused, limit, busy, special), códigos de resposta, tipos, os clientes que mais
  perguntam (no máximo 1024 guardados, Space-Saving: topo certo sob inundação) e as respostas
  por upstream. As `after` agora também veem descartes (`Query::dropped()`). Comandos
  `ip.dns.statistics.print {top?}` e `ip.dns.statistics.reset` (estado de execução, sem
  rollback); botão Statistics na janela IP › DNS abre a janela DNS Statistics.
  `Session::dns_allowed_networks`: `allowed_from` com lista de interfaces passa a contar os
  endereços aprendidos por DHCP e os `from_pool` do IPv6 já resolvidos; o daemon recalcula a cada
  segundo. Testar: `corerouter-daemon --control 7979 --dns-port 5353`, `ip.dns.set
  allow_remote_requests=yes servers=1.1.1.1`, `dig -p 5353 @127.0.0.1 example.com`, depois
  `corerouter-cli --connect 127.0.0.1:7979 run ip.dns.statistics.print` ou IP › DNS ›
  Statistics. Custo **medido**: +45 a +80 ns por consulta.

- 2026-10-22 — G6.6: Registro da G6.6: a ferramenta DNS Lookup (estilo `dig`) em Tools, com a tela aprovada pelo
  usuário. Começa depois que a G4.1d entrar, porque reaproveita o `ip.dns.resolve` como tarefa e
  o upstream DoH dela.

- 2026-10-22 — G4.1c: Assinatura DNSSEC das zonas autoritativas. `ip.dns.zone.set dnssec=yes` (e `dnssec_algorithm`,
  `signature_validity_secs`): o daemon gera KSK e ZSK (ring, pelo `hickory-proto`, feature `dnssec`
  do proto-dns ligada só nele), guardadas no estado operacional `dnssec-keys` (fora das revisões:
  um rollback nunca tira uma chave cujo DS está no pai), e assina a zona inteira: RRSIG de todo
  RRset autoritativo (delegação e glue não, RFC 4035 §2.2), cadeia NSEC3 com 0 iteração e sem salt
  (RFC 9276), NSEC3PARAM, serial próprio sempre maior. A etapa `zones` responde DO com os RRSIG e as
  provas NSEC3 da RFC 5155 §7.2; AXFR/IXFR/NOTIFY levam a versão assinada; uma secundária de zona
  assinada serve as assinaturas. Comandos `ip.dns.zone.dnssec.print/rollover/ds-published/forget`;
  DS (SHA-256) em `ip.dns.zone.print`; diálogo da zona com as chaves, Copy DS e os botões de rotação.
  Rotação: ZSK por pré-publicação, KSK por assinatura dupla esperando `ds-published` (RFC 6781
  §4.1, tempos da RFC 7583). Testar: `ip.dns.zone.set '{"id":"example.com","dnssec":true}'`,
  `ip.dns.zone.print` (DS), `dig +dnssec @… www.example.com`; namespace com o `delv` do BIND
  validando resposta, NXDOMAIN, NODATA, curinga e CNAME. Desempenho **medido**: 24 ms para assinar
  1000 registros (ECDSA), 1,56 µs por resposta assinada, 6,6 µs por NXDOMAIN com prova.

- 2026-10-22 — G4.1c: Atualização dinâmica das zonas: `ip.dns.tsig-key.*` (HMAC-SHA256/384/512; secret aleatório de 32
  bytes se não for dado; escondido no `print`, no export e no log da GUI) e, por zona, `update_keys`
  e `allow_update`. Um RFC 2136 UPDATE (Kea dhcp-ddns, ISC dhcpd, `nsupdate`) é checado em
  `proto-dns/src/zone/update.rs` (zona, TSIG: chave, MAC, tempo e repetição; permissão; pré-requisitos
  da §3.2; seção de atualização) e aplicado pelo engine tudo ou nada (`engine/src/dns_dynamic.rs`,
  estado `dns-dynamic`, salvo antes da resposta), com as regras da §3.4.2 e o serial servido subindo
  (e a zona assinada assinada de novo). Registros configurados nunca mudam por UPDATE. Os dinâmicos
  aparecem em `ip.dns.zone.record.print` com `D`, saem com `ip.dns.zone.dynamic.remove/flush` e no
  arquivo de zona. `Session::dns_dynamic_lease`/`_release` criam e tiram o A/AAAA e o PTR de uma
  concessão (para a G4.2, cujo critério foi atualizado). GUI: janela IP › DNS TSIG Keys, Update Keys
  e Allow Update no diálogo da zona, linhas `D` nos registros. Testar: `ip.dns.tsig-key.add
  '{"name":"dhcp-ddns"}'`, `ip.dns.zone.set '{"id":"lan.example","update_keys":"dhcp-ddns"}'`,
  `nsupdate -y hmac-sha256:dhcp-ddns:<secret>`; namespace com o `nsupdate` do BIND.

- 2026-10-22 — G4.2: Servidor DHCPv4 (G4.2a), Rust puro sobre o `dhcproto`, com os menus e nomes do RouterOS v7:
  `ip.pool.*` (faixas, `next_pool`, `/ip pool used`), `ip.dhcp-server.*` (interface, pool ou
  `static-only`, `lease_time` 30m, `authoritative` com os atrasos, `conflict_detection`,
  `always_broadcast`, `server_address`, `relay`, `dhcp_option_set`, `address_lists`,
  `client_mac_limit`, `client_rate_limit`), `network.*` (gateway, DNS, domínio, NTP, WINS, PXE,
  opções e `dns_zone`), `lease.*` (fixas e dinâmicas, `make-static`, `release`, `block`,
  `check-status`), `option.*`, `option-set.*`, `matcher.*` (vendor class e outros, `exact`/`substring`)
  e `alert.*` (servidor estranho, log `dhcp,critical`). O núcleo é puro
  (`proto-dhcp/src/server/`: RFC 2131 §4.3.1–§4.3.5, §4.1, §4.4.5, RFC 6842, 3046, 4702, 4361),
  o engine (`engine/src/dhcp_server.rs`) grava o diário (`journal-dhcp-leases.log`, uma linha JSON
  por mudança, `fdatasync` por rodada antes de qualquer ACK, compactação atômica por hora ou a 2×
  os registros), responde, nomeia a concessão no DNS (A + PTR, TTL ⅓ da concessão, mínimo 600 s,
  via `dns_dynamic_lease`) e a põe nas address-lists do firewall; o serviço `dhcp-server` do daemon
  o dirige sob o supervisor; o `hal-linux` fala `AF_PACKET`+BPF, UDP 67 e ARP. Sonda ARP antes de
  oferecer (endereço que responde vira `conflict` com o motivo e outro é oferecido), checagens contra
  erro do operador (pool com gateway ou endereço do roteador, pools sobrepostos: erro; interface com
  cara de WAN: aviso), limite de mensagens por cliente com descartes contados por motivo,
  estatísticas (`ip.dhcp-server.statistics.print/reset`: uso de pool com alerta a 80 %, mensagens,
  ACK/s com pico, p50/p99, descartes) e no `/metrics` (`corerouter_dhcp_*`). GUI: IP › DHCP Server
  (abas DHCP, Networks, Leases com selos, Options, Option Sets, Matchers, Alerts), IP › DHCP
  Statistics e IP › Pool; selos dentro de células de tabela (`chip::cell`). O lab tem hosts
  simulados atrás de cada porta (quatro clientes, um invasor no `.11`, um servidor estranho).
  Testar: `ip.address.add '{"address":"192.168.88.1/24","interface":"ether2"}'`, `ip.pool.add
  '{"name":"lan","ranges":"192.168.88.10-192.168.88.50"}'`, `ip.dhcp-server.add
  '{"interface":"ether2","address_pool":"lan"}'`, `ip.dhcp-server.network.add
  '{"address":"192.168.88.0/24","gateway":"192.168.88.1"}'`, `ip.dhcp-server.lease.print`; netns
  com o nosso cliente (`apps/corerouter-daemon/tests/netns_dhcp_server.rs`: concessão, conflito,
  DNS, renovação, reinício pelo diário, release). Achado: o `dhcproto` 0.15 escreve uma opção 82
  crua duas vezes (a 82 é escrita por nós).

- 2026-10-22 — G4.2: A G4.2 fecha com a parte 3 (G4.2c, servidor DHCPv6): servidor DHCP completo, v4 e v6, com relay,
  em Rust puro.

- 2026-10-22 — G4.2b: DHCP, parte 2 (G4.2b): `ip.dhcp-relay.*` (interface, servidores, `local_address`/giaddr,
  `add_relay_info` com circuit id = nome da interface e remote id = MAC do cliente,
  `relay_info_remote_id`; contadores de pedidos, respostas e descartes) — núcleo puro em
  `proto-dhcp/src/relay.rs` (RFC 1542 §4.1, RFC 3046 §2.1/§2.2), em tempo de execução em
  `engine/src/dhcp_relay.rs` (com servidor do próprio roteador em memória; para fora, socket UDP 67
  do `hal-linux`). No servidor: opção 82 lida (`server/agent.rs`) e mostrada (`agent_circuit_id`,
  `agent_remote_id`), concessão fixa por porta (`agent_circuit_id`/`agent_remote_id`, RouterOS 7.21),
  renovação unicast direta reconhecida pela concessão (antes caía no servidor da interface de
  chegada e levava NAK). Histórico (`server/history.rs`, `engine/src/dhcp_history.rs`): uma entrada
  por vinculação, diário próprio, `ip.dhcp-server.history.print` (inclusive "quem tinha às HH:MM"),
  `.export` (CSV), `ip.dhcp-server.config.set history_retention` (padrão 1 ano, Marco Civil; 0
  desliga). Durações também em semanas e dias longos (`365d`, `52w`). O alerta manda um DISCOVER por
  minuto. GUI: IP › DHCP Relay; aba History no DHCP Server (busca, Export CSV para a área de
  transferência); selo da porta, colorido por hash, nas concessões. Testar: `ip.dhcp-relay.add
  '{"interface":"ether3","dhcp_server":"192.168.88.1","add_relay_info":true}'` com um servidor
  `relay` = o endereço de ether3; `ip.dhcp-server.history.print '{"address":"10.20.0.10"}'`; netns
  `apps/corerouter-daemon/tests/netns_dhcp_relay.rs` (três daemons).

- 2026-10-22 — G4.2c: DHCP, parte 3 (G4.2c): servidor DHCPv6 puro (`proto-dhcp/src/server6.rs`, RFC 9915 §16, §18.3,
  §19, §21.4) com Solicit/Advertise/Request/Renew/Rebind/Release/Decline/Confirm/Information-request,
  Rapid Commit, Preference, Relay-Forw/Relay-Repl aninhados (até 8 saltos); IA_NA por hash do cliente
  (o mesmo endereço em qualquer roteador), IA_PD do pool (dica, fixo, próximo livre); diário
  `journal-dhcp6-leases.log`. Engine (`engine/src/dhcp6_server.rs`): rota dinâmica (flag D) a cada
  prefixo delegado via o cliente ou o relay, aplicada pelo `Session::effective`; AAAA + PTR pela opção
  39; relay v6 em memória para o servidor do roteador, ou por UDP 547. Comandos `ipv6.pool.*`,
  `ipv6.dhcp-server.*`, `ipv6.dhcp-server.binding.*`, `ipv6.dhcp-relay.*`; hal-linux UDP 547 por
  interface no `ff02::1:2`; hosts DHCPv6 simulados no lab (`lab_hosts6.rs`). GUI: IPv6 › DHCPv6
  Server (Servers, Bindings, Pools, Relays). Testar: `ipv6.pool.add
  '{"name":"cpe","prefix":"2001:db8:100::/48","prefix_length":56}'`, `ipv6.dhcp-server.add
  '{"interface":"ether2","prefix_pool":"cpe"}'`, `ipv6.dhcp-server.binding.print`; netns
  `apps/corerouter-daemon/tests/netns_dhcp6_server.rs` (o nosso cliente DHCPv6 recebe endereço e /56,
  a rota ao /56 aparece no kernel, e volta depois de reiniciar o servidor).

- 2026-10-22 — G6.6: DNS Lookup estilo `dig`: `tool.dns.query {name, type?, server?, recursion?, dnssec?, tcp?,
  trace?, compare?}` roda como tarefa (nunca espera a rede sob o lock do `Session`). Com o
  servidor padrão (o roteador), a pergunta desce a cadeia do encaminhador da LAN dentro do
  processo e a resposta diz a etapa que respondeu (`cache`, `static`, `adlist`, `zones`,
  `upstream`); também um IP (UDP, TCP no truncamento ou com `tcp`), DoH/DoT (cliente da G4.1d) ou
  todos os upstreams. `compare` pergunta a todos em paralelo e marca `diverge` em quem foge da
  maioria (endereços comparados pelo AS de origem: CDN não diverge, sinkhole e sequestro sim) e
  `timeout` em quem não respondeu; `trace` vai da raiz até a resposta, uma linha por delegação,
  com o selo `assinada` quando veio DS/RRSIG (sem validar: G4.1f). Codec em
  `proto-dns/src/dig.rs`: consulta com RD/DO, resposta inteira (flags, EDNS, as três seções, RRSIG,
  DS e DNSKEY no formato da RFC 4034), texto no formato do `dig` e as delegações do trace. Janela
  Tools › DNS Lookup com selos (status, flags, tempo, servidor, etapa), Answer/Authority/Additional
  uma linha por registro com a pílula do AS, tabelas de compare e trace, "Copy as dig". Terminal:
  `/tool dns-lookup example.com type=MX dnssec=yes`.

  Como testar: `corerouter-cli --connect 127.0.0.1:7979 watch tool.dns.query
  '{"name":"example.com","compare":true}'`; na GUI, Tools › DNS Lookup. Testes: codec e texto do
  `dig` (proto-dns, com proptest), tarefa com sucesso, validação, timeout, PTR, compare e trace
  com backend falso (engine), compare na rede com quatro upstreams UDP em 127.0.0.1–4 (um diverge,
  um calado; daemon), `/tool dns-lookup` no terminal (shell) e a janela headless (ui).
  Ao vivo (**medido**, 2026-10-22, daemon debug no lab virtual): compare de 4 upstreams com um
  calado em ~3 s (o timeout de um, não a soma); trace de `www.example.com` em 3 delegações.

- 2026-10-22 — ui: Janelas de ferramentas do tamanho do conteúdo, e o `:resolve` só no Tools (pedido do usuário).

  - **IP › DNS Resolve saiu.** Era um subconjunto do Tools › DNS Lookup (G6.6), e perguntar um nome é
    diagnóstico, não configuração. O **Resolve…** da janela DNS Cache abre o DNS Lookup já com o nome
    e o tipo da entrada selecionada, perguntando ao roteador. O comando `ip.dns.resolve` (o
    `:resolve` do RouterOS) continua para o terminal, scripts e MCP.
  - **Tools › DNS Lookup e MTR abrem da altura do formulário** e crescem com as respostas (o egui
    aumenta a janela quando o conteúdo cresce), em vez de abrir num tamanho fixo com a tabela
    ocupando o espaço vazio. Redimensionada pelo usuário, a janela fica do tamanho que ele deu. As
    listas (Interfaces, Leases, Firewall…) continuam com tamanho fixo, como no WinBox.

  Como testar: abra Tools › DNS Lookup (só o formulário), pergunte `uol.com.br` (a janela cresce
  com as respostas); DNS Cache › selecione uma entrada › **Resolve…**; Tools › MTR.

- 2026-10-22 — audit-control: Auditoria do canal de controle (TCP/TLS/WebSocket, login, MCP, CLI): 13 dos 14 achados
  corrigidos, 1 parcialmente (vira gap). Cada teste abaixo falhou na `origin/main` (19b550e) antes
  da correção (**medido**: rodados numa cópia da `main` com a API adaptada).

  - **Safe Mode nunca desfeito quando o caminho do dono morre em silêncio** (alta). Sem keepalive
    nem timeout, a thread da conexão ficava presa no `read` para sempre quando rota, endereço ou
    firewall cortavam a gerência (nenhum FIN/RST chega), e o `hang_up` nunca rodava. Agora todo
    socket aceito tem TCP keepalive (15 s + 3 × 5 s) e `TCP_USER_TIMEOUT` de 30 s no Linux
    (`control::conn::keepalive`, crate `socket2` já presente no lockfile). Teste
    `netns_safe_mode_drop` (namespace sem root: TLS em `10.77.0.1`, Safe Mode, `ip addr del`): o
    desfazer roda em 3,1 s com keepalive curto (**medido**); na `main`, nada em 20 s.
  - **Vagas esgotadas antes do login / slowloris** (alta). 16 conexões TLS ociosas seguravam
    todas as vagas para sempre, e os 10 s do handshake/cabeçalho eram por `read`, não prazo. Agora
    `conn::Sock` aplica um **prazo total** (handshake TLS e cabeçalho HTTP: 10 s), conexão sem
    login cai após 30 s ociosa, só 8 das 16 vagas podem estar sem login e 4 por origem de rede
    (IPv4 ou /64 IPv6). Testes `idle_strangers_do_not_lock_the_operator_out`,
    `a_trickled_tls_handshake_is_cut_at_the_deadline`, `websocket_head_deadline_and_503`,
    `conn::tests::*`.
  - **Requisição de 16 MiB virava `Value` antes de conferir o token** (alta). O envelope agora é
    lido com `&RawValue` (`id`, `params`); `params` só é convertido depois do token (ou, no
    `auth.login`, até 4 KiB); da rede, antes do login, a linha (e a mensagem WebSocket) vai até
    64 KiB, subindo para 16 MiB depois. Teste `params_are_parsed_only_after_the_token_check` e a
    parte "stranger" do `netns_safe_mode_drop`.
  - **Limite de login furado por paralelismo e IPv6; Argon2 sem limite** (média). Falhas contam
    por origem IPv4 ou /64 IPv6; a tentativa conta ao começar (checar e contar sob a mesma trava);
    no máximo 2 verificações Argon2 ao mesmo tempo (`LOGIN_BUSY` após 5 s); mapa cheio descarta
    primeiro origens não bloqueadas, nunca `user admin`, e fica sempre ≤ 4096. Testes
    `a_full_failure_map_keeps_the_user_keys`, `parallel_and_rotated_attempts_are_all_counted`
    (16 tentativas paralelas de um /64 → 6 Argon2, 10 recusadas).
  - **`localhost` mandava o token local para quem escutasse em `[::1]`** (média). `dial` resolve
    `localhost` como `127.0.0.1`, tenta todos os endereços em ordem e só envia o token local se o
    par conectado for `127.0.0.1` (único endereço em que o roteador escuta em claro). Teste
    `dial::tests::the_local_token_goes_only_to_127_0_0_1`.
  - **MCP `run_task` (read-only) executava qualquer comando** (média). Agora só `tool.*` (fora
    `tool.task.*`), recusado antes de rodar. Teste `run_task_refuses_anything_but_a_tool`.
  - **Um usuário derrubava as sessões dos outros** (baixa). Limite de 16 sessões por usuário no
    `Gate` e no `Logins` do engine (o 17º login tira o mais antigo **dele**); token despejado
    encerra o login em `user.active.list`. Testes `repeated_logins_do_not_evict_other_users`,
    `engine::auth::tests::repeated_logins_evict_only_the_same_user`.
  - **Panic numa thread de conexão vazava a vaga e pulava o `hang_up`** (baixa). A vaga vive no
    socket (devolvida no `Drop`) e `serve_then_hang_up` roda o `hang_up` sob `catch_unwind`.
    Teste `a_panicking_connection_frees_its_slot_and_undoes_safe_mode`.
  - **Erro de `accept` girava a 100 % de CPU** (baixa): pausa de 100 ms após a falha (sem teste:
    exigiria esgotar descritores).
  - **Arquivo estático lido inteiro na memória, sem timeout de escrita** (baixa): arquivos vão em
    fluxo (`io::copy`) e todo socket tem timeout de escrita de 30 s.
  - **Conexão WebSocket acima do limite recebia uma linha JSON, não `503`** (baixa): `503` no
    WebSocket/HTTP, linha JSON no TCP, nada no TLS (coberto em `websocket_head_deadline_and_503`).
  - **`server.info` revelava versão e commit sem login pela rede** (baixa): da rede, sem login, só
    `{name, auth}`; loopback inalterado (`server_info_on_loopback_is_complete`, netns).
  - **Chave TLS restaurada com 0644 ficava legível** (baixa): escrita em arquivo temporário 0600 +
    `rename`, e chave existente com bits de grupo/outros volta a 0600 com aviso. Teste
    `tls::tests::a_world_readable_key_is_made_private`.
  - **MCP respondia respostas JSON-RPC e ecoava `id` objeto/array** (baixa): resposta não é
    respondida (§5), `id` não escalar dá `-32600` com `id: null` (§4). Teste
    `responses_are_not_answered_and_ids_are_scalars`.

  Conferido e correto (sem mudança): ping do servidor WebSocket não é necessário (o keepalive TCP
  acha o par morto); depois do login não há limite de ociosidade de propósito (MCP e GUI ficam
  horas parados, o token local não expira, e o MCP `Remote` não reconecta).

  Ficou para depois:

- 2026-10-22 — audit-dhcp: Auditoria do DHCP (servidor v4/v6, relay, histórico): 19 achados verificados no código, 18
  corrigidos (um em parte), dois viram gaps. Cada correção tem um teste que falhava na `main`.

  Altos:

  - **DHCPv6: SOLICIT de DUIDs aleatórios enchia a memória.** Cada SOLICIT num pool IA_NA /64 criava
    um registro `offered` guardado 120 s + 7 dias, sem teto (100k SOLICITs = 100k registros, **medido**).
    Agora a tabela tem teto (`MAX_BINDINGS6` = 131.072; cheia, sai primeiro o registro livre mais
    antigo, senão o cliente é recusado com `table-full`), uma oferta não aceita some quando o prazo
    acaba (nunca foi vinculada nem escrita no diário) e o `tick` acha o que vence por um índice
    ordenado, sem percorrer a tabela. Testes `a_solicit_flood_cannot_fill_memory`,
    `the_cap_evicts_free_records_first`.
  - **Opção 82 do próprio cliente era acreditada.** Um cliente na rede (`giaddr` 0) com a 82 de outro
    assinante pegava a concessão fixa dele, e o histórico (Marco Civil) gravava o circuito da vítima.
    RFC 3046 §2.1/§5: o servidor ignora a 82 sem relay, a menos que `relay_info_trusted` (novo, em
    `ip.dhcp-server`: agente L2 confiável, como uma OLT); o relay descarta o pedido que já chega com
    82 (`untrusted-82`) a menos que `relay_info_trusted` (novo, em `ip.dhcp-relay`; o Cisco faz o
    mesmo por padrão). Junto: a renovação sem relay apagava a 82 guardada na concessão, e a segunda
    renovação de uma fixa por circuito levava NAK — corrigido. Testes
    `option_82_from_a_client_is_not_believed`, `renewals_keep_the_relay_agent_information`,
    `a_clients_option_82_is_not_relayed`.
  - **Tempestade: escritas síncronas por concessão, sob o lock da sessão.** Uma rodada de 128
    vinculações fazia 129 appends com fsync (o histórico, um por concessão), 256 regravações do estado
    do DNS dinâmico (A e PTR, cada uma com o estado inteiro e dois syncs) e 128 cópias da config
    inteira para a checagem de lockout das address lists: 220 ms por rodada em memória, 840 ms com
    fsync no NVMe (**medido**), tudo com o `Mutex<Session>` preso. Agora o histórico é um append por
    rodada, o DNS é salvo uma vez por rodada (o serial das zonas sobe uma vez) e as entradas de lista
    da rodada passam por uma checagem de lockout só, contra a config emprestada. Teste
    `a_storm_round_writes_once_per_journal` (2 appends e 1 save por rodada; era 129 e 256).
  - **O serviço DHCP matava de fome o plano de controle.** Com mensagens chegando, o laço voltava a
    pegar o lock sem pausa (o mutex não é justo): canal de controle, MCP e GUI quase não entravam.
    Agora há sempre 1 ms entre rodadas, e cada rodada para de ler depois de 20 ms
    (`ROUND_BUDGET_US`), além do limite de 256 mensagens. Testes `a_storm_round_is_bounded_in_time`,
    `the_loop_always_rests`.

  Médios:

  - **Depois de reiniciar, as concessões perdiam as address lists e os nomes no DNS ficavam para
    sempre.** As entradas de lista (não guardadas) voltam ao carregar o diário, e os nomes A/PTR
    guardados são reconhecidos para sair quando a concessão acaba. Teste
    `bindings_get_their_names_and_lists_back_after_a_restart`.
  - **Histórico no teto (500k): O(N) por vinculação e a compactação apagava registros legais.** Agora
    é um `VecDeque` com numeração (descartar o mais antigo é O(1): 5,2 ms → microssegundos por
    vinculação, **medido**). O que sai da memória pelo teto fica só no disco: a compactação (escrita
    da memória) não roda enquanto houver registro assim dentro da retenção, e isso é avisado uma vez no
    log (`dhcp,error`). Testes `opening_at_the_cap_is_cheap` (inclui `can_compact`). O arquivo
    segmentado que limita o disco virou a gap G4.2g.
  - **Custo por DISCOVER linear em fixas, concessões e pool.** Fixas indexadas por client id, MAC,
    circuit id, remote id e endereço (65.536 fixas: 1,76 ms → µs por DORA, **medido**); reuso do
    endereço livre mais antigo por um índice ordenado; pool esgotado lembrado mesmo com endereços
    pulados (quem responde a todo ARP fazia cada resposta varrer o pool); `client_mac_limit` por
    índice de MAC; "pool cheio" no log uma vez por minuto por pool (era um aviso por DISCOVER).
    Testes `many_static_leases_are_found_by_index`, `a_full_pool_is_logged_once_a_minute`.
  - **DHCPv6 PD esgotado: o pool inteiro varrido a cada SOLICIT** (2^16 prefixos: 6,4 ms por mensagem,
    **medido**). O pool cheio é lembrado até um prefixo se soltar. Teste
    `a_full_pd_pool_is_remembered_until_a_prefix_frees`.
  - **Client id ou opção 82 com mais de 255 bytes (RFC 3396)** passavam no servidor e eram recusados na
    volta do diário, trazendo de volta a linha anterior do endereço (outro cliente). Agora o pedido é
    recusado (RFC 2132 §9.14, RFC 3046 §2.0). Teste `oversized_client_id_or_agent_info_is_refused`.
  - **Cliente não-Ethernet sem client id levava NAK em laço** (e todos dividiam a mesma chave). A
    concessão guarda `htype` + `chaddr` (campo `hw` no diário, opcional). Teste
    `non_ethernet_clients_are_bound`.

  Baixos:

  - Diário com falha: o ACK continua saindo (escolha documentada: disponibilidade primeiro, o erro
    fica na linha do serviço), mas a compactação que falha só é tentada de novo depois de 60 s (era a
    cada rodada, serializando a tabela inteira). Teste `a_failing_disk_is_not_rewritten_every_round`.
  - CSV do histórico: célula que começa com `= + - @ tab CR` sai como texto (`'`), OWASP. Teste
    `csv_cells_are_never_formulas`.
  - `parse_time` com ano, hora ou fuso absurdos dava overflow (panic em debug); `covers` também.
    Teste `hostile_times_do_not_overflow`.
  - DHCPv6: Information-request sem Client Identifier agora tem resposta (RFC 9915 §18.3.6); DUID
    vazio (ou de 1 byte) é recusado (§11.1). Teste `information_request_without_client_id_and_empty_duids`.
  - A resposta ARP do próprio cliente ao endereço oferecido a ele não é conflito (RFC 5227). Teste
    `the_clients_own_arp_answer_is_not_a_conflict`.
  - Relay: resposta que não vem de um dos `dhcp_server` dele é descartada (`not-from-server`). Teste
    `the_relay_only_takes_replies_from_its_servers`.
  - RELEASE/DECLINE no enlace do servidor só valem vindos do MAC Ethernet e da porta do próprio
    cliente. Teste `spoofed_release_is_dropped`.
  - Opção 52 (overload, RFC 2132 §9.3) agora é lida (`file` e `sname`). Teste
    `option_overload_is_honoured`. A segunda metade do achado (resposta acima da opção 57 mesmo sem as
    opções não forçadas) ficou como está: descartar a resposta transformaria uma opção forçada grande
    demais numa queda do DHCP, e os clientes reais aceitam 1500.
  - Diário maior que o limite de leitura (512 MB) agora é lido pelo fim (as linhas mais novas; "a
    última vence"), e os replays de concessões v4/v6 e do histórico guardam as últimas linhas, não as
    primeiras. Testes `an_oversized_journal_keeps_its_newest_lines`, `replay_keeps_the_newest_lines`.

  Verificado e certo: o que o revisor listou em "Checked, looks fine" confere. Limite de taxa por
  cliente no DHCPv6 já é parte da G4.2f (não virou gap nova).

  Como testar: `cargo test -p corerouter-proto-dhcp`, `cargo test -p corerouter-engine --test
  dhcp_storm`; benchmarks `cargo bench -p corerouter-proto-dhcp --bench server_attack` e `cargo bench
  -p corerouter-engine --bench dhcp_round` (rodada de tempestade com histórico, zona DNS e address
  list; `fsync` grava arquivos de verdade).

- 2026-10-22 — audit-dns: Auditoria do DNS (resolvedor, encaminhador da LAN, zonas, transferências, UPDATE/TSIG, cliente
  HTTP das adlists e do DoH). Corrigido, cada um com teste que falhava antes:

  - **TCP/53 tomado por quem não pode perguntar nada, e por gotejamento** (alta). O accept dava
    vaga de `max_concurrent_tcp_sessions` a qualquer um antes do ACL, e o `TCP_IDLE` valia por
    `read()`: 20 conexões mandando um byte a cada 9 s seguravam o TCP da LAN (fallback do TC,
    AXFR, UPDATE) por dias. Agora o accept fecha quem não é o roteador, `allowed_from` nem um par
    que alguma zona nomeia (`zone::xfr::may_connect`: `allow_transfer`, `allow_update`,
    `primaries`; zona com TSIG sem `allow_update` aceita qualquer origem), cada origem fica com no
    máximo 1/4 das vagas, a mensagem tem 10 s do primeiro ao último byte (o buffer cresce com o
    que chega, o tamanho 65 535 sozinho não aloca nada) e a conexão não lê consulta nova depois
    de 2 min. Testes `who_may_connect`, `tcp_slots_survive_slow_and_greedy_peers`.
  - **IXFR falsificado por UDP serializava a zona inteira no thread do listener** (média). Um IXFR
    de serial antigo vindo (forjado) de um endereço de `allow_transfer` copiava e codificava a zona
    toda (200 ms por pacote numa zona de 50 000 registros, build de debug, **medido**) só para
    descobrir que não cabia no UDP. Agora a contagem de registros decide antes (RFC 1995 §2: o SOA
    na hora). Teste `udp_ixfr_of_a_big_zone_is_the_soa_without_encoding_it`.
  - **Despejo do cache O(n) por inserção, sob o lock do resolvedor** (média). Com o cache cheio,
    cada `put` varria o mapa duas vezes sob o mutex que todo acerto de cache também pega. Agora um
    índice por expiração (`BTreeSet`) despeja em O(log n). Teste
    `eviction_follows_the_expiry_index`; números em `## perf`.
  - **Pré-requisitos do RFC 2136 checados fora do que aplica** (média, RFC 2136 §3.7). Dois UPDATEs
    "nome não está em uso" lidos antes de qualquer um aplicar passavam os dois. Agora o UPDATE
    guarda a versão dos registros dinâmicos que viu; `Session::dns_dynamic_update` só aplica se ela
    não mudou, senão o daemon confere os pré-requisitos de novo (`zone::update::recheck`) e tenta
    outra vez (YXDOMAIN no segundo). Testes `prerequisites_hold_when_the_update_applies`,
    `an_update_checked_against_old_records_waits`.
  - **UPDATE por UDP esperava o lock da sessão e a gravação em disco no thread do listener**
    (média). Agora vai para o thread `dns-update` (fila de 64; cheia, descarta e o cliente
    repete). Teste `an_update_never_holds_up_queries`.
  - **Cliente HTTP sem prazo de verdade** (média). O timeout do socket recomeçava a cada byte e o
    laço de trailers não tinha limite: um servidor de adlist lento segurava o thread por semanas e
    trailers sem fim, para sempre. Agora cada leitura espera só o que falta até o prazo, e no
    máximo 64 linhas de trailer. Testes `a_slow_server_never_outlives_the_deadline`,
    `endless_trailers_are_refused`.
  - **EXPIRE da secundária sem piso** (média). `refresh 3600 expire 60` derrubava a cópia 60 s depois
    de cada checagem (SERVFAIL ~59 min por hora). Agora EXPIRE ≥ REFRESH + RETRY (RFC 1912 §2.2,
    como o BIND). Teste `expire_is_at_least_refresh_plus_retry`.
  - **Tabela do limite por cliente varrida a cada pacote novo com ela cheia** (baixa). Agora no
    máximo uma varredura por segundo. Teste `a_full_table_is_swept_once_a_second`.
  - **Janela do TSIG vinha do Fudge do cliente (até 18 h)** (baixa). Agora vale também o nosso
    limite de 300 s (RFC 8945 §5.2.3/§10), a mesma mensagem (mesmo Time Signed e MAC) é recusada
    como repetição, e um Time Signed menor que o Fudge é recusado antes do hickory (que subtrai sem
    checar e daria panic no build de debug). Teste `signed_updates_follow_rfc8945`.
  - **`ip.dns.cache.print/flush` formatavam o cache inteiro sob o lock** (baixa). O flush conta sem
    formatar (`DnsBackend::cache_len`); o print filtra nome e tipo dentro do cache antes de formatar
    e para em `limit` (novo parâmetro, padrão 1000, máximo 100 000). Teste
    `cache_print_is_bounded_and_flush_does_not_format`.
  - **Config antiga reconstruía as zonas para trás** (baixa). Uma consulta com o `ServerConfig`
    anterior que chegava depois do novo construído refazia as zonas velhas (diff invertido no
    diário do IXFR, NOTIFY com o serial antigo). Agora usa a config mais nova; os registros
    dinâmicos são relidos sob o lock. Teste `an_older_config_never_rolls_the_zones_back`. (A
    reconstrução de todas as zonas a cada mudança virou a G4.1p.)
  - **Fila de efeitos sem limite** (baixa). Agora `sync_channel(4096)`; cheia, descarta (a próxima
    resposta acrescenta o endereço de novo). Teste `effects_queue_is_bounded`.
  - **Redirect de adlist para dentro do roteador** (baixa, SSRF cego). Um redirect de um servidor
    de fora para loopback, rede privada, CGNAT, ULA ou link-local é recusado (uma lista que já
    estava dentro pode). Teste `redirects_inward_are_refused`.
  - **Respostas perdidas em silêncio** (baixa). Transferência com mensagem que falha ao codificar
    vira SERVFAIL em vez de SOA … SOA incompleto (`xfr::whole`); falha ao criar o thread de uma
    consulta UDP responde SERVFAIL; resposta TCP acima de 64 KiB vira SERVFAIL.

  Teste instável `answers_the_lan_over_udp_and_tcp` (saiu FLAKY num CI completo da `main`): o
  upstream de teste tinha 300 ms de timeout e o cliente 500 ms; numa máquina carregada o resolvedor
  perguntava duas vezes (contador do upstream em 2) ou o cliente desistia antes da resposta. Agora
  3 s no upstream, 5 s no cliente para as respostas que dependem do upstream e 20 s no `wait`.

  Conferido e sem mudança: o restante da lista "Checked, looks fine" do auditor (limites do parser,
  TTLs, ACL antes do limite, NOTIFY só de primário, transferência de entrada limitada).

  Ficou para depois:

- 2026-10-22 — audit-net: Auditoria de interfaces, endereços, rotas, VRF, listas de interface e firewall (com a aplicação no
  kernel): 12 dos 14 achados corrigidos aqui, 2 já tinham entrado pelo `audit-persist` (#123), 1
  parte vira gap. Resolve a gap **G0.14** (validação do firewall O(n²) no commit). Cada teste
  abaixo falhou na `main` (63116ed) antes da correção (**medido**: rodados com o código da `main` e
  a API adaptada); os de desempenho têm bench antes/depois na seção `## perf`.

  Corrigido:

  - **Alto — validar o firewall era O(N²) em todo commit** (#1, G0.14). `rule_issues` clonava a
    tabela inteira e remontava o grafo de jumps para cada regra; com 3000 regras qualquer commit
    levava ~0,58 s em release. Agora `validate` monta as arestas uma vez por tabela
    (`graph::edges`) e guarda as raízes de cada chain (`graph::roots_in`); o comando de uma regra
    só monta o grafo uma vez, sem clonar. Bench `engine_scale/validate_all/filter_rules/3000`:
    562 ms → 0,22 ms; `commit/filter_rules/3000`: 584 ms → 49 ms (o resto é gravar o arquivo).
  - **Alto — validar rotas era O(R²) em todo commit** (#2). Cada rota era comparada com todas as
    anteriores; agora só com as do mesmo `(routing_table, dst_address)` (`BTreeMap`).
    `validate_all/routes/10000`: 48 ms → 1,2 ms. Teste `duplicate_routes_are_found_across_the_list`
    (guarda: duplicata separada por outras rotas ainda é achada).
  - **Médio — expirar entradas dinâmicas rodava um `nft` por entrada, sob o lock** (#3). Agora a
    expiração vai num só `DynamicChange::Expired(&[..])` (variante nova, aditiva, em `hal`); o
    `LinuxHal` não roda nada (o timeout do próprio set já as tirou do kernel), o lab esquece todas
    de uma vez. Teste `dynamic_entries_expiring_together_are_one_data_plane_change` (300 entradas:
    1 chamada, eram 300).
  - **Médio — porta sem gaiola SFP era sondada a cada 30 s, sob o lock** (#3). O `scan_modules`
    lembra as portas que respondem "sem EEPROM de módulo" (`Unsupported`) e não pergunta de novo
    (porta que sai da config volta a ser sondada). Teste
    `ports_without_a_cage_are_not_probed_on_every_scan` (4 varreduras de 8 portas: 8 leituras,
    eram 32). Tirar a varredura de dentro do lock vira a gap G1.22.
  - **Médio — remover endereços era O(n²) no kernel** (#4). Cada `DelAddress` fazia um dump
    `RTM_GETADDR` de todos os endereços do namespace (filtrado em espaço de usuário); agora manda
    `RTM_DELADDR` com o endereço montado (`AddressMessageBuilder`), e o kernel responde
    EADDRNOTAVAIL se ele já não está. Bench netns novo `hal_linux_apply/addresses_remove/1000`:
    260 ms → 32 ms.
  - **Médio — IPv6 com o mesmo endereço e outro prefixo era aceito e não instalado** (#5). O Linux
    identifica o endereço IPv6 só por endereço + interface (EEXIST no segundo), o plano adotava o
    erro como "já existe" e, removido o primeiro, a interface ficava sem endereço. Agora
    `ip.address.add` e `validate_all` recusam ("2001:db8::1 is already on ether1 as
    2001:db8::1/64"); outra interface, outro pool e IPv4 com outra máscara continuam valendo.
    Testes `an_ipv6_address_cannot_be_on_one_interface_twice_with_two_prefixes`,
    `validation_refuses_an_ipv6_address_twice_on_one_interface`.
  - **Médio — renomear lista de interfaces quebrava RA e DNS** (#6). `interface.list.set
    new_name` agora leva junto `ipv6.settings accept_router_advertisements_on` e os itens de
    `ip.dns allowed_from` (como o RouterOS); células da matriz de zonas entram no `used_by` (a
    renomeação é recusada, como já era com regras). `interface.list.remove` de uma lista que o DNS
    usa é recusado com o motivo (antes: erro de validação sem relação no commit). Testes
    `renaming_an_interface_list_renames_its_references`,
    `removing_an_interface_list_dns_uses_is_refused`.
  - **Médio — checagem de lockout via a interface errada** (#7, parte que faltava). A sonda usava
    como entrada a interface que tem o endereço local: com gerência num loopback /32 (`lo0`)
    alcançado pela WAN, um `drop` na lista WAN passava. Agora a entrada é a interface para onde o
    roteamento aponta o par (rede conectada ou rota mais específica, na tabela do endereço local;
    sem rota, a de antes). E `ip.firewall.address-list.add` com timeout checa sobre a config
    efetiva (endereços/rotas de DHCP), como o commit. Testes
    `lockout_sees_the_wan_ingress_of_a_loopback_management_address`,
    `lockout_uses_the_port_facing_a_connected_peer`.
  - **Baixo — `ip.route.list` era O(L²)** (#8): o vencedor de cada grupo (tabela, destino) sai numa
    passada. `ip.route.list/10000`: 64,6 ms → 14,0 ms.
  - **Baixo — endereços sem limite e com etapas quadráticas** (#9). `MAX_ADDRESSES` = 65 536 em
    `ip.address.add` e `validate_all` (`corerouter_engine::validate::MAX_ADDRESSES`);
    `route::connected` deduplica com `BTreeMap`; `plan::rebuilt_links` calcula os links com IPv4
    uma vez. Teste `addresses_are_bounded`.
  - **Baixo — address-lists: varreduras lineares e render duplo** (#10). `render` agrupa entradas
    por lista e regras por chain uma vez (era O(listas × entradas)); `nft::changed` só renderiza
    quando firewall ou listas de interface mudaram (o `LinuxHal` e o lab renderizavam as duas
    configs em todo commit); entradas dinâmicas têm índice `(lista, endereço)`.
  - **Baixo — `address-list.set` duplicava uma entrada dinâmica** (#11). Agora confere as
    dinâmicas como o `add`. Teste `address_list_set_refuses_an_address_a_dynamic_entry_has`.
  - **Baixo — `nft` e genl sem prazo total** (#12). `nft::run_bounded` mata o `nft` depois de 30 s
    (stdin, stdout e stderr em threads, para um filho que não lê nem sai também não travar), usado
    por `run` e `list_json`; `Genl::call` tem um prazo de 1 s para a resposta inteira (notificações
    de multicast reiniciavam o timeout de cada `poll`). Testes `nft::tests::*`.
  - **Baixo — `LinkWatch::observe` era O(vigiados × vivos) por segundo** (#13): `BTreeSet`.
  - **Lab — `VirtualHal::carry`** recalculava o estado esperado inteiro das duas configs em todo
    apply; agora só a parte cujas entradas mudaram (links/endereços só se interfaces ou endereços
    mudaram; com só rotas mudando, só as rotas alteradas). Um commit que não toca rotas não resolve
    nenhuma. `hal_virtual_apply/routes/1000` (todas as rotas novas) continua ~120 µs: é o custo de
    resolver 1000 rotas novas.

  Já corrigidos pelo `audit-persist` (#123), conferidos na `main`: #14 (o lockout só olhava o
  firewall; agora também endereço e interface) e a parte de #7 sobre a interface do endereço em
  cada lado.

  Conferido e falso ou parcial: #6 dizia que nenhuma validação conferia
  `accept_router_advertisements_on` — o `proto-dhcp` confere; o problema real era o modo
  transacional aceitar a renomeação e todo commit seguinte falhar com erro sem relação (corrigido
  acima).

  Como testar: `cargo test -p corerouter-engine --test net_audit`; `cargo bench -p
  corerouter-engine --bench scale`; `COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net
  -- cargo bench -p corerouter-hal-linux --bench netns_apply -- addresses_remove`.

  Observação (**estimado**, sem perfil: `perf` não é permitido na máquina): com as validações
  lineares, o commit com 10 000 rotas ou 20 000 entradas de address-list ainda leva ~0,3 s; o resto
  é gravar o arquivo (a running + até 64 revisões inteiras, até 32 MiB, a cada commit). Vira a gap
  G1.23.

- 2026-10-22 — audit-persist: Auditoria do núcleo do engine (persistência, Safe Mode, transações, journal, import, script do
  terminal). Cada correção tem um teste que falhava na `main` antes dela.

  Corrigido:

  - **Crítico — config grande fazia o roteador subir em branco** (#1). O arquivo guardava a running
    e as 64 revisões completas em JSON indentado, sem limite; com ~4000 entradas de address-list
    comentadas passava dos 64 MiB que a leitura aceita, as duas cópias iam para quarentena e o boot
    voltava às portas descobertas, sem endereço nem firewall. Agora o JSON é compacto, a gravação
    fica abaixo de 32 MiB (`persist::encode_bounded` deixa de fora as revisões mais antigas, nunca
    a running; `storage.revisions_not_saved` mostra quantas), um commit cuja config sozinha passaria
    de ~15 MiB é recusado com o motivo e a leitura aceita até 256 MiB (arquivos de versões
    anteriores ainda carregam). Testes: `a_big_config_with_a_full_history_still_boots`,
    `bounded_encoding_leaves_the_oldest_revisions_out`, `encoded_len_is_exact`.
  - **Alto — segredos TSIG no journal, no log e para o grupo `read`** (#3). `secret` (e `psk`,
    `private_key`, `passphrase`, para o que vier) entrou em `SECRET_KEYS`: some do journal, da
    mensagem e do detalhe do log (e portanto do syslog remoto), inclusive o secret gerado no
    resultado do `add`. Abaixo do grupo `full`, `state.inspect` e `config.diff` mostram `***`, e
    `ip.dns.tsig-key.print show_secret` exige `full` (como a política `sensitive` do RouterOS).
    Nenhum outro parâmetro secreto existe hoje na `main` (DHCP, relay e DHCPv6 não têm chave).
    Teste: `tsig_secrets_stay_out_of_the_journal_the_log_and_read_accounts`.
  - **Médio — journal sem limite** (#4): parâmetros guardados inteiros (16 MiB × 1024 entradas).
    Agora limitados como o detalhe do log (2 KiB) e o erro a 512 bytes. Teste:
    `journal_entries_are_bounded`.
  - **Médio — `config.commit`/`config.mode.set` dentro de batch atômico** (#5) comitava de verdade e
    um passo seguinte com erro deixava diferença escondida no candidate. O batch atômico agora
    recusa `config.commit`, `config.discard`, `config.mode.set` e `config.safe-mode.*` antes de rodar
    qualquer passo. Teste: `an_atomic_batch_refuses_transaction_control_steps`.
  - **Médio — commit fora do guarda de panic** (#6): um panic no validador ou no plano de dados
    deixava a edição no candidate para o próximo comando comitar. O commit do `execute`, o do batch,
    o desfazer do Safe Mode e o `tick` inteiro rodam no `guard`. Teste:
    `a_panic_while_committing_leaves_nothing_pending`.
  - **Médio — prazo do Safe Mode no relógio de parede** (#7): `Hal::monotonic_secs` (novo, padrão
    `None`; o `hal-linux` usa `CLOCK_MONOTONIC`) conduz o prazo; um passo do NTP não dispara nem
    desarma mais o Safe Mode. Teste: `the_deadline_follows_the_monotonic_clock`. O resto dos prazos
    por relógio de parede virou a gap G0.13.
  - **Médio — falha ao aplicar a config restaurada no boot** (#8) só ia para o log; kernel e
    `running` divergiam para sempre. Agora `storage.boot_apply_error` mostra o motivo, o `tick`
    tenta de novo a config inteira a cada segundo e o próximo commit aplica tudo a partir do vazio.
    Testes: `a_failed_boot_apply_is_reported_and_retried`,
    `a_commit_after_a_failed_boot_apply_applies_everything`.
  - **Médio — `/import` de um `/export` com mais de 256 comandos** (#9) era recusado. `MAX_BATCH`
    subiu para 32 768 (cobre qualquer script de 1 MiB). Testes: `an_atomic_batch_takes_a_big_import`,
    `a_big_export_imports_back`.
  - **Baixo — lockout só olhava o firewall** (#10): remover ou desativar o endereço da sessão de
    gerência, ou desativar a interface dele, agora é lockout; e cada lado da comparação usa a
    interface que tem o endereço naquela config (mover o endereço atrás de `in-interface` é pego).
    Teste: `removing_the_management_address_or_its_interface_is_a_lockout`.
  - **Baixo — contadores de id atrasados num arquivo editado** (#11): o `decode` acerta cada
    `next_*` para o maior id da sua lista e renumera ids duplicados (`persist::repair_ids`). Testes:
    `a_counter_behind_its_items_is_repaired_on_load`, `counters_behind_their_items_are_repaired`.
  - **Baixo — `tool.task.stop`/`poll` sem dono** (#12): só quem iniciou a tarefa (mesma conta) ou o
    grupo `write` para cima. Teste: `only_the_owner_or_a_writer_stops_or_polls_a_task`.
  - **Baixo — Safe Mode desfeito em modo transacional** (#13) descartava edições pendentes dizendo
    "nothing to undo"; agora `last` diz quantas foram descartadas. Teste:
    `cancel_says_when_it_drops_pending_edits`.
  - **Baixo — caracteres de controle na mensagem do log** (#14): viram espaço (linha forjada, ESC).
    Teste: `log_messages_carry_no_control_characters`.
  - **Baixo — script terminado em `\`** (#15) perdia o último comando em silêncio; agora é erro com o
    número da linha. Teste: `a_script_ending_in_a_continuation_is_refused`.
  - **Baixo — storage-fs** (#16): cada quarentena ganha seu arquivo (`.corrupt`, `.corrupt.1`, …) e
    `state-*.tmp`/`journal-*.tmp` de gravação interrompida são apagados no `open`. Testes:
    `every_quarantine_keeps_its_own_copy`,
    `stale_temp_files_of_state_and_journals_are_removed_on_open`.

  Verificado e falso:

  - #2 (mudar usuários em Safe Mode gravava a config não confirmada): `user.add/set/remove` já são
    recusados em Safe Mode desde o G0.3 (`not_in_safe_mode`). Mesmo assim o `save()` agora grava o
    store da entrada sempre que o Safe Mode está ativo (defesa em profundidade; teste
    `a_save_in_safe_mode_writes_the_entry_config`, e `user_changes_wait_for_the_end_of_safe_mode`
    documenta a recusa).
  - Em #1, "regras de firewall sem limite" não procede (`MAX_RULES` = 4096 por tabela); as
    address-lists (65 536) e o DNS estático bastam para o problema.

  Como testar: `cargo test -p corerouter-engine -p corerouter-model -p corerouter-shell -p
  corerouter-storage-fs`. No daemon, `state.inspect` mostra `storage.boot_apply_error` e
  `storage.revisions_not_saved`.

- 2026-10-22 — audit-services: Auditoria dos serviços do daemon (supervisor, NTP, syslog remoto, métricas Prometheus), das
  ferramentas ping/MTR/MTU e da descoberta de vizinhos (CRDP/LLDP/MNDP). Corrigido:

  - **CRDP travava o lock da sessão por datagrama (alta).** Cada anúncio pegava o lock e varria a
    tabela de vizinhos clonando todas as chaves (~120 µs com a tabela cheia), sem limite de taxa:
    poucos milhares de pps paravam comandos, GUI, MCP e serviços. Agora a `NeighborTable` tem
    índices (idade por interface, contagem por interface), `record` diz se o vizinho é novo em
    O(log n) (`Session::hear_neighbor`), e o receptor CRDP aceita no máximo 200 anúncios/s (50 por
    origem) antes do lock. Testes: `recording_into_a_full_table_is_cheap`,
    `receive_rate_is_limited_per_second_and_per_source`; benchmark `neighbors` (abaixo).
  - **Raspagem `/metrics` fazia netlink + ethtool por interface sob o lock (média).** Os contadores
    de erro/descarte vêm agora do próprio `poll` (`LinkState::errors`, `IFLA_STATS64`), a junção
    config × kernel é por mapa: uma raspagem custa um lock e um `poll`, como a doc prometia.
    Teste: `a_scrape_does_not_query_counters_per_interface`.
  - **Ping/MTR acima de ~68 sondas/s mostravam perda falsa (média).** Com 8192 sondas recentes a
    tabela de enviadas era apagada inteira, inclusive as em voo. Agora só sai o que passou de
    120 s (no máximo uma varredura por segundo); a chave `u16` limita a tabela a 65 536. Teste:
    `a_full_sent_table_keeps_probes_in_flight`.
  - **Tabela de vizinhos envenenada por 18 h (média).** A expulsão tirava a entrada que expira
    primeiro (sempre a legítima) e não havia teto por interface. Agora o hold aceito é no máximo
    14 400 s, cada interface guarda até 256 vizinhos e sai a entrada ouvida há mais tempo da mesma
    interface (ou da interface com mais entradas). Teste:
    `a_flood_on_one_port_does_not_evict_the_others`, `a_full_table_evicts_from_the_busiest_port`.
  - **Cliente NTP dava panic com `min_poll > max_poll` vindo do disco (média).** `clamp` com
    mínimo acima do máximo; o supervisor desistia do serviço. `next_poll` normaliza os limites
    (6..=17, em ordem) e a validação da config inteira (`validate_all`, que também roda ao
    restaurar) aponta `min_poll`/`max_poll` fora da faixa, invertidos, mais de 8 servidores ou
    servidor inválido. Testes: `poll_interval_backs_off_and_resets`,
    `a_loaded_config_with_bad_poll_bounds_is_reported`.
  - **Erros ICMP aceitos só por ident+seq (média).** Um host fora do caminho forjava "frag
    needed mtu=68" ou "unreachable" e mudava o resultado do MTU/MTR/ping. Agora o erro precisa
    citar uma sonda que ia para o mesmo destino (cabeçalho IP citado; na fila de erros do socket
    ping, o `msg_name`), o ident do socket raw é aleatório (`RandomState`) e "too big" abaixo de
    68/1280 não informa MTU. Teste: `an_icmp_error_must_quote_the_probe_destination`.
  - **MNDP aceitava unicast de qualquer lugar (média).** O listener escuta em `0.0.0.0:5678`;
    agora só valem datagramas para 255.255.255.255, para o broadcast de uma sub-rede da interface
    de chegada ou para multicast IPv6 (destino lido do `IP_PKTINFO`). Teste:
    `mndp_takes_only_broadcast_and_link_multicast` (e o `netns_l2` confere o destino).
  - **Listener CRDP da GUI com fila sem limite (média).** Com a GUI conectada (sem `poll`), cada
    anúncio da LAN se acumulava. Agora `sync_channel(MAX_HEARD)` com `try_send` (cheio: descarta).
    Teste: `the_queue_is_bounded_while_nobody_polls`.
  - **Leitor lento segurava o endpoint de métricas (baixa).** Prazo total de 10 s para a resposta,
    escrita em blocos de 16 KB. Teste: `a_slow_reader_is_cut_off_at_the_deadline`.
  - **`HostSocket::recv` girava sem fim sob enxurrada ICMP (baixa).** `drain` lê no máximo 256
    mensagens por vez; `recv` volta no prazo e a tarefa vê o stop. Teste:
    `draining_stops_after_its_budget`.
  - **SNTP: atraso negativo sempre vencia e receive = 0 era aceito (baixa).** `check_reply`
    recusa receive zero e T3 < T2 (RFC 5905 §8); `poll_round` descarta amostra com atraso
    negativo. Testes: `replies_are_checked_like_rfc_4330_section_5`,
    `a_negative_round_trip_never_wins`.
  - **Supervisor (baixa).** (a) falha ao criar a thread agora conta como falha e chega a `failed`
    depois da rajada; (b) um `restart` espera (até 2 s) as threads auxiliares da execução antiga
    soltarem os sockets antes de subir a nova. Testes: `spawn_failures_count_and_give_up`,
    `a_restart_waits_for_the_old_helpers`.
  - **Syslog remoto (baixa).** O erro de uma ação apagada ou renomeada deixa de aparecer na linha
    do serviço, e um reinício do serviço continua de onde parou no log (eventos do período em
    backoff, como "falhou", também vão). Testes: `errors_of_removed_actions_are_forgotten`,
    `a_restart_resumes_where_the_last_run_stopped`.
  - **NTP: rodada ignorava stop e heartbeat (baixa).** `poll_round` bate o heartbeat e confere o
    stop entre servidores. Teste: `a_round_stops_between_servers`.
  - **`tool.ping.mtu` com `max_size=65535` (baixa).** O sentinela "nenhum falhou" saturava em
    65535 e aparecia como `smallest_failing`. Agora é `u32`. Teste:
    `a_clean_path_passes_at_the_maximum`.

  Verificado e sem mudança: o achado "qualquer usuário consulta ou para tarefas de outro" já foi
  corrigido pelo audit-persist (#123). `tool.dns.query` ser comando de consulta é igual a
  `tool.ping.start`/`tool.mtr.start` (mesma permissão); falta uma política para ferramentas que
  geram tráfego, que virou gap (abaixo). A porta `--metrics` (flag de linha de comando, só
  loopback por padrão) continua sem `available_from`: é escolha explícita do operador.

  Como testar: `cargo test -p corerouter-engine neighbors`, `cargo test -p corerouter-daemon
  service::`, `cargo test -p corerouter-hal-linux icmp`, `cargo test -p corerouter-discovery`,
  `cargo bench -p corerouter-engine --bench neighbors`.

- 2026-10-22 — processo: Fila de entrada: o merge do fold não para mais a fila quando o GitHub já apagou a branch. O
  `gh pr merge --delete-branch` saía com erro (404 ao apagar a branch que o GitHub apaga sozinho no
  merge) depois de um merge que tinha dado certo, e a fila parou em #120. Agora o merge é feito sem
  `--delete-branch`, o estado do PR decide se houve falha, e a branch é apagada à parte, sem erro.

- 2026-10-22 — G0.14: A validação do firewall no commit deixou de ser O(n²): entrou no PR da auditoria de rede (#125),
  com o benchmark `crates/engine/benches/scale.rs`; detalhes em `docs/audit-2026-10.md`.

- 2026-10-22 — G1.23: Commit não regrava mais o histórico: resolvido pelo `audit-perf` (detalhes e números em
  `docs/changes/audit-perf.md`).

- 2026-10-22 — audit-dns-lab: Auditoria (achado do teste de ponta a ponta, `audit-e2e`): com `--backend virtual` e
  `ip.dns.set allow_remote_requests=yes`, o encaminhador DNS escutava em `0.0.0.0`/`[::]` do
  **host**, então a rede real da máquina chegava ao resolvedor do lab (as interfaces do lab não são
  as do host, e a ACL `allowed_from` compara com as redes do lab, que podem coincidir com a LAN de
  verdade). Agora o lab virtual escuta só em `127.0.0.1` e `::1`, como o CRDP do G5.4; no backend
  Linux nada muda. Teste: `service::dns_server::tests::the_virtual_lab_answers_only_on_the_loopback`.
  Os outros sockets do daemon que usam endereço curinga são clientes de porta efêmera (zonas,
  syslog) ou só rótulo de exibição (DHCP, que no lab usa os sockets simulados) — conferidos.

  Quem roda o lab num network namespace e quer o encaminhador nas interfaces do namespace (os
  testes `netns_dns_*`) passa `--dns-lab-any`; no backend Linux a opção não muda nada.

- 2026-10-22 — audit-e2e: Auditoria ponta a ponta: o `corerouter-daemon` de verdade (backend virtual, `--config-dir`
  temporário, porta alta, `--no-discovery`), dirigido pela CLI (`--connect`, token local), pelo
  MCP (`corerouter-cli mcp`, JSON-RPC no stdin) e por um harness em Python no canal de controle.

  Cenários exercitados (todos passaram, salvo os bugs abaixo, já corrigidos): bridge + porta, VLAN
  sobre ether e sobre bridge, bonding 802.3ad, VRF com membro, endereços v4/v6 (comentário com
  aspas), rotas (main e VRF), address-list, filter, NAT, DNS (servidores, estático, zona primária
  com registro), pool + servidor DHCP + rede + concessão fixa, NTP, syslog remoto, identidade;
  modo transacional (`config.diff`, commit, discard, rollback + commit); Safe Mode (exit mantém,
  cancel desfaz, outro cliente não entra nem sai sem `force`, dono desconecta e dono morto com
  `kill -9` desfazem); `/export` → `/import` num daemon novo (export idêntico; running idêntico a
  menos dos ids internos, que seguem a ordem do script); SIGTERM e reinício no mesmo diretório
  (running e histórico idênticos); `kill -9` no meio de uma rajada de commits (sobe na última
  revisão salva, com todo commit confirmado presente); entradas hostis no TCP e no stdin do MCP
  (lixo, HTTP, UTF-8 inválido, NUL, array, tipos errados, chave desconhecida, aninhamento de
  100 000 níveis, id gigante, linha de 17 MiB com e sem `\n`, 1000 conexões seguidas, conexões
  meio abertas): o daemon nunca caiu nem travou; 16 clientes escrevendo em paralelo por 60 s.

  Corrigido (cada um com teste que falha na `main`):

  - **Estranho "ocupado" segurava vaga sem login para sempre (média).** O limite de ociosidade
    (30 s) zerava a cada byte: 8 conexões mandando um byte (ou um `ping`) a cada 29 s ocupavam
    todas as vagas sem login e **ninguém mais entrava**, nem o operador com token (medido contra o
    daemon: após 45 s, `too many connections that have not logged in`). Agora uma conexão fica no
    máximo `login_grace` (60 s) sem login no total, como o `LoginGraceTime` do SSH; logada, não há
    prazo. Teste: `control/tests/limits.rs::busy_strangers_are_cut_at_the_login_grace`.
  - **Clientes com token esperando o lock contavam como "sem login" (média).** A conexão só virava
    logada depois de respondida; com um commit em curso, os 8 primeiros clientes que chegavam
    esperavam o lock ainda "sem login" e o 9º era recusado. Na rodada de 16 clientes por 60 s:
    548 recusas e 517 `Broken pipe` em 1740 operações. Agora o token conferido marca a conexão
    antes de o comando esperar a vez (`answer_with`, TCP/TLS e WebSocket). Depois: 4665 operações,
    zero erros. Teste: `limits.rs::clients_waiting_for_the_session_are_not_logged_out`.
  - **MCP morto depois de reiniciar o daemon (média).** O backend `Remote` nunca reconectava: toda
    tool call respondia `send: Broken pipe` até reiniciar o próprio MCP (o daemon é recompilado e
    reiniciado pela fila de entrada). Agora a próxima chamada redisca (relê o token local, loga de
    novo com `--user`, no TLS exige o mesmo certificado), uma sessão de login expirada é refeita, e
    um pedido cuja resposta se perdeu **não** é reenviado ("may or may not have run").
    `Client::is_stale` detecta o fechamento entre pedidos. Testes:
    `mcp/tests/remote_reconnect.rs` (3).
  - **`/import` grande era quadrático (média, desempenho) — corrigido pelo #130 (audit-perf).**
    Cada passo de um `engine.batch` atômico copiava o candidate inteiro. Achado aqui no daemon
    (release: 20 000 entradas de address-list 22,8 s, 10 000 rotas 18,3 s); a correção que ficou é
    a do #130 (`AtomicBatch` nas extensões da sessão). Este PR só acrescenta o benchmark
    `engine/benches/batch_import.rs` e os números de ponta a ponta (abaixo).
  - **`/export` de um bond saía com nota falsa (baixa).** O bond aparece em `/interface` (tipo
    `bonding`) e em `/interface bonding`, que tem `print` próprio: o export trazia
    `# add name=bond1: slaves is not exported` (como se fosse segredo) ao lado do `add` correto.
    Agora o submenu com `print` exporta a linha uma vez, e `/interface set` guarda o que só a
    interface sabe (`disabled`). Teste: `shell/tests/terminal.rs::bond_exports_once_without_a_note`.

  Processo: a etiqueta de `docs/changes/` aceita dígitos (`audit-e2e`), começando por letra
  (`xtask/src/changes.rs`).

  Testes duráveis novos: `apps/corerouter-daemon/tests/e2e.rs` sobe o binário real (porta
  efêmera, sem descoberta) — config de todas as áreas sobrevive a SIGTERM e a `kill -9` no meio de
  commits, linhas hostis, Safe Mode desfeito quando o dono morre, 8 escritores paralelos sem perda
  nem duplicata (~13 s em debug, **medido**).

  Verificado e OK (sem mudança): limite de 16 MiB por linha (TCP e MCP), `recursion limit` do
  serde para JSON profundo, `MAX_BATCH`, limites de tamanho por parâmetro, lote JSON-RPC recusado,
  MCP sai no EOF do stdin, histórico sempre crescente, journal coerente (seq = revisão).
  Comportamentos registrados, não bugs: no máximo 16 conexões por porta (o 17º cliente simultâneo
  é recusado), e 8 delas sem login; uma conexão que conecta e não manda nada ocupa vaga sem login
  até falar; em Safe Mode, mudanças de outro cliente também são desfeitas (como no RouterOS,
  `docs/architecture.md`).

  Para outras frentes (não mexido aqui):

  - **Desempenho (persistência):** antes do #130 cada commit regravava o arquivo inteiro com o
    histórico (`running.json` no teto de 32 MiB, commit p50 110 ms / máx. 297 ms com 4000 regras
    + 20 000 entradas + 10 000 rotas). Resolvido pelo #130 (revisões em arquivos, G1.23): mesma
    config, commit p50 36 ms / máx. 55 ms (release, **medido**).
  - **DNS:** com `--backend virtual`, `allow_remote_requests` abre o encaminhador em
    `0.0.0.0`/`[::]` do host (a ACL `allowed_from` filtra, mas a porta fica exposta em todas as
    interfaces da máquina de desenvolvimento).

- 2026-10-22 — audit-gui: Auditoria da GUI (`crates/ui`, `apps/corerouter-gui`): 11 dos 12 achados corrigidos aqui, 1 vira
  gap (G1.24) e o resto de custo por quadro com listas enormes vira a G1.25. Os testes novos
  falharam com o código da `main` (rodados com a correção desligada, **medido**); os de desempenho
  têm bench antes/depois na seção `## perf` (bench novo `crates/ui/benches/frames.rs`, que desenha a
  UI de verdade sobre listas grandes postas no cache, pelos ganchos `corerouter_ui::perf`).

  Corrigido:

  - **Médio — seleção de tabela O(n²) por quadro** (#1). `table::show` recalculava a seleção
    inteira (`state.selection(rows)`) uma vez **por linha**, e `retain` fazia `order.contains`
    (um `Vec`) para cada chave selecionada; cada janela ainda filtrava as linhas com
    `selection.contains` num `Vec<String>`. Com 10 000 endereços e Ctrl+A, **15 s por quadro**. Agora
    a seleção é um `table::Selection` (ordem de exibição + `HashSet`, `contains` O(1)), calculada uma
    vez por quadro; `retain` usa um `HashSet`; e a tabela só desenha e registra as linhas que estão
    na tela (as outras só ocupam o lugar; a linha arrastada continua viva fora da tela). Testes
    `table::tests::only_the_rows_in_view_are_drawn` e o bench `ui_frame/addresses_10k_all_selected`:
    15,15 s → 28 ms.
  - **Médio — aba Filter Rules copiava todas as regras a cada quadro e o "NUNCA CASA" era O(n²)**
    (#2). As listas do firewall ficam num `Arc<Vec<Value>>` (o quadro pega emprestado, não copia), e
    a posição de cada regra por id é um `HashMap` montado uma vez por quadro (`firewall::positions`).
    Bench `ui_frame/firewall_5k_shadowed`: 155 ms → 21 ms.
  - **Médio — célula de tabela nunca era cortada** (#3, docs/ui-style.md › Tabelas). Um valor longo
    esticava a coluna sem limite e era medido inteiro em toda linha e todo quadro. Agora a célula
    mostra até 120 caracteres (`table::CELL_CHARS`) numa linha só, termina em `…` e o texto inteiro
    (até 4096 caracteres) vai no tooltip da célula; os selos (chips) depois do texto ficam. Teste
    `table::tests::a_long_cell_is_cut_with_an_ellipsis`; bench `addresses_1k_4kB_comments`: 94 ms →
    1,8 ms. (O engine já limita `comment` a 256 caracteres; a correção vale para toda célula.)
  - **Médio — consulta ou poll sem resposta travava a atualização para sempre** (#4). O `refresh` não
    manda nada enquanto houver consulta pendente, e o Ping/MTR só pede de novo quando a resposta
    chega. Agora cada pedido pendente tem prazo: consulta, poll de ferramenta e aba de interface
    30 s, ação e terminal 120 s (o mesmo do cliente nativo). Consulta vencida: a UI pede de novo,
    registra no log e mostra o selo âmbar `stale` na barra de status até a próxima resposta; poll
    vencido: pergunta de novo sem dar a tarefa por perdida; ação vencida: sai do "waiting for the
    router" com erro ("pode ter sido aplicada: confira"). Na web, o `WsBackend` também dá prazo de
    120 s a cada id em voo (e um login sem resposta reabre a conexão). Testes
    `a_lost_query_reply_does_not_freeze_the_refresh`,
    `a_lost_poll_polls_again_and_a_lost_action_is_released`.
  - **Médio — terminal re-quebrava e re-diagramava as 5000 linhas a cada quadro** (#5). As linhas
    quebradas ficam em cache por largura (só as novas são quebradas), só as linhas visíveis viram
    `Label`, e uma linha de saída guarda no máximo 64 Ki caracteres (`…` no fim). Teste
    `a_full_terminal_lays_out_only_what_is_in_view`; bench `terminal_5000_lines`: 8,5 ms → 0,09 ms.
  - **Baixo — firewall mostrava listas de interface entre colchetes** (`[LAN]`, `![LAN]`, #6). Agora
    é um selo colorido pelo nome da lista (`chip::name_hue`, FNV-1a; a mesma função passou a servir
    o DHCP Server). Teste `firewall::interface_lists_are_chips_not_brackets`.
  - **Baixo — cores escolhidas na hora** (#7): o `ALERT …` branco sobre vermelho fixo do Ping virou o
    selo vermelho `alerta` com os detalhes no tooltip; o status do NTP (`synchronized`/`waiting`) e
    o `link-ok`/`no-link` da aba Status da interface viraram selos GREEN/AMBER/RED; o âmbar da aba
    Ethernet vem do `chip::AMBER`. Ficou o vermelho do botão Safe Mode (`SAFE_MODE_FILL`): é o
    botão no estilo do WinBox, não um selo de estado.
  - **Baixo — `TaskView::absorb` somava o contador `lost` do router sem saturar** (#8): dois
    `u64::MAX` davam panic em debug. Agora `saturating_add`. Teste `a_hostile_lost_counter_saturates`.
  - **Baixo — `target as usize` no wasm32** (#9): `usize::try_from`, o evento fora de faixa é
    ignorado (só reproduz com ponteiro de 32 bits; sem teste que falhe em x86_64).
  - **Baixo — CSV do Ping** (#10): campo que começa com `=`, `+`, `-`, `@`, tab ou CR (e não é
    número) ganha `'` na frente (injeção de fórmula em planilha); o app nativo nunca sobrescreve um
    arquivo (`create_new`, depois `ping-1-2.csv`, …). Testes `csv_quotes_what_needs_it` e
    `export::tests::a_second_export_never_replaces_the_first`.
  - **Baixo — cobertura headless** (#12): `every_window_renders_with_data_and_long_values` abre
    todas as janelas (IPv6, rotas, VRF, DHCP Server/Relay com `relay_info_trusted`, firewall…) sobre
    um lab com dados e comentários longos e confere que nada sai inteiro nem entre colchetes;
    `every_interface_tab_renders_with_data` passa por todas as abas de "Interface <ether2>" com
    amostras de tráfego.

  Conferido: os dois checkboxes `relay_info_trusted` (DHCP Server "Trust Option 82 Without Relay",
  DHCP Relay "Trust Client Option 82") alinham no formulário (screenshots no PR). Como testar:
  `cargo test -p corerouter-ui`, `cargo bench -p corerouter-ui --bench frames`; na GUI, IP ›
  Addresses com comentários longos (passe o mouse no `…`) e IP › Firewall com
  `in_interface_list=!LAN`.

- 2026-10-22 — audit-perf: Desempenho do caminho de commit e de `Session::execute`, e o canal de controle sob carga.
  Resolve G1.23. Números na seção `## perf` (antes = `main` c5db148, mesma máquina).

  Corrigido:

  - **Alto — todo commit regravava o histórico inteiro** (G1.23). A gravação serializava a
    running e as até 64 revisões (até 32 MiB) e fazia fsync disso a cada comando: com 10 000 rotas
    um commit levava ~0,4 s. Agora o backend com arquivos de revisão (`FileStorage` e
    `MemoryStorage`, `ConfigStorage::revision_files`) guarda cada revisão num arquivo próprio
    (`rev-<n>.json`, `persist::encode_revision`), escrito uma vez pelo commit que a criou e
    apagado quando sai do histórico; o slot (`running.json`/`.prev`) guarda só a running e a
    revisão mais nova, no mesmo formato de antes (versões anteriores leem o arquivo, com
    histórico de uma entrada). O commit serializa a config uma vez (`persist::encode_config`, que
    também mede o limite de tamanho) e o texto é emendado no slot e no arquivo da revisão. Ordem
    da gravação: arquivos que faltam (temp + fsync + rename) → slot (como antes: temp, fsync,
    rotação, fsync do diretório, que torna os renames dos arquivos duráveis) → apagar os que saíram
    do histórico. Boot: os arquivos mais antigos que o slot completam o histórico; um ilegível ou
    com outro número custa só aquela revisão (`storage.boot_errors`); um mais novo que o slot
    (gravação interrompida, ou volta ao `previous`) é ignorado e reescrito pelo próximo commit;
    `rev-*.json.tmp` é apagado ao abrir. Arquivo de versão anterior (histórico inteiro no slot)
    carrega e migra no primeiro commit. O limite de 32 MiB vale para a soma dos arquivos de
    revisão. Testes `a_commit_writes_its_revision_not_the_whole_history` (o slot tinha 22 cópias
    da config, agora 2), `the_history_survives_a_reboot_and_old_files_are_deleted`,
    `an_unreadable_revision_file_costs_that_revision_only`,
    `a_file_with_the_whole_history_from_an_older_build_loads_and_moves_to_files`,
    `a_revision_file_newer_than_the_slot_is_replaced`, `safe_mode_saves_nothing_of_its_revisions`
    (`crates/engine/tests/history_files.rs`), `revisions_are_files_of_their_own` e
    `revision_names_are_strict` (storage-fs), `spliced_running_file_is_the_one_revision_file` e
    `revision_files_round_trip_and_are_checked` (model). Bench novo
    `storage_fs/commit/routes_history64/*` (arquivo de verdade, fsync, 64 revisões):
    396 → 11,0 ms com 10 000 rotas.
  - **Médio — `/import` era quadrático** (achado nesta auditoria). Cada passo de um batch
    atômico copiava o candidate inteiro como ponto de rollback, mas um passo que falha desfaz o
    batch inteiro pela cópia do próprio batch. Dentro de um batch atômico os passos não copiam
    mais. Bench novo `engine_scale/import/address_lists/5000`: 423 → 61 ms.
  - **Médio — consultas copiavam a config** (`store.candidate().clone()` em todo `execute`). Só
    comandos de ação (`journal`) copiam agora; teste `queries_leave_the_candidate_alone` roda toda
    consulta do registro sobre um candidate sujo e confere que nada muda.
  - **Médio — `cmd::find` varria o registro duas vezes por `execute`** e `doc_keys` reanalisava o
    `params` em toda chamada. Índice por id (`OnceLock<HashMap>`, montado uma vez, com as chaves
    já analisadas); `execute` procura uma vez. `ip.address.list`: 1,39 µs → 0,22 µs.
  - **Baixo — commit copiava a config duas vezes para o plano de dados** (`effective(..)
    .into_owned()` mesmo sem nada de DHCP para acrescentar): agora só copia quando o DHCP
    acrescenta algo.
  - **Baixo — journal com `Vec::remove(0)`** a cada comando depois de 1024: agora apara em blocos
    de 256 (`journal()` continua mostrando as 1024 mais novas).

  Verificado e mantido:

  - `is_dirty` compara a config inteira (1,6 µs na config do lab, **medido**; O(config) com 10 000
    rotas) e `ConfigStore::commit` copia a candidate duas vezes; junto com o ponto de rollback por
    comando de ação é o que resta do custo por comando proporcional à config. Tirar isso pede
    `Arc`/cópia na escrita no `ConfigStore`: vira a gap G0.16.
  - `engine_execute/virtual_lab_new` (3,42 µs na tabela; 8,0 µs na `main` → 7,4 µs): não é um bug, a `Config` do lab
    cresceu (clonar 1,1 µs, comparar 1,6 µs, aplicar no lab virtual 2,2 µs, **medido**), e o
    `ConfigStore::new` a copia duas vezes. Fica com a G0.16.
  - `rejected_param` 1,21 → 0,81 µs com o índice; o resto é a sugestão "did you mean".
  - Canal de controle sob carga (bench novo `control_load/tcp/interface.list/{1,4,16}`): escala de
    18 mil para 77 mil pedidos/s com 16 conexões; com 16 o p50 sobe para 0,2 ms porque cada
    `interface.list` passa ~9 µs com o lock da sessão (uma sessão, um lock, por desenho). Não há
    gargalo além desse. 32 conexões não cabem: `MAX_CONNECTIONS` = 16 por endpoint, de propósito.


  Como testar: `cargo test -p corerouter-engine --test history_files --test query_purity`,
  `cargo test -p corerouter-storage-fs`, `cargo bench -p corerouter-storage-fs --bench commit`,
  `cargo bench -p corerouter-engine --bench scale -- 'commit|import'`,
  `cargo bench -p corerouter-control --bench load`.

- 2026-10-22 — audit-relatorio: Relatório da auditoria de outubro de 2026 em `docs/audit-2026-10.md`: o que foi testado por
  área, os bugs achados (corrigidos nos PRs #122–#127 e #129–#132, ou virados gap), os números
  **medidos** de antes e depois e o que ficou de fora. Também acerta o limite do `command_batch` do
  MCP, que a descrição da ferramenta e o `docs/mcp.md` ainda davam como 256 passos (é 32 768 desde
  o #123).

- 2026-10-23 — G0.15: Idioma configurável na GUI, com **dois idiomas independentes**: o dos rótulos (menus, títulos,
  colunas, botões) e o das explicações (texto de ajuda, modal do botão ⓘ). Padrão: rótulos em
  inglês, como o resto do app, e explicações em português. Menu novo **Settings** com a janela
  Settings (seletores English/Português) e a nota "guardado neste computador, não no roteador": a
  escolha vai para as preferências da janela (`prefs.rs`, `labels_lang`/`help_lang`), no arquivo do
  eframe no nativo e no `localStorage` no WASM; nenhum comando vai ao roteador. Base de i18n em
  `crates/ui/src/i18n/` (catálogo por idioma, ordenado, busca binária): `tr` para rótulos (texto em
  inglês como chave e fallback) e `explain` para explicações em Markdown simples por chave (cai
  para o idioma dos rótulos e depois para o inglês); `help.rs` (botão ⓘ desenhado, sem depender de
  glifo da fonte, e o modal) e `markdown.rs` (títulos, parágrafos, listas, código e negrito, sem
  panic com marcação solta). Títulos de janela e grupos do menu passam pelo `tr` (sem tradução, ficam
  em inglês). O `build.rs` da UI passou a aceitar módulos em pasta (`src/<nome>/mod.rs`). Como
  testar: Settings › Settings, troque "Labels" para Português (título, menu e campos mudam) e clique
  no ⓘ (explicação em português; com "Explanations" em English, em inglês). Testes: catálogos
  ordenados e sem repetição, toda chave de explicação em EN e PT, fallback de rótulo e de explicação,
  tradução sem uso no código (erro de digitação da chave), preferências hostis, Markdown com marcação
  solta, janela headless (padrão, troca pelo seletor, modal). Screenshots claro e escuro conferidos.
  Como uma janela nova usa rótulos e explicações traduzíveis: `docs/ui-style.md`.

- 2026-10-23 — G0.16: Comando sem cópia da config inteira. As seções grandes da `Config` (`interfaces`, `ip` e, dentro
  dele, endereços, rotas, firewall com `filter`/`nat`/`mangle`/`address_lists`, DNS estático, zonas
  e servidor DHCP) passaram a ser `model::cow::CowArc<T>`: um `Arc` que só copia quando alguém
  escreve (`Arc::make_mut` no `DerefMut`), serializado igual a `T` (os arquivos salvos não mudam).
  Com isso o ponto de rollback de cada comando, a running, as revisões do histórico, o snapshot do
  `engine.batch` e o store da entrada do Safe Mode compartilham o que ninguém escreveu, e um comando
  paga a cópia só das seções em que escreve. A igualdade compara o ponteiro antes do conteúdo, e o
  `ConfigStore` só compara candidate × running depois de um `candidate_mut`/`set_candidate`/
  `rollback` (antes, toda checagem de `is_dirty` comparava a árvore inteira). O `Name` do firewall
  (nome de lista, chain, mark) virou `Arc<str>`: copiar uma address list não copia texto. A busca de
  duplicata do `ip.firewall.address-list.add`/`set` compara o endereço antes do nome.

  A semântica não muda: um comando que falha (inclusive no commit, no data plane ou por panic)
  devolve exatamente a candidate de antes, Safe Mode, transações, `config.diff` e o build WASM
  seguem iguais. Testes novos: `crates/engine/tests/cow_sections.rs` (comando que falha depois de
  mexer na candidate a devolve bit a bit e sem cópia; um `interface.set` não copia as rotas; a
  revisão nova compartilha as rotas com a anterior; um ponto de rollback sobrevive a escritas),
  `store::tests::copies_share_what_was_not_written`, `a_write_that_changes_nothing_is_not_dirty` e
  os de `model::cow`. Bench novo `engine_txn` (`crates/engine/benches/transactional.rs`): um
  comando por vez em modo transacional sobre uma config grande.

  O que o critério antigo supunha não se confirmou: das 6,6 ms de um commit com 10 000 rotas, as
  cópias eram ~0,5 ms (**medido**: 6,57 → 6,04 ms). O resto é trabalho O(N) do próprio commit, fora
  desta gap: `validate_all` da config inteira (~1,2 ms), `persist::encode_config` para conferir o
  tamanho (~2,2 ms) e o `Hal::apply` do lab virtual (~1,5 ms), **medidos** com 10 000 rotas. Também
  fica de fora: acrescentar a uma lista enorme ainda copia aquela lista (60 000 entradas: ~0,6 ms
  por comando, **medido**), então montar uma config item a item continua crescendo com o tamanho
  da lista tocada; resolver isso pede listas persistentes (cópia O(log n)) ou índice por chave.
  Sugestões de gaps novas (sem id: a sessão principal atribui): commit incremental (validar,
  codificar e aplicar só as seções que mudaram, usando `CowArc::ptr_eq`) e listas persistentes
  para address lists e rotas.

  Como testar: `cargo test -p corerouter-engine --test cow_sections`, `cargo test -p
  corerouter-model`, `cargo bench -p corerouter-engine --bench transactional`.

- 2026-10-23 — G1.26a: System › Tuning, parte 1 (Resumo, Kernel, Perfis): o CoreRouter ajusta o kernel para encaminhamento
  em Rust puro (arquivos de `/proc/sys`, sem `tuned`, `irqbalance` nem `sysctl.conf`).

  - **Valores na config** (`system.tuning.sysctl`): transação, diff, Safe Mode e rollback como
    qualquer comando.
  - **Catálogo de 38 parâmetros** em `model::tuning`, em seis grupos:
    - recepção (`netdev_max_backlog`, `netdev_budget(_usecs)`, `dev_weight`);
    - roteamento (forwarding v4/v6, `rp_filter` all/default, hash ECMP v4/v6, `route.max_size`
      v4/v6);
    - conntrack (max, buckets e 10 timeouts);
    - vizinhos (`gc_thresh1/2/3` v4/v6);
    - estabilidade (`kernel.panic`, `panic_on_oops`, `vm.min_free_kbytes`);
    - plano de controle (`rmem/wmem_max`, `somaxconn`, `tcp_syncookies`, `tcp_max_syn_backlog`).
  - **`hal-linux`**:
    - grava tudo ou nada; o `ip_forward` vai primeiro;
    - o valor original fica guardado na primeira mudança, e tirar o parâmetro o restaura;
    - recusa com o motivo o parâmetro ausente, só leitura ou que o kernel não aceitou;
    - lê a máquina (CPUs, NUMA, RAM, kernel) e os contadores (`softnet_stat`,
      `nf_conntrack_count`, `table_fulls` de `arp_cache`/`ndisc_cache`).
  - **Laboratório virtual**: simula um servidor de 16 CPUs, 2 nós NUMA e 32 GiB, com contadores que
    disparam o diagnóstico.
  - **Engine** (`engine::tuning`, puro):
    - perfis conservador, balanceado, alto desempenho e baixa latência, calculados da RAM, das CPUs e
      da velocidade das portas, cada valor com o motivo;
    - timeouts de CGNAT dentro das RFCs 5382, 4787 e 5508;
    - faixas com teto pela RAM;
    - diagnóstico com sugestão.
  - **Comandos**: `system.tuning.print|parameter.print|set|unset|profile.diff|profile.apply|hardware|diagnose`.
  - **Janela System › Tuning**:
    - abas Resumo, Kernel e Perfis; Interfaces, CPU e IRQ e Boot dizem em que gap chegam;
    - lista de propriedades com seções e Find;
    - selos `differs`, `not applied`, `control plane`, `obsolete`;
    - editor da linha selecionada;
    - ⓘ com explicação em EN/PT (G0.15), valor recomendado aqui e comando equivalente;
    - "Show differences" (modal com motivo) e "Apply with Safe Mode".

  Como testar: `cargo run -p corerouter-gui -- --control 7979`, Virtual lab › System › Tuning. No
  terminal:

  - `/system tuning parameter print`;
  - `/system tuning profile diff profile=throughput`;
  - `/system tuning set name=net.core.netdev_budget value=600`.

  Testes:

  - catálogo;
  - perfis dentro da faixa em 1/4/32/512 GiB, com a ordem dos `gc_thresh`;
  - diagnóstico;
  - comandos (sucesso, faixa, nome desconhecido com "did you mean", obsoleto, ordem dos `gc_thresh`,
    perfil num commit e rollback de uma vez);
  - `hal-linux` sobre um `/proc` de mentira (tudo ou nada, restauração, nome fora do catálogo);
  - netns (grava e restaura os parâmetros por namespace; o só leitura e o ausente desfazem a mudança
    toda);
  - explicação de todo parâmetro em EN e PT;
  - todo motivo do engine com modelo em PT e os mesmos argumentos;
  - janela headless (Resumo, Kernel, ⓘ, Find, rótulos PT, Aplicar com Safe Mode, Perfis, Ver
    diferenças).

  Screenshots claro e escuro conferidos. O `netdevsim` não serviu: criar um dispositivo exige root no
  namespace do host. Pesquisa e decisões: `docs/tuning.md` e `docs/architecture.md`.

- 2026-10-23 — audit-history: Histórico de revisões em disco como diferenças, não cópias inteiras (auditoria de 2026-10-23).

  - **Só 6 das 64 revisões sobreviviam ao reboot com config de 5 MiB (3 com 10 MiB)** — severidade
    média (a running nunca se perdia; o `config.rollback` para trás depois de um reboot, sim).
    Causa: desde o G1.23 cada revisão é um arquivo `rev-<n>.json` com a config inteira, e a soma
    cabe em 32 MiB (`SAVE_BUDGET_BYTES`). Correção: o arquivo da revisão `k` guarda a diferença
    estrutural para a revisão `k+1` (delta reverso; `base` + `delta` no lugar de `config`); a mais
    nova não tem arquivo, o slot a guarda inteira. Módulo novo `model::json_delta` (objetos por
    chave, listas por `id` em trechos copiados + itens novos, listas sem id por prefixo/sufixo;
    `diff_text` compara os textos JSON que o commit já tem sem montar as árvores; `apply_owned`
    move as partes mantidas). `engine::history_files` grava a diferença do penúltimo no commit e
    percorre a cadeia do slot para trás no boot. Testes:
    `all_64_revisions_of_a_big_config_survive_a_reboot` (config de ~750 KB, 64 commits, reboot com
    as 64 iguais às da memória e rollback exato para a mais velha; na `main` falha com 19 revisões
    não salvas), `a_crash_between_the_steps_of_a_save_loses_only_that_revision` (storage que falha
    na gravação do arquivo de revisão, do slot ou na remoção: só a revisão em voo se perde, e os
    commits seguintes continuam), `a_broken_revision_file_costs_it_and_the_older_ones_only`,
    `a_difference_that_does_not_fit_its_base_is_refused` (trecho fora da lista, base errada, base
    mais velha, delta que não dá uma `Config`), `full_copy_revision_files_from_g1_23_load_and_become_differences`,
    `a_file_with_the_whole_history_from_an_older_build_loads_and_moves_to_files`,
    `a_revision_file_newer_than_the_slot_is_replaced`; em `json_delta`, proptest de ida e volta
    (`apply(diff(a, b)) == b`, `diff_text == diff`) e de lixo (`apply` nunca entra em pânico),
    entradas hostis (trecho fora, trechos sobrepostos, profundidade > 64) e a troca de um item numa
    lista de 65 536 em menos de 200 bytes.

  Propriedades de segurança mantidas do G1.23: ordem arquivos novos → slot → apagar; arquivo da
  revisão do slot ou mais novo é ignorado no boot e reescrito; `.tmp` limpo ao abrir; histórico
  inteiro no slot (antes do G1.23) e arquivos com cópia inteira (G1.23) carregam e migram no próximo
  commit. Muda: um arquivo ilegível no meio custa ele **e os mais velhos** (dependem dele), relatado
  em `storage.boot_errors` como `revisions a..b: N left out`; o boot pelo slot `previous` não perde
  nada. Uma versão anterior lendo o diretório novo (downgrade) carrega a running e acusa as revisões
  antigas como ilegíveis. Escolha e números em `docs/architecture.md` (Persistência).

  Como testar: `cargo test -p corerouter-engine --test history_files`; `cargo test -p
  corerouter-model json_delta`; `cargo bench -p corerouter-storage-fs --bench commit -- history64`
  (imprime quantas revisões o reboot restaura e os bytes em disco).

- 2026-10-23 — docs: `docs/desempenho.md`: painel com os números de referência de desempenho e de memória medidos na
  auditoria de outubro de 2026 (motor, import, kernel, DHCP, DNS, canal de controle, descoberta,
  GUI e memória do daemon), para comparar versões futuras.

- 2026-10-23 — fix: System › Services: Start/Stop agora mostram o que fizeram (relato do usuário: "start e stop não
  funcionam nem mostram o resultado no log"). Eles funcionavam no supervisor, mas nada aparecia:

  - **Start num serviço desligado pela config** (`disabled`, ex.: dns-server com
    `allow_remote_requests=no`) respondia OK e não mudava nada. Agora recusa dizendo por quê e
    como ligar (`turn it on with ip.dns.set allow_remote_requests=yes`). Stop continua valendo.
  - **O resultado de cada comando vai para o log do roteador**, no tópico do serviço (`dns`,
    `system`…): "Serviço dns-server: parando / parado / iniciando / reiniciando / já estava
    parado (… por comando)". Antes só ia para o stderr do daemon.
  - **A linha mostra "stopping"/"restarting"** enquanto a parada não termina (antes continuava
    `disabled`), e `stopped` (pelo admin) fica âmbar, separado do cinza de `disabled` (pela config).
  - A janela diz "stop sent to dns-server" ao enviar; o erro do comando aparece no lugar.

  Como testar: System › Services › dns-server › Start (mensagem explicando), Stop (stopping →
  stopped, âmbar; linha no Log · dns), Start de novo.

- 2026-10-23 — fix: System › Services: serviço desligado pela config ganha **Enable** e **Open settings** (relato do
  usuário: "quando dou start dá o erro e não mostra startado"). Start num serviço `disabled` não
  tem o que iniciar (ele já roda, ocioso, porque a config o desliga), então:

  - **Start fica cinza** nesses serviços, com o motivo na dica.
  - **Enable** aparece no detalhe quando ligar é só um interruptor da config (dns-server:
    `ip.dns.set allow_remote_requests=yes`; metrics: `ip.service.metrics.set enabled=yes`): um
    clique roda esse comando (journal, transação e Safe Mode como qualquer outro), e o serviço
    passa a `running` em seguida.
  - **Open settings** abre a janela que configura o serviço (DNS, Adlist, Zones, DHCP Server,
    NTP, Logging) quando ligar pede valores que só o operador sabe (interface, pool, servidores).
  - `system.service.print` ganha `turn_on: {id, params}|null`, o `enable` como comando quando ele
    está completo (sem `…`).

  Como testar: System › Services › dns-server (disabled): Start cinza com a dica; Enable → o
  serviço vira `running` e o `ip.dns.get` mostra `allow_remote_requests: true`; dhcp-server:
  Open settings abre IP › DHCP Server.

  Também: o e2e `hostile_lines_never_crash_or_hang_it` espera o daemon soltar as 500 conexões
  fechadas de uma vez antes de conectar de novo (falhava com a máquina carregada: "too many
  connections that have not logged in").

- 2026-10-23 — G0.20: O boot com o histórico inteiro voltou para menos de 400 ms (critério da gap) no #143; números em
  `docs/audit-2026-10.md`, seção "Capacidade e persistência".

- 2026-10-23 — G1.26b: System › Tuning, parte 2 (Interfaces): os ajustes de cada porta em Rust puro, sem `ethtool` nem
  `tc`.

  - **Onde ficam**: `system.tuning.ports` (porta → chave → valor, catálogo `PORT_PARAMS` no model).
  - **Como gravam**:
    - anel RX/TX e filas (combinadas ou RX/TX) por `RINGS_SET`/`CHANNELS_SET`, com o máximo da
      própria placa como limite;
    - coalescência (adaptativa, `rx-usecs`/`tx-usecs`) por `COALESCE_SET`;
    - `txqueuelen` e qdisc raiz (fq_codel, fq, pfifo_fast, mq, noqueue) por rtnetlink;
    - `rp_filter` da porta por `/proc/sys`.
  - **Offloads e controle de fluxo**: aparecem na mesma lista e editam as opções Ethernet da porta
    (G1.20), um lugar só. Ligar o LRO aqui é recusado.
  - **Aplicação** (`hal-linux::port_tuning`):
    - tudo ou nada por porta, com o valor original guardado: tirar o ajuste o restaura;
    - um valor que o driver arredondou ou não guardou desfaz a mudança da porta;
    - só alcança portas que o CoreRouter gerencia (regra de posse do G1.18).
  - **Laboratório virtual**: placa de 4 filas (máximo 8) e anéis de 1024 (máximo 4096), metade das
    portas em cada nó NUMA.
  - **Engine** (`engine::tuning_port`): recomendação por porta.
    - anéis de 2048 no balanceado e no máximo no alto desempenho;
    - uma fila por CPU do nó NUMA da porta;
    - coalescência adaptativa (desligada na baixa latência);
    - GRO ligado, LRO desligado, controle de fluxo desligado;
    - qdisc: `mq` com várias filas, `fq_codel` com uma, `noqueue` mantido em porta virtual;
    - `rp_filter` igual ao `all` do perfil.
  - **Diagnóstico**: "LRO ligado" e "controle de fluxo ligado".
  - **Comandos**: `system.tuning.interface.print|parameter.print|set|unset|apply`. O `apply` é um
    commit só; `set` avisa quando a mudança pisca o link.
  - **Janela**: aba Interfaces com seletor de porta, a lista de propriedades (selos `flaps link` e
    `fixed`), ⓘ com o comando da porta e "Apply to all ports with Safe Mode". Na faixa, valores
    nomeados aparecem pelo nome.
  - **`/export`** escreve `/system tuning interface set name=… key=… value=…`.

  Como testar: Virtual lab › System › Tuning › Interfaces. No terminal:

  - `/system tuning interface parameter print name=ether1`;
  - `/system tuning interface set name=ether1 key=rx_ring value=4096`.

  Testes:

  - catálogo de portas;
  - recomendação por porta (faixa da placa, nó NUMA, `mq`/`fq_codel`/`noqueue`);
  - comandos:
    - máximo da placa;
    - chave ausente;
    - LRO fixo;
    - chave desconhecida;
    - controle de fluxo nas opções Ethernet;
    - `unset`;
    - `apply` num commit e `rollback`;
  - netns num veth de 4 filas:
    - canais, `txqueuelen`, qdisc e `rp_filter` mudam e voltam;
    - um anel (o veth não tem) desfaz tudo;
    - uma porta `--unmanaged` fica intacta;
  - `/export` e `/import` de ida e volta;
  - explicações das 18 chaves em EN e PT;
  - headless da aba Interfaces (editar, ⓘ, aplicar com Safe Mode).

  Screenshots claro e escuro conferidos. O `netdevsim` não serve sem root: criar o dispositivo exige
  o namespace do host.

- 2026-10-23 — G1.26c: System › Tuning, parte 3 (CPU e IRQ), em Rust puro, sem `irqbalance`, `cpupower` nem `tuned`.

  - **Governor**: o do cpufreq, recusando o que o driver não oferece.
  - **C-states sem reboot**: requisição PM QoS em `/dev/cpu_dma_latency`, mantida aberta pelo HAL
    enquanto o daemon roda. Se o daemon cair, o limite some (falha segura).
  - **Watchdog de hardware**: alimentado a cada `poll`, com fechamento mágico ao desligar.
  - **Por porta**:
    - afinidade das IRQs das filas, uma por CPU do nó NUMA da porta (só os vetores das filas; IRQ
      gerenciada é recusada com o motivo);
    - RPS para placa de fila única e XPS para várias filas;
    - o arquivo original fica guardado e desligar o restaura.
  - **Diagnóstico**: avisa quando o `irqbalance` roda; o motivo de não usá-lo está nas explicações e
    em `docs/tuning.md`.
  - **Comandos**: `system.tuning.cpu.print|parameter.print|set|unset`. As chaves de porta vão pelos
    comandos `system.tuning.interface.*`, que agora também trazem o mapa de IRQs.
  - **Janela**: aba CPU e IRQ com o aviso, a lista da CPU, o seletor de porta e o mapa "IRQ: CPUs".
  - **Achados dos testes**: documentados numa seção de `docs/tuning.md` e no ⓘ dos parâmetros
    afetados (com o número medido):
    - `rp_filter`;
    - qdisc em porta virtual;
    - ordem do `ip_forward`;
    - parâmetros só do host;
    - sysfs num namespace;
    - glifos sem fonte.

    Um teste novo impede glifos sem fonte nos catálogos de texto.

  Como testar: Virtual lab › System › Tuning › CPU and IRQ. No terminal:

  - `/system tuning cpu set key=governor value=0`;
  - `/system tuning interface set name=ether1 key=irq_affinity value=1`.

  Testes:

  - `hal-linux` sobre `/proc`, `/sys` e `/dev` de mentira:
    - governor (recusa e restauração);
    - PM QoS (o s32 binário);
    - watchdog (fechamento mágico);
    - IRQs da porta pelo `/proc/interrupts`;
    - espalhamento por nó;
    - máscaras de RPS/XPS;
  - engine: recomendações de CPU e de IRQ/RPS/XPS, comandos, achado do irqbalance;
  - explicações das 6 chaves novas em EN e PT;
  - headless da aba (governor, afinidade de IRQ).

  Screenshots claro e escuro conferidos. Nada disso é gravado num namespace de teste: são arquivos do
  host.

- 2026-10-23 — audit-capacidade-relatorio: Relatório da auditoria (`docs/audit-2026-10.md`), seção nova "Capacidade e persistência": limites
  da config (15 MiB por config; tetos por item), medição de commit, boot e revisões que voltam do
  reboot com configs de 5 e 10 MiB (**medido**, 2026-10-23), e o antes/depois das duas correções
  pedidas pelo usuário: histórico em disco como diferença (#141, 64 de 64 revisões voltam do reboot)
  e seções copy-on-write (#139, G0.16), com o ajuste do #143 (boot de 149 ms com 5 MiB e 208 ms com
  10 MiB, 64 revisões, mesma memória). Duas gaps novas para o que ainda não é linear.

- 2026-10-23 — audit-history-share: Continuação do audit-history (#141), em cima do G0.16 (#139). Depois do #141, o boot desserializava
  cada uma das 64 revisões como uma `Config` independente. Com 10 MiB, isso deixava 64 cópias
  inteiras na RAM e o boot ia de ~0,3 s para 1,2–1,5 s. Este PR **resolve a G0.20**: a coluna Status
  da linha G0.20 em `docs/gaps.md` pode passar a "feito (`stream/audit-history-share`)".

  - `model::config_delta` (novo): aplica e calcula a diferença seção por seção sobre os `CowArc` do
    G0.16, nos níveis `Config`, `Ip` e `Firewall`.
    - **Boot:** a revisão `k` é um clone da `k+1` (só contadores de referência), com só as seções
      que o delta toca reconstruídas. Os campos pequenos de cada nível passam pelo JSON com as
      seções grandes vazias. Uma seção que o delta não cita continua a mesma alocação nas duas
      revisões (`CowArc::ptr_eq`).
    - **Commit:** uma seção que a revisão nova divide com a anterior (o que o commit não tocou) nem
      é serializada. O arquivo de revisão custa o que o commit mudou, e saiu a comparação dos dois
      textos inteiros (`json_delta::diff_text` e o texto guardado entre saves foram removidos).
    - O formato dos arquivos não muda. O resultado é o mesmo da árvore inteira, e a diferença
      tipada é a mesma da árvore (testado). Os deltas continuam sendo tratados como entrada hostil.
  - Testes:
    - `all_64_revisions_of_a_big_config_survive_a_reboot` agora confere que, depois do reboot,
      seção igual entre revisões vizinhas ⇔ mesmo ponteiro (`ip`, `firewall`, address lists), e que
      as seções que nenhum commit tocou (interfaces, rotas, endereços, filtro, DHCP) são uma
      alocação só nas 64 revisões.
    - Em `config_delta`: igualdade com o caminho da árvore, compartilhamento, seções que somem e
      voltam do JSON, e deltas hostis recusados.
  - Bench: `storage_fs/history64/*` mede também o pico de RSS do boot (`VmHWM`), num processo filho
    que só faz o `Session::with_storage`.

  Como testar:

  - `cargo test -p corerouter-engine --test history_files`
  - `cargo test -p corerouter-model config_delta`
  - `cargo bench -p corerouter-storage-fs --bench commit -- storage_fs/history64`

- 2026-10-23 — processo: Fila de entrada: um CI cancelado não trava mais o lote por 30 minutos. Quando a sessão dona envia
  um push novo, o GitHub cancela o CI do commit anterior; a fila, que tinha montado o lote com esse
  commit, esperava um verde que nunca vinha até o prazo de 30 min (lote do #144, 2026-10-23). Agora
  um run cancelado sem outro verde no mesmo commit tira o PR do lote na hora, e ele volta com o head
  novo na rodada seguinte.

- 2026-10-23 — processo: Fila de entrada: um PR que conflita só com outro PR do lote (ou do lote especulativo) não fica
  mais marcado até a branch mudar. O conflito é com o vizinho, não com a `main`: quando o vizinho
  entra, ele pode mesclar limpo. O #144 ficou parado assim (2026-10-23). Agora ele volta na rodada
  seguinte; só o conflito com a própria `main` e o CI vermelho seguem marcando o PR.

- 2026-10-23 — G0.23a: Menu lateral da GUI, parte 1: árvore com subgrupos e ícones.

  - **Subgrupos**: IP › DHCP (Client, Pool, Relay, Server, Statistics), IP › DNS (Settings,
    Adlist, Cache, Forwarders, Static, Statistics, TSIG Keys, Zones…) e IPv6 › DHCP (Client,
    Pool, Server). Itens únicos ficam soltos (Addresses, Firewall, Neighbors, Routes, VRF). Dentro
    do subgrupo o rótulo é curto ("Static"); o título da janela continua "DNS Static". O nome "IP"
    continua (RouterOS/WinBox; DNS, DHCP Server e Firewall servem às duas famílias).
  - **Grupos principais em negrito com ícone**; subgrupo recolhido mostra a contagem num selo; o
    menu lembra o que está aberto (preferência da GUI, chave `menu` do `prefs`).
  - **Ícone em todo item** (Phosphor Icons, MIT): subconjunto de 50 ícones embutido
    (`crates/ui/assets/phosphor/`, 16,0 KB, **medido**), cortado por `scripts/icons-subset.sh`; o
    `egui-phosphor` 0.14 pede egui 0.36 e o workspace está no 0.37 (decisão em
    `docs/architecture.md`).
  - **Item selecionado mostra ⓘ**: o modal da G0.15 com o que a janela faz (idioma das
    explicações, `i18n/menu_pt.rs`/`menu_en.rs`), o caminho no RouterOS (`/ip dns static`) e os
    comandos do roteador para ela (do `engine.list`).
  - **Áreas sem comandos** (MPLS, CGNAT, OSPF): apagadas, com cadeado e o selo `soon`; a dica diz a
    gap.
  - Tabela central `crates/ui/src/menu.rs` (`CATALOG`, por chave da janela): subgrupo, rótulo,
    ícone, caminho, comandos e sinônimos; nenhum painel foi editado. Teste: toda janela tem
    entrada, ícone com glifo na fonte, explicação em EN e PT, sinônimos e comandos que existem.

  Como testar: `cargo run -p corerouter-gui -- --control 7979`, abra IP › DNS, clique em Static e
  no ⓘ. Testes: `cargo test -p corerouter-ui menu` (árvore, abre/fecha e lembra, ⓘ, cadeado).

- 2026-10-23 — G0.23b: Menu lateral da GUI, parte 2: busca rápida e teclado.

  - **Campo "Search menu…"** no topo do menu: acha a janela pelo nome (EN ou PT), pelo lugar no
    menu (`IP DNS Static`), pelo **caminho do RouterOS** (`/ip dns static`) e por **sinônimos** da
    tabela central (nat, masquerade, rota padrão, lease, blacklist, ipv4…), sem diferença de
    maiúsculas e acentos. Cada resultado mostra onde fica (`IP › DNS`). Enter abre o primeiro (ou
    o escolhido com as setas) e mostra a janela na árvore; Esc limpa e não fecha a janela de baixo.
  - **Ctrl+K abre a paleta**: a mesma busca, mais os **comandos** do roteador (do `engine.list`,
    por id ou caminho: `ip dns static add`). Num comando, Enter abre um terminal com ele digitado
    (`/ip dns static add `), esperando os parâmetros. Com a busca vazia, mostra as **recentes**
    (e os favoritos).
  - **Favoritos**: botão direito num item, "Add to favorites"; ficam no topo do menu.
  - **Teclado**: `/` (nada com foco) vai para a busca; com o campo vazio, as setas andam pela árvore
    (direita abre o grupo, esquerda fecha ou sobe), Enter abre a janela; o item selecionado mostra
    o ⓘ.
  - Recentes e favoritos são preferências da GUI (chave `menu` do `prefs`); chaves desconhecidas ou
    repetidas guardadas são descartadas.

  Como testar: `cargo run -p corerouter-gui -- --control 7979`, digite `nat` no campo do menu ou
  aperte Ctrl+K e `ip dns static add`. Testes: `cargo test -p corerouter-ui menu` (busca por nome,
  sinônimo e caminho; `/` e Enter; paleta com recentes e comando no terminal; setas na árvore;
  favoritos lembrados; Esc).

- 2026-10-23 — G0.23c: Menu lateral da GUI, parte 3: abas e selos de estado.

  - **Abas em vez de itens do menu**: DNS Zone Records e DNS Zone File viraram as abas **Records** e
    **Zone File** da janela DNS Zones (os botões da barra abrem a aba da zona escolhida; Esc não
    fecha a janela na aba do arquivo, que pode estar sendo editado). DHCP Statistics virou a aba
    **Statistics** da janela DHCP Server, ao lado de History (o botão Statistics da barra saiu).
    IP › DNS passa de 10 para 8 itens e IP › DHCP de 5 para 4.
  - **DNS Statistics continua janela própria**: é outro painel (`dns_statistics.rs`), um monitor
    que se deixa aberto ao lado do DNS Settings, e a janela DNS já é um formulário, não uma janela
    com abas. Pode virar aba quando a janela DNS for redesenhada.
  - **Selos de estado no menu** (`crates/ui/src/menu_badges.rs`, um painel sem janela): a cada
    5 s pergunta `system.service.print`, `ip.dhcp-server.statistics.print` e `config.drift.list`
    (só os que o roteador tem) e o menu mostra `1 failed` em vermelho em System › Services,
    `2 conflict` em âmbar em IP › DHCP › Server e `drift 1` em âmbar em System › History
    (tooltip com o que divergiu e `/config drift reconcile`). Grupo ou subgrupo fechado mostra o
    selo dos seus itens. Nada é decidido na UI: os estados vêm do engine.
  - Ícones: saíram os de Zone File e Zone Records; o subconjunto Phosphor volta a 50 ícones, 16,0 KB
    (**medido**).

  Como testar: `cargo test -p corerouter-ui` (`tests::menu::state_badges_come_from_the_existing_queries`,
  `tests::dns_zones`, `tests::dhcp_server`). Manual: IP › DNS › Zones e as abas; IP › DHCP ›
  Server › Statistics.

- 2026-10-23 — G1.26d: System › Tuning, parte 4 (Boot): parâmetros da linha de comando do kernel **da imagem** (não há
  GRUB; a imagem é imutável e A/B), valendo no próximo boot.

  - **Parâmetros**:
    - `isolcpus` e `nohz_full` (listas de CPU, a CPU 0 fica com o sistema);
    - `intel_idle.max_cstate` e `processor.max_cstate`;
    - `pcie_aspm=off`;
    - `iommu=pt`;
    - `mitigations`: `off` exige `confirm=yes` e aparece com o selo vermelho "security risk".
  - **Onde ficam**: `system.tuning.boot`, validados no model. Nada de espaço, aspas ou `=`, porque o
    valor vai direto para a linha de comando.
  - **Comandos**: `system.tuning.boot.print|parameter.print|set|unset`, com a linha em uso
    (`/proc/cmdline`, `Hal::boot_cmdline`) e a do próximo boot.
  - **Recomendação**:
    - C-state 1 e ASPM desligado na baixa latência;
    - `iommu=pt` no alto desempenho e na baixa latência;
    - isolamento e `mitigations` nunca, com a explicação.
  - **Janela**: aba Boot com as duas linhas, o selo "next boot" nos pendentes, o ⓘ em EN/PT e a
    confirmação do risco.
  - **Imagem A/B**: ainda não existe (G1.6). Os parâmetros ficam gravados na config e a aplicação na
    imagem é a G1.26h.

  Como testar: Virtual lab › System › Tuning › Boot. No terminal:

  - `/system tuning boot set key=isolcpus value=2-7`;
  - `/system tuning boot set key=mitigations value=off confirm=yes`.

  Testes:

  - validação no model: lista de CPU, CPU 0, CPU inexistente, injeção na linha de comando, inteiro e
    opção;
  - `cmdline` e `parse_cmdline` de ida e volta;
  - comandos: pendente até o reboot, confirmação, recusas, `rollback`;
  - explicações EN/PT;
  - headless (salvar para o próximo boot, `mitigations` só com a caixa marcada).

  Screenshots claro e escuro conferidos.

- 2026-10-23 — G1.27a: IP › Routes, parte 1 (leitura e diagnóstico). `ip.route.list` traz por rota `state`
  (`active`/`standby`/`inactive`), `origin` (`connected`/`static`/`dhcp`/`ra`), o gateway separado
  (`gateway_address`, `gateway_interface`, `interface`, `gateway_status`), `check_gateway` das rotas de
  lease, `ecmp`, o motivo (`reason` + `reason_id` + `reason_args`, lista em `route_table::REASONS`) e
  `changed_secs` (o daemon olha a cada segundo; acima de 4096 rotas, a cada 10 s); filtros `family`,
  `state`, `origin`; as flags do RouterOS continuam para o terminal (`+` no ECMP). Motivos novos:
  interface sem link (carrier), "perde para a distância N (rota X via Y)", "check-gateway=arp falhou há
  N s". Rotas de mesma distância formam ECMP (como no RouterOS v7; antes o validador recusava) e viram
  uma rota multipath no kernel (`RTA_MULTIPATH`, só com caminhos do CoreRouter). `ip.route.lookup
  {address, table?, src?}` (o `ip route get`): local, maior prefixo entre as ativas, ECMP, tabela pela
  VRF da origem, IP de origem; compara com o plano de dados (`Hal::route_get`: `RTM_GETROUTE` no Linux,
  o kernel simulado no lab) e lista as diferenças. Janela: selos de estado e origem, gateway com selos
  de interface e alcançabilidade, tabela em selo colorido pelo nome, colunas Changed e Reason (em cinza,
  traduzida), filtros em selos, rodapé com as contagens, grupo ECMP numa linha que abre com um clique,
  campo Route Lookup na barra. Pesquisa e detalhes em `docs/routes.md`.

  Como testar: `cargo nextest run -p corerouter-engine --test route_view`; `cargo xtask netns`
  (`netns_routes`: multipath e `RTM_GETROUTE` num namespace); na GUI, IP › Routes com duas rotas
  padrão de distância 1 e uma de distância 10; `corerouter-cli run ip.route.lookup '{"address":"8.8.8.8"}'`.

- 2026-10-23 — G1.27b: IP › Routes, parte 2 (detalhe da rota selecionada). `ip.route.detail {key}` diz de onde a rota veio
  (a revisão e o comando que a criaram e mudaram; "DHCP client on ether1 (lease from …)"; RA; o
  endereço de uma conectada), por que foi escolhida ou não (distância comparada com as concorrentes,
  traduzida por id: `route_detail::CHOICES`), o check-gateway (método, intervalo, falhas, estado, há
  quanto tempo caiu), as trocas de estado das últimas 24 h (anel de até 64 por rota, alimentado pelo
  tick do daemon) e o que o kernel tem para ela (esperado, presente, faltando, alheio; reaproveita o
  drift da G1.3). As trocas também vão para o log no tópico `route` (no máximo 16 por olhada). Na GUI,
  um painel abaixo da tabela com uma rota selecionada (o painel `route_detail` pede a consulta com a
  atualização da janela). A janela Routes abre com 1000×640.

  Como testar: `cargo nextest run -p corerouter-engine --test route_view --test dhcp_resilience`
  (origem, escolha, failover e volta, 24 h, kernel com drift, chave inválida); na GUI, selecione uma
  rota e desligue/religue a interface dela.

  O custo no tick é o do G1.27a (o anel só grava quando um estado muda); a consulta só roda com a
  janela aberta e uma rota selecionada (**estimado**: uma `ip.route.list` interna + um `snapshot`).

- 2026-10-23 — G2.3a: CGNAT, parte 1 (núcleo):

  - `corerouter_model::cgnat`: pools, exceções e a função de mapeamento `Layout`. É a RFC 7422 §2,
    ida e volta. Fica no L0 e é pura, para o kernel, o engine e o XDP (G2.5) usarem a mesma.
  - `proto-cgnat::checks`: erros e avisos antes do commit.
  - Os comandos `ip.firewall.cgnat.pool.*`, `exception.*`, `lookup`, `who-was`, `mapping.list`,
    `history.list`, `rules`, `set`/`get`.
  - O histórico de definições num journal próprio. "Quem era?" usa a definição em vigor naquela
    hora (RFC 7422 §3), junto com o MAC e o Option 82 do DHCP.
  - `corerouter_firewall::cgnat` gera a tabela `ip corerouter_cgnat`: um mapa por pool, EIM, EIF e
    hairpin com mapas dinâmicos, e o drop do bloco público não reclamado. O `hal-linux` a carrega
    numa transação.

  Como testar:

  ```sh
  cargo test -p corerouter-model cgnat
  cargo test -p corerouter-proto-cgnat
  cargo test -p corerouter-engine --test cgnat
  COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_cgnat
  ```

  O teste em netns (**medido**) passou nestes casos:

  - UDP, TCP e ICMP saem no IP e na faixa da fórmula, e a volta da fórmula dá o assinante;
  - a exceção 1:1 mantém a porta;
  - EIM, EIF e hairpin funcionam;
  - tirar os pools apaga a tabela.

  Carga de 65 536 elementos pelo `nft -f`: 0,60–0,63 s (**medido** na pesquisa, Ryzen AI MAX+ 395,
  kernel 7.0).

- 2026-10-23 — G2.3b: CGNAT, parte 2:

  - A tabela `ip corerouter_cgnat` chega ao kernel por **nfnetlink direto**:
    - encoder próprio em `crates/hal-linux/src/nfnl.rs`, sem `unsafe`;
    - lote atômico `NFNL_MSG_BATCH_BEGIN/END`, sem o programa `nft`.
  - Descrição única `corerouter_firewall::program::Table`: dela saem o texto de "Ver regras" e as
    mensagens, e o `nft list` lê o mesmo.
  - Mudança só de elementos vai como diferença:
    - o diff é posicional, com hash só no que sobra desalinhado;
    - os mapeamentos UDP vivos sobrevivem;
    - lote incremental recusado → troca da tabela.
  - Uma regra `snat` por pool cobre TCP, UDP, ICMP e o resto: o kernel aceita faixa de portas sem
    correspondência de protocolo, o `nft` não. O mapa `a_` saiu.
  - Depois de um remapeamento:
    - as conexões dos remapeados são derrubadas, por ctnetlink (`crates/hal-linux/src/ctnl.rs`,
      codec com proptest);
    - os mapeamentos UDP do pool são esquecidos.
  - `hal::conntrack` traz os tipos da tabela de conexões (base do G2.2).

  Como testar:

  ```sh
  cargo test -p corerouter-firewall
  cargo test -p corerouter-hal-linux --lib
  COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_cgnat
  COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- cargo bench -p corerouter-hal-linux --bench netns_cgnat
  ```

  O netns cobre:

  - NAT de UDP, TCP e ICMP pela fórmula;
  - 1:1, EIM, EIF e hairpin;
  - crescer a faixa mantém conexões e mapeamentos;
  - mudar portas derruba as conexões e esquece os mapeamentos;
  - um lote recusado não muda nada.

- 2026-10-23 — G6.8: DNS Lookup, parte 1 de 2 (G6.8a): **Why this answer**, **Ask as** e a janela da largura do
  conteúdo.

  - `tool.dns.query explain=yes` (só com o roteador como servidor): o evento `why`, um por etapa
    da cadeia (acl, limit, special, adlist, static, zones, cache, upstream), diz o que ela decidiu
    (`passed`, `answered`, `dropped`, `not-reached`) e a regra exata: a entrada static (id e
    `name=`/`regexp=`), a adlist e a linha que bloqueou (número e texto), o grupo de forwarders de
    um FWD, a zona, o servidor que respondeu, o serve-stale (RFC 8767) e o nome retido no cache de
    falhas (RFC 9520 §3.2). Terminal: `;; WHY <etapa> <decisão> <texto>`.
  - `as_client=<IP>`: pergunta como se fosse um IP da LAN, sem pacote: ACL `allowed_from`, limite
    por cliente e regras por origem veem o endereço; não gasta ficha do limite, não conta em
    estatística nem no `match-count` da adlist e não põe endereço em address list.
  - Janela: campo **Ask as**, seção "Why this answer" (selo da decisão, texto no idioma das
    explicações, botões Open entry/list/group/zone que abrem a janela da regra com ela
    selecionada, `TableState::reveal` espera as linhas chegarem). A janela alarga com as tabelas
    até a área de trabalho: o selo `AS8075 MICROSOFT-CORP-MSN-AS-BLOCK` sai inteiro (relato do
    usuário: saía `AS8075 MICROSOFT-CORP-…`); "…" com tooltip só quando não cabe mesmo.
  - Adlist: cada nome guarda a linha e o texto da linha (+5 bytes por nome, **medido**).

  Como testar: `corerouter-cli --connect 127.0.0.1:7979 watch tool.dns.query
  '{"name":"nas.lan","explain":true,"as_client":"192.168.88.10"}'`; na GUI, Tools › DNS Lookup com
  Ask as preenchido. Testes: cada etapa no `server/explain.rs`, `as_client` recusado pela ACL
  (proto-dns e daemon), limite visto sem gastar, linha da adlist, comando e validação no engine,
  headless da janela (largura, AS inteiro, corte só no que não cabe, Open entry/list).

- 2026-10-23 — processo: `AGENTS.md`/`CLAUDE.md`: "Todo pedido, feature ou correção: o que mostrar antes de implementar"
  (pedido do usuário). Antes do código, para feature, melhoria de tela ou bug: o que existe hoje
  (no bug, a causa reproduzida), os padrões do projeto que se aplicam, mockup com opções quando há
  tela, como deve funcionar pela RFC e pelo MikroTik/outros, uma seção de **extras** (ideias não
  pedidas) e os **riscos** do próprio pedido. O mesmo resumo vai no corpo do PR.

- 2026-10-23 — processo: Fila de entrada: resolve sozinha o conflito de **PR empilhado**. Quando a parte seguinte de uma
  feature sai da branch da anterior e a anterior entra por squash, a seguinte traz as mudanças dela
  duas vezes (os commits originais e o squash na `main`), e o GitHub acusa conflito. A fila agora
  confere, arquivo por arquivo, se a `main` tem exatamente o que o PR pai tinha (o pai é um PR já
  integrado cujo último commit é ancestral da branch); se sim, fica com o lado do PR (pai + o que
  ele mudou), dá push na branch e segue, no lote e no merge da `main` antes do squash. Arquivo que
  não bate com o pai continua sendo conflito de verdade, para a sessão dona. Era o que as sessões
  faziam à mão, uma volta de CI cada (#112, G4.2b/c, #146, #147 duas vezes, 2026-10-22/23).
  `AGENTS.md`: "Pode empilhar". Testado com repositório de mentira: pai integrado por squash e filho
  empilhado (resolve, nas duas direções), e main que mudou o mesmo trecho depois (recusa).

- 2026-10-23 — G0.24: Componentes do padrão de janela de lista e modal de adicionar (`docs/ui-style.md`, seção nova
  "Como adotar"): `crates/ui/src/list.rs` (`Tools`/`toolbar` com o motivo de cada botão cinza — o do
  roteador pelo `engine.list`, depois o da seleção —, `Filters`, `footer`, `row_menu`,
  `from_shortcut`, `copy_rows`, `copy_commands`, `run_steps` = `engine.batch` atômico) e
  `crates/ui/src/list_modal.rs` (`Spec`/`Field`/`Modal`: ⓘ no título e em cada rótulo, pede a
  pré-visualização do engine enquanto se digita, mostra campos calculados, checagens com selo
  ok/aviso/erro, risco de perda de acesso com "Entendi" ou Safe Mode, prévia dos comandos na sintaxe
  do terminal; erro embaixo do campo; Enter = OK, Ctrl+Enter = Apply, Esc = Cancel). No terminal,
  `corerouter_shell::command_line` e `recreate` escrevem um comando como se digita
  (`/ip address set *3 disabled=yes`) e o `add` que recria uma linha. Rótulos em PT em
  `i18n/list_pt.rs`. Testes: `crates/ui/src/tests/list.rs` (botões cinza com o porquê, teclas,
  filtros, cópias, série atômica, Apply × OK, erro que bloqueia, risco que pede `force`) e
  `copy_as_command_lines` no shell. A primeira janela a adotar é IP › Addresses (G1.28, PR seguinte).

- 2026-10-23 — G1.27c: IP › Routes, parte 3 (escala para a tabela cheia, ~1 milhão de rotas). Comando novo `ip.route.page`
  com os filtros do `ip.route.list` (origem aceita várias), busca por prefixo (`exact`, `longer`,
  `orlonger` = contido, `covering` = contém; padrão: contido para um prefixo, contém para um endereço),
  agregação (`aggregate`: as rotas mais longas que /16, IPv6 /32, numa linha por /16 com as contagens),
  `offset`/`limit` (até 5000) e as contagens da tabela inteira (estados, famílias, por origem, por
  tabela). O engine guarda as linhas calculadas (`route_table::RouteCache`) e só refaz quando muda a
  geração do candidato (`ConfigStore::generation`, novo, aditivo), o que DHCP/DHCPv6 instalaram, o que
  o kernel aprendeu, os links sem carrier ou um check-gateway; `ip.route.list` e o lookup usam o mesmo
  cache. Na GUI a janela pede uma página (500) com os filtros, mostra "1–500 de N" com `<`/`>`, o rodapé
  vem das contagens, a busca por prefixo tem os modos contido/contém/exato, "aggregate /16" dobra a
  tabela e um clique numa linha agregada abre aquele /16; as linhas são montadas uma vez por resposta,
  não por quadro. Gancho de benchmark escondido `corerouter_engine::perf` (sessão com uma tabela cheia
  direto na memória: ela não cabe na config salva, de 32 MB).

  Como testar: `cargo nextest run -p corerouter-engine --test route_page`; `cargo nextest run -p
  corerouter-ui route`; `corerouter-cli run ip.route.page '{"prefix":"192.0.2.0/24","match":"longer"}'`;
  `cargo xtask bench routes_1m`.

- 2026-10-23 — G2.2: IP › Firewall › Connections:

  - A tabela do conntrack vem por ctnetlink, sem o programa `conntrack`:
    - `Hal::connections`, `connection_stats` e `connections_kill`;
    - `hal-linux` usa `ctnl`; o lab simula a tabela pelos pools de CGNAT.
  - Os comandos `ip.firewall.connection.list`, `top`, `kill`, `tracking.info` e `tracking.set`:
    - páginas de até 5000 linhas e uma leitura do kernel reaproveitada por 2 s;
    - `kill` sem filtro exige `all=true`;
    - os timeouts são os parâmetros `nf_conntrack_*` do Tuning.
  - A aba Connections da janela Firewall:
    - barra de uso ligada ao Tuning;
    - filtros e páginas de 500;
    - selos de estado e de Via, e o pool na origem;
    - "Top subscribers" com o selo de % do bloco;
    - Kill e "Kill matching", que pede confirmação;
    - diálogo "Tracking…" com ⓘ em cada campo; as explicações em PT e EN citam as RFCs.

  Como testar:

  ```sh
  cargo test -p corerouter-engine --test connections
  cargo test -p corerouter-ui connections
  cargo test -p corerouter-hal-linux --lib ctnl
  ```

  Na GUI (daemon de lab), crie um pool CGNAT, abra IP › Firewall › Connections e clique num assinante do
  top.

  Os screenshots claro e escuro, do diálogo e do modal foram olhados.

- 2026-10-23 — G2.3c: CGNAT, parte 3:

  - **Modo blocos (RFC 6888 §5).** O primeiro pacote de um assinante sem bloco espera na fila do
    netfilter 7422:
    - `hal-linux::nfqueue` (nfnetlink, sem libnetfilter_queue);
    - o serviço `cgnat` do daemon atende a fila, o engine (`cgnat_blocks.rs`) aloca e o bloco vai para o
      mapa (`Hal::cgnat_blocks`).
  - **Regras do alocador:**
    - pareado: um IP por assinante (REQ-2);
    - novo bloco a 80 % de uso, até `max_blocks`;
    - liberação após `block_timeout` sem conexões, com quarentena de 120 s (REQ-8);
    - geometria mudada: libera na hora e derruba as conexões;
    - sem bloco livre: o pacote cai (REQ-11).
  - **Log por bloco:** `ALLOC` e `RELEASE` no log do roteador, tópico `cgnat` (novo), que vai ao syslog
    remoto por uma regra do `/system logging`. O journal `cgnat-blocks` reconstrói os blocos no boot e
    responde ao "Quem era?".
  - **Alertas de portas, nos dois modos:** uma linha por travessia de `alert_percent`, a lista com
    contagem e pico, e o `insert_failed` do kernel.
  - **Comandos:** `ip.firewall.cgnat.block.list`, `block.history`, `alert.list` e `alert.clear`.
  - **Lab:** finge 40 assinantes online por pool de blocos; os pesados (um a cada 17) usam 95 % das
    portas TCP.
  - **Correção:** `Pool::layout` aceita mais assinantes que blocos no modo blocos (a validação avisa
    "oversubscribed"). Removido também um overflow no texto de capacidade de um pool superlotado.

  Como testar:

  ```sh
  cargo test -p corerouter-engine --test cgnat_blocks
  COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_cgnat
  ```

  O netns (**medido**) confere três coisas: sem ouvinte da fila o primeiro pacote cai; com ouvinte, ele
  sai no bloco dado; o bloco sobrevive à troca da tabela.

- 2026-10-23 — G2.3d: CGNAT, parte 4: a janela. É um painel (`crates/ui/src/cgnat.rs`) no grupo CGNAT do menu, que deixou de
  estar trancado com o selo "soon". O placeholder `Win::Cgnat` saiu.

  Abas:

  - **Pools:** no **padrão de janela de lista do G0.24** (primeira janela a adotá-lo, com
    `list.rs`/`list_modal.rs`):
    - barra + − ✓ ✗ 💬;
    - filtro por modo em selos;
    - rodapé com contagens;
    - menu de clique direito: abrir, copiar, copiar como comando CoreRouter e RouterOS, ativar,
      desativar, remover;
    - modal com ⓘ em cada rótulo.
    - Os novos `ip.firewall.cgnat.pool.preview` e `exception.preview` calculam enquanto você digita:
      assinantes, por IP, capacidade, IPs usados e, ao editar, quantos assinantes mudam de lugar. Mostram
      também as checagens e o comando exato que o OK manda.
    - Linhas: modo como selo e selo de capacidade "IPs usados/IPs", com os avisos da validação.
    - O `pool.add`/`set` aceita números também como texto, como o modal manda.
  - **Exceptions:** as exceções 1:1, no mesmo padrão; a pré-visualização mostra o pool e o slot que fica
    vazio.
  - **Who Was:**
    - IP público, porta e data/hora com fuso; a resposta traz o assinante, o pool, o slot, a validade do
      mapeamento e o DHCP daquela hora;
    - consulta de um assinante: o slot dele agora.
  - **Mapping:** a tabela de correspondência em páginas de 500, filtrada por assinante ou IP público. As
    exceções aparecem apagadas, com o selo 1:1.
  - **Blocks** (só com pool de blocos): os blocos ativos, com os selos `current` e `idle`, e o log de
    blocos.
  - **Alerts:** assinantes no limite, com % em uso, pico e vezes, mais o selo `insert failed`.
  - **History:** as definições ao longo do tempo (RFC 7422 §3).

  As explicações (ⓘ) estão em PT e EN (`i18n/cgnat_pt.rs`, `cgnat_en.rs`): o que é, quando mudar,
  cuidado, padrão e a RFC.

  Como testar: `cargo test -p corerouter-ui cgnat` (headless: abas, diálogo que cria pool, Who Was,
  página do mapeamento, blocos e alertas). Screenshots claro e escuro olhados.

- 2026-10-23 — G4.4b: Traffic Flow, parte 1: o crate `corerouter-proto-flow` (L2, puro, compila em wasm). Codifica e
  decodifica IPFIX (RFC 7011) e NetFlow v9 (RFC 3954) com templates de fluxo IPv4 e IPv6 que levam
  os endereços e portas antes e depois do NAT, eventos de sessão NAT44 e de bloco de portas
  (RFC 8158) e registros de opções (taxa de amostragem, nomes das interfaces). Os templates voltam
  por tempo e por contagem de pacotes no UDP e uma vez por conexão no TCP. O medidor transforma os
  eventos `NEW`/`DESTROY` do conntrack e leituras periódicas da tabela em registros de fluxo, com
  timeouts ativo e inativo, amostragem determinística 1 em N (os eventos de NAT nunca são
  amostrados), filtro por interface e cache limitado sem perder bytes. O HAL ganhou o tipo
  `conntrack::Event` e o trait `EventSource`. Teste: `cargo test -p corerouter-proto-flow` (exemplo
  do RFC 7011 Apêndice A, pacote v9, retirada de template, ida e volta das duas versões, números de
  sequência, reenvio de templates, timeouts, proptest de ida e volta e de bytes hostis).

- 2026-10-23 — G4.4b: Traffic Flow, parte 2: o exportador funcionando.

  - **Comandos:** `ip.traffic-flow.set/get` (interfaces, cache, timeouts ativo e inativo, amostragem,
    eventos de NAT, destino nos eventos de NAT, retenção local) e `ip.traffic-flow.target.*`
    (IPFIX/UDP, IPFIX/TCP, NetFlow v9/UDP; templates reenviados por pacotes e por tempo; `src_address`
    só do roteador).
  - **Saídas:** `ip.traffic-flow.stats`, `ip.traffic-flow.top` (top talkers dos últimos minutos, sem
    coletor), `ip.traffic-flow.records` (lote com `since`/`next`, para o exportador de ClickHouse) e
    `ip.traffic-flow.export` (CSV).
  - **Fonte:** o HAL ganhou `conntrack_events`. No `hal-linux` são os grupos multicast NEW/DESTROY
    do ctnetlink, com `CTA_TIMESTAMP`, `ENOBUFS` contado e `nf_conntrack_acct`/`timestamp` ligados. No
    lab, as conexões simuladas do G2.2 abrem e fecham.
  - **Serviço `traffic-flow` no daemon:** um leitor põe os eventos numa fila fixa (o descarte é
    contado). O exportador roda o medidor e lê a tabela para os timeouts. Ele também lê o log de
    blocos do CGNAT (G2.3c) e emite `natEvent` 16/17. Codifica uma vez por destino e envia fora do
    lock.
  - **Marco Civil (art. 14):** os eventos de NAT saem sem destino por padrão. O delete leva o início
    da sessão e por isso basta sozinho.

  Documentação em `docs/traffic-flow.md` (pesquisa, riscos, números).

  Teste:

  ```sh
  cargo test -p corerouter-engine traffic_flow
  COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-daemon --test netns_traffic_flow -- --nocapture
  ```

  O teste em netns abre conexões TCP e UDP reais através de um SNAT para dois coletores em Rust (v9
  por UDP e IPFIX por TCP). Ele confere:

  - o NAT antes e depois;
  - os tempos do kernel;
  - o top talker;
  - que um destino removido não recebe mais nada;
  - uma rajada sem perda.

- 2026-10-23 — G6.8: DNS Lookup, parte 2 de 2 (G6.8b): **Watch**, **Upstreams** e **Check hijack**.

  - `tool.dns.watch` (`/tool dns-watch`, aba Watch): a mesma pergunta a cada intervalo até o Stop
    ou o Esc, como o `dnsping`; latência × tempo com os picos marcados e a tabela (hora, ms,
    etapa, TTL, resposta) com o selo `changed` quando a resposta troca.
  - `tool.dns.upstreams` (`/tool dns-upstreams`, aba Upstreams): cada servidor de `ip.dns`,
    `use_doh_server` e dos grupos de forwarders recebe 200 consultas (nomes populares e
    aleatórios abaixo deles), com p50, p99, perda, SERVFAIL, TCP, EDNS e DoH/DoT; um servidor
    morto é largado depois de 6 timeouts. Check hijack: NXDOMAIN sequestrado (nomes aleatórios) e
    proxy no caminho (o resolvedor que chega ao autoritativo, por `whoami.ds.akahelp.net` e
    `o-o.myaddr.l.google.com`, é da rede do próprio cliente). Recomendação de quais usar e quais
    remover, explicada, no idioma das explicações.
  - Achado no lab (rede real, **medido**): 1.1.1.1 e 8.8.8.8 saem pelas redes deles; 9.9.9.9 sai
    pelo AS7195 (parceiro do Quad9), por isso "outra rede" é nota e não "proxy". A primeira
    versão tomava o `"ip"` da resposta da Akamai (o IP público do cliente) como resolvedor e
    marcava os três como proxy: o teste de unidade cobre o formato.

  Como testar: `corerouter-cli --connect 127.0.0.1:7979 watch tool.dns.upstreams '{"count":50}'`;
  `… watch tool.dns.watch '{"name":"www.netflix.com","server":"8.8.8.8","interval_ms":300}'`
  (Ctrl+C para); na GUI, Tools › DNS Lookup, abas Watch e Upstreams. Testes: watch detecta a
  mudança e o pico; benchmark com upstream lento, sequestrador, interceptado e morto (engine) e
  com sockets reais (daemon: lento e sequestrador); headless das abas (Esc para o watch).

- 2026-10-23 — docs: `docs/ui-style.md`: padrão aprovado pelo usuário para janelas de lista e o modal de adicionar
  (G0.24): barra **+ − ✓ ✗ 💬** com filtros e Find, selos de estado e origem, rodapé com contagens,
  editar por duplo clique, modal com ⓘ em cada rótulo, campos calculados, cadastro em série numa
  transação, checagens (conflito, uso na rede, perda de acesso), prévia dos comandos e Cancel/Apply/OK.
  A referência é IP › Addresses (G1.28). Também: regra geral "Explicação ⓘ em todo lugar que couber" (`docs/ui-style.md` e `AGENTS.md`), em português por padrão.

- 2026-10-23 — fix: i18n: a mesma chave em duas tabelas de rótulos passa no teste quando o texto é igual (só reprova
  se a tradução divergir). Sessões em paralelo registravam a mesma palavra ("changed", "of") em
  catálogos diferentes, e cada combinação quebrava o lote da fila (#159, #165, 2026-10-23) sem
  nenhum erro de verdade: o `lookup` pega a primeira, e com o mesmo texto não há diferença na tela.

- 2026-10-23 — G2.5b: XDP, parte 2a: a aritmética de portas do CGNAT determinístico (RFC 7422 §2) sai do
  `Layout` do model para o crate novo `corerouter-cgnat-map` (L0, `no_std`, sem alocação, sem
  `unsafe`, sem panic): número do assinante ↔ (número do endereço público, bloco) e bloco ↔ portas
  (`Geometry::split/join/ports_of/block_of`). O `Layout` chama essas funções e mantém a API
  pública (`forward/reverse/slot/locate/block/subscriber_index/per_address/capacity`); ganha
  `geometry()`. O programa XDP da G2.5b vai usar as mesmas funções: uma fórmula só para o fast path
  e para o "Quem era?". Combinado com a sessão do CGNAT (G2.3).

  Testes: os proptests do `model::cgnat` passam sem mudança; no crate novo, o exemplo da RFC 7422
  §2.3, geometria degenerada sem panic e proptests (ida e volta, blocos sem sobreposição, igual à
  fórmula em inteiros largos). `cargo test -p corerouter-cgnat-map -p corerouter-model cgnat`.

- 2026-10-23 — G4.4b: Traffic Flow, parte 3: a janela **IP › Traffic Flow**, com quatro abas.

  - **Estado** no topo: `running`/`stopped`/`error`, a fonte (`conntrack` ou `lab`), se o kernel
    conta bytes e marca tempos, registros por minuto, e estouros do kernel e descartes da fila
    quando há.
  - **General:** as configurações, com Apply e Revert. O destino nos eventos de NAT mostra o selo
    "Marco Civil art. 14" quando ligado.
  - **Targets:** os coletores no padrão de lista (G0.24): barra + − ✓ ✗ 💬, estado por selo, coletor,
    versão e transporte, registros por minuto, templates (quantas vezes e a última), fila e perda. O
    modal de adicionar e editar usa a pré-visualização nova `ip.traffic-flow.target.preview`, que
    diz o que vai enviar, as checagens e os comandos.
  - **Top Talkers:** os últimos 1, 5, 15 ou 60 minutos, por bytes, pacotes ou conexões, com envio e
    recebido. O nome do assinante aparece quando o roteador tem `ip.identity.lookup` (G0.25). **Copy
    CSV** copia os registros do período.
  - **Statistics:** todos os contadores.

  Toda caixa e todo rótulo têm ⓘ com a explicação em português e inglês. A entrada do menu tem
  sinônimos (netflow, ipfix, log de NAT, Marco Civil…). O lab ficou com um tráfego mais realista,
  de poucos Mbit/s por assinante pesado.

  Teste: `cargo test -p corerouter-ui traffic_flow` e `cargo test -p corerouter-engine
  traffic_flow`. Screenshots nos temas escuro e claro olhados.

- 2026-10-23 — G4.5: Gráficos de tráfego, parte 1: o histórico local.

  - `engine::graph`: banco round-robin próprio (`graph::rrd`), de tamanho fixo, com média e máximo
    por slot. São quatro anéis: 1 s por 1 h, 1 min por 1 dia, 5 min por 1 semana e 1 h por 1 ano.
    - Balde com menos da metade dos segundos conhecidos fica desconhecido (`xff` 0,5).
    - Contador que volta (reset, link recriado) é desconhecido, nunca pico (`DERIVE min=0` do
      RRDtool).
    - Buraco maior que 10 s é desconhecido; relógio que volta é ignorado.
  - Coleta no `Session::tick` (a mesma varredura de links de todo segundo, sem dump extra):
    - por interface: bps e pps de entrada e saída, erros e drops por segundo;
    - do roteador, por `Hal::resources` (novo; `/proc/stat`, `/proc/meminfo`,
      `nf_conntrack_count`): CPU, memória e conntrack.
  - `system.graph.set` (config `system.graphing`, estilo `/tool graphing`):
    - escolhe por classe: físicas e bonds por padrão; bridges, VLANs e túneis opcionais;
    - `include`/`exclude` por nome;
    - `max_memory_mib`, 64 MiB por padrão: série que não cabe é recusada, vai para o log e aparece
      em `system.graph.print`;
    - `store_every`, 5 min por padrão.
  - Série que deixa de ser guardada sai depois de 10 min (uma varredura que falhou não apaga um ano).
  - `system.graph.query {series, range, step?}`:
    - pontos de hora, dia, semana, mês ou ano;
    - corrente, média, máximo, **p95** e totais;
    - o p95 vem das médias de 5 min (padrão de cobrança, posto mais próximo, descarta os 5 % de
      cima); acima de uma semana vem das de 1 h e a resposta diz `p95_approximate`;
    - `p95_billing` (maior entre entrada e saída, como o LibreNMS) e `p95_sum`.
  - `system.graph.export {since, resolution}` entrega os baldes fechados depois de um cursor, sem
    cortar um balde entre páginas: é o que o exportador ClickHouse (G4.4f) ainda não enviou. Em
    Rust: `GraphDb::export`.
  - Daemon: serviço `graphing` (`<config-dir>/graphs/`, um arquivo por série).
    - Grava em lote, no lugar, só os baldes fechados desde o último store.
    - O anel de 1 s vai só no desligamento limpo (`final_store` no shutdown do `main.rs`).
    - Arquivo novo vai por temporário + rename; arquivo ilegível vira `*.corrupt`.
    - `service::Ctx` ganhou `config_dir`.
  - O lab virtual varia o tráfego e a CPU (ondas determinísticas), para os gráficos se mexerem.
  - A decisão formato próprio × `redb` × `fjall` está em `docs/architecture.md` ("Histórico de
    tráfego").

  Como testar:

  ```sh
  cargo test -p corerouter-engine --lib graph
  cargo test -p corerouter-daemon graphing
  cargo bench -p corerouter-engine --bench graph
  cargo run -p corerouter-daemon -- --control 7979 --config-dir /tmp/cr
  cargo run -p corerouter-cli -- --connect 127.0.0.1:7979 run system.graph.query '{"series":"ether1","range":"hour","step":60}'
  ```

- 2026-10-23 — G4.5: Gráficos de tráfego, parte 2: a janela **Tools › Graphs** (`crates/ui/src/graphs.rs`).

  - Mostra uma interface guardada ou o **Sistema** (CPU, memória e conntrack, um gráfico de cada), na
    última hora, dia, semana, mês ou ano (egui_plot, como o Ping).
    - Uma série: Rx azul e Tx vermelho (como a aba Traffic), o máximo em linha clara e o p95
      tracejado.
    - **Comparar** até 6 interfaces no mesmo gráfico, cada uma na cor do seu nome (`chip::name_hue`),
      com Rx em linha cheia e Tx tracejado.
    - Tempo desconhecido aparece como buraco na linha, nunca como zero.
  - Abaixo do gráfico, os números que o roteador calculou (`system.graph.query`; a UI não calcula):
    - atual, média, máximo, **percentil 95** e total em GB;
    - o **p95 de cobrança** (a maior das direções) e o p95 de Rx+Tx.
  - Selos:
    - resolução;
    - cobertura abaixo de 95 %;
    - "p95 de médias de 1 h" quando a faixa passa de uma semana.
  - **CSV** (todos os pontos, hora UTC e Unix) e **PNG** (só o gráfico, recortado de um screenshot
    da janela).
    - A GUI nativa salva na pasta Downloads, sem sobrescrever (`export.rs`: o app instala o
      `SaveFile` no contexto do egui; a UI não faz I/O).
    - No navegador vão para a área de transferência.
  - **Configurações…** abre o diálogo de `system.graph.set`:
    - classes (físicas, bridges, VLANs, túneis, recursos);
    - include e exclude;
    - memória máxima e intervalo de gravação;
    - a ocupação e o estado do disco.
  - ⓘ em cada rótulo, coluna e campo, com explicação em português e inglês
    (`i18n/graphs_pt.rs`, `graphs_en.rs`). Entrada no menu pela tabela central (`menu.rs`, "graphs",
    `/tool graphing`).
  - **Mini gráfico na janela Interfaces** (coluna Traffic, `spark.rs`):
    - os últimos 5 minutos de Rx e Tx de cada interface guardada, numa consulta só a cada 5 s;
    - a célula leva o desenho codificado, como os selos, e o `table.rs` o pinta (mudança mínima nos
      dois arquivos);
    - o tooltip mostra os valores.
  - Ícone: `CHART_BAR`, por ora (um ícone novo pede o `pyftsubset`, que não está nesta máquina).

  Como testar:

  ```sh
  cargo test -p corerouter-ui --lib graphs
  cargo run -p corerouter-daemon -- --control 7979 --config-dir /tmp/cr
  cargo run -p corerouter-gui -- --connect 127.0.0.1:7979 --control 7990
  ```

  Depois abra Tools › Graphs (ou Ctrl+K "graphs") e a janela Interfaces (coluna Traffic). Os
  screenshots claro e escuro foram olhados.

- 2026-10-23 — fix: conntrack: matar conexões não para mais numa conexão ICMP. O `delete` por ctnetlink mandava o
  tuple ICMP só com o id, e o kernel exige também tipo e código (`CTA_PROTO_ICMP_TYPE`/`CODE`):
  devolvia EINVAL, e o laço desistia no primeiro erro, deixando vivas as conexões que vinham
  depois. No CGNAT isso deixava assinantes remapeados com a tradução antiga (o "Quem era?" erraria
  para elas), e o `ip.firewall.connection.kill` parava no primeiro ping.

  - o parser guarda tipo e código do ICMP no `dst_port` (`tipo << 8 | código`) e o pedido de
    delete os devolve;
  - o `delete` tenta todas e só depois devolve a primeira recusa;
  - o filtro `port` de `ip.firewall.connection.list` ignora ICMP (o campo é tipo/código ali).

  Era a causa do teste instável `netns_cgnat::element_changes_go_incremental_and_remaps_kill_connections`
  ("killed: left 1, right 0"): falhava quando um teste anterior do mesmo binário deixava um ping no
  conntrack. **Medido** (Ryzen AI MAX+ 395, 2026-10-23): antes 2 falhas em 4 execuções do binário,
  depois 10 de 10 verdes. Teste novo de bytes: `ctnl::an_icmp_tuple_carries_type_and_code`.
