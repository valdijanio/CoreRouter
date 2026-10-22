# CoreRouter — log

Só de acrescentar (`merge=union` no `.gitattributes`): cada PR adiciona sua entrada **no fim**, sem
editar ou reordenar entradas antigas. Uma entrada = um item `- AAAA-MM-DD — <id>: …` (pode ter
linhas de continuação indentadas). PRs paralelos se juntam sem conflito; a ordem entre entradas do
mesmo dia pode variar.

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
