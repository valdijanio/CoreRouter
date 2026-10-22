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
