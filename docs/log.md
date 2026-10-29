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

- 2026-10-23 — G0.25: Identidade do assinante: um selo com o nome ao lado do IP.

  - Comando `ip.identity.lookup {addresses, at?, sources?}`:
    - até 4096 endereços por chamada;
    - fontes em ordem configurável: login PPPoE (gancho para a G4.3), comentário da concessão fixa,
      host-name da concessão, comentário de IP › Addresses (/29 ou menor), comentário de
      address-list (até 256 endereços) e PTR das zonas próprias;
    - devolve o primário, `more` (nomes diferentes além dele) e todos com fonte, detalhe e `ref`
      (janela, aba, id);
    - IP público com porta passa pelo CGNAT (a função de mapeamento da G2.3, no instante pedido);
    - `at` usa o histórico de concessões (G4.2b);
    - nomes limpos (sem controle nem bidi) e cortados em 64 caracteres.
  - Desempenho: o índice da config é feito uma vez por mudança das seções (comparação de ponteiro
    dos `CowArc`) e guardado no `Session::ext`; uma consulta é um hash por endereço, sem I/O sob o
    lock.
  - GUI (`crates/ui/src/identity.rs`):
    - selo reutilizável: o nome com ícone, `+N`, tooltip com todas as fontes e clique que abre o item
      de origem selecionado;
    - aplicado em IP › Firewall › Connections (origem, top assinantes e filtro de assinante) e em
      CGNAT › Quem era? (o nome de quem tinha o IP no instante consultado, `badge_at`) e em
      IP › Traffic Flow › Top talkers (no lugar do selo simples da G4.4b);
    - traduções em `crates/ui/src/i18n/auto/identity_{en,pt}.rs`;
    - Settings › Subscriber identity: liga/desliga, ordem das fontes, onde mostrar; guardado com o
      tema (preferência do cliente);
    - ⓘ com explicação em PT e EN; padrão documentado em `docs/ui-style.md`.

  Como testar:

  ```sh
  cargo test -p corerouter-engine --test identity
  cargo test -p corerouter-ui --lib identity
  corerouter-cli run ip.identity.lookup '{"addresses":["100.64.0.1","203.0.113.0:1100"]}'
  ```

  Na GUI (daemon de lab): crie um pool CGNAT, ponha um comentário numa concessão fixa de
  100.64.0.1 e abra IP › Firewall › Connections. Passe o mouse no selo e clique nele.

- 2026-10-23 — G2.3e: CGNAT, parte 5: a bateria final e os números.

  - **Esgotamento no kernel** (`netns_cgnat::a_subscriber_out_of_ports_never_borrows_another_s`, RFC 6888
    REQ-3/11): um assinante com 64 portas abre 80 fluxos para o mesmo servidor. Passam exatamente 64,
    todos dentro do slot dele (nunca uma porta do vizinho), e o kernel conta as recusas, que é o que os
    alertas leem.
  - **Propriedades** (`crates/engine/tests/cgnat_battery.rs`):
    - para formas aleatórias de pool, o que o planner (`tool.ip-calc.cgnat.plan`) diz que cabe é o que
      o pool criado com os parâmetros dele faz;
    - a prévia é a tabela do pool;
    - todo assinante volta pelo "Quem era?" a partir do próprio slot;
    - entrada hostil no planner, na exportação e no "Quem era?" vira erro, nunca panic.
  - **Benchmarks:**
    - `hal-linux/benches/netns_cgnat_pps.rs`: gerador `AF_PACKET` em Rust; as respostas de cada fluxo
      saem do conntrack, para os fluxos UDP ficarem estabelecidos e entrarem no flowtable. Mede pps sem
      NAT, com CGNAT e com CGNAT + fast path, e conexões novas/s com e sem EIM e só com conntrack;
    - `engine/benches/cgnat_who_was.rs`: latência do "Quem era?" com 1 e 365 épocas.
  - **Relatório** em `docs/cgnat.md` §6, incluindo o que veth mede e o que só hardware mostra.
    - Achado: com o slot quase cheio, abrir conexão fica ~20× mais caro (a busca de porta livre no
      `nf_nat`). O alerta de 90 % avisa antes.

  Como testar:

  ```sh
  cargo test -p corerouter-engine --test cgnat_battery
  COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_cgnat
  COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- cargo bench -p corerouter-hal-linux --bench netns_cgnat_pps
  cargo bench -p corerouter-engine --bench cgnat_who_was
  ```

- 2026-10-23 — G2.4: Fast path (G2.4a): o flowtable do Linux (`nf_flowtable`), equivalente ao FastTrack do RouterOS, por
  nfnetlink no mesmo encoder do CGNAT (tabela `inet corerouter_fastpath`, sem o binário `nft`).

  - **Uma opção, não duas regras:** `ip.firewall.fastpath.set {enabled}`. A cadeia que põe as
    conexões no flowtable (`ct state established flow add @ft`, TCP e UDP, IPv4 e IPv6) roda em
    `forward` com prioridade `filter + 10`, **depois** do firewall: só entra o que as regras
    aceitaram, e uma regra de drop sempre vale. Ao mudar o firewall o flowtable é recriado, e as
    conexões voltam a passar pelas regras.
  - **Portas:** `interfaces` vazio = todas as Ethernet e bonds (sem os slaves). Nomear uma VLAN é
    recusado, com a sugestão de nomear a porta (o kernel 5.13+ segue as VLANs).
  - **Hardware:** `hw_offload`:
    - `auto` (padrão) pede `flags offload` e, se o kernel recusar, cai para software, e o
      `status` diz por quê;
    - `yes` recusa a mudança, já no comando quando nenhuma porta é capaz;
    - `no` fica só em software.
  - **`ip.firewall.fastpath.status`:** porta a porta, com:
    - `hardware`/`software`/`off`;
    - driver, firmware, devlink, modo do eSwitch (`DEVLINK_CMD_ESWITCH_GET`), representor e
      `hw-tc-offload`;
    - o motivo e o comando que falta (`devlink dev eswitch set … mode switchdev`, ou o
      `interface.ethernet.set` do hw-tc-offload);
    - quantas conexões estão no flowtable (software e hardware, pelo conntrack).
  - **Lab:** ether7 e ether8 simulam portas ConnectX-6 Dx (legacy e switchdev). A coluna Via de
    Connections só mostra flowtable com o fast path ligado.
  - **Janela IP › Fast Path:**
    - formulário com ⓘ;
    - selos de estado;
    - tabela das portas, com os selos da placa;
    - os comandos de correção com Copiar.

  Como testar:

  ```sh
  cargo test -p corerouter-engine --test fastpath
  cargo test -p corerouter-ui fastpath
  COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_fastpath
  ```

  O teste em namespace (veth + CGNAT) abre uma conexão TCP de um assinante e confere no conntrack que
  ela foi traduzida e entrou no flowtable (`OFFLOAD`). `flags offload` numa veth é recusado: `auto`
  roda em software, `yes` é recusado inteiro, e desligar remove a tabela. **Medido** (Ryzen AI MAX+ 395,
  2026-10-23). A vazão com e sem flowtable fica para a bateria do G2.3e.

- 2026-10-23 — G2.5a: XDP, parte 1: base e filtro anti-DDoS antes do kernel (`docs/xdp.md`).

  - **Programa XDP em Rust** (`crates/dataplane-ebpf`, `aya-ebpf`, fora do workspace, nightly
    fixado + `bpf-linker`), único crate com `unsafe` (6 blocos com `SAFETY:`, listados no
    `docs/xdp.md` para revisão humana). A lógica (parse Ethernet/QinQ/IPv4/IPv6/TCP/UDP/ICMP,
    decisão, token bucket, layout dos mapas) fica em `crates/dataplane-ebpf-common` (`no_std`, sem
    `unsafe`), compilada também para o host e testada lá.
  - **Objeto pré-compilado** em `crates/dataplane-ebpf/prebuilt/` com o hash das fontes:
    `cargo xtask ebpf` recompila; o passo `ebpf-check` do `cargo xtask ci` reprova fonte mudada sem
    recompilar, sem precisar do nightly.
  - **Filtro**: listas de bloqueio (address lists do firewall, prefixos v4/v6 em LPM trie, faixas
    em CIDR exato, entradas dinâmicas inclusive), listas de exceção, limite de taxa por origem
    (token bucket em LRU hash), descarte de malformados (RFC 1858 incluso) e de flags TCP
    impossíveis (tabela do `nf_conntrack`), contadores por interface e motivo, top origens.
  - **`hal-linux`**: carrega só quando há interface configurada, `auto` = native senão generic,
    sincroniza os mapas por diferença, XDP por último no `apply` (falhou: o resto volta), links do
    processo do daemon (morreu: fail-open).
  - **Comandos** `ip.firewall.xdp.interface.add/set/remove/list`, `ip.firewall.xdp.set/print/top`,
    `ip.firewall.xdp.reset-counters`; pps calculado no engine; **lockout**: bloquear o endereço da
    própria sessão de gerência é recusado (`force`/Safe Mode), avisos de lista vazia e taxa baixa.
  - **Janela** IP › Firewall XDP: Interfaces (modo, ativo, pps, descartes por motivo), Filtro, Top
    Sources, ⓘ em cada rótulo (PT e EN). Laboratório virtual simula os contadores.
  - **Testes**: proptest no host (parse, cortes, padding, listas contra LPM de referência, token
    bucket); no CI com root (`cargo xtask xdp-root`, ligado por `ci/kernel-modules/veth`): o
    verificador aceita, native e generic em veth, **diferencial kernel × host** em 4000 quadros
    gerados/cortados/corrompidos pelo `BPF_PROG_TEST_RUN`, ping real para contadores, top, exceção
    e taxa; engine (sucesso, validação, rollback, lockout) e UI.
  - Teste: `cargo test -p corerouter-dataplane-ebpf-common -p corerouter-engine --test xdp`,
    `cargo test -p corerouter-ui xdp`; na GUI, IP › Firewall XDP.

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

- 2026-10-23 — G4.5: Gráficos de tráfego, parte 3: **alertas de banda**.

  - Regras em `system.graphing.alerts` (config, com revisão e transação):
    - comandos `system.graph.alert.add/set/remove/print`;
    - campos: interface, direção (`rx`, `tx` ou `any`, a mais ocupada a cada minuto), `percent` (1–100), `minutes` (1–1440), `capacity_mbps` opcional e `disabled`;
    - a interface precisa estar guardada no histórico; o erro diz como incluí-la.
  - **Avaliação** (`engine::graph::alert`):
    - nas médias de 1 minuto do histórico, a cada minuto fechado: rajada menor que um minuto não conta, e um minuto desconhecido quebra a sequência;
    - a capacidade é a da regra ou a velocidade negociada da porta (`Hal::ethernet_monitor`, consultada uma vez por minuto, nunca a cada segundo);
    - sem nenhuma das duas, o estado é `unknown`, com o motivo.
  - **Log:**
    - uma linha `warning` (tópico `interface`) quando começa, como `graphing: ether8 any 50% of 40 Mbit/s: above for 2 min (last minute 62.5%)`;
    - uma linha `info` quando termina (`back below`), uma vez cada;
    - o log remoto (`system.logging`) pode encaminhar as duas.
  - **GUI:** botão "Alerts… (n)" na janela Graphs, com selo vermelho quando há regra alertando.
    - A janela lista as regras: estado em selo (ok, alertando, desconhecido; o tooltip mostra o último minuto e o motivo), capacidade, remover, e um formulário para adicionar. ⓘ em cada coluna.
    - O gráfico de uma interface traz a linha tracejada do limiar de cada regra dela.

  Como testar:

  ```sh
  cargo test -p corerouter-engine --lib graphing_alert
  cargo test -p corerouter-ui --lib graphs
  cargo run -p corerouter-cli -- --connect 127.0.0.1:7979 run system.graph.alert.add '{"interface":"ether8","percent":50,"minutes":2,"capacity_mbps":40}'
  cargo run -p corerouter-cli -- --connect 127.0.0.1:7979 run system.graph.alert.print '{}'
  ```

  No lab, `ether8` passa de 50 % de 40 Mbit/s em 2 a 3 minutos: o alerta aparece no log e na janela.

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

- 2026-10-23 — G6.4: G6.4b — Tools › Bandwidth Test com o **protocolo do iperf3**, interoperável com qualquer `iperf3`
  (não é o btest proprietário do MikroTik). Cliente `tool.bandwidth-test.start` (tarefa; terminal
  `/tool bandwidth-test`): TCP ou UDP, 1–128 streams, `send`/`receive`/`both`, taxa por stream,
  **prazo máximo** de 300 s, gráfico Tx/Rx por segundo, perda e jitter no UDP, a **CPU do roteador**
  durante o teste e o que o outro lado mediu; recusa o teste que sairia pela porta da própria
  conexão fora do Safe Mode e avisa quanto vai encher o caminho (a GUI confirma antes). Servidor
  `tool.bandwidth-server.set/get` (config com journal e rollback): **desligado por padrão**, ligar
  exige a lista de prefixos permitidos, um teste por vez, limites de duração, streams e taxa,
  recusa com os códigos de erro do iperf3; serviço `bandwidth-server` sob o supervisor. Protocolo
  puro em `crates/proto-iperf` (novo, L2), sockets no daemon. Testar: GUI › Tools › Bandwidth Test
  (aba Server: ligue com `127.0.0.0/8`; aba Test: `127.0.0.1`), `corerouter-cli --connect … watch
  tool.bandwidth-test.start '{"address":"…","protocol":"udp","bandwidth":"100M"}'`, `iperf3 -c
  <roteador>`; testes de codec (proptest), do cliente contra o servidor em loopback (TCP nos dois
  sentidos, UDP com perda e jitter, limites, ocupado), do serviço (ACL, contagem, desligar fecha a
  porta), dos comandos e headless da janela; interoperabilidade com o binário `iperf3`
  (`interop_*` em `service/iperf.rs`) roda quando ele está instalado. Screenshots em
  `docs/changes/G6.4-bandwidth-test-screenshots/`.

- 2026-10-23 — G6.4: G6.4a — Tools › Torch e Tools › Packet Sniffer. **Torch** (`tool.torch.start`, tarefa; terminal
  `/tool torch ether1`): o tráfego de uma interface por fluxo, agrupado em selos (src, dst,
  protocolo, porta, VLAN, DSCP, MAC) e filtrado (prefixos, porta, protocolo, VLAN, DSCP, MAC), com
  Tx/Rx em bit/s e pacotes/s, a pílula do AS no destino (como no MTR), `CGNAT`/`privada` e o lugar do
  selo do assinante (`ip.identity.lookup` do G0.25, pedido só quando o roteador tem o comando).
  Cada linha é a conversa vista da interface (origem = o lado dela). Captura em Rust puro no
  `hal-linux`: `AF_PACKET` por dispositivo, filtro BPF clássico que amostra 1:N no kernel e evita
  contar duas vezes um quadro de VLAN; `sampling: auto` amostra acima de 500 kpps e avisa; os
  contadores da interface conferem quanto a captura viu. Lab virtual com tráfego simulado
  determinístico. **Packet Sniffer** (`tool.sniffer.start` / `tool.sniffer.download`): pcap em
  memória, limitado em tamanho (≤ 64 MiB) e duração (≤ 1 h), só cabeçalhos por padrão, grupo write
  para iniciar, download em pedaços pela GUI (abre no Wireshark/tcpdump). Testar: GUI › Tools ›
  Torch (escolha ether1, Start) e Tools › Packet Sniffer (Start, Download .pcap);
  `corerouter-cli watch tool.torch.start '{"interface":"ether1","duration":3}'`; testes de codec
  (proptest), do job com relógio falso, dos comandos, headless das janelas e em netns com veth
  (`netns_capture`: ida e volta, tamanho no fio, amostragem do kernel, VLAN contada uma vez).
  Screenshots em `docs/changes/G6.4-torch-screenshots/`.

- 2026-10-23 — G6.4: G6.4c — **traceroute como modo do MTR**: `tool.traceroute.start` (terminal `/tool traceroute`,
  `traceroute`) faz uma passada com N sondas por salto e imprime a tabela clássica do
  `traceroute`; o MTR e o traceroute sondam por **ICMP, UDP ou TCP SYN** (porta escolhida; sem
  socket raw, pela fila de erros do socket) e no modo **Paris** (padrão: o mesmo fluxo em toda
  sonda — no ICMP uma palavra da carga mantém o checksum —, então um balanceador ECMP manda todas
  pelo mesmo caminho; Paris UDP/TCP vai uma sonda por vez). Reaproveita nomes, ASN e MPLS do MTR.
  Janela Tools › MTR: selos MTR | Traceroute, protocolo, porta, Paris (ⓘ em cada um), coluna Probes
  e o selo `ECMP n` num salto que respondeu de vários roteadores. Lab: par ECMP simulado no salto
  3. Testar: GUI › Tools › MTR › Traceroute (8.8.8.8, tcp 443, Paris ligado e desligado);
  `corerouter-cli watch tool.traceroute.start '{"address":"8.8.8.8","protocol":"udp"}'`; testes do
  job (Paris × clássico no ECMP, fim por port unreachable/SYN-ACK), dos comandos, do checksum
  Paris, headless da janela e em netns (`netns_icmp`: UDP e TCP, clássico e Paris, IPv4 e IPv6,
  time exceeded do roteador e port unreachable/RST/SYN-ACK do destino). Screenshots em
  `docs/changes/G6.4-traceroute-screenshots/`.

- 2026-10-23 — G6.9: Tools › IP Calculator: um painel (`crates/ui/src/ip_calc.rs`) no grupo Tools, com três abas. Todo
  número vem dos comandos novos `tool.ip-calc.*` (`crates/engine/src/cmd/ip_calc.rs`), que o CLI, o
  MCP e o terminal também usam.

  - **Subnet** (`tool.ip-calc.subnet`, `split`, `summarize`, `range`):
    - aceita prefixo, máscara ou IPv6;
    - mostra rede, broadcast, primeiro e último host, hosts (/31 tem 2, RFC 3021), máscara,
      wildcard e escopo (RFC 1918, RFC 6598, documentação…);
    - avisa sobreposição com endereços, rotas, pools e faixas de CGNAT já configurados;
    - dividir por prefixo ou por quantidade, sumarizar (com a super-rede e os endereços que ela
      acrescenta), faixa → menor conjunto de prefixos.
  - **IPv6 PD** (`tool.ip-calc.pd`): quantas delegações de /48 a /64 cabem num prefixo (em texto:
    passa de 2^64), as primeiras e a última, e os pools de DHCPv6-PD dentro dele.
  - **CGNAT planner** (`tool.ip-calc.cgnat.plan`, `cgnat.export`):
    - usa o `Layout` do `corerouter-model` (a mesma fórmula RFC 7422 dos pools): o que ele mostra é o
      que o pool faz;
    - aceita faixas ou só quantidades (`4096` assinantes, `32` IPs);
    - mostra assinantes por IP, capacidade, IPs necessários e sobrando, portas sobrando, as
      checagens do pool e sugestões ("acrescente 48 IPs, ou use 252 portas");
    - prévia da correspondência;
    - botões: **Create CGNAT pool** (manda o `ip.firewall.cgnat.pool.add` com os parâmetros do
      plano), **Copy CSV**, **Copy printable**, **Copy as RouterOS script** (uma regra src-nat por
      assinante e protocolo, para quem ainda opera MikroTik) e **View rules** (o nftables que o pool
      gera).
    - recalcula 0,4 s depois que você para de digitar.
  - ⓘ em cada campo (PT e EN), o item de menu tem explicação e sinônimos ("sub-rede", "máscara",
    "planejar cgnat"…).

  Como testar:

  ```sh
  cargo test -p corerouter-engine --test ip_calc
  cargo test -p corerouter-ui ip_calc
  cargo run -p corerouter-cli -- run tool.ip-calc.cgnat.plan '{"inside":"4096","outside":"32","ports_per_subscriber":500}'
  ```

  O PDF ficou de fora de propósito: o texto imprimível sai em colunas fixas e qualquer editor
  imprime ou gera PDF dele, sem crate novo de PDF.

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

- 2026-10-23 — processo: i18n: traduções de janela nova em `crates/ui/src/i18n/auto/<escopo>_<idioma>.rs`, registradas
  pelo `build.rs` (sem editar as listas do `i18n/mod.rs`), com rótulos procurados primeiro no escopo
  da janela (`i18n::tr_in`). O `i18n/mod.rs` era o ponto quente da rodada de 2026-10-23: todo PR com
  tela acrescentava linhas nas mesmas listas (a fila só conseguia integrar um por lote), e a mesma
  palavra em inglês com traduções diferentes em janelas diferentes ("Checks", "Last") reprovava o
  lote. O registro antigo continua valendo (mudança aditiva); `AGENTS.md` e `docs/ui-style.md`
  explicam o caminho novo.

- 2026-10-23 — processo: Fila de entrada: o PR pai de um PR empilhado é reconhecido por **qualquer** commit dele que esteja
  na branch do filho, não só pelo último. A fila manda merges da `main` na branch do pai antes do
  squash, e esse último commit não está na branch do filho; a resolução automática não reconhecia o
  pai e devolvia o PR à sessão (#177 e #186, 2026-10-23). Testado no #186 real: os 4 arquivos do
  conflito resolvidos sozinhos.

- 2026-10-23 — G1.28: IP › Addresses é a primeira janela no padrão de lista (G0.24) e serve de referência
  (`crates/ui/src/ip_address.rs`).

  - **Engine:**
    - `ip.address.set {id, address?, interface?, disabled?, comment?, force?}`: editar, ativar,
      desativar e comentar; o `disabled` fica na config e sai do kernel.
    - `ip.address.remove` aceita `force?`.
    - `ip.address.list` ganhou `state` (`active`, `disabled`, `invalid`, `tentative`, `dad-failed`,
      `deprecated`), `family`, `vrf` e `access` (por que esta sessão depende do endereço); as flags
      continuam para o terminal.
    - `ip.address.check` é a consulta por trás do modal. Ela calcula rede, máscara, broadcast,
      hosts e faixa, monta a série `to` (até 256 endereços, numa transação) e confere: endereço
      repetido, sobreposição com outra interface da mesma VRF, endereço de rede ou broadcast, ARP e
      risco de acesso. Também devolve os comandos.
    - O `ip.address.add` não mudou.
  - **Perda de acesso:** a checagem de lockout passa a recusar também a remoção da rede, ou da rota,
    por onde a sessão de gerência chega (antes só o próprio endereço). O `lockout_reason` responde
    sem aplicar, para a pré-visualização avisar antes.
  - **ARP (RFC 5227):** uma sonda com remetente 0.0.0.0 pelo socket do cliente DHCP (`AF_PACKET`)
    e resposta lida entre 1 e 2 s, em segundo plano: a janela mostra "checando…" e pergunta de novo.
    Desligável, só para um endereço IPv4. No lab virtual, quem responde é o roteador do lab.
  - **HAL:** `address_states` (Linux, rtnetlink) informa DAD do IPv6 (RFC 4862: tentative,
    dadfailed) e deprecated.
  - **GUI:**
    - barra + − ✓ ✗ 💬, filtros IPv4/IPv6 e por estado, selos de estado, origem, interface e VRF,
      coluna Lifetime e rodapé com contagens;
    - clique direito com copiar como comando, duplo clique para editar, 💬 para comentar vários de
      uma vez;
    - ⓘ em cada coluna (`Column::help`, novo no `table.rs`: o clique volta em
      `TableOutput::help`) e em cada campo do modal, menos o Comment, que é óbvio (regra "Explicação
      ⓘ em todo lugar que couber"); explicações em PT e EN em `i18n/address_*.rs`;
    - ✗ e − num endereço de gerência abrem antes a janela "This change would lock you out" (Safe
      Mode ou aplicar mesmo assim).

  Como testar:
  - **Engine:** `cargo test -p corerouter-engine --test ip_address`. Cobre disable e volta, rollback
    em modo transacional e em lote atômico, cálculo, série com teto, sobreposição e VRF, edição só
    do que mudou, ARP pendente → em uso/livre, e lockout do endereço e da rede de chegada.
  - **GUI:** `cargo test -p corerouter-ui --lib tests::ip_address`.
  - **Kernel:** `cargo xtask netns` (`hal-linux/tests/netns_address.rs`: disabled sai e volta, DAD
    tentative → livre ou dad-failed, sonda ARP acha o MAC de quem tem o endereço; 1,7–2,2 s,
    **medido** em 3 execuções).

- 2026-10-23 — G2.5b: Licença dos crates do XDP (decisão do usuário, opção "c"): `crates/dataplane-ebpf`,
  `crates/dataplane-ebpf-common` e `crates/cgnat-map` passam a **GPL-2.0-or-later** (valor explícito
  no `Cargo.toml` e cabeçalho SPDX em cada arquivo); o programa declara `"GPL"` ao kernel, o que
  libera os helpers `gpl_only`, como o `bpf_fib_lookup` que o fast path do CGNAT usa para encaminhar
  no próprio XDP. O resto do projeto continua AGPL-3.0-or-later; GPL-2.0-or-later combina com ela
  (GPL-2.0-only não combinaria) e o copyleft continua. Objeto pré-compilado regerado; o teste
  `the_xdp_crates_and_object_are_gpl` (`hal-linux`) confere a string do objeto e os manifestos.
  Registro em `docs/xdp.md` § Licença e `docs/architecture.md`.

- 2026-10-23 — G2.5b: XDP, parte 2c: `dataplane-ebpf-common::nat`, a reescrita do fast path do CGNAT. Troca origem e/ou
  destino (endereço IPv4 e porta TCP/UDP) no lugar e atualiza os checksums IP e TCP/UDP de forma
  incremental, sem somar o payload: RFC 1624 Eqn 3, HC' = ~(~HC + ~m + m'), pulando a palavra que
  não mudou (errata 4782). UDP sem checksum (0, RFC 768) continua sem; um checksum calculado 0
  sai 0xFFFF. Fragmento e protocolo que não seja TCP/UDP ficam no kernel (`NotHere`). Nada é
  escrito se algum campo não couber. Ainda não é chamada pelo programa (G2.5b, próxima parte).

  Teste: exemplo da RFC 1624 §4; proptest (3000 casos) contra o recálculo completo
  (`testing::with_checksums`/`checksums_ok`): checksums válidos depois de qualquer reescrita,
  campos novos, payload intacto, ida e volta devolve o quadro original. `cargo test -p
  corerouter-dataplane-ebpf-common --test nat_props`.

- 2026-10-23 — G4.4f: Exportador para um ClickHouse externo e opcional (`docs/analytics.md`): o roteador não guarda
  nada de longo prazo, envia em lotes. Comandos `system.analytics.set|print|test|schema` (destino,
  credenciais por senha ou certificado, CA própria, o que enviar, lote, intervalo, fila em memória e
  em disco, compressão; segredos sempre `***`); serviço `analytics` do daemon sob o supervisor
  (`INSERT … FORMAT JSONEachRow` com gzip pela interface HTTP, cliente HTTP/TLS do próprio daemon
  com rustls, sem driver em C; reenvio com espera de 1 s a 60 s e sorteio, `insert_deduplication_token`
  por lote, 4xx de dado ruim descartado e contado, 401/403/404/408/429/5xx guardados; fila de
  tamanho fixo que descarta o lote mais antigo e conta, disco opcional com teto em
  `--analytics-spool`, que sobrevive a reinício); ação de log embutida `analytics` (regras do
  `/system logging` escolhem os eventos, esquema único com severidade, prioridade, tópico, origem,
  mensagem e detalhe JSON); métricas do `/metrics` a cada `metrics_interval` e o histórico de
  tráfego da G4.5 (média e máximo de cada minuto, CPU, memória, conntrack e por interface); blocos de portas do
  CGNAT (G2.3c, pelo log) e sessões NAT44 do Traffic Flow em `nat_events`; fluxos do Traffic Flow
  (G4.4b) em `flows`, com as interfaces por nome. Esquema SQL pronto (MergeTree, partição por dia, ordem por roteador e tempo, TTL, view
  `otel_logs` com os nomes do OpenTelemetry), igual ao gerado pelo roteador (teste). Janela
  System › Analytics: estado em selos, contadores, Test Connection (versão e tabelas que faltam),
  formulário com ⓘ em cada rótulo, "Add rules" para os logs e aba Schema com Copy.

  Como testar: `corerouter-cli run system.analytics.set '{"enabled": true, "url":
  "http://127.0.0.1:18123"}'`, regras `system.logging.add topics=info action=analytics`,
  `system.analytics.test`, `system.analytics.print`; com um ClickHouse de verdade sem root,
  `COREROUTER_CLICKHOUSE_URL=http://127.0.0.1:18123 cargo test -p corerouter-daemon --bin
  corerouter-daemon real_clickhouse` (docs/analytics.md §8: logs, métricas, fluxo, NAT e a view;
  TLS com CA própria e login por certificado com `COREROUTER_CLICKHOUSE_TLS_URL`), testado com o
  ClickHouse 26.9.25.15.

- 2026-10-24 — G2.5b: XDP, parte 2d: o caminho rápido do CGNAT (`docs/xdp.md` § G2.5b), desenho escolhido pelo
  usuário (offload guiado pelo conntrack).

  - **Kernel decide, XDP executa.** Os primeiros pacotes de cada conexão passam pelo nftables da
    G2.3, que escolhe a porta na faixa determinística; o serviço novo `xdp-nat` do daemon ouve o
    conntrack (NEW/UPDATE/DESTROY) e instala os dois sentidos de cada conexão IPv4 TCP/UDP com NAT
    já `ASSURED` (TCP `established`) no mapa `NAT_FLOWS`; tira quando o conntrack a destrói ou o
    TCP sai de `established`; relê a tabela depois de eventos perdidos ou de um mapa novo; renova
    a cada 2 s o timeout do conntrack das conexões que o XDP carregou (`IPCTNL_MSG_CT_NEW` com
    `CTA_TIMEOUT`, o valor do kernel para o estado).
  - **No XDP** (`dataplane-ebpf-common::fastnat`), depois do filtro: fluxo conhecido, sem VLAN,
    sem opções IP, sem SYN/FIN/RST, TTL > 1 → `bpf_fib_lookup`; se resolver, reescrita com
    checksum incremental (RFC 1624), TTL − 1, MACs da FIB e `bpf_redirect`; senão, intacto para o
    kernel, com o motivo contado em `NAT_MISS`. Motivo novo de contador `fast-nat`.
  - **Comando** `ip.firewall.xdp.set fast_nat` (avisos: sem pool de CGNAT, menos de duas
    interfaces com XDP); `print` com `fast_nat_flows`, `fast_nat_misses` e o estado do serviço;
    `interface.list` com `fast_nat_pps`. Mapa preallocado só com o caminho rápido ligado (ligar ou
    desligar recarrega o objeto). Até 262 144 conexões.
  - **Janela** IP › Firewall XDP: "CGNAT Fast Path" no Filtro (ⓘ PT/EN), conexões carregadas,
    sentidos, timeouts renovados, "Enviado ao kernel" por motivo, coluna Fast NAT pps.
  - **Verificador:** offsets constantes no caminho rápido (IP em 14, transporte em 34): o
    verificador recusava aritmética de pacote com o offset do `IpInfo` copiado pela pilha; o
    `IpInfo::v4_offsets` dá limites visíveis (máscaras identidade, provadas por proptest).
  - **Testes:** proptest no host dos dois sentidos de uma conexão contra o quadro já traduzido
    (byte a byte, TTL − 1, checksums), do que fica no kernel e da política (`xdp_nat::Book`:
    ciclo de vida, limite, releitura, renovação); engine (opção e avisos); UI; no CI com root:
    tradução e encaminhamento dos dois sentidos por três namespaces sem NAT no kernel, e de ponta
    a ponta com SNAT do nftables, eventos do conntrack instalando o fluxo, renovação aceita e a
    conexão morta saindo do mapa.

- 2026-10-24 — G4.3b: BNG, parte RADIUS: crate novo `crates/proto-radius` (L2, Rust puro, sans-IO, sem `unsafe`),
  desenho e pesquisa em `docs/radius.md`.

  - **Codec** zero cópia (RFC 2865/2866/2869/3162/6911/6929): `Packet::parse` valida tudo uma vez,
    iteradores sem alocação, VSA com vários sub-atributos (RFC 4679), atributos estendidos e longos
    com fragmentação; Message-Authenticator, User-Password, sal (Tunnel-Password, MS-MPPE), CHAP,
    MS-CHAPv1/v2 e chaves MPPE (RFC 2759/3079), Error-Cause (RFC 5176).
  - **Dicionário** tipado (RFC 8044) com padrão, Microsoft, DSL Forum, MikroTik, Juniper/ERX
    (só leitura), Ascend e Redback; estendível com texto de dicionário do FreeRADIUS.
  - **`Mikrotik-Rate-Limit`** (`rate_limit::RateLimit`), o mesmo tipo do `rate-limit` do perfil PPP.
  - **Cliente:** Access/Accounting/Status-Server, retransmissão da RFC 5080 §2.2.1 (recuo e
    dispersão), failover, servidor morto com Status-Server ou `dead-time`, 256 identificadores por
    socket e mais sockets sob carga, Message-Authenticator exigido por padrão (Blast-RADIUS),
    Acct-Delay-Time por tentativa, interim novo substitui o pendente, interims com dispersão.
  - **CoA/DM (RFC 5176):** lista de fontes com segredo por fonte, janela de Event-Timestamp de 300 s,
    cache de duplicados, seletor de sessão, prechecks com Error-Cause, Authorize Only (trocar IP por
    CoA, o que o RouterOS não faz); o daemon aplica de forma atômica e responde ACK/NAK.
  - **Servidor de teste** em Rust puro (PAP/CHAP/MS-CHAPv1/v2, atrasos e perdas programados) para o
    laboratório em massa do G4.3d.
  - **Testes:** exemplos da RFC 2865 §7 (com as erratas 1469 e 6486), RFC 5997 §6, RFC 2759 §9 e
    RFC 3079 §3.5.3 como testes dourados; proptest em tudo; alvo de fuzz `radius`; cliente contra o
    servidor de teste (12 cenários); UDP real em 127.0.0.1; simulação de 100 000 Access-Requests e
    100 000 interims com 3 % de perda e o servidor primário morto por um minuto, conferindo a cada
    datagrama que nenhum identificador se repete enquanto pendente e que retransmissões são
    idênticas (**medido**: 233 243 datagramas, 30 199 retransmissões, 3 034 failovers, 17 timeouts,
    4 s em debug).

  Como testar: `cargo test -p corerouter-proto-radius` e
  `cargo bench -p corerouter-proto-radius --bench radius`.

- 2026-10-24 — processo: Teste instável `corerouter-control conn::tests::deadline_bounds_the_total_not_each_read`: o limite
  de 900 ms estourou num runner do CI carregado (2026-10-24, branch da G2.5b, TRY 2 FAIL). Agora o
  limite é 1600 ms, ainda bem abaixo dos 2 s em que o alimentador mantém cada leitura viva, então o
  teste continua provando que o prazo vale para o total, não para cada leitura.

- 2026-10-24 — processo: Teste que precisa de root (`cargo xtask xdp-root`): o usuário roda na máquina dele, num namespace
  descartável, e o `sudo` pede a senha dele. A receita está em `AGENTS.md`, "Acesso root e testes de
  rede". O agente continua sem `sudo`. Uma rodada local leva segundos; um `workflow_dispatch` no
  runner leva cerca de 15 min (**medido**, 2026-10-24). A saída local traz o `Verifier output`
  inteiro, que o log do CI corta. A primeira rodada local mostrou que o verificador aceita o
  programa da G2.5b e isolou a única falha restante (`perf_fast_nat`).

- 2026-10-24 — G4.3a: BNG, parte PPPoE/PPP: crate novo `crates/proto-pppoe` (L2, Rust puro, sans-IO, sem `unsafe`,
  compila para wasm), desenho, pesquisa e a tabela das RFCs em `docs/pppoe.md`. A linha PPPoE/IPoE
  de `docs/architecture.md` §1.4 passa de "orquestrar accel-ppp" para Rust puro.

  - **Codecs** zero cópia e à prova de entrada hostil: Ethernet com QinQ; Discovery com todas as
    tags (RFC 2516, PPP-Max-Payload da RFC 4638, Agent-Circuit-Id/Remote-Id da RFC 4679, PADM/PADN);
    sessão e campo Protocol; LCP com todas as opções (multilink só leitura); PAP, CHAP-MD5,
    MS-CHAPv1/v2 (o cálculo e as chaves MPPE vêm do `proto-radius`, aresta lateral nova em
    `xtask/src/layers.rs`); IPCP com DNS/NBNS e IPv6CP.
  - **Autômato** da RFC 1661 §4 célula a célula, com Max-Configure/Terminate/Failure e restart de 3 s
    (§4.6); a lógica de opções por camada (LCP com as recusas da RFC 2516 §7, IPCP, IPv6CP).
  - **Servidor BNG sans-IO** (`Server`): AC-Cookie HMAC-SHA-256 com segredo rotativo, `padi_limit`
    global e por MAC, `pado_delay`, política de Service-Name, `max_sessions`,
    `one_session_per_host`, faixa de VLAN, SIDs num slab com fila FIFO, roda de timers, autenticação e
    endereço pedidos ao chamador por evento (`Authenticate`/`NeedAddress` → `auth_reply`/
    `address_reply`), keepalive, PADT para sessão desconhecida (limitado). `SessionDescriptor` com
    os nomes do mapa da G4.3c e o `RateLimit` do `proto-radius`.
  - **Cliente** (`Client`, o gerador de carga) e **laboratório** (`lab`): N clientes × servidores
    com relógio falso, perda, duplicação, reordenação, latência de RADIUS e pool.
  - **Testes**: 105 de unidade (regra por regra, citando a seção; amostras das RFC 2759 §9.2,
    RFC 2433 B, RFC 3079 §3.5.3), 9 simulações (100 mil sessões em Opened numa rede com perda; 5 %
    de perda/duplicação e 10 % de reordenação; MS-CHAPv2 + IPv6CP em 5000; flood de 200 mil PADIs;
    100 mil PADRs forjados; replay de cookie; 10 % de senha errada em 10 mil; apagão de 60 s com 20
    mil; reboot de 5000 CPEs), 8 propriedades de fuzz (bytes aleatórios, quadros reais mutados,
    conversa viva com edições em voo) e os alvos libFuzzer em `crates/proto-pppoe/fuzz`.
  - **A simulação achou e corrigiu dez defeitos** que os testes por regra não pegavam (lista em
    `docs/pppoe.md` §5): Ack duplicado renegociando, reautenticação depois de renegociar, Success e
    Ack perdidos, Challenge duplicado e reordenado, PADR duplicado atrasado, PADT perdido, timer de
    echo sobrando depois do LCP cair.

  Como testar: `cargo test -p corerouter-proto-pppoe` (≈ 40 s; a de 100 mil sessões leva ≈ 39 s em
  debug, **medido**); `SIM_N=20000 cargo test -p corerouter-proto-pppoe --test sim hundred` para uma
  rodada menor; `PPPOE_FUZZ_CASES=20000 cargo test -p corerouter-proto-pppoe --test fuzz`;
  `cargo bench -p corerouter-proto-pppoe --bench pppoe`.

- 2026-10-24 — G4.3c: BNG, parte plano de dados: o tráfego dos assinantes PPPoE passa pelo programa XDP da G2.5, sem
  `/dev/ppp` e sem uma interface por sessão (`docs/pppoe-dataplane.md`).

  - **Mapas de sessão** (`dataplane-ebpf-common::pppoe`): `Session` e `SessionKey` `#[repr(C)]`
    com codificação explícita para o daemon (G4.3d) preencher; chave de subida (porta, VLAN externa
    e interna, SID, MAC do cliente), descida por IPv4 exato e por /64 ou prefixo delegado (LPM).
  - **Subida** na porta de acesso: RFC 2516 (VER/TYPE, CODE, LENGTH), campo de protocolo pela
    RFC 1661 (controle e descoberta intactos para o userspace), sessão e MAC conferidos (SID forjado
    descartado), anti-spoofing de origem (IPv4 do IPCP, /64, prefixo delegado; link-local IPv6 para
    o userspace), policer de upload, decapsulação (`bpf_xdp_adjust_head`), depois o filtro da G2.5a,
    o fast path do CGNAT da G2.5b e a FIB (`F_FAST_UP`) ou o kernel.
  - **Descida**: pacote para um assinante (`F_FAST_DOWN`, ou fluxo do CGNAT já aceito pelo
    conntrack) ganha TTL − 1, cabeçalhos Ethernet, VLAN e PPPoE e sai pela porta de acesso; hairpin
    entre assinantes; TTL ≤ 1, maior que o MTU da sessão (RFC 1191/8201/4638), sessão lenta ou uplink
    com VLAN vão para o kernel.
  - **Policer** (`dataplane-ebpf-common::policer`) com a semântica do `rate-limit` do RouterOS:
    taxa, `burst-rate`, `burst-threshold` e `burst-time` (média em 16 fatias).
  - **Contadores** por sessão (bytes e pacotes por sentido, descartes por motivo; adição atômica
    BPF) e globais por motivo (`PPPOE_STATS`).
  - **Carregador** (`hal-linux/src/xdp_pppoe.rs`): `XdpState::set_pppoe`, `pppoe_upsert`,
    `pppoe_remove`, `pppoe_counters`, `pppoe_stats`; as sessões voltam sozinhas depois de um
    reload; mapas com 1 entrada enquanto o PPPoE está desligado.
  - O programa virou estágios em funções BPF separadas (a pilha de 512 bytes estourava inline).
  - Testes: `dataplane-ebpf-common/tests/pppoe_props.rs` (proptest: ruído, ida e volta, cortes,
    padding, spoofing, protocolo, caminho lento, limites do policer) e, com root, o diferencial
    kernel × host de 6000 quadros byte a byte, tráfego real nos dois sentidos, 100 mil sessões,
    precisão do policer (1, 100 e 10 mil assinantes, ±5%) e kpps (`xdp_root.rs`, `pppoe_*`).
  - 11 blocos `unsafe` novos, listados em `docs/xdp.md` para revisão humana.

  Como testar: `cargo test -p corerouter-dataplane-ebpf-common`; com root,
  `COREROUTER_REQUIRE_XDP=1 COREROUTER_XDP_TESTS=pppoe_kernel_and_host_agree,pppoe_traffic_both_ways,pppoe_scale_100k_sessions,pppoe_policer_accuracy,perf_pppoe_forward cargo xtask xdp-root`.

- 2026-10-24 — G4.3j: RADIUS como serviço do sistema, parte 1 (configuração e comandos): `radius.add/set/remove/enable/disable/move/list` com os nomes do RouterOS v7 (`address`, `service`, `secret`, `authentication-port` 1812, `accounting-port` 1813, `timeout` 1100 ms, `src-address`, `vrf`, `require-message-auth=yes-for-request-resp`, `protocol`, `realm`, `called-id`, `domain`, `accounting-backup`) e `status_server` (sonda RFC 5997, além do RouterOS); `radius.incoming.set/get` com a porta 3799 da RFC 5176 por padrão (o RouterOS usa 1700) e `accept=no`; `radius.monitor`; `radius.test` (tarefa: Access-Request de teste e a resposta decodificada); `ppp.aaa.set/get` (`use-radius`, `accounting`, `interim-update`, `interim_jitter`, `use-circuit-id-in-nas-port-id`, `enable-ipv6-accounting`). Recusa segredo vazio, `src_address` que não é do roteador ou de outra família, o mesmo servidor duas vezes para o mesmo serviço, RadSec (G4.3ba) e `interim_update` abaixo de 60 s (RFC 2869 §5.16). O segredo só se escreve: `radius.list` mostra `***` e o journal o mascara. Tópico de log `radius` novo. Teste: `cargo test -p corerouter-engine radius ppp_aaa`; `corerouter-cli run radius.add '{"address":"10.0.0.1","service":"ppp","secret":"x"}'` e `run radius.list`.

- 2026-10-24 — G4.3j: RADIUS como serviço do sistema, parte 2 (serviço AAA no daemon): o serviço `radius` (`apps/corerouter-daemon/src/service/radius.rs` e o driver `radius_aaa.rs`) põe o `proto-radius` na rede. Uma pista por serviço (ppp, login…) com as entradas na ordem do failover; sockets UDP do `src_address`/VRF, mais um quando os 256 identificadores acabam (até 16 por servidor), buffer de recepção de 4 MiB; estado por servidor (`up`, `down`, `probing` com Status-Server); config nova sem perder pedido pendente. API sem async para o PPP (G4.3d), IPoE (G4.3f) e login: `authenticate(pedido, callback)` e `account(pedido, fonte de contadores)` com interims agendados e dispersos por sessão. CoA/Disconnect com as entradas do `/radius` como lista de origens, janela de replay, cache de retransmissão, donos de sessão registráveis (`register_owner`) e NAK 503 sem dono. Log em português no tópico `radius`. `radius.test` espera o serviço carregar um servidor recém-criado. Testes: 9 de serviço contra o servidor de teste em UDP (failover, retransmissão, timeout, 10 000 autenticações, contabilização, dispersão de 10 000 interims, CoA aceito/retransmitido/velho/desconhecido/sem dono, recarga) e 2 de ponta a ponta no daemon. Teste: `cargo test -p corerouter-daemon radius`. Detalhes em `docs/radius.md`.

- 2026-10-24 — G4.3j: RADIUS como serviço do sistema, parte 3 (janela): grupo RADIUS no menu com a janela de três abas. Servers no padrão de lista G0.24 com o modal alimentado por `radius.preview` (nova consulta: posição no failover, retransmissão, avisos), segredo digitado oculto (`Input::Secret` novo no modal) e nunca mostrado na prévia dos comandos (`list::steps_text` passa pelo `redact`), e o botão **Test…** (Access-Request de teste com a resposta decodificada). Incoming com a porta 3799 e a nota do 1700 do MikroTik; Monitor ao vivo. ⓘ em português em todo rótulo. Conferido na GUI de verdade contra o daemon e um servidor RADIUS independente em Python (assinaturas e Message-Authenticator calculados por outro código): screenshots das três abas e do Test. Teste: `cargo test -p corerouter-ui radius`.

- 2026-10-24 — fix-main-pppoe-policer: `main` vermelha (issue #202). Dois testes corrigidos:
  - `pppoe_policer_accuracy` (G4.3c) media o limite do remetente, não o policer. No runner de 4 vCPUs, o AF_PACKET oferece ~1,5 Gbit/s, abaixo dos 100 × 20 Mbit/s configurados (−26%). Agora cada caso mede antes o que o remetente oferece e limita a taxa a um terço do que cada assinante recebe. A referência passou a ser por assinante: quem o policer cortou tem de receber a taxa com ±5% (tolerância mantida); quem ele não cortou tem de receber exatamente o que ofereceu. Ninguém pode passar do limite, e ao menos 90% dos assinantes têm de ser cortados (para o caso testar o policer).
  - `netns_capture` `frames_both_ways_with_their_wire_length`, que é instável: até o linkwatch ver a portadora, o veth recém-ligado fica com a `noop_qdisc`, que descarta os quadros enviados. O teste agora espera o `state UP` dos dois lados, via netlink (`ip -o link`). Passou 5 vezes seguidas.

- 2026-10-24 — G4.3d: BNG, parte 1 (modelo e comandos, com os nomes do RouterOS v7): `interface.pppoe-server.server.*`
  (add/set/remove/enable/disable/list e `interface.pppoe-server.monitor`), `ppp.profile.*` (com os
  perfis embutidos `default` e `default-encryption`), `ppp.secret.*` (senha só de escrita, `***` e
  mascarada no journal), `ppp.active.list/remove`, `ppp.why {name|mac}` e `ppp.history`, lidos do
  serviço do daemon por `PppBackend` (`crates/engine/src/ppp.rs`). Padrões do RouterOS mais os
  seguros: `one_session_per_host=yes`, `ac_cookie=yes`, `padi_limit` 2000/s, `mac_padi_limit` 1/s,
  `new_session_rate` 2000/s e `pado_delay_by_load`. `on_up`/`on_down` são listas de comandos do
  motor (validados ao gravar, com `$user`, `$remote-address`…), não scripts. Mudar a interface,
  VLAN ou Service-Name, desligar ou remover um servidor com sessões ativas é recusado com "drops N
  active session(s)" até `force=yes`. Precedência secret > perfil > `default-profile` > `default`
  em `Ppp::effective`. Desenho do serviço e pesquisa em `docs/pppoe.md` §8. Testar: `cargo test -p
  corerouter-engine ppp_`; `corerouter-cli run interface.pppoe-server.server.add
  '{"interface":"ether2"}'`. Lote atômico de 10 mil `ppp.secret.add`: 0,47 s em debug (**medido**).

- 2026-10-24 — G4.8a: System › Resources, parte 1 (coletores e comandos). `Hal::resource_sampler` (padrão: nenhum)
  entrega um amostrador que vive fora do `Hal`, para o daemon ler `/proc` e `/sys` sem segurar o
  lock da sessão. No Linux (`hal-linux/src/resource.rs`, sem root nem `unsafe`): tempos de CPU por
  núcleo, memória e swap, PSI (`/proc/pressure/{cpu,memory,io}`), loadavg, softirqs e interrupções
  por CPU, discos (`/proc/mounts` + `statvfs`, `/proc/diskstats`), sensores hwmon com `max`/`crit`
  (limites absurdos como `temp2_max = 65261 °C` de NVMe descartados) e o `critical` da zona
  térmica, contadores de rede, `oom_kill`, conntrack e, sob demanda, os processos. O laboratório
  virtual inventa valores plausíveis que se movem (16 CPUs, 8 portas, uma com cabo ruim).
  Comandos: `system.resource.print` (nomes do RouterOS: `cpu-load`, `free-memory`,
  `free-hdd-space`, `write-sect-since-reboot`… em snake_case, mais PSI, discos, temperatura e
  histórico de 10 min para sparklines), `system.resource.cpu.print` (carga por núcleo com
  irq/softirq e taxa de NET_RX por CPU), `system.resource.process.print` (como `/tool profile`,
  ordenável), `system.resource.network.print` (taxas, erros e descartes por interface) e
  `system.health.print` (sensores com limites e estado ok/warning/error). Testes: parsers com
  arquivos reais de um AMD Ryzen AI Max+ 395 (NVMe, r8169, mt7925) em
  `crates/hal-linux/tests/fixtures/resource`, todo truncamento dos arquivos, proptest com lixo,
  comandos de sucesso e de erro de validação. Como testar:
  `cargo run -p corerouter-cli -- run system.resource.print`, `… run system.resource.process.print '{"sort":"memory","limit":5}'`.

- 2026-10-24 — G4.8a: System › Resources, parte 2 (serviço e verificações). Serviço `health` do daemon
  (`service/health.rs`, sob o supervisor): lê a máquina a cada 5 s, a cada 1 s enquanto alguém
  olha (janela, leitura na barra ou comando nos últimos 15 s), com amostrador próprio e **fora**
  do lock da sessão; sob o lock só entrega a leitura (`Session::resource_ingest`) e julga as
  verificações. `system.health.check`: 12 verificações com severidade
  (`ok`/`warning`/`error`/`unknown`), valor, motivo e ação em português e chave estável em inglês:
  CPU sustentada (média de 5 min), pressão de memória (PSI, ou % em uso sem PSI), swap (uso e
  leitura do swap), disco, temperatura perto do crítico, erros e descartes de NIC subindo,
  conntrack, portas do CGNAT, OOM kills na última hora, NTP, serviços supervisionados e
  desequilíbrio de RSS (uma CPU com mais da metade dos softirqs de recepção). Alertas: a mudança
  de estado de uma verificação (mantida por duas leituras) vai ao log do roteador uma vez, tópicos
  `system` + nível, origem `health` — o caminho dos alertas de banda do G4.5, que as regras de
  logging levam ao syslog e ao ClickHouse. Testes: regras por tabela (34 casos), comando no
  laboratório, alerta registrado uma vez, e2e no daemon real (`tests/health.rs`). Como testar:
  `cargo run -p corerouter-daemon -- --control 7979` e
  `cargo run -p corerouter-cli -- --connect 127.0.0.1:7979 run system.health.check`.

- 2026-10-24 — G4.8a: System › Resources, parte 3 (janela e barra superior). Painel `crates/ui/src/resources.rs`,
  abas Overview (cartões de CPU, memória, disco e temperatura com sparkline de 5 min, mini-tabela
  de interfaces com selo de link e de erros, verificações de saúde com selo ok/aviso/erro e o
  motivo em português, a ação no tooltip), CPU (barras por núcleo: usuário, sistema, irq,
  softirq, e a fatia de softirq de recepção de cada CPU), Memory (uso, PSI de memória, CPU e E/S,
  maiores processos), Disk, Network (taxas, erros e descartes por segundo), Sensors (todo sensor
  com max/crit e estado), Processes (ordenável pelo roteador) e OS Log (marcador até a G4.8b).
  Cabeçalho com o selo de saúde, identidade, commit e uptime. ⓘ em português em toda aba,
  cartão, coluna e verificação (`i18n/auto/resources_*.rs`), entrada no menu System com
  sinônimos. Barra superior: selo de saúde sempre (consulta a cada 5 s sem acelerar o serviço;
  clique abre a janela) e, ligada em Settings › Top bar (desligada por padrão), a CPU e a memória
  **do roteador** ao lado da troca de tema, a 1 Hz só enquanto ligada. A janela consulta a 1 Hz
  só aberta. A parte esquerda da barra agora é cortada quando falta largura, em vez de passar por
  cima da direita. Como testar: abra System › Resources (ou clique no selo de saúde no canto
  superior direito) e Settings › Top bar › Show the router's CPU and memory. Screenshots nos dois
  temas conferidos.

- 2026-10-24 — G4.8b: Log do sistema operacional (System › OS Log). `crates/hal/src/oslog.rs`: a linha (RFC 5424
  0–7, origem kernel/services/auth, unidade, dispositivo, PID, boot), parsers de `/dev/kmsg` e de
  `journalctl -o json` tratando a entrada como hostil (tetos, sem controle nem bidi, `\xNN`,
  UTF-8 inválido, cursor seguro), `Hal::os_log` (padrão: nenhum) e as linhas inventadas do lab.
  `crates/hal-linux/src/oslog.rs`: kmsg non-blocking (EAGAIN/EPIPE, perdas contadas) com a hora
  por `CLOCK_BOOTTIME` e o journal por `journalctl` com cursor, sem shell, teto de linhas e bytes,
  prazo, grupo de processo morto e colhido; fonte ilegível diz por quê. Engine: `OsLogBook` (anel de
  20 000 linhas, repetição = mesma origem/unidade/nível/texto sem os números em 10 min, a linha
  conta e vai para o fim), catálogo de dados `oslog_known.rs` (anel da placa cheio → Tuning da
  porta e gráfico; TX timeout; LACP; link flap; conntrack cheio; vizinhos; SYN flood; martian; OOM;
  disco; MCE; temperatura; lockup; segfault; login recusado; callbacks suppressed), comandos
  `log.os.print {since, level, source, find, limit}` e `log.os.known`. Daemon: serviço `os-log`
  (`--os-log host|lab|off`; padrão `host` com `--backend linux`, `lab` no virtual) lê kmsg a cada
  1 s e o journal a cada 2 s fora do lock e entrega em lote; mensagem conhecida que custa tráfego
  ou hardware vai uma vez ao Log do roteador (`system,error`). GUI: `crates/ui/src/os_log.rs`
  (selos de nível com contagem, de origem, busca, estado das fontes, tabela virtualizada com selo
  `37×` e o da mensagem conhecida, detalhe com "repetido 37× em 9 min", "O que significa" e os
  botões que abrem a janela — Tuning já na aba Interfaces da porta), ⓘ em português em tudo,
  `os_log::tab(app, ui)` para o G4.8a. Testes: fixtures sintéticas no formato real (kmsg com
  dicionário e journal JSON, nenhum dado de máquina), linhas truncadas e estranhas, um teste
  `#[ignore]` que lê o journal local à mão, proptest, alvo de fuzz `oslog`, tabela do catálogo, repetições,
  100 mil linhas no anel e na tabela, e2e do daemon (lab e host), headless da GUI. Pesquisa em
  `docs/os-log.md`. Como testar: `cargo run -p corerouter-cli -- run log.os.print '{"level":"warning"}'`;
  `corerouter-daemon --control 7979 --os-log host` e na GUI System › OS Log.

- 2026-10-25 — G0.26: Laboratório em VM com root para agentes: `cargo xtask vm-lab <create|up|down|status|ssh|sync|put|run|snapshot|reset|destroy>` (`xtask/src/vm_lab.rs`, `docs/vm-lab.md`). A VM `corerouter-lab` (libvirt `qemu:///system`, sem `sudo` no host) sobe de uma imagem Ubuntu 24.04 cloud baixada uma vez e conferida com o `SHA256SUMS` publicado, com overlay qcow2 fino de 20 GiB, 8 vCPUs e 16 GiB, CPU `host-model` (o `host-passthrough` expunha o CET do host e, depois de ~45 min, todo processo da VM caía por shadow stack, **medido**), `spec_rstack_overflow=off` no convidado (sem ele o SRSO "Safe RET" deixava a VM 3× mais lenta, **medido**), kernel HWE 7.0, pacotes de teste (clang, llvm, tcpdump, ppp, pppoe, ethtool, nftables…) e rustup em `/opt/rust`. Gerência na rede `default` NAT que já existia; enlaces de teste são pares de NICs virtio ligados por UDP no loopback do host (`wire0a` ↔ `wire0b`), sem bridge nem iptables novos. `run -- <cmd>` copia a worktree (rsync, sem `target*`/`.git`) e roda como root com cache de build por worktree, uma rodada por vez (trava na VM; `--shared` para só compilar), depois de um health-check que faz `reset` sozinho se a VM estiver quebrada. Testar: `cargo xtask vm-lab create`, depois `cargo xtask vm-lab run -- env COREROUTER_REQUIRE_XDP=1 cargo xtask xdp-root`. Validado: os 13 testes do `xdp-root` passam na VM; `auto` vira `native` no `virtio_net` (`ip.firewall.xdp.interface.list` com `active: native`, `ip link` mostra `xdp`). Achado: o kernel 6.8 (Ubuntu 24.04 GA) recusa o programa XDP no verificador ("combined stack size of 3 calls is 544. Too large", **medido**); a VM usa o HWE 7.0.

- 2026-10-25 — G4.3d: BNG, parte 2 (o serviço `pppoe` do daemon). O núcleo `service/pppoe_bng.rs` não faz E/S: recebe os
  quadros e devolve quadros e efeitos. Ele faz quatro coisas:

  - dirige um `proto_pppoe::Server` por `/interface pppoe-server server`;
  - autentica pelo `/ppp secret` (caller-id, service, disabled, only-one, limit-bytes) ou pelo
    RADIUS da G4.3j (Framed-IP-Address, Framed-Pool, Mikrotik-Rate-Limit, Mikrotik-Group,
    Session-Timeout, Acct-Interim-Interval, MS-CHAP2-Success, Reply-Message);
  - dá o endereço por um alocador próprio sobre o `/ip pool`, com `next_pool`;
  - mantém o que `ppp.active`, `ppp.why` e `ppp.history` leem.

  O driver `service/pppoe.rs` abre as portas de acesso por AF_PACKET (`hal-linux::pppoe_io`): um
  socket por VLAN do `pppoe-over-vlan-range`, cada um com um filtro BPF clássico. Assim a tag que o
  kernel tira volta sem `PACKET_AUXDATA` e sem `unsafe`. O driver nunca segura o lock da sessão na
  rede.

  **Plano de dados:**

  - **Com XDP** nas portas (`ip.firewall.xdp`): cada sessão vai para o mapa da G4.3c pelos métodos
    novos do `Hal` (`pppoe_dataplane`, `pppoe_apply`, `pppoe_counters`). O rate-limit vai em
    termos do RouterOS para o policer, a descida com `F_FAST_DOWN` e os contadores alimentam os
    interims.
  - **Sem XDP:** o caminho lento carrega o IPv4: subida por socket raw com anti-spoofing, descida
    por rotas /32 num dummy `bng0`.

  **O resto do serviço:**

  - Contabilização Start/Interim/Stop com Acct-Terminate-Cause (RFC 2866 §5.10).
  - Dono de CoA/DM (RFC 5176): rate-limit ao vivo, Disconnect, Framed-IP = reconectar; atributo
    não suportado dá NAK 401, valor ruim NAK 407.
  - `idle_timeout` e `limit_bytes_*` pelos contadores; `address_list` como entrada dinâmica;
    `on_up`/`on_down` como comandos.
  - `new_session_rate` gasto no PADI: no PADR o AC-Cookie venceria durante o recuo do CPE.
  - Logs em português (tópico novo `ppp`).
  - `ppp.active.remove` aceita `server=` e listas grandes.
  - **Sem O(n) por sessão**, achado e corrigido pela G4.3g no laboratório: um índice dos secrets
    por nome (refeito quando a lista muda) e o `SubIndex` (por MAC, por endereço e por id, conferido
    em `Bng::check()`). De 19 → 181 µs para 12–16 µs por sessão. O CI do lote chegava a 45
    sessões/s com a busca linear.
  - **O teste em namespace usa 2 mil sessões no CI** e 10 mil+ no laboratório
    (`COREROUTER_PPPOE_E2E_SESSIONS`). Os prazos crescem com o tamanho, o limite da reconexão é
    `n/10` por segundo e as verificações são as mesmas.
  - **Os 226 s fixos da reconexão em massa** (achado pela G4.3e e pela fila) vinham do CPE simulado.
    O cliente do `proto-pppoe` retransmitia o PADI com recuo determinístico (1, 2, 4, 8 s), então
    10 mil CPEs reiniciados juntos tentavam em ondas sincronizadas a cada 8 s. O balde do
    `new_session_rate` guarda 1 s de fichas: só passava `rate` por onda, e o keepalive de 60 s
    derrubava parte das sessões velhas antes da troca. O cliente ganhou `discovery_jitter_pct`
    (0 por padrão, como o pppd; ±25% no gerador de carga). Medido com 2 mil (200/s) e com 10 mil
    (1000/s): 21 s nos dois casos, todas as sessões velhas trocadas (**medido**, debug, veth).

  - `proto-pppoe`: `Server::reconfigure`, para mudanças que valem para sessões novas sem derrubar
    as que existem.

  **Como testar:**

  ```sh
  cargo test -p corerouter-daemon pppoe_bng
  COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
      cargo test -p corerouter-daemon --test netns_pppoe -- --test-threads 1 --nocapture
  ```

  - `pppoe_bng`: 1, 100 e 10 mil sessões em memória, senha errada explicada pelo Why, pool
    cheio, CoA, reconexão em massa de 2000 CPEs, only-one/caller-id/disabled, caminho lento,
    RADIUS com Accounting.
  - `netns_pppoe`: daemon real, veth, 1/100/10 mil sessões, ping ida e volta, terminate,
    reconexão em massa de 10 mil, usuário RADIUS no servidor de teste.
  - O mapa XDP fica no `xdp_root.rs` (`pppoe_bng_ops_reach_the_maps`, rodada com root).

- 2026-10-25 — G4.3d: BNG, parte 3 (a janela PPP, `crates/ui/src/ppp.rs`). O grupo PPP fica no menu logo depois de
  Interfaces, como no RouterOS, e a janela tem as abas do WinBox:

  - **Interface:** o serviço de relance (rodando, plano de dados XDP ou caminho lento, sessões,
    contadores do Discovery, segurados pelos limites).
  - **PPPoE Servers**, **Secrets** e **Profiles**, no padrão de lista G0.24. O modal é alimentado
    pelos comandos novos `interface.pppoe-server.server.preview`, `ppp.secret.preview` e
    `ppp.profile.preview` (o `add`/`set` tentado no candidato e desfeito, com o que o login ou o
    perfil recebe).
  - **Active Connections:** selo de identidade, `R` do RADIUS, rate-limit em selo colorido por
    chave, Rx/Tx, VLAN e Circuit ID; ações Disconnect, Torch (na porta de acesso, filtrando o
    endereço) e Why?.
  - **AAA** (`/ppp aaa`), **RADIUS** (abre a janela RADIUS) e **History** (filtros up/failed/ended).

  O que mais a janela traz:

  - **Why?** mostra as etapas PADI > PADR > LCP > Auth > NCP > Up com as tentativas, o motivo da
    última queda em português e a Reply-Message do RADIUS.
  - **Mudança que derruba sessões:** pela barra, o recusado "drops N active session(s)" vira uma
    pergunta com "Aplicar mesmo assim" e "Entrar em Safe Mode"; no modal, é o `risk` da
    pré-visualização.
  - **ⓘ em toda aba, coluna e campo**, explicações em português (`i18n/auto/ppp_*.rs`, 95 chaves
    conferidas por teste).

  O serviço passa a contar as recusas locais em `auth_reject`. Testar:
  `cargo test -p corerouter-ui tests::ppp`. As capturas foram feitas com o daemon e 43 CPEs reais
  num namespace, a GUI em Xvfb.

- 2026-10-25 — G4.3d: BNG, parte 4 (os extras aprovados):

  - **Identidade e "Quem era?" do CGNAT com o login.** A fonte `pppoe` do `ip.identity.lookup`
    (G0.25) responde pelo serviço: agora, pelas sessões ativas; num instante passado, pelo
    histórico do serviço. Então CGNAT › Quem era? diz o login de quem tinha o endereço. Clicar no
    selo abre PPP › Active Connections com a sessão selecionada.
  - **Gráfico por assinante:** o serviço mede rx/tx em bits/s a cada segundo (`rx_bps`, `tx_bps`
    no `ppp.active.list`). A tabela Active Connections ganha a coluna Traffic, um gráfico de linha
    por sessão desde que a janela abriu. O histórico longo por assinante é a G4.3o.
  - **Aviso de inadimplência por address-list.** O sistema de cobrança manda um CoA com
    `Mikrotik-Address-List=inadimplentes`, e o endereço do assinante entra na lista na hora, sem
    derrubar a sessão; um valor inválido responde NAK 407. A regra de dstnat para a página de aviso
    é a receita de `docs/pppoe.md` §8.6. No login, o `Mikrotik-Address-List` do Access-Accept e o
    `address_list` do perfil fazem o mesmo.
  - **Address-list em massa sem travar:** cada `ip.firewall.address-list.add` dinâmico copiava
    todas as entradas e rodava a checagem de perda de acesso, num processo `nft` por entrada, e cada
    remoção reconstruía o índice. Com o `address_list` no perfil, 10 mil logins chegavam a só 300 em
    5 min. Agora o serviço aplica as entradas de cada rodada de uma vez: `Session::ppp_address_lists`,
    com `Hal::address_list_dynamic_many` (método novo com padrão; no Linux, um `nft` só) e
    `DynamicLists::remove_many` (um reindex só). Resultado: 10 mil sessões em 6,9 s e reconexão em
    massa de 10 mil em 18 s, em debug, com a address-list (**medido**).
  - **Falha antes do login entra no Why? pelo MAC:** LCP que não fecha, tempo de setup, o CPE
    recusando todos os métodos de autenticação (`auth-protocol`, com a dica certa).
  - **Teste em namespace:** a entrada da address-list aparece com a sessão e sai com ela, e o selo
    de identidade dá `pppoe`/`u0`.

- 2026-10-25 — G4.3d: BNG: o teste de root `pppoe_bng_ops_reach_the_maps` (xdp_root.rs) passa a rodar no
  `cargo xtask xdp-root`; antes ficava fora da lista e não rodava em lugar nenhum. Ele confere o
  caminho do serviço `pppoe` até o mapa XDP: `pppoe_ready` recusa porta sem XDP, o `Upsert` com o
  rate-limit do RouterOS no policer, os contadores e a remoção. Rodado com root na VM do G0.26 (XDP
  nativo, 2026-10-25): passa sozinho em 0,6 s.

  Achado na rodada completa da VM: o `pppoe_policer_accuracy` (G4.3c) às vezes deixa o namespace
  `crxsub` inválido ("setting the network namespace failed: Invalid argument") na etapa de 10 mil
  assinantes, e os testes seguintes que usam o `crxsub` caem em cascata. Isolado, ele passa (erro
  máximo de −2,78% com 10 mil assinantes, **medido**).

- 2026-10-25 — G4.3e: BNG dual-stack, parte a (codecs, sem mudança de comportamento no serviço). `proto-pppoe::nd`: o
  IPv6 de um enlace PPP do lado do concentrador — link-local do IPv6CP (RFC 5072 §5), identificador
  estável e opaco (RFC 8064 com o algoritmo da RFC 7217, fora dos reservados da RFC 5453), leitura
  de RS/NS/Echo e DHCPv6 com as validações da RFC 4861 §6.1.1/§7.1.1 e o checksum da RFC 8200 §8.1,
  o RA da sessão com PIO, MTU, RDNSS e DNSSL (RFC 8106) e os tempos do RA (RFC 4861 §6.2.4/§6.2.6).
  O servidor do PPPoE ganha `ServerConfig::ipv6_iid_key`: com ela o IPv6CP usa e sugere
  identificadores estáveis por linha (porta, VLANs, MAC), e `Server::set_ipv6` dá o `use-ipv6` do
  perfil por sessão (`Off`: o IPv6CP do CPE recebe Protocol-Reject; `Require`: a falha do IPv6CP
  derruba a sessão). A simulação de 100 mil sessões passa a ser dual-stack (IPv6CP em todas, com o
  identificador sugerido pelo BNG, um por assinante). `proto-dhcp::sub6`: o DHCPv6 de uma sessão
  (RFC 9915 §16 e §18.3: Solicit/Advertise, Rapid Commit, Request, Renew/Rebind com o que não é da
  sessão zerado, Release, Decline, Confirm, Information-request; T1/T2 de §21.4), sem tabela nem
  diário — o prefixo é da sessão. Pesquisa (MikroTik v7, accel-ppp, Junos, IOS-XE, TR-187, RFCs) em
  `docs/pppoe.md` §9.

  Testar: `cargo test -p corerouter-proto-pppoe nd` e `rfc8064`, `cargo test -p corerouter-proto-dhcp sub6`
  (proptest de bytes hostis e mensagens mutadas), `cargo test -p corerouter-proto-pppoe --test fuzz`
  (`nd_*`, `ra_built_from_any_config_reads_back`); alvo libFuzzer `nd` em `crates/proto-pppoe/fuzz`.

- 2026-10-25 — processo: `AGENTS.md`: análise de desempenho e paralelismo passa a ser **obrigatória** em toda feature,
  correção e revisão (pedido do usuário, 2026-10-25). O PR responde onde está o trabalho por item,
  se ele cresce com o total, se várias threads ou núcleos ajudam e por quê, e mede quando houver
  dúvida. Ganho mensurável em caminho quente entra no mesmo trabalho, e não como gap. A revisão
  procura sempre:
  - custo O(n) escondido;
  - trabalho preso num núcleo;
  - lock disputado;
  - fila sem limite.

  Origem: o laboratório do BNG (G4.3g) mostrou o plano de controle PPPoE num núcleo a 98%.

- 2026-10-25 — G0.26: Correção do `cargo xtask vm-lab tools`. Quando só faltavam pacotes apt (o `iperf3`), o script mandava uma lista de hashes vazia ao `sha256sum -c`, que falha ("no properly formatted checksum lines found", **medido**). Agora o script é montado por `vm_tools::install_script` (com testes): o `sha256sum` só entra quando há `.deb`, e os hashes vão por heredoc. `snapshot`, `reset` e `tools` também aceitam rodar dentro do `flock vm/root.lock` do próprio usuário: a trava de um processo ancestral conta como dele. O `status` mostra se a VM está ociosa ("rounds"). Testar: `cargo xtask vm-lab status` e `cargo xtask vm-lab tools --check`.

- 2026-10-25 — G0.26: Laboratório em VM, ferramentas de terceiros: `cargo xtask vm-lab tools` instala na VM as ferramentas declaradas em `xtask/src/vm_tools.rs` (hoje: BNG Blaster 1.0.1, o `.deb` do release oficial da rtbrick com SHA-256 fixado e igual ao `digest` do GitHub, e `ppp`, `pppoe`, `tcpdump`, `iperf3` e `ethtool` do arquivo do Ubuntu). O comando baixa uma vez para `vm/tools/`, confere o hash no host e na VM, instala num `apt-get install` só, imprime as versões e tira o snapshot `tools`, para o qual `reset` passa a voltar por padrão. `tools --check` só confere e diz ao agente o que pedir ao usuário. Instalar código de terceiros é do usuário, uma vez por ferramenta (o classificador do app bloqueia o agente; o nosso código roda sem perguntar). `snapshot` e `reset` recusam enquanto há rodada (trava do `run` na VM ou `vm/root.lock` do usuário no host); `--force` passa por cima. Testar: `cargo xtask vm-lab tools --check`.

- 2026-10-25 — G4.1c: Teste instável `nsupdate_changes_the_zone` (`netns_dns_ddns`) corrigido no servidor: um UPDATE
  (RFC 2136) que chegava entre o `dns-server` abrir a porta 53 e o supervisor iniciar o serviço
  `dns-zones` levava NOTIMP sem TSIG ("expected a TSIG or SIG(0)"), enquanto a zona já respondia
  com AA; um `nsupdate` ou o DDNS de um servidor DHCP nessa janela falhava de vez (NOTIMP é "não
  implementado", RFC 2136 §2.2). Agora o servidor do daemon nasce com o serviço de zonas acoplado
  (`dns_server::make` → `dns_zones::attach`), antes de qualquer socket: o UPDATE é atendido desde o
  primeiro pacote, e a thread `dns-zones` só faz o trabalho periódico (NOTIFY, secundárias, DNSSEC).
  Teste de regressão `the_daemons_server_takes_updates_before_the_zone_thread` (UPDATE assinado pelo
  servidor recém-montado, sem a thread de zonas: NOERROR assinado; com a montagem antiga, NOTIMP).
  Reproduzido antes (**medido**, 2026-10-25): 2 falhas em 30 execuções, 10 em paralelo, cada uma
  no seu namespace, com os 32 núcleos ocupados; depois: 0 em 60 nas mesmas condições.

- 2026-10-25 — G4.3e: BNG dual-stack, parte b (o serviço `pppoe`, empilhada sobre a parte a e o #216). O perfil PPP ganha
  `use_ipv6`, `remote_ipv6_prefix_pool`, `dhcpv6_pd_pool`, `dhcpv6_lease_time` e `dns_server_ipv6`
  (nomes do RouterOS; o último é nosso). Quando o IPv6CP abre, a sessão recebe o /64 e o prefixo
  delegado. A origem é, em ordem: `Framed-IPv6-Prefix`/`Delegated-IPv6-Prefix` do RADIUS, os pools
  do RADIUS (`Framed-IPv6-Pool`, `Delegated-IPv6-Prefix-Pool`, `Mikrotik-Delegated-IPv6-Pool`), os
  pools do perfil. A sessão também recebe o RA (PIO, MTU, RDNSS), a resposta a RS/NS/Echo e o DHCPv6
  da sessão (IA_PD e IA_NA = /64 + identificador do IPv6CP).

  O XDP recebe o /64 e o PD (`PppoeSession::{ipv6_prefix, delegated}` no HAL; as estruturas da G4.3c
  já tinham as chaves). O Accounting-Start/Interim/Stop leva `Framed-IPv6-Prefix`,
  `Delegated-IPv6-Prefix` e `Framed-Interface-Id`; o serviço RADIUS passa a codificar `ipv6prefix` e
  `ifid`. `ppp.active.list` ganha `ipv6_prefix`, `delegated_prefix`, `delegated_bound` e
  `link_local`; `interface.pppoe-server.monitor` ganha `ipv6_sessions`, `delegated` e `ipv6_dropped`.
  O segredo do identificador estável (RFC 8064) fica em `<config-dir>/pppoe-ipv6cp.key`. Uma sessão
  sem IPv4 agora espera o IPv6CP (assinante só IPv6) antes de cair.

  Testar:

  - `cargo test -p corerouter-daemon --bin corerouter-daemon pppoe_bng`: 1000 sessões dual-stack em
    memória, RA periódico, `use_ipv6=no`, prefixos do RADIUS na contabilização.
  - `cargo test -p corerouter-engine ppp_profile`.
  - `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-daemon --test netns_pppoe6 -- --test-threads 1`:
    10 mil CPEs dual-stack por veth.
  - `xdp_root` › `pppoe_bng_ops_reach_the_maps`: IPv6 do /64 e do PD passa, de outro prefixo é
    falsificado; roda no runner com root.

- 2026-10-25 — G4.3e: BNG dual-stack, parte c: a janela PPP.

  - **Active Connections:** colunas `IPv6 Prefix` (o /64 do RA) e `Delegated Prefix` (o PD), com o
    selo `bound` (o DHCPv6 do CPE pegou) ou `reserved` (guardado para a sessão).
  - **Profiles:** a coluna `IPv6` resume o `use_ipv6` e os pools (`/64 wan6 · PD pd6`). O modal ganha
    `Use IPv6`, `Remote IPv6 Prefix Pool`, `DHCPv6 PD Pool`, `DHCPv6 Lease Time` e `IPv6 DNS Server`.
  - **Interface:** o monitor ganha a linha IPv6 (sessões, delegados, recusados).
  - Todos os rótulos novos têm ⓘ em português e inglês.
  - O teste `cpe_lab6` (`#[ignore]`, em `netns_pppoe6`) monta um laboratório dual-stack para capturas.

  Testar:

  - `cargo test -p corerouter-ui ppp`;
  - para olhar: `cpe_lab6` num namespace, e a GUI com `--connect 127.0.0.1:7979` e
    `COREROUTER_RUNTIME_DIR` apontando para a pasta do laboratório.

- 2026-10-25 — G4.3f: IPoE, parte 1 (modelo, comandos e a autorização no servidor DHCP). O servidor DHCPv4 puro
  (`proto-dhcp`) ganha um portão: num servidor com `ipoe=yes` ou `use_radius=yes`, o DISCOVER (ou o
  REQUEST de quem não tem concessão) de cada cliente vira `Effect::Authorize` com o MAC, o client id
  e a opção 82 (circuit e remote id, RFC 3046), e a mensagem espera o veredito
  (`Server::authorized`). O Accept escolhe o endereço (Framed-IP-Address, nunca o de outro
  cliente), o pool (Framed-Pool), o tempo do lease (Session-Timeout, como o RouterOS) e address
  lists; o Reject não oferece nada (o REQUEST recebe NAK) e o cliente fica 30 s sem ser perguntado
  de novo; sem resposta em 15 s o pedido é esquecido; no máximo 8192 esperando. `Server::revoke`
  encerra os leases e tira a concessão (o Disconnect da parte 2).

  Comandos: `ip.dhcp-server.add/set` com `use_radius=no|yes|accounting` (RouterOS),
  `ipoe=yes`, `ipoe_username=mac|circuit-id|remote-id|circuit-remote` e `ipoe_unknown=accept|reject`;
  `ip.dhcp-server.lease.add/set rate_limit=10M/50M` (sintaxe do RouterOS); `ppp.secret` com
  `service=ipoe` (sem senha; `service=any` não casa IPoE). Avisos: `use_radius` sem `/radius
  service=dhcp`, `ipoe_unknown=reject` sem nenhum secret IPoE, `ipoe_username` por opção 82 num
  link sem `relay_info_trusted`, `rate_limit` fora de um servidor IPoE. O engine
  (`engine/src/ipoe.rs`) decide pela lista local quando não há o serviço do daemon (o laboratório
  virtual serve IPoE sozinho) e junta as sessões IPoE às do PPP em `ppp.active`/`ppp.why`/`ppp.history`
  (`Session::set_ipoe_sessions`). Pesquisa em `docs/pppoe.md` §10.

  Como testar: `cargo test -p corerouter-proto-dhcp --lib server::tests` (portão: espera, concessão,
  reject lembrado, tempo esgotado, opção 82, revoke) e `cargo test -p corerouter-engine --test ipoe`
  (os hosts do laboratório: só o do secret recebe endereço, o endereço fixo do secret; depois
  `ipoe_unknown=accept` serve todos).

  Desempenho: as decisões IPoE leem `/ppp secret service=ipoe` e os `rate_limit` dos leases estáticos
  por um índice refeito a cada revisão da config (`IpoeIndex`, O(1) por lease; antes, uma varredura
  dos secrets por DISCOVER). E o limitador por cliente do servidor DHCP (G4.2a), com a tabela cheia
  (65 536 clientes), varria a tabela inteira a cada cliente novo e recusava os que não cabiam: numa
  tempestade de 100 000 CPEs depois de uma queda de energia, 34 464 ficavam sem endereço e cada um
  custava O(65 536). Agora a varredura é no máximo a cada 250 ms e o cliente que não cabe é servido
  sem balde (`untracked`, contado): a tabela continua limitada, e um limite por MAC não freia mesmo
  uma enxurrada de MACs aleatórios.

- 2026-10-25 — G4.3f: IPoE, parte 2 (plano de dados XDP). Os assinantes IPoE entram nos mesmos mapas do PPPoE (G4.3c),
  de forma aditiva: flag `F_IPOE`, chave porta + MAC com SESSION_ID 0 (nunca o de uma sessão PPPoE,
  RFC 2516 §5), mapa novo `IPOE_PORTS` e o bit 1 do `SETTINGS` dos assinantes. Subida: DHCP passa ao
  daemon, MAC desconhecido segue como sem IPoE, a origem tem de ser o endereço da sessão (TR-146
  R-38, senão `spoofed`), policer e contadores, quadro intacto. Descida: policer e contadores e o
  kernel encaminha (o firewall continua vendo); o CGNAT rápido sai pelo XDP com os MACs reescritos.
  HAL: `Hal::ipoe_dataplane(on, ports)`, `PppoeSession.ipoe`, `pppoe_io::port_info`; o carregador
  recusa IPoE com SID ≠ 0 ou tag e PPPoE com SID 0. Detalhes em `docs/pppoe-dataplane.md` (IPoE).

  Como testar: `cargo test -p corerouter-dataplane-ebpf-common --all-features --test ipoe_props`
  (amarração, DHCP, estranhos, outra porta, policer nos dois sentidos, CGNAT, ruído em proptest) e,
  com root, `cargo xtask xdp-root` › `ipoe_kernel_and_host_agree` (agora na lista do `xdp-root`):
  os quadros IPoE no programa do kernel (`BPF_PROG_TEST_RUN`) e no modelo do host, ação e bytes
  iguais, e o ns/pacote de subida e descida. Rodado na VM `corerouter-lab` (G0.26, kernel 7.0): o
  verificador aceita, 1944 quadros iguais (263 spoofed descartados).

- 2026-10-25 — G4.3f: IPoE, parte 3 (o serviço `ipoe` do daemon). O dono das sessões que os leases DHCP viram
  (`service/ipoe.rs` e o núcleo sem E/S `service/ipoe_bng.rs`): autoriza pela lista local ou pelo
  RADIUS `service=dhcp` (User-Name = `ipoe_username`, senha vazia como o RouterOS, NAS-Port-Type
  Ethernet, a opção 82 em ADSL-Agent-Circuit-Id/Remote-Id da RFC 4679); a sessão nasce no ACK com a
  taxa do RADIUS, do lease estático ou do perfil; contabilização Start/Interim/Stop com Class e
  Acct-Terminate-Cause; `ppp.active.remove` e o Disconnect-Request encerram o lease (o CPE recomeça
  autorizado); CoA muda a taxa do policer na hora; o XDP da parte 2 ligado nas portas IPoE (sem
  XDP, a sessão existe sem policer e a linha do serviço diz por quê); keepalive por ARP opcional
  (`ipoe_keepalive`, TR-146 R-92); "Why?" com os estágios `dhcp`/`auth`/`up` e o motivo. As sessões
  aparecem em `ppp.active`, `ppp.why` e `ppp.history` com `service=ipoe`.

  Como testar: `cargo test -p corerouter-daemon --bin corerouter-daemon ipoe` (RADIUS, accounting,
  remover, CoA/DM, secrets e taxa do lease, keepalive, contra o servidor DHCP do engine e os hosts do
  laboratório) e
  `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-daemon --test netns_ipoe`
  (10 000 clientes DHCP simulados num veth, RADIUS de teste).


  Mapa XDP de sessões dividido entre os serviços: o PPPoE fica com a metade de baixo (`XDP_SLOTS`
  = 65 536 sessões no XDP; antes, o mapa inteiro) e o IPoE com a de cima, do topo para baixo; um
  teste garante que as faixas não se encontram (a G4.3g distribui os índices do PPPoE entre os
  workers abaixo de `XDP_SLOTS`).

  Desempenho: por lease, o núcleo faz a decisão local e cria a sessão em ~7–10 µs, igual com 10 000
  e 100 000 assinantes (`benches/ipoe_bng.rs`): os secrets e o `rate_limit` do lease vêm do índice
  do engine, os perfis por nome (Mikrotik-Group) são refeitos uma vez por segundo, e o callback do
  RADIUS só interpreta a resposta e põe o veredito na fila.

- 2026-10-25 — G4.3f: IPoE, parte 4 (janela). Em PPP › Active Connections as sessões IPoE ficam com as PPPoE, com um
  selo por serviço (`ipoe`, `pppoe`), a marca R, a taxa, o circuito da opção 82 e o selo de
  identidade (o `who` das duas metades). O "Why?" de um assinante IPoE mostra DHCP › Auth › Up e o
  motivo; em Secrets, `ipoe` entra nos serviços (sem senha). Na janela DHCP Server, o formulário do
  servidor ganha Use RADIUS, IPoE Sessions, IPoE Username, IPoE Unknown Clients e IPoE Keepalive, o
  do lease ganha Rate Limit, e a lista mostra o selo `ipoe`/`ipoe radius`. Explicações ⓘ em
  português.

  Como testar: `cargo test -p corerouter-ui --lib tests::ipoe`; na GUI com o laboratório do
  `netns_ipoe` › `ipoe_lab` (40 assinantes, 2 recusados pelo RADIUS): PPP › Active Connections,
  Why? com `02:30:00:00:07:01`, IP › DHCP › Server.

- 2026-10-25 — G4.3g: BNG sem custo O(n) por sessão (achado pelo laboratório da G4.3g): na rodada de 100 mil
  sessões com o BNG Blaster o setup caía de ~9,8 mil para ~3,2 mil sessões/s e a CPU por sessão
  subia de 39 para 267 µs. Medido no `benches/pppoe_bng.rs`, por lote de 10 mil sessões sobre o
  mesmo BNG, a autenticação (CHAP Response) levava 106 dos 118 µs: o `/ppp secret` era procurado
  com `Ppp::secret`, que percorre a lista, e o usuário `userN` estava na posição N.

  - `/ppp secret` por nome num índice do BNG, refeito só quando a lista muda (`CowArc::ptr_eq`).
  - `SubIndex` ao lado das sessões: sessões no ar por endereço (a descida do caminho lento
    percorria todas as sessões **por pacote**), por login (`only-one`) e as em autenticação por
    (porta, MAC) (o `new_session_rate` no PADI). `Bng::check` confere o índice contra as sessões.
  - `interface.pppoe-server.monitor` › `dataplane` passa a dizer se as sessões estão no XDP (o
    campo existia e nunca era preenchido).

  Como testar:

  ```sh
  cargo test -p corerouter-daemon pppoe_bng
  cargo bench -p corerouter-daemon --bench pppoe_bng -- --test   # imprime µs por lote
  ```

- 2026-10-25 — G4.3g: Laboratório em massa do BNG com o BNG Blaster (rtbrick, BSD-3): `cargo xtask bng-lab`.

  - **Topologia:** o daemon real (`--backend linux`, build release) num namespace descartável;
    num segundo namespace, o BNG Blaster nas pontas dos veth das portas de acesso e da rede.
    Uma porta de acesso a cada 50 mil sessões (o SESSION_ID tem 16 bits).
  - **Sem root** (`unshare --user --map-root-user --net`): caminho lento, sem policer.
  - **Com `--root`** (`sudo ip netns add crbng`, apagado no fim): XDP nas portas e o cliente
    Linux `pppd` 2.4.9 com o plugin `pppoe.so` (rp-pppoe) e `tcpdump`. Nada toca as placas do
    host.

  **Etapas por escala** (`--scales 1000,10000,100000`):

  - setup com as proteções desligadas;
  - keepalive e tráfego de sessão mantidos por 30 s, sem queda (uma amostra de 10 mil sessões
    acima de 10 mil);
  - queda total (BNG Blaster morto, sem PADT) e reconexão em massa com as proteções padrão e
    depois sem elas;
  - encerramento por PADT.

  **Etapa RADIUS** (`--radius 100`, `proto_radius::testserver`):

  - `Mikrotik-Rate-Limit` 1M/2M e fluxos nos dois sentidos a 2× a taxa: precisão do policer;
  - CoA que sobe a taxa de um décimo dos assinantes;
  - Disconnect-Request de outro décimo com o tráfego correndo.

  **Saídas:**

  - `summary.json` (máquina) e `summary.md` (tabela);
  - relatórios e logs do BNG Blaster;
  - capturas. As capturas reais viram goldens em `crates/proto-pppoe/tests/fixtures`
    (`tests/goldens.rs`: todo quadro dos dois lados decodifica, volta aos mesmos bytes pelos
    oráculos de fuzz e cada captura tem a conversa inteira):
    - BNG Blaster 1.0.1 com CHAP: 27 quadros;
    - `pppd` 2.4.9: 73 quadros, com IPv4, LCP echo e IPv6CP recusado.

  **Como testar:**

  ```sh
  cargo test -p corerouter-proto-pppoe --test goldens
  cargo xtask bng-lab --blaster <bngblaster> --scales 1000 --only capture,scale   # sem root
  cargo xtask bng-lab --root --blaster <bngblaster>                               # tudo, pede sudo
  ```

  O BNG Blaster vem do `.deb` do release oficial (`dpkg-deb -x` basta, sem instalar).

  **Achados da primeira rodada** (corrigidos no PR anterior): setup O(n) por sessão (o secret era
  procurado na lista) e o `dataplane` do monitor nunca era preenchido.

- 2026-10-25 — G4.3g: BNG em escala, parte c (achados do laboratório):

  - **`/ppp secret` com índice por nome** (`corerouter_model::ppp_secrets::Secrets`, no lugar do
    `CowArc<Vec<PppSecret>>`):
    - `Ppp::secret` passa a ser O(1), e com isso o `ppp.secret.add` (a checagem de nome
      repetido) e o login do BNG, que agora usa o índice do modelo em vez do seu próprio.
    - O índice nasce na primeira consulta e é compartilhado pelas cópias do config; o `push` o
      mantém e qualquer outra escrita o descarta.
    - Migrar 100 mil assinantes de um RouterOS deixa de ser O(n²).
  - **"Why?" sem apagar tudo:** ao encher (agora 2 × as vagas do XDP = 262 144 chaves, duas por
    assinante), sai a chave usada há mais tempo. Antes, a tabela se apagava inteira a cada 100
    mil chaves, isto é, a cada 50 mil logins.
  - **Buffer de recepção dos sockets com rajada** (RADIUS e portas PPPoE):
    - `SO_RCVBUFFORCE` com CAP_NET_ADMIN (passa do `net.core.rmem_max`); sem ela, `SO_RCVBUF`;
    - o tamanho obtido vai para a verificação nova **Socket buffers** do
      `system.health.check` (13 verificações), que avisa quando ficou menor que o pedido e diz
      como subir.
  - **`new_session_rate=auto`:** o limite de sessões novas segue a saúde do RADIUS, como a
    janela do TCP (AIMD), medida pelo próprio BNG em cada resposta:
    - sobe 500/s a cada segundo enquanto o p90 fica em até 100 ms e há CPEs esperando, até
      20 000/s;
    - cai pela metade quando o p90 passa de 300 ms ou há timeout, até 50/s.

    `interface.pppoe-server.monitor` (`admission_rate`, `admission_reason`) e a coluna nova **New
    Sessions** da aba PPPoE Servers mostram o limite atual e o motivo ("RADIUS lento: 380 ms").
    Um número volta ao modo fixo.
  - **`ppp.active.list` sem copiar a tabela:** `PppBackend::active_page` filtra no lugar e copia só
    a página (seleção parcial, O(n)); `server.list` conta as sessões por servidor sem copiá-las.
    Com 100 mil no ar, cada atualização da GUI copiava e ordenava as 100 mil com o lock do engine.
  - **Laboratório:** etapa `wave`, a onda de 100 mil contra um RADIUS de capacidade limitada
    (`--radius-cap`, padrão 3000/s: a fila faz a latência crescer como num servidor saturado), com
    `new_session_rate` desligado, fixo em 2000 e `auto`.
  - **Callbacks do RADIUS:** conferido que o do BNG só põe a resposta na fila do BNG (canal); a
    thread do RADIUS não faz trabalho do PPPoE.

  Como testar:

  ```sh
  cargo test -p corerouter-model ppp_secrets
  cargo test -p corerouter-daemon admission_tests
  cargo test -p corerouter-engine new_session_rate_auto
  cargo test -p corerouter-engine health
  cargo bench -p corerouter-engine --bench batch_import -- ppp_secret   # imprime µs por lote de 10 mil
  ```

- 2026-10-25 — G4.3g: O plano de controle do PPPoE em vários núcleos (o laboratório mostrou uma thread a 98% e as
  outras livres).

  **Como fica:**

  - **Leitura e workers:** a thread do serviço lê as portas de acesso (e o `bng0` do caminho
    lento) e entrega cada quadro a um worker pelo MAC do cliente, como o RSS. O PADI, o PADR e a
    sessão de um CPE caem sempre no mesmo worker.
  - **Cada worker tem um `Bng`:** servidores com uma faixa (`sid_lane`) do SESSION_ID de cada
    porta, sem lock entre eles (RFC 2516 §4: único por porta); sessões, timers, perguntas ao
    RADIUS; os próprios sockets de envio (`PortSender`, `SlowTx`).
  - **Compartilhado:**
    - a tabela ativa, o histórico e os pools IPv4/IPv6, com um endereço emprestado uma vez só;
    - as vagas do XDP, intercaladas por worker.
  - **Sem lock compartilhado por quadro:** o "Why?" fica numa tabela por worker (`ppp.why` olha
    todas) e os contadores do monitor são locais, publicados uma vez por segundo.
  - **Limites repartidos:** `new_session_rate` (fixo ou auto), `padi_limit` e as faixas do
    `pado_delay_by_load` são divididos entre os workers; o `mac_padi_limit` fica, porque um MAC
    vai sempre ao mesmo worker.
  - **Pedidos por SESSION_ID:** `ppp.active.remove`, CoA e Disconnect vão ao worker dono pelo id
    (`*server-sid`), em O(1). Antes, cada id percorria todas as sessões, e derrubar N sessões
    era O(N²).
  - **Configuração:** `interface.pppoe-server.settings.set workers=auto|N`, lida quando o
    serviço começa. `auto` = CPUs − 2, no máximo 8. O monitor e o `settings.get` mostram quantos
    rodam.
  - **Caminho lento:** as rotas /32 de uma rodada saem juntas por uma conexão netlink que fica
    aberta; antes era um runtime e um socket por rota. `who(ip)` usa um índice por endereço em
    vez de percorrer a tabela ativa.
  - **Laboratório:** etapa `workers`, 100 mil com `workers=1` e com `auto`, com a CPU de cada
    thread e os quadros perdidos antes do BNG.

  **Recepção: fica o leitor único** (decisão por números, `docs/architecture.md`). O socket
  filtrado por worker (cBPF pelo hash do MAC, `SO_ATTACH_FILTER` sem
  `unsafe`) foi medido e descartado. O código e o teste dele saíram da árvore (estão no commit
  8c3859f): o teste contava também os quadros que o próprio namespace gera no veth (IPv6 ND/MLD)
  e falhou no CI do lote.

  - Num netns, ele baixou a parte serial: a thread mais ocupada passou de 550–1050 ns para
    150–350 ns por quadro.
  - Com o BNG Blaster na VM, ficou abaixo do leitor:
    - **Sem fila (rodada 4):** 22,4 mil sessões/s com 6 workers, contra 57,9 mil do leitor. Um
      socket de 4 MiB guarda 8739 PADIs, e a rajada de 100 mil chegava em 1,5 s.
    - **Com uma fila de 65 536 no worker (rodada 5):** 24,0 mil/s, sem perda, com o BNG Blaster
      a 91% de um núcleo.
    - A hipótese é retransmissão do CPE por latência, porque o worker esvazia a rajada inteira
      antes de responder. Ela está registrada, não confirmada.
  - O PACKET_FANOUT por MAC exigiria `unsafe`, e o `recvmmsg` no leitor não entrou: o leitor
    ficou a 51% de um núcleo, e não é o gargalo.

  Do trabalho do socket por worker ficou:

  - o filtro das portas descarta as cópias do que o BNG envia (`PACKET_OUTGOING`);
  - as perdas do kernel por socket (`SO_RXQ_OVFL`, API segura do nix) e as do canal saem no
    `interface.pppoe-server.monitor` (`rx_dropped`) e no laboratório.

  **Bug no cliente RADIUS:** o timer de um pedido respondido disparava no pedido seguinte do
  mesmo slot. O `seq` de cada slot recomeçava em 0 e o timer era identificado por (slot, seq).
  Com muitos logins por segundo, quase todo login saía duas vezes, 0–250 ms depois do
  original. Isso bate com as 59–93 mil retransmissões das rodadas 3 e 4. Agora o `seq` é único no
  cliente inteiro (`an_answered_request_leaves_no_timer_behind`: sem a correção, 30 de 40 logins
  iam em dobro).

  **A onda de reconexão contra um RADIUS lento** (a primeira rodada na VM, com 100 mil sessões
  contra 3000 respostas/s, deu: desligado 6039 no ar, fixo 2000 com 11 686 e auto com todas em
  517 s):

  - **O laboratório:** o servidor RADIUS de teste era um só para os três modos, com fila FIFO
    sem limite que guardava as cópias. Agora é um por modo, com fila de no máximo 2 s de trabalho
    que descarta a cópia de um pedido que já tem (RFC 5080 §2.2.2, como o FreeRADIUS).
  - **`auto` à moda do BBR:**
    - a capacidade é medida em logins respondidos por segundo (o melhor dos últimos 10 s);
    - o ritmo dobra enquanto ela cresce, depois segue o ciclo 1,25/0,9/1;
    - uma fila parada (p90 bem acima do tempo sem fila) baixa para 0,9× e um timeout para 0,75×;
    - **o limite fica nos logins, não nos PADIs:** até ~10 s de capacidade esperam no BNG (o CPE
      fica no Authenticate, onde as repetições são ignoradas) e saem conforme as respostas
      voltam, numa janela de pedidos em voo. Um PADI recusado faz o CPE recuar (RFC 2516 §5) e
      voltar tarde, e o servidor fica ocioso; era o que deixava o auto lento.
  - **Cliente RADIUS:**
    - o primeiro timeout de um pedido segue o servidor (SRTT + 4·RTTVAR, RFC 6298 §2, com as
      amostras de Karn), sem descer do IRT e no máximo MRT. Um servidor que fica lento devagar,
      como numa onda, não recebe cópias do que ainda está fazendo;
    - medir também os pedidos retransmitidos (desde a primeira cópia) foi testado e descartado:
      com 3% de perda prendia o timeout em MRT e atrasava o failover.
  - **Autenticação na frente do accounting:** com 64 ou mais logins esperando resposta numa
    lane do serviço RADIUS, os Accounting (Start, Interim, Stop) esperam, no máximo 60 s, e
    saem quando os logins diminuem. O Acct-Delay-Time conta a espera (RFC 2866 §5.2,
    `Client::accounting_at`).
    - Na segunda rodada da VM, 100 mil logins dividiam um servidor de 3000/s meio a meio com os
      próprios Starts: desligado 69 s, fixo 2000 95 s, auto 107 s, contra um teto de ~67 s.
    - Na onda, o login vem primeiro e a contabilização logo depois.
  - **Pedidos em voo pelo BDP:** a janela é a capacidade medida (só os logins respondidos, o
    máximo dos últimos 10 s) vezes o tempo de resposta sem fila (pelo menos 300 ms), 2× só na
    partida. A partida passa a 2× o que o servidor respondeu, não 2× o ritmo anterior.
    - Na terceira rodada da VM, o limite foi a 5503/s com ~1500 logins/s possíveis. A janela
      seguia esse ritmo e não a capacidade.
    - O cruzeiro já era 1,0× a capacidade (o ciclo de ganhos 1,25/0,9/1… do BBR).
  - **Janela inicial:** 64 pedidos em voo até o primeiro segundo com respostas, como a janela
    inicial do TCP e do BBR. A do ritmo inicial (1000/s × 0,6 s) fazia 2 s de fila num servidor de
    300/s, acima do timeout de 1,1 s do cliente.
  - **Login cancelado:** `AaaBackend::authenticate_until`. Quando a sessão acaba (o CPE desistiu),
    o pedido sai do cliente RADIUS e para de ser retransmitido.

  Como testar:

  ```sh
  cargo test -p corerouter-proto-pppoe sid_lanes
  cargo test -p corerouter-daemon workers_split_one_port
  cargo test -p corerouter-engine pppoe_settings
  cargo test -p corerouter-daemon --release mass_reconnect_against_a_slow_radius -- --nocapture
  cargo test -p corerouter-daemon --release --bin corerouter-daemon wave_of_the_vm_round -- --ignored --nocapture
  cargo test -p corerouter-daemon --release --bin corerouter-daemon wave_with_the_real_client -- --ignored --nocapture
  cargo test -p corerouter-daemon auto_keeps_the_real_client_from_resending
  cargo test -p corerouter-proto-radius --test client an_answered_request
  cargo test -p corerouter-daemon a_called_off_login
  cargo test -p corerouter-daemon accounting_waits_behind
  cargo test -p corerouter-proto-radius --test client slowing_server
  cargo bench -p corerouter-daemon --bench pppoe_bng -- --test     # sessões/s por número de workers
  COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-daemon --test netns_pppoe -- --test-threads 1
  ```

- 2026-10-25 — G4.3g: O relatório do PPPoE para o operador: `docs/pppoe-relatorio.md`.

  - **Conteúdo:**
    - as capacidades e cada camada de teste com os números **medidos**;
    - o laboratório com o BNG Blaster na VM corerouter-lab (8 vCPUs, 16 GiB, kernel 7.0), com o
      histórico das seis rodadas e o que cada correção mudou;
    - a comparação com o MikroTik v7, o accel-ppp/VyOS e os BNGs Juniper MX, Cisco ASR 9000 e
      Nokia 7750, com as fontes: onde estamos à frente, onde empatamos e o que falta (HA G4.3h,
      L2TP G4.3i, shaping G4.3ca, placa real G4.3cb).
  - **A rodada no hardware do usuário** fica como verificação extra.

  Também entra o workflow `.github/workflows/bng-lab.yml`, só `workflow_dispatch`, que roda
  `cargo xtask bng-lab --root` no runner do GitHub. Ele baixa o BNG Blaster 1.0.1 do release
  oficial, confere o SHA-256 e desempacota com `dpkg-deb -x`. Os números do runner (4 vCPUs) saem
  marcados como "runner do CI".

- 2026-10-25 — processo: Dois testes instáveis travavam a fila (o #227 ficou fora seis vezes):

  - **`corerouter-control` `deadline_bounds_the_total_not_each_read`.** Era um bug de verdade. No Unix, um `SO_RCVTIMEO` vencido volta como `WouldBlock` (EAGAIN), e não como `TimedOut`. O `Sock::read` do canal de controle devolvia um ou outro, conforme quem vencia antes: o prazo verificado por nós ou o do socket. Agora os dois casos saem como `TimedOut`.
  - **`service::dns::tests` (`a_silent_server_is_skipped` e os outros).** O servidor DNS de teste pegava uma porta UDP livre e tentava a mesma porta em TCP, que um teste paralelo podia estar usando (`AddrInUse`). Agora ele tenta de novo até achar uma porta livre nos dois.

- 2026-10-26 — G4.3cd: Rotas por assinante, parte 1 (modelo e comandos). Cliente empresarial com bloco roteado (/29,
  /28, /48 IPv6): o `/ppp secret` ganha `routes` com o texto do RouterOS (`dst-address gateway
  metric`, várias separadas por vírgula), em IPv4 e IPv6, e vale também para os secrets IPoE
  (`service=ipoe`). O tipo `corerouter_model::framed_route::FramedRoute` lê o mesmo texto do
  `Framed-Route` (RFC 2865 §5.22) e do `Framed-IPv6-Route` (RFC 3162 §2.5): gateway `0.0.0.0`, `::`
  ou ausente é o próprio assinante; vários métricas como no exemplo da RFC (vale a primeira);
  prefixo sem tamanho é um host (/32, /128); prefixo com bits de host (`10.0.0.1/24`) é recusado
  em vez de adivinhado.

  Recusas (`ppp.secret.add/set`), com o motivo: bloco especial (padrão, loopback, link-local,
  multicast, reservado, mais largo que /8 ou /16), sobreposição com a rota de outro secret, com um
  `/ip pool` ou `/ipv6 pool`, um bloco que contém um endereço do roteador ou o endereço fixo de outro
  secret, e gateway IPv4 diferente do endereço fixo do assinante. Avisos: gateway IPv4 sem endereço
  fixo, bloco dentro de uma rede conectada, bloco que uma sessão ativa (RADIUS) segura agora. No
  sentido contrário, `ip.pool.add/set`, `ipv6.pool.add/set` e o `remote_address` de um secret recusam
  o que cai num bloco roteado. `ppp.secret.list` mostra e procura nas rotas; `ppp.active.list` e
  `ppp.why` ganham `routes` (com a origem: secret, Framed-Route, Framed-IPv6-Route,
  Framed-IPv6-Prefix) e `refused_routes`, preenchidos pelo serviço na parte 2.

  Custo: um índice das rotas dos secrets (como o índice por nome da G4.3g) deixa a conferência em
  O(log n) por rota; `RouteSet` guarda blocos disjuntos num `BTreeMap`, e a busca do bloco que
  contém um endereço é o casamento de prefixo mais longo. 10 mil secrets com rota num lote atômico:
  o teste inteiro do `ppp_secret` roda em 0,84 s em debug (**medido**, 2026-10-26, 32 CPUs).

  Testes: `framed_route` (textos das RFCs e do RouterOS, especiais, proptest de ida e volta e do
  `RouteSet` contra uma busca linear), `ppp_secrets` (índice segue as escritas), `ppp_secret`
  (recusas, avisos, rollback, 10 mil num lote).

- 2026-10-26 — G4.3cd: Rotas por assinante, parte 2 (serviço e XDP). O BNG PPPoE pega as rotas do `routes` do secret ou
  do Access-Accept (`Framed-Route` e `Framed-IPv6-Route` repetidos, RFC 2865 §5.22 e RFC 3162 §2.5;
  o segundo `Framed-IPv6-Prefix` em diante, RFC 3162 §2.3) e as instala na subida da sessão: com XDP
  num LPM novo de descida (`PPPOE_RT4`/`PPPOE_RT6` → índice da sessão), sem XDP como rota
  `bloco dev bng0` com o caminho lento entregando ao worker certo. Um bloco tem um dono só
  (`corerouter_engine::framed::FramedTable`, compartilhada pelos workers, pelo IPoE e pelos
  comandos): bloco de outro assinante, especial, de pool ou do roteador é recusado com o motivo em
  português no log, em `ppp.active` (`refused_routes`) e no histórico. Na queda as rotas saem antes
  da sessão (sem blackhole). CoA com `Framed-Route`/`Framed-IPv6-Route` troca as rotas sem derrubar
  (o novo entra antes de o velho sair; inválido = CoA-NAK 407, nada muda). O anti-spoofing aceita
  origem dentro de um bloco da própria sessão (XDP, IPoE no XDP e caminho lento). Accounting
  Start/Stop com as rotas.

  XDP: descida rápida num uplink com uma ou duas tags (antes `down-tagged` ia ao kernel); a decisão
  virou `pppoe::to_subscriber`, a mesma função no programa e no modelo de teste; contadores novos
  `down-tagged` (agora encapsulado no XDP) e `down-routed`.

  Testes: `framed` (engine), `pppoe_routes_tests` (BNG em memória: secret no caminho lento, RADIUS no
  LPM com dois assinantes disputando um bloco, CoA trocando e recusando), `radius_aaa_tests` (Accept
  com `Framed-Route` repetido pelo `proto_radius::testserver` real em UDP, CoA com rotas e NAK 407),
  `pppoe_routes` (proptest do programa inteiro: bloco, uplink com tags, anti-spoofing),
  `netns_pppoe_routes` (e2e sem root: um host do /29 pinga pelo assinante certo, o outro não vê, e
  depois do logout a rota some do kernel), `xdp_root` › `pppoe_routes_kernel_and_host_agree` e
  `perf_pppoe_routes_10k` (na VM, com root).

- 2026-10-26 — G4.3h: BNG em alta disponibilidade, parte a: o crate L2 `corerouter-proto-ha`, sans-IO e compilável para
  WASM. Máquina de papéis (init, standby, active, fenced, yielding) com cerca por maioria de três
  (este nó, o par e uma testemunha), dois caminhos para ouvir o par (o stream de sync e um hello
  autenticado no L2 de acesso, que também é o MAC update gratuito do MAC virtual) e eleição que não
  cruza visões (encarnação, `hears`, `view_seq`/`acked`); sync hot-standby da tabela de sessões
  (snapshot, deltas com sequência, ack em lote, resync depois de um buraco, log limitado); registro
  da sessão em TLV (SID, MACs, os dois Magic-Numbers, MRU, IPCP/IPv6CP, prefixos, RADIUS, Class,
  Acct-Session-Id, contadores) compatível entre versões; switchover e "simular falha". Pesquisa
  (Cisco SRG, Nokia MC-Sync/SRRP, Juniper, MikroTik, accel-ppp, RFC 2516/1661/2866/2865/5798) e
  desenho em `docs/bng-ha.md`.

  Como testar: `cargo test -p corerouter-proto-ha` (27 de unidade, 11 simulações, 4 proptests);
  `HA_SIM_SEEDS=2000 cargo test --release -p corerouter-proto-ha --test sim` (2000 sementes de falhas
  aleatórias, nunca dois ativos que se ouvem; **medido** 34 s); `cargo bench -p corerouter-proto-ha
  --bench ha`. Na simulação com 100 mil sessões, a morte do ativo vira troca em 1175 ms (morte 1200
  ms) com 0 sessões perdidas (**medido**, relógio simulado).

- 2026-10-26 — G4.3h: BNG em alta disponibilidade, parte b: o modelo `ppp.redundancy` (`crates/model/src/ppp_redundancy.rs`)
  e os comandos `ppp.redundancy.set/get/monitor/switchover/simulate-failure`. O `set` recusa par
  inseguro com o parâmetro culpado: habilitar sem `peer`, sem `secret` de 16+ caracteres ou, com
  `fencing` que usa testemunha, sem `witness`; `dead_interval` menor que 3 × `hello_interval`;
  MAC virtual multicast; testemunha que não é IP; interface inexistente. Avisa quando: não há
  servidor PPPoE, o MAC virtual não é administrado localmente, `fencing=witness` está sozinho,
  o modo é stateless ou o `dead_interval` é curto. O `secret` só se escreve: `get` mostra `***`
  e o journal o mascara. `monitor`, `switchover` e `simulate-failure` falam com o serviço por
  `HaBackend` (`crates/engine/src/ppp_redundancy.rs`); sem o serviço, o monitor diz
  `running: false` e as ações explicam por que não rodam.

  Como testar: `cargo test -p corerouter-engine ppp_redundancy`;
  `corerouter-cli run ppp.redundancy.set '{"peer":"10.0.0.2:8730","secret":"segredo-do-par-123","witness":["10.0.0.254"],"enabled":true}'`.

- 2026-10-26 — G4.3h: BNG em alta disponibilidade, parte c: o serviço `ppp-ha` do daemon. Ele leva o link de sync em
  TLS na `listen_port` (o certificado do roteador, fixado no primeiro uso, e só um link por par: o
  nó de id menor disca) e o hello de acesso por `AF_PACKET` (0x88b5, do MAC virtual enquanto ativo),
  via `hal-linux::ha_io`. Sonda a testemunha por ICMP e confere as portas do `track`.
  `ppp.redundancy.monitor`, `switchover` e `simulate-failure` funcionam no daemon. O
  `proto_ha::node::Node` junta papéis, sync, hellos e a autenticação mútua do link (desafio e
  prova HMAC com o segredo do par); o laboratório em memória roda o mesmo código. O
  `pppoe` ainda não consulta o papel: vem no PR d.

  Como testar: `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p
  corerouter-daemon --test netns_ha -- --test-threads 1 --nocapture` (dois daemons, sem root):
  par formado em 762 ms, switchover em 53 ms, failover após matar o ativo em 1,16 s, nó isolado
  cercado (**medido**, debug).

- 2026-10-26 — G4.3k: PPPoE com vários Service-Names numa porta, parte 1: a tabela de Service-Names do servidor, como
  os `service-name-tables` do Junos (`docs/pppoe.md` §11). Cada linha tem nome, perfil, ação
  (`terminate`, `delay`, `drop`), `pado_delay`, `max_sessions` e `padi_limit`, mais as linhas fixas
  `empty` e `any`. Os comandos são `interface.pppoe-server.server.add/set services=[…]` e
  `interface.pppoe-server.server.service.add/set/remove/list`. Uma config só com `service_name`
  (RouterOS) vale como a tabela que quer dizer e é gravada como tabela na primeira mudança. O AC do
  `proto-pppoe` segue a RFC 2516: o PADO ecoa o nome (§5.2), `drop` não responde (§5.2), o PADR
  recebe Service-Name-Error com SID 0 (§5.4) e AC-System-Error quando a linha está cheia. O perfil
  da linha vale no PADR. O nome fica por sessão (`ppp.active.list` › `service_name`) e vai ao
  RADIUS como Called-Station-Id.

  Como testar: `cargo test -p corerouter-proto-pppoe` (regras da RFC, proptest da tabela,
  simulação de 20 mil assinantes com 40 nomes sobre 5000 VLANs QinQ) e `cargo test -p
  corerouter-engine ppp_pppoe`. Pela CLI:
  `interface.pppoe-server.server.service.add {"server":"pppoe-ether2","name":"iptv","profile":"tv"}`.

- 2026-10-26 — G4.3k: PPPoE com vários Service-Names numa porta, parte 2: a tabela de Service-Names na aba PPPoE
  Servers da janela PPP, embaixo da lista de servidores (a do servidor selecionado, senão a do
  primeiro). Uma linha por nome, mais `empty name` e `other names` em selos. Selos coloridos por
  ação (`terminate` verde, `delay 300 ms` âmbar, `drop` vermelho, linha apagada) e o perfil num selo
  com cor por hash. O modal de adicionar e editar passa pela prévia do engine
  (`interface.pppoe-server.server.service.preview`: nomes atendidos e descartados, o que recebem o
  nome vazio e os outros, e os avisos). As linhas aceitam `id` = `<servidor>/<nome>`. A coluna
  Service de Active Connections mostra o nome pedido ao lado do selo `pppoe`. O ⓘ de cada coluna e
  campo está em português.

  Como testar: `cargo test -p corerouter-ui ppp` (`the_service_name_table_under_the_servers`) ou
  PPP › PPPoE Servers na GUI.

- 2026-10-26 — G4.9a: Filas (G4.9), parte 1: modelo e comandos. Controle de banda genérico por alvo (endereço, prefixo ou
  interface), não só PPPoE: decisão do usuário em 2026-10-26.

  - `queue.simple.add/set/remove/enable/disable/move/list` com `target`, `max-limit`, `limit-at`,
    `burst-limit/threshold/time`, `bucket-size`, `priority`, `queue` e `comment`, em pares
    `upload/download` do ponto de vista do alvo, como o RouterOS. Primeira-que-casa: um alvo dentro do
    alvo de uma fila acima não é instalado e a fila é avisada.
  - `queue.type.add/set/remove/list`: `pfifo`, `bfifo`, `pcq` (taxa, classificador, máscaras v4/v6,
    limites, burst), `fq-codel`, `cake`; os tipos do RouterOS existem sem entrada, mais
    `fq-codel-default` (padrão das filas dinâmicas) e `cake-default`.
  - `queue.per-ip.add/list`: "cada IP de 10.0.0.0/16 com 10M/20M" vira dois tipos `pcq` (reaproveitados
    entre regras de mesma taxa) e uma simple queue, o mesmo que uma importação do MikroTik produz.
  - Filas dinâmicas (selo D e origem): sessões PPPoE/IPoE com `rate-limit`, leases estáticos com
    `rate_limit` e, novidade, `rate_limit` na rede do DHCP (`ip.dhcp-server.network.*`) para todo
    cliente dela. Dinâmica vence fixa no próprio endereço, com aviso nos dois lados.
  - Perfil PPP: `queue_type` (tipo da fila de descida) e `download_mode` (`shaper`, o padrão, ou
    `policer`, com aviso).
  - O plano de dados (shaper EDT, policer sem corrida) é a G4.9b; a janela, a G4.9c.

  Testar: `cargo test -p corerouter-engine queue` (comandos, rollback, plano com 100 mil sessões) e
  `cargo test -p corerouter-engine --test queue` (leases reais do servidor DHCP viram filas dinâmicas).

- 2026-10-26 — G4.3ca: PPPoE: entrega pelo kernel ao assinante. Com o PPPoE no XDP ligado, o carregador cria `bng0` e põe
  nele o programa `bng_egress`; cada sessão PPPoE ganha rotas (/32, /64, prefixo delegado) por
  `bng0` com o MTU da sessão. O que o XDP manda ao kernel no sentido de descida (sessão sem fast down,
  TTL, MTU, descida moldada) chega ao assinante encapsulado; o ICMP do roteador também ("fragmentation
  needed" com o MTU da rota, RFC 1191; time exceeded). Teste com root
  `pppoe_kernel_delivery_through_bng0` (datagrama, ICMP 11, PMTU 1400, sessão moldada a 5 Mbit/s:
  200 de 200 entregues espalhados em 227 ms). O shaping é o EDT da G4.9b.

- 2026-10-26 — G4.3cc: PPPoE: policer sem corrida entre CPUs. O balde virou GCRA (ITU-T I.371): o estado exato é o tempo
  teórico de chegada, uma palavra de 64 bits em ticks de 1/64 ns, trocada com `cmpxchg`; as 16 fatias
  da janela de burst do RouterOS somam com adição atômica e só a CPU que ganha a troca do início da
  janela limpa as fatias velhas. Quatro trocas perdidas seguidas descartam o pacote. `bpf_spin_lock`
  foi descartado (nenhum helper com ele preso, mapa com BTF, um lock por assinante serializando as
  CPUs), e prender o assinante numa CPU (cpumap) não foi preciso: o erro já é zero. Medido com o mesmo
  teste antes (`main`) e depois: 4 CPUs +4,87% → −0,22%; 8 CPUs +14,87% → −0,42%; 16 remetentes em
  8 CPUs +14,97% → −0,35%. Proptest `policer_exact_under_races` simula até 16 CPUs intercaladas.

- 2026-10-26 — G4.3h: BNG em alta disponibilidade, parte e1: `proto_pppoe::server::ha`. `Server::export_all` e
  `Server::import` levam uma sessão estabelecida de um servidor para outro já em Opened no LCP, no
  IPCP e no IPv6CP, sem renegociar e sem mandar nada. Ficam o SID, o par de MACs, os dois
  Magic-Numbers (RFC 1661 §6.4), o MRU, o endereço, o DNS, os identificadores IPv6CP, o
  rate-limit e o resto do Session-Timeout. `Fsm::opened` é o autômato já aberto. A lista de SIDs
  livres é refeita uma vez por lote (O(n)).

  Como testar: `cargo test -p corerouter-proto-pppoe --test ha`. 1000 assinantes passam para
  servidores novos e ficam 2 min de keepalive de pé, sem relogar; o export do novo é idêntico ao
  do antigo; com 5 % de perda depois da tomada, as sessões aguentam.

- 2026-10-26 — G4.3h: BNG em alta disponibilidade: o `SessionRecord` do `proto-ha` agora leva tudo o que o outro nó
  precisa para reconstruir a sessão. Campos novos: pools do /64 e do prefixo delegado, DNS IPv6,
  NBNS, rotas (G4.3cd), `limit-bytes-in/out` e o perfil da linha de Service-Name. A chave de
  replicação usa o nome do servidor PPPoE no lugar do índice da porta, que muda entre as duas
  máquinas. Os tipos novos (26 a 32) são TLV: um nó antigo os guarda e reescreve.

  Como testar: `cargo test -p corerouter-proto-ha` e `HA_FUZZ_CASES=30000 cargo test --release
  -p corerouter-proto-ha --test fuzz`.

- 2026-10-26 — G4.3h: BNG em alta disponibilidade, parte f: a aba **PPP › Redundancy**. À esquerda fica
  `ppp.redundancy.set/get`, com o segredo só de escrita; o Apply manda só o que mudou. À direita, o
  par ao vivo pelo `ppp.redundancy.monitor`:
  - o papel em selo colorido e a época;
  - o par e os dois caminhos (sync e acesso);
  - a testemunha;
  - o sync N/N com pendentes e atraso;
  - a divergência de config;
  - as trocas de papel com o motivo.

  Os botões Switchover e Simulate Failure pedem confirmação. Todo rótulo leva ⓘ em português
  (`i18n/auto/ppp_ha_*.rs`). A aba é o módulo `crates/ui/src/ppp_redundancy.rs`; no `ppp.rs`
  entraram só a aba e o roteamento.

  Como testar: `cargo test -p corerouter-ui ppp_redundancy`; na GUI, PPP › Redundancy com dois
  daemons em par (o script do teste `netns_ha`). As capturas, com daemons reais (switchover, falha
  simulada e volta como standby), estão nos temas escuro e claro.

- 2026-10-26 — G4.9b: Filas (G4.9), parte 2: o plano de dados.

  - **Descida moldada (EDT):** o programa tc `shape_egress` dá a cada pacote para um alvo (sessão
    moldada, fila por prefixo ou por interface) o horário de saída, e o `fq` (`mq` + um por fila de
    transmissão, instalado pelo carregador) o segura. O que esperaria demais é descartado antes de
    entrar: `pfifo`/`bfifo` pelo limite, `fq-codel`/`cake` pelo CoDel (RFC 8289) na espera prevista,
    com ECN só em pacote ECN-capaz.
  - **Subida policiada:** `shape_ingress` (filas) e o policer do XDP (sessões) com balde de
    `bucket-size × taxa` (0,1 = 100 ms, antes 50 ms) e a rajada do RouterOS.
  - **Relógios sem corrida** (G4.3cc): GCRA e EDT numa palavra com `cmpxchg` (ISA v3 do BPF).
  - **PCQ:** sub-fluxo por endereço mascarado (LRU), limitado também pelo relógio da fila.
  - **Sessões:** `download_mode=shaper` (padrão) liga `F_SHAPE_DOWN`; a descida vai pelo kernel e
    por `bng0` (G4.3ca) até a fila da porta de acesso. Active Connections ganha `queue_us` e `drops`.
  - **Daemon:** serviço `queue` (um plano por segundo quando muda, contadores de volta para
    `queue.simple.list`); `hal::queue::ShaperPlan` e `Hal::shaper_apply/shaper_status`.
  - Testes: proptests do shaper e do policer (limites, corrida de 1 a 16 "CPUs", média de longo prazo
    da rajada do RouterOS), `shaper_root.rs` (carga, precisão a 1/100/10 mil alvos, TCP com shaper ×
    policer, EDT × HTB a 1 mil e 10 mil), `policer_race_root.rs` e `xdp_root.rs`
    (`pppoe_kernel_delivery_through_bng0`), rodados como root na VM do laboratório.

  Testar: `cargo test -p corerouter-dataplane-ebpf-common`; com root (VM):
  `cargo xtask vm-lab run -- env COREROUTER_REQUIRE_XDP=1 cargo xtask xdp-root`.

- 2026-10-26 — G0.21: Config grande, parte a: os benchmarks que faltavam para a G4.3gb (`ppp.secret.add` com 100 mil
  secrets), a G0.21 (add numa address-list de 60 mil) e a G0.22 (commit com 10 mil rotas e uma
  mudança fora delas), com a linha de base da `main`. Nada muda no comportamento.

  - `cargo bench -p corerouter-engine --bench config_store` (novo): `ppp.secret.add` sozinho, em lote
    não atômico (cada passo faz commit) e em lote atômico, e `ppp.secret.set`, com 1 mil, 10 mil e
    100 mil secrets.
  - `engine_txn/single/address_list_add/60000`: só o add (o par add + remove já existia).
  - `storage_fs/commit/ppp_secret_add/{10000,100000}`: o add com o arquivo de verdade (fsync).

  Onde vão os 219 ms de um add com 100 mil secrets (**medido**, instrumentação temporária no
  `commit_counted`): `validate_all` 22 µs, `persist::encode_config` 10,8 ms, `hal.apply` e
  `store.commit` < 0,1 ms, o `save` 195 ms. No `save`, o delta da revisão (`config_delta::diff`)
  serializa a seção `ppp` inteira das duas configs para JSON e compara as árvores: os secrets não
  são uma seção copy-on-write separada. Depois vêm o texto do slot (a config inteira de novo) e a
  gravação.

- 2026-10-26 — G0.21: Config grande, parte b: dois tipos novos no `corerouter-model`, ainda sem uso nas seções.

  - `cow_list::CowList<T>`: lista em blocos de até 128 itens, cada bloco compartilhado entre as
    cópias da config até um lado escrever nele. Clonar custa uma contagem de referência; a primeira
    escrita depois do clone copia o "espinho" (um ponteiro por bloco) e o bloco tocado. Lê como um
    `Vec` (`len`, `get`, `iter` de duas pontas, `push`, `insert`, `remove`, `retain`, `get_mut`,
    `find_mut`, `find_by_key` com busca binária pelo id), serializa igual a um `Vec` (os arquivos
    salvos não mudam), compara pulando os blocos compartilhados e diz quais blocos duas versões ainda
    compartilham (`shared_blocks`, para o delta da revisão).
  - `cow_map::CowMap<K, V>`: mapa de hash em árvore fixa de 64 × 64 folhas, cada nó compartilhado até
    ser escrito; uma escrita copia dois nós de 64 ponteiros e uma folha (~25 entradas com 100 mil).
    Chaves de hash aleatórias por mapa (um nome escolhido para colidir não empilha uma folha).

  Testes: proptest contra `Vec` e `HashMap` com cópias tiradas no meio (cada cópia guarda o que
  tinha), serialização igual à do `Vec`, tamanho dos blocos limitado depois de remoções.
  `cargo test -p corerouter-model cow_`; `cargo bench -p corerouter-model --bench cow_list`.

- 2026-10-26 — G0.21: Config grande, parte c: as listas grandes da config passam a ser `CowList` (blocos de 128 itens
  copy-on-write, parte b): `ip.addresses`, `ip.routes`, as tabelas `filter`/`nat`/`mangle`,
  `ip.firewall.address_lists`, `ppp.secrets`, `ip.dhcp_server.leases` e `ip.dns_static.entries`.
  Uma escrita depois de um commit copia um bloco e o espinho, não a lista.

  - **Índices incrementais.** `Secrets` (nome → id em `CowMap`, rotas → id) e o novo `AddressLists`
    (quantas entradas põem um endereço numa lista) são mantidos por `push`, `update` e `remove` em
    vez de refeitos; os valores são ids, não posições (remover não desloca o índice). O id acha a
    posição por busca binária (`find_by_key`: a lista está em ordem de id). `ppp.secret.set/remove/
    enable/disable` e `ip.firewall.address-list.add/set/remove` usam isso: o add não varre mais a
    address-list para achar duplicata.
  - **Delta da revisão por bloco.** `config_delta::diff` copia os blocos que as duas versões
    compartilham e só serializa e compara os itens entre eles; `ppp.secrets`, os leases estáticos e o
    DNS estático viraram seções próprias do delta (antes a seção `ppp` inteira ia para JSON duas
    vezes por commit: 195 dos 219 ms de um `ppp.secret.add` com 100 mil secrets).
  - **Formato em disco igual.** `CowList` serializa como o `Vec`; os arquivos de revisão continuam
    no formato do `json_delta` (o delta por bloco é um `{"a": [...]}` como os outros). Testes:
    proptest de edições aleatórias nos secrets (o delta entre quaisquer duas versões reconstrói a
    mais velha, tipado e pela árvore), delta de um secret, um lease e um nome DNS em milhares
    (< 400 bytes), os testes de ida e volta do histórico.

  Para quem acrescenta seção: lista grande nova = `CowList<T>` (ou um invólucro com índice, como
  `Secrets`/`AddressLists`) e uma linha em `config_delta` (`p.list` no diff, `list()` no apply).
  Sem slice: `&CowList<T>` ou um iterador no lugar de `&[T]`; `get_mut`/`find_mut` copiam um bloco,
  `iter_mut` copia todos.

  Fica para depois (anotado em G0.22): o serviço IPoE ainda refaz o seu índice de secrets
  (`IpoeIndex::of`, O(n)) a cada revisão, na thread dele; pode passar a usar `Secrets::by_name`.

- 2026-10-26 — G0.21: Config grande, parte d: `queue.simple` (G4.9) entra nas listas em blocos (`CowList`), com
  delta próprio no `config_delta` (a seção `queue` como a `ppp`, a lista `simple` por bloco) e
  na lista de seções grandes da validação (nenhum validador lê as filas; o teste de dependências
  confere). Com 10 mil filas qualquer commit comparava a lista inteira por valor (detecção de
  mudança, data plane) e a serializava duas vezes por revisão.

  Como testar: `cargo test -p corerouter-model config_delta` (`one_queue_of_many_is_one_small_delta`),
  `cargo bench -p corerouter-engine --bench config_store -- identity_set`.

- 2026-10-26 — G0.22: Commit incremental, parte a: um commit valida e planeja só o que mudou.

  - `corerouter_model::sections`: `Sections` (conjunto das seções da config, 22 bits), `changed(a, b)`
    (por ponteiro primeiro, por valor só nas seções pequenas; os comentários das interfaces são
    uma seção à parte, `IFACE_COMMENTS`; campo novo sem seção cai em `OTHER`/`IP_REST`/`PPP_REST`/
    `FIREWALL_REST` sozinho) e `restrict(cfg, s)` (a config só com as seções de `s`).
  - `validate::UNITS`: a validação virou uma tabela de unidades (núcleo: interfaces, endereços,
    rotas, NTP; e cada `proto-*`), cada uma com as seções que lê. O commit roda só as que leem
    uma seção alterada, quando a config em execução é a última que passou na validação inteira
    (`ValidRunning` na extensão da sessão); config restaurada, importada ou trocada de outro jeito
    valida tudo. `validate_all` continua igual (todas as unidades, mesma ordem).
  - **Dependência esquecida não passa:** `tests/incremental_validate.rs` (1) confere, num corpus
    (uma config rica montada por comandos e ela quebrada de cada jeito: interface, endereço,
    rota, regra, pool, perfil, lista a menos, endereço numa interface qualquer, MTU, NTP), que cada
    unidade responde igual na config restrita ao que declara; (2) proptest: mudanças aleatórias
    validadas pelo caminho incremental e pelo inteiro dão as mesmas issues. E todo build de debug
    (todos os testes do workspace) confere cada commit incremental contra a validação inteira e
    falha o comando se divergirem. O teste (1) pegou na primeira versão que as interfaces leem os
    endereços (escravo de bond sem endereço); o corpus agora tem esse caso.
  - Data plane: o `VirtualHal` e o plano do `hal-linux` ignoram mudança só de comentário de
    interface e o plano não refaz endereços e rotas do kernel quando interfaces, endereços e
    rotas são os mesmos (`sections::links_and_routes_same`).
  - `proto-dhcp`: a checagem de IPoE só passeia pelos secrets quando há servidor que precisa.

  Para quem acrescenta validador: uma linha em `UNITS` com as seções lidas; os testes acima dizem
  se faltou alguma.

- 2026-10-26 — G0.22: Commit incremental, parte b: o commit não serializa nem grava mais a config inteira.

  - **Journal da config** (`history_files`, num backend com `config_journal()`: `FileStorage` e
    `MemoryStorage`): o commit grava uma linha em `journal-config.log` com a diferença para a frente
    da revisão anterior (`persist::encode_journal_line`, mesmo formato dos arquivos de revisão). O
    slot só é reescrito num checkpoint: mais de 1024 linhas ou de ¼ da config (mínimo 1 MiB) em
    linhas, usuários mudados, store que não é o registrado (Safe Mode, restore), ou enquanto os
    dois slots não existem. O checkpoint anota a revisão nova no journal, grava o slot e deixa no
    journal só as linhas depois da revisão que virou o slot `previous`: o `previous` + o journal
    sempre dão a revisão mais nova (antes, perder o slot corrente perdia o último commit; os testes
    `corrupt_current_*` e `missing_current_uses_previous` agora recuperam tudo).
  - **Boot**: as linhas que encadeiam a partir do slot carregado são reaplicadas por bloco (um
    trecho copiado reaproveita os blocos da `CowList`, `CowList::extend_from`); linha ruim encerra o
    replay e vai para `storage.boot_errors`; última linha cortada (queda no meio do append) é só
    descartada, e o próximo save faz checkpoint em vez de anexar depois dela. Os arquivos de revisão
    das revisões refeitas pelo journal são conferidos (delta aplicado = revisão em memória) e não
    são regravados.
  - **Limite de tamanho sem serializar**: teto = config do slot + bytes das linhas desde ele (uma
    linha só cresce a config com o que carrega); a config só é medida de verdade quando o teto passa
    de `MAX_CONFIG_BYTES`.
  - **Delta de bloco mais barato**: os itens iguais nas pontas de um bloco alterado viram cópia por
    comparação tipada; só o que mudou é serializado (o custo deixou de depender do tamanho do bloco).
    `CowList::range` virou um iterador limitado de duas pontas.
  - **Formato**: o slot continua o mesmo (versões anteriores o leem); o journal é um arquivo novo.
    Risco anotado em `docs/architecture.md`: um build anterior ao G0.22 lê só o slot e perde as
    linhas desde o último checkpoint (G0.27: checkpoint no desligamento).

  Testes: `tests/config_journal.rs` (reboot igual, checkpoint depois do limite, linha cortada, linha
  ruim no meio, queda de energia em cada passo do save — revisão, append, slot, reescrita do
  journal, remoção — com 5, 1023, 1024 e 1025 commits, `previous` + journal depois de 1 a 2100
  commits, usuário mudado, Safe Mode com `exit` e `cancel`, e um proptest de sequências aleatórias de
  comandos com reboots no meio: o journal salva o mesmo store que o slot salvaria); `storage-fs`
  com arquivos de verdade (`commits_go_to_the_config_journal_file`). `MemoryStorage::slots_only()`
  mantém os testes do encadeamento de arquivos de revisão sem journal.

- 2026-10-26 — G4.3cd: Rotas por assinante, parte 3 (janela PPP). O diálogo do secret ganha o campo **Routes** (texto do
  RouterOS; a recusa do engine aparece embaixo do campo e trava o OK), a aba Secrets a coluna Routes,
  e Active Connections a coluna **Routes**: um selo por bloco e um selo da origem (secret,
  Framed-Route, Framed-IPv6-Route, Framed-IPv6-Prefix), mais um selo vermelho com quantas foram
  recusadas. O **Why?** lista as rotas da sessão conectada com a origem e cada recusada com o motivo
  em português. ⓘ em português (e inglês) nos três lugares.

  Duas correções que as capturas acharam no diálogo do secret (existiam antes):
  - editar um secret sem limites dava "bytes, a non-negative integer" e travava o OK (o diálogo manda
    o campo vazio como texto; o `ppp.secret.set` agora aceita `""` e números em texto);
  - editar um secret mandava `password: ""` e **apagava a senha** a cada edição, embora o campo diga
    "vazio mantém"; um campo só de escrita vazio não vai mais no comando (`list_modal`).

  Testes: `tests/ppp_routes.rs` (selos da coluna, coluna do secret, Why? com recusa, a senha mantida),
  `ppp_secret::limits_as_text_like_the_modal_sends_them`. Capturas (olhadas) no laboratório em
  namespace com 6 CPEs.

- 2026-10-26 — G4.3cd: Rotas por assinante, parte 4 (IPoE). O serviço `ipoe` instala os blocos do secret `service=ipoe`
  ou do Access-Accept (`Framed-Route`, `Framed-IPv6-Route`, o segundo `Framed-IPv6-Prefix`) quando o
  lease vira sessão, com a mesma tabela de donos do PPPoE e as mesmas recusas. O kernel entrega o
  IPoE ao assinante, então cada bloco IPv4 vira uma rota `bloco via <assinante>`
  (`pppoe_io::gateway_routes`, com ou sem XDP); com XDP, também a entrada no LPM (policer e
  contadores). Na queda as rotas saem antes da sessão; CoA com `Framed-Route` troca sem derrubar o
  lease (inválido = NAK 407). IPv6 IPoE é recusado com o motivo (G4.3s). Log das rotas e recusas no
  tópico `ppp`; Accounting com as rotas.

  A lógica do CoA de rotas (`RouteChange`, `route_change`, `check_change`) foi para
  `corerouter_engine::framed`, usada pelos dois serviços.

  Testes: `ipoe_bng_tests` (`routed_blocks_follow_the_ipoe_session`, `coa_changes_ipoe_routes`),
  `netns_gateway_routes` (a rota de verdade num namespace, sem root).

  Também: a exportação dos secrets com `routes` (e senha) segue no G4.3n.

  Desempenho (**medido**, 2026-10-26, Ryzen AI Max+ 395, release):
  - `ppp.secret.add` com rota sobre 100 000 secrets com endereço fixo: a conferência "o bloco tem o
    endereço fixo de outro secret" passeava por todos os secrets (O(n) por secret com rota). Com um
    índice dos endereços fixos em `Secrets` (como os de nome e de rotas), 1000 secrets com rota num
    lote: 634 → 354 ms; o que sobra é o custo de qualquer `add` nesse tamanho (278 ms para 1000
    secrets sem rota, abaixo).
  - Rotas do kernel do IPoE (`netns_gateway_routes`): 1000 blocos numa rodada de netlink 4,0 ms
    (remover 2,3 ms), uma rodada por bloco 9,8 ms; o serviço manda uma rodada por volta da thread.
  - Achado fora da G4.3cd: com 100 mil secrets, um `ppp.secret.add` sozinho custa 232 ms (1,5 ms com
    mil) e, num lote, 1,2 ms por passo (14 µs com mil): cada passo do lote faz commit, e a escrita
    seguinte copia a lista inteira de secrets (copy-on-write da seção). Vira a G4.3gb.

- 2026-10-26 — G4.3gb: `ppp.secret.add/set` em O(1) com 100 mil secrets: o fim da série G0.21 (listas em blocos e
  índices incrementais), G0.22 parte a (validação e plano só do que mudou) e G0.22 parte b (journal
  da config, neste PR). Números na seção `## perf` da G0.22 parte b.

- 2026-10-26 — G4.3h: BNG em alta disponibilidade, fases 1 e 2 no serviço `pppoe`.

  Fase 1:
  - só o nó ativo do par fala com os assinantes: o standby não responde nem manda o PADT a sessão
    desconhecida, que derrubaria o CPE no ativo;
  - o AC MAC é o MAC virtual, e as portas de acesso ficam em modo promíscuo;
  - o AC-Cookie usa a chave do par sem amarrar a porta (`ServerConfig::cookie_secret`).

  Fase 2 (hot standby):
  - cada worker publica as suas sessões ao `ppp-ha` (`pppoe_bng/ha.rs`);
  - na tomada, os workers adotam as sessões antes de responder: Opened no `proto-pppoe`, endereço,
    XDP ou rota, rotas, tabela ativa com os contadores herdados;
  - a contabilização continua: o mesmo Acct-Session-Id e um Interim-Update; o serviço RADIUS agenda
    os próximos Interims a partir dele;
  - o nó que entrega o papel não manda Acct-Stop;
  - o número de workers entra na divergência de config.

  Correção: o Acct-Session-Id se repetia entre workers no mesmo segundo (RFC 2866 §5.5); agora
  leva a lane do worker.

  Como testar: `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p
  corerouter-daemon --test netns_ha_pppoe -- --test-threads 1 --nocapture`.

  **Medido**, debug, com dois daemons reais e 200 CPEs:

  | Modo | Depois da morte do ativo |
  |---|---|
  | Stateless | os CPEs voltam no outro nó em 4,9 s |
  | Hot standby | sessões no outro nó em 1,22 s, nenhum CPE cai |

  Teste de unidade: `cargo test -p corerouter-daemon --bin corerouter-daemon pppoe_ha_tests`.

  Desempenho: o worker nunca espera o lock do par. Se o lock está ocupado (a thread do sync
  codificando um snapshot), as mudanças voltam para a fila do worker e saem na rodada seguinte. Os
  contadores para o standby saem na passada do `tick` de 1 s, sem varredura própria. Os números
  estão em `docs/bng-ha.md` §4.

- 2026-10-26 — G4.3h: Laboratório da G4.3h: `cargo xtask bng-lab --only ha` (`tests/bng_lab_ha.rs`, `docs/bng-ha.md`
  §2.10).

  O teste monta três namespaces: o nó A, o nó C e o BNG Blaster. Tem uma bridge de acesso por porta,
  o uplink, o link de sync, a testemunha e um servidor RADIUS de teste. Com todas as sessões em A e a
  réplica de C completa, A perde a energia: todas as portas caem juntas.

  O teste confere:
  - a tomada;
  - a volta do tráfego de subida;
  - as sessões perdidas (flaps no BNG Blaster);
  - os Starts com ids únicos;
  - nenhum Stop;
  - um Interim do nó novo para cada sessão.

  Com `--root` (na VM), o XDP genérico roda nos dois nós, e as sessões adotadas são programadas nos
  mapas do nó novo.

  Como testar: `flock vm/root.lock cargo xtask vm-lab run -- cargo xtask bng-lab --only ha --scales
  1000,10000,100000` (com `--root` para o XDP).

  **Medido** na VM `corerouter-lab` (8 vCPUs, release, BNG Blaster 1.0.1, 2026-10-26). Em todas as
  escalas, nos dois planos: 0 sessões perdidas, 0 Stops, todos os Starts com ids distintos e um
  Interim do nó novo por sessão.

  | Sessões | Tomada, caminho lento | Tomada, XDP | Tráfego de subida de volta |
  |---:|---:|---:|---:|
  | 1 000 | 1,13 s | 1,23 s | 1,14–1,25 s |
  | 10 000 | 1,12 s | 1,24 s | 1,14–1,27 s |
  | 100 000 | 1,15 s | 0,99 s | 1,12–1,29 s |

  A tomada é quase toda a espera pela morte do par: 4 hellos de 300 ms.

- 2026-10-26 — G4.3l: PPPoE em QinQ e VLANs no caminho lento, parte 1 (`docs/pppoe.md` §13). O servidor ganha
  `vlan_mode=stacked` com `outer_vlan_range`, `inner_vlan_range` (`any`), `outer_tpid`
  (0x88a8/0x8100), `max_sessions_per_vlan` (1 = TR-101 1:1) e `max_payload` (RFC 4638, até a MTU −
  8). O caminho lento abre um socket `ETH_P_ALL` por S-tag com filtro BPF de VID, TPID e EtherType
  (`hal-linux::pppoe_io::Listen`). Isso conserta a VLAN simples sem XDP: o socket preso ao
  protocolo recebia o quadro com a tag já apagada. Um quadro QinQ vai ao worker pelo par de tags. O
  RADIUS recebe ADSL-Agent-Circuit-Id/Remote-Id e NAS-Port-Id `<porta>:<s>-<c>`, e o Active traz
  `vlan` e `inner_vlan`.

  Como testar: `cargo xtask netns` (`netns_pppoe_io`: cada combinação de tags chega a um socket só;
  `netns_pppoe_qinq`: 400 linhas QinQ com 1 sessão cada, ping pelo caminho lento dentro das duas
  tags, VLAN simples e CPE sem tag recusado), `cargo test -p corerouter-proto-pppoe` e
  `cargo test -p corerouter-daemon qinq_lines`.

- 2026-10-26 — G4.3l: PPPoE sem XDP, parte 2: o IPv6 dos assinantes é encaminhado no caminho lento (`docs/pppoe.md`
  §12.5). Na subida, só da fonte no /64 ou no prefixo delegado da sessão, no MAC e nas tags dela,
  por um socket IPv6 cru. Na descida, há rotas de cada /64 e prefixo delegado para o `bng0`, e o
  pacote volta ao worker dono pelo maior prefixo (`Net6Index`, ~16 ns com 200 mil prefixos,
  **medido**), encapsulado nas tags da linha. O IPv4 do caminho lento passa a conferir também as tags
  da sessão.

  Como testar: `cargo xtask netns` (`netns_pppoe_qinq`: ping IPv6 de um assinante QinQ dual-stack
  até o `wan0` e de volta, e a fonte falsificada é recusada) e
  `cargo test -p corerouter-daemon ipv6_on_the_slow_path`.

- 2026-10-26 — G4.9b: Filas (G4.9b), correção: com XDP ligado, a descida dos assinantes PPPoE/IPoE no modo padrão
  (`download_mode=shaper`) saía **sem limite** (2× o plano no laboratório BNG Blaster, **medido**).
  Duas causas no carregador (`hal-linux`):

  - o bit `ON_SESSIONS` do `SETTINGS`, que liga a busca de sessão no `shape_egress`, só era escrito
    quando o plano da fila entrava, e o daemon aplica o plano antes de qualquer sessão subir: o XDP
    largava a descida para o kernel e ninguém moldava. Agora a primeira sessão moldada liga o bit e
    a última o desliga;
  - uma sessão que pede shaper só larga o policer do XDP depois que o shaper está preso nas portas
    de acesso (e no `bng0`); antes disso, ou se o shaper cair, ela fica policiada no XDP (nunca sem
    limite) e troca sozinha quando ele volta.

  Como testar: `cargo test -p corerouter-hal-linux shaped_sessions` (sem root); na VM,
  `xdp_root::pppoe_kernel_delivery_through_bng0` agora aplica o plano antes da sessão, como o
  daemon; e `cargo xtask bng-lab --root --only radius` volta a medir a descida dentro de 5%.
  Laboratório (VM, 8 vCPUs, kernel 7.0, BNG Blaster, 100 sessões RADIUS a 1M/2M com 2× oferecido,
  **medido** 2026-10-26): descida 1,004× o limite (mín 1,000, máx 1,009), antes 2,015× na `main`;
  com CoA 1,002×. `xdp_root` 18 de 18.

- 2026-10-26 — G4.9c: Filas (G4.9), parte 3: a interface.

  - **Janela Queues** (grupo próprio no menu, `crates/ui/src/queues.rs`): abas Simple Queues, Per-IP
    (PCQ) e Queue Types, barra + − ✓ ✗ 💬, filtros por origem (fixa, PPPoE, IPoE, lease e rede do
    DHCP), selo da origem, colunas Name, Target, Max Limit, Rate, Queue (ms), Drops, Queue Type. A
    fila selecionada mostra os avisos inteiros (alvo encoberto por uma fila acima, sobreposição com
    dinâmica). Sem plano de dados que molde (laboratório virtual), a janela diz por quê.
  - **Prévia no modal:** `queue.simple.preview`, `queue.per-ip.preview` e `queue.type.preview`
    checam como o `add`/`set` e mostram o que a fila faz (descida moldada a X, subida policiada a Y,
    alvos em vigor) e o comando RouterOS equivalente, sem mudar nada.
  - **PPP:** o perfil ganha Download Mode (shaper/policer) e Queue Type (lista de `queue.type.list`);
    Active Connections ganha Queue (espera da fila da sessão) e Drops; `ppp.active.list` documenta
    `queue_us` e `drops`.
  - **Correção:** um limite por IP (PCQ com taxa) não recebe mais o aviso "max-limit 0/0: a fila só
    conta".
  - Explicação ⓘ de cada aba, coluna e campo em português e inglês (testes conferem todas as
    chaves).

  Como testar: `cargo test -p corerouter-ui queues ppp`, `cargo test -p corerouter-engine --test
  queue`; na GUI, menu Queues (capturas no PR).

- 2026-10-26 — G4.9d: Filas (G4.9), parte 4: o laboratório em massa.

  - `cargo xtask bng-lab --root --only shaping --shaping <n>`: `n` sessões pelo perfil, fluxos a 2× o
    plano nos dois sentidos; a descida segurada pelo policer do XDP e depois pelo shaper (EDT); mede
    descida e subida contra o limite (média, mín, máx), a fila que as sessões mostram, a CPU e se o
    shaper está ativo. Falha se a descida moldada sair de ±5%.
  - Acima de 100 sessões o plano encolhe para o BNG Blaster oferecer ~75 mil pacotes/s (um gerador
    só não dá os 750 mil de 1000 sessões a 1M/2M, **medido**).
  - O laboratório achou o defeito corrigido em #260 (descida moldada sem limite no modo padrão).

  Como testar: `cargo xtask vm-lab run -- cargo xtask bng-lab --root --only shaping --shaping 1000
  --scales 1000`.

- 2026-10-26 — processo: CI completo do lote em jobs paralelos: de ~23 min para ~6,5 min por lote (**medido**), sem
  tirar nenhum passo.

  - `.github/workflows/ci.yml`: o job serial `xtask ci (linux)` virou cinco jobs paralelos, cada
    um com `cargo xtask ci --only <passos>`: `lint` (fmt, clippy, docs, ebpf-check, layers,
    agents-sync, wasm), `test`, `bench-check`, `netns` e `xdp-root`. O PR (`--fast`) roda só
    `lint` e `test`; os três lentos rodam no lote da fila (workflow_dispatch) e na `main`. O
    check exigido pela proteção da `main` continua com o nome `xtask ci (linux)`: agora é o job
    final (`if: always()`) que confere o resultado de todos e só aceita "pulado" onde é de
    propósito (PR, PR só de documentação). Os outros dois checks exigidos não mudaram. O
    `scripts/land.sh` lê a conclusão do run inteiro, que já espera todos os jobs; o `main-red`
    também.
  - `.github/actions/setup`: a preparação comum (pacotes apt, toolchain, rust-cache, nextest,
    módulos do kernel) numa action local. O cache do cargo é por job (cada um guarda só o que
    compila: 0,2–0,5 GB cada, 1,6 GB os cinco, contra 1,1 GB do job único).
  - `cargo xtask ci --only a,b` roda só esses passos, na ordem do `ci` (`--fast` junto tira os
    lentos). `cargo xtask ci` sem opção continua igual.
  - `bench-check`: compila no perfil novo `bench-check` (`opt-level = 1` com as debug assertions e
    a checagem de overflow de um build de teste) e roda os binários em paralelo, um por CPU, os
    mais lentos primeiro. Continua provando que todo benchmark compila e roda uma vez no modo de
    teste do criterion. Em debug e um depois do outro, eram 9 min 55 s no CI, quase tudo
    rodando montagens grandes (1M de rotas, 100 mil sessões); o maior, `ui frames`, levava 177 s.
  - `scripts/land.sh`: os testes instáveis (FLAKY do nextest, "flaky netns test") do CI de cada
    lote vão para o log da fila (`instável (run …): …`), para serem corrigidos antes de causarem
    uma bisseção.

  Como testar: `cargo xtask ci --only fmt,wasm`; `cargo xtask ci --only bench-check`;
  `cargo xtask ci` (completo, como antes). No GitHub, Actions → ci → Run workflow numa branch.

  Atenção: depois do merge, o primeiro CI de PR roda com o cache frio (as chaves novas só são
  salvas pela `main`): ~7 min no lote, **medido**; o push na `main` que segue o merge salva os
  cinco caches.

- 2026-10-26 — processo: O teste `the_daemon_authenticates_through_its_radius_service` era instável e reprovou o lote do #262 e do #264 em 2026-10-26. Ele lia o log logo depois da resposta do RADIUS, mas o serviço só esvazia a fila de log do driver no tick dele, então a linha "recusado" às vezes ainda não tinha chegado. Agora o teste espera a linha aparecer, com prazo de 5 s.

- 2026-10-26 — G0.21: Config grande, parte e: o índice que o servidor DHCP usa para decidir o IPoE (`IpoeIndex`,
  G4.3f) era refeito do zero a cada revisão da config, num laço sobre todos os `/ppp secret` e
  todas as concessões fixas: 22 ms com 100 mil de cada a cada commit, dentro da rodada do DHCP e
  com o lock do `Session`. Agora o nome do secret é procurado no índice que a própria lista já
  mantém (`Secrets::first_named`, incremental desde a G4.3gb; anda a lista só numa config editada
  à mão com um nome repetido e quando o primeiro não é IPoE), e as velocidades das concessões
  fixas seguem a lista bloco a bloco (`CowList::shared_blocks`): uma revisão que mudou uma
  concessão lê o bloco dela (128), não a lista. Duas concessões no mesmo endereço (só à mão)
  fazem o índice ser refeito, e a última vale, como antes.

  Como testar: `cargo test -p corerouter-engine --lib ipoe` (`refresh_equals_a_rebuild`: proptest,
  o índice seguido é igual a um refeito do zero depois de qualquer série de escritas),
  `cargo test -p corerouter-model --lib ppp_secrets`,
  `cargo bench -p corerouter-engine --bench config_store -- ipoe_index`.

- 2026-10-26 — G0.21: Config grande, parte f: `queue.simple.add` com milhares de filas. Medido na `main` (já com a G4.9c,
  que tirou o O(n²) do nome padrão): 39,5 ms por add com 80 mil filas, um lote de 100 em 5,3 s, e o
  serviço `queue` do daemon resolvendo o plano inteiro uma vez por segundo, com o lock do `Session`,
  mesmo sem nada mudar (99 ms por rodada com 80 mil: o plano de controle parado 10% do tempo).

  - `queue.simple` vira `SimpleQueues` (`model/simple_queues.rs`, como `Secrets` e `AddressLists`):
    `CowList` com um índice copy-on-write de nome → id, alvo → quantas filas ativas o têm e o menor
    `queue<k>` livre, mantido por `push`/`insert`/`update`/`remove` (qualquer outra escrita por
    `DerefMut` derruba o índice). Disco igual (serializa como a lista).
  - `add`/`set`/`remove`/`enable`/`disable`/`move` por nome ou id usam o índice; o nome padrão só é
    calculado quando o nome não veio.
  - Os avisos do `add`/`set` (alvo sombreado por outra fila, sobreposição com fila dinâmica) só andam
    as filas quando o índice diz que alguém toca nos alvos da fila (`may_warn`: O(alvos × tamanho
    do prefixo) consultas); sem sobreposição a resposta já é "sem aviso", provado pelo índice.
  - `Session::queue_sync` só resolve o plano quando a revisão da config ou as filas dinâmicas do DHCP
    mudaram.

  Achado: 100 mil filas (o `MAX_SIMPLE`) não cabem nos 15 MiB que a config pode ocupar no disco
  (~170 bytes por fila salva; o commit é recusado perto de 90 mil, **medido**); o bench usa 80 mil.

  Como testar: `cargo test -p corerouter-model --lib simple_queues` (`index_equals_a_walk`: proptest,
  o índice mantido responde o mesmo que andar a lista), `cargo test -p corerouter-engine queue`,
  `cargo bench -p corerouter-engine --bench config_store -- queue_s`.

- 2026-10-26 — G0.22: Commit incremental, parte c: o filtro XDP (G2.5a) refazia o plano inteiro a cada commit e a cada
  entrada dinâmica de address-list (`XdpPlan::of`: cobrir cada entrada em prefixos, ordenar,
  deduplicar) e comparava com o plano aplicado por dois `BTreeMap`: 11 ms com 100 mil entradas, por
  commit sem relação e por sessão PPP que subia com address list, com o lock do `Session`. As
  entradas dinâmicas ainda eram um `Vec` com `retain` (O(n) por mudança).

  - `corerouter_hal::xdp::XdpPrefixes` (puro, compila em WASM): segue as entradas estáticas por
    bloco (`CowList::shared_blocks`: só os blocos que o commit mudou) e as dinâmicas uma a uma;
    cada prefixo conta as entradas de cada lista que o cobrem (entrada repetida ou em duas listas
    entra e sai exata) e devolve só os prefixos que mudaram (`take_changes`). Troca de nomes em
    `block_lists`/`allow_lists` recontam tudo (raro).
  - `hal-linux::XdpState`: `sync` usa `XdpPlan::settings_of` (sem prefixos) + `XdpPrefixes`; as
    tries recebem só as mudanças; objeto recarregado recebe tudo; filtro sem portas esvazia as
    tries (como antes). Escrita recusada deixa as mudanças pendentes para a próxima. Dinâmicas
    num `HashMap` por (lista, endereço); `address_list_dynamic_many` conta todas e escreve uma vez.
  - `XdpPlan::of` continua (laboratório virtual, `ip.firewall.xdp` "bloqueado?").

  Como testar: `cargo test -p corerouter-hal --lib xdp` (`followed_prefixes_equal_the_plan`:
  proptest, as mudanças aplicadas a um espelho das tries dão exatamente o `XdpPlan::of`, depois de
  qualquer série de escritas estáticas, dinâmicas e troca de listas),
  `cargo bench -p corerouter-hal --bench xdp_prefixes`, e com root (VM do G0.26):
  `cargo xtask vm-lab run -- env COREROUTER_REQUIRE_XDP=1 cargo xtask xdp-root` (passa na VM; a
  primeira rodada pegou que o `SETTINGS` do programa liga a busca de block/allow pelo número de
  prefixos, que agora vem do `XdpPrefixes`).

- 2026-10-26 — G0.27: Checkpoint da config no desligamento: com o journal da config (G0.22) os commits vão para
  `journal-config.log` e o slot só é regravado de tempos em tempos. Um build anterior ao G0.22 que
  bootasse o diretório leria só o slot e perderia os commits desde o último checkpoint.

  - `Session::checkpoint()` (novo): grava a revisão salva mais nova no slot quando ele ainda não a
    tem (`Ok(false)` sem nada a fazer; em Safe Mode grava o store da entrada, como todo save).
    `history_files::save` ganhou o modo "slot" (o mesmo caminho do checkpoint por tamanho).
  - O daemon chama depois de pegar o lock final do desligamento limpo (G5.5) e registra o tempo.
  - O formato do journal não muda: o checkpoint deixa nele as linhas que o slot `previous` ainda
    precisa (perder o slot corrente continua sem perder commit), e o boot seguinte as pula.

  Testes: `crates/engine/tests/config_journal.rs` (`the_shutdown_checkpoint_loses_no_journal_line`,
  com 3, 40 e 1 100 commits: reinício igual, a visão de um build sem journal tem todos os commits,
  o journal ainda fecha com o slot `previous`, segundo checkpoint não grava;
  `the_shutdown_checkpoint_in_safe_mode_saves_the_entry`) e
  `apps/corerouter-daemon/tests/shutdown_checkpoint.rs` (daemon de verdade com `--config-dir`, 20
  commits, `kill -TERM`, sai com 0; o diretório inteiro e o diretório sem o journal bootam a mesma
  revisão com os 20 commits).

- 2026-10-26 — G4.3l: PPPoE QinQ, parte 3: o QinQ no laboratório (`docs/pppoe.md` §13.6). O `xdp-root` na VM cobre linhas
  com TPID externo 0x8100 no diferencial kernel × host do PPPoE. O BNG Blaster ganha a etapa `qinq`
  (`cargo xtask bng-lab --only qinq [--qinq N]`): 4000 linhas 802.1ad 1:1 com Service-Name e
  TR-101 sobem a ~7800 sessões/s no XDP e no caminho lento, com 8000 de 8000 fluxos de tráfego
  verificados (**medido** na VM). Um nome descartado não sobe nenhuma sessão.

- 2026-10-26 — G4.3n: Migrar os secrets PPP do MikroTik com as senhas (`docs/ppp-secret-import.md`).

  - **`ppp.secret.import {text, profile_map?, on_conflict?, create_profiles?, dry_run?}`**: lê um
    `/ppp secret export show-sensitive` (ou `/export show-sensitive`) do RouterOS v7 ou o nosso;
    relatório com quantos têm senha, os sem senha, perfis (mapeados, criados do arquivo ou
    faltando), nomes que já existem (`skip`, `replace` ou `rename`), erros por linha, campos sem
    equivalente; aplica numa mudança só (uma revisão; Safe Mode desfaz). `routes=` (G4.3cd) entra com
    as mesmas recusas do `ppp.secret.add`, e o arquivo é conferido contra si mesmo (dois secrets
    no mesmo bloco, IP fixo dentro do bloco de outro).
  - **Leitor do export** (`engine::rsc`): continuações (também dentro de aspas), escapes do
    RouterOS (`\XX` em hexa, `\_`, `\$`…), UTF-8 ou Latin-1, `set [ find … ]` e `set *0`;
    limites de tamanho; erro com linha e coluna, nunca o texto. Proptests e alvo de fuzz
    `routeros_export`.
  - **Senhas seladas** (`engine::sealing`, `model::sealed`): a config, as revisões, os arquivos,
    o diff e o undo levam a caixa `$cr1$…`; a chave fica fora (`state-secret-key.json`, 0600). O
    BNG abre por login (0,5 µs; +1 a +5 % no setup de sessão, **medido**). Configs antigas são seladas na partida (revisão automática).
  - **Teto da config salva** de 15 para 31 MiB (`persist::SAVE_BUDGET_BYTES` de 32 para 64 MiB): 100
    mil secrets completos (26,5 MB selados) salvam e dão boot; antes nem em claro cabiam.
  - **Fora de tudo:** journal (o `text` vira `*** (N bytes)`), log, `config.diff`, histórico,
    `state.inspect`, saída do MCP (toda chave de segredo mascarada) e a GUI; testes procuram as
    senhas em cada saída.
  - **`/export show-sensitive`**: bandeira como no RouterOS v7; senhas só para `full`; ida e volta
    RouterOS → import → nosso export → import idêntica (`crates/shell/tests/ppp_export.rs`).
  - **GUI:** PPP › Secrets › Import from MikroTik: caminho, arrastar ou colar; selos da
    pré-visualização; mapa de perfis que refaz a pré-visualização; Safe Mode; aviso e lembrete de
    apagar o arquivo; ⓘ em português.

  Testar: `cargo test -p corerouter-engine --test ppp_import`, `cargo test -p corerouter-shell
  --test ppp_export`, `cargo test -p corerouter-ui ppp_import`, `cargo test -p corerouter-mcp
  --test protocol ppp`; na GUI, PPP › Secrets › Import from MikroTik com um `.rsc`.

- 2026-10-26 — processo: Partes do CI (8 núcleos nos testes somando runners), complemento do #269. O #269 entrou com
  dois commits temporários das medições, que este PR desfaz: o `test` volta a 2 partes (eram 3)
  e o cache do cargo volta a ser salvo só pela `main` (salvava também a branch do #269).

  - **8 núcleos nos testes, somando runners:** o `test` e o `xdp-root` rodam em duas partes,
    cada uma num runner de 4 vCPU (`COREROUTER_CI_PARTITION=i/2`). O `test` passa
    `--partition hash:i/2` ao nextest (um teste fica na mesma parte quando outros entram; os
    doctests só na parte 1); `.config/nextest.toml` começa primeiro os três testes de mais de
    60 s, que antes, começando por último, seguravam sozinhos o fim de uma parte. O `xdp-root`
    divide os testes de root pelo tempo medido de cada um (o mais longo para a parte mais leve),
    e cada parte continua rodando um por vez, porque eles medem vazão e precisão. Dentro de cada
    job, o nextest e o cargo já usam todos os núcleos (o padrão é o número de CPUs). Runner maior
    é pago e runner próprio na máquina do usuário rodaria código de PR de fork (repositório
    público): nenhum dos dois.

- 2026-10-26 — G4.3ha: Class do RADIUS (RFC 2865 §5.25) na contabilização do PPPoE e do IPoE. O Class do Access-Accept
  volta sem modificação no Start, nos Interims e no Stop. Ele é lido do pacote recebido
  (`corerouter_engine::radius::reply_classes`), byte a byte, na ordem e até 4. Antes:
  - o PPPoE não mandava o Class;
  - o IPoE mandava o texto decodificado: um Class binário (o Windows NPS manda um assim) virava
    "0x…" em hex, e um Class com mais de 64 bytes era cortado com "…".

  Mudanças:
  - `AcctRequest::class` novo (`crates/model`, aditivo). O serviço RADIUS o codifica como
    atributo 25 cru.
  - O registro do par em alta disponibilidade leva o Class (`SessionRecord::class`, que já
    existia). O nó que assume manda o Interim e o Stop com o mesmo Class e o mesmo Acct-Session-Id.
  - O servidor de teste do `proto-radius` registra o Class de cada Accounting-Request
    (`AcctLog::class`).

  Testes:
  - `radius_aaa_tests::class_is_echoed_byte_for_byte_in_every_accounting_request`: servidor de
    teste em UDP; um Class binário (NUL, 0xff) e um de texto que parece hex chegam iguais no Start,
    no Interim e no Stop.
  - `pppoe_bng_tests::radius_users_get_framed_ip_rate_and_accounting`: Start e Stop com o Class
    binário.
  - `pppoe_ha_tests::the_class_of_a_radius_session_survives_a_takeover`: o registro leva o Class;
    no outro nó, o Interim da tomada e o Stop o levam, sem Start novo e com o mesmo
    Acct-Session-Id.
  - `ipoe_bng_tests`: o Start do IPoE com o Class.
  - Laboratório `cargo xtask bng-lab --only ha`: cada usuário recebe um Class binário próprio. O
    laboratório conta os registros sem o Class do usuário, os do nó novo incluídos (coluna nova).

  Os testes do `pppoe_ha_tests` passam a rodar um de cada vez (`pair_lock`). Eles dividem o
  `HA_ACTIVE` e a tomada global, e um teste via a tomada do outro.

  **Medido**:
  - Custo no link de sync: um TLV por Class, 3 B + o tamanho. O Class de 8 B do teste soma 11 B a
    um registro de ≈ 180 B. Um Class típico de cobrança (10–30 B) soma 13–33 B por sessão, só no
    upsert. Os contadores (50 B a cada 10 s) não mudam.
  - Laboratório na VM `corerouter-lab` (8 vCPUs, release, BNG Blaster 1.0.1, sem root, caminho
    lento, 2026-10-26, `cargo xtask bng-lab --only ha --scales 1000,10000`):

  | Sessões | Tomada | Tráfego de volta | Sessões perdidas | Starts (ids únicos) | Stops | Com Interim do nó novo | Registros sem o Class do usuário |
  |---:|---:|---:|---:|---:|---:|---:|---:|
  | 1 000 | 1,14 s | 1,16 s | 0 | 1 000 (1 000) | 0 | 1 000 | 0 |
  | 10 000 | 1,14 s | 1,17 s | 0 | 10 000 (10 000) | 0 | 10 000 | 0 |

- 2026-10-26 — G4.9g: Filas, parte g: a janela de **uma fila** (aprovada pelo usuário em 2026-10-26). Duplo clique em
  qualquer fila da janela Queues (fixa, PPPoE, IPoE, lease ou rede do DHCP, PCQ) abre "Queue <nome>"
  com as abas do WinBox: General/Advanced (o formulário de edição da fila fixa; só leitura na
  dinâmica), **Traffic** (1 s, 1/5/15 min, download e upload com o max-limit tracejado, cartões de
  taxa com % do limite, atraso na fila com p95, descartes/s com o selo "at limit", pausa, CSV,
  atalhos Torch e Sniffer), **Statistics** (por sentido: taxa, pps, bytes, pacotes, descartes com %,
  espera agora e p95, tempo no limite, estado e tempo restante da rajada, endereços PCQ) e
  **History** (hora, dia, semana com p95). A lista ganhou o selo "near limit" (ícone de medidor)
  na coluna Rate quando um sentido está a 90% do max-limit ou mais, e a contagem no rodapé (pedido
  do usuário durante o trabalho).

  Engine: `queue.simple.stats {id}` (uma fila, sem resolver o plano: índice de nomes, mapa de
  contadores por chave, `PppBackend::session` por id; anel de amostras só das filas olhadas,
  `QueueWatch`, até 64, "busy" depois); `queue.simple.graph {id, graph}` (fixa: o campo novo
  `graph` da fila, padrão sim; dinâmica: o nome em `system.graph.set queue_include`);
  `system.graph.set` ganhou `queues` (liga/desliga todas) e `dynamic_queues` (todas as dinâmicas);
  séries `queue:<nome>` (up_bps, down_bps, drops, delay) amostradas na rodada do serviço `queue`.
  O laboratório virtual ganhou um shaper simulado (`hal::queue::lab`) para a janela e o histórico se
  mexerem; nada é moldado e a lista continua dizendo isso. Detalhes em `docs/queues.md`.

  Testar: `cargo run -p corerouter-daemon -- --control 7979`, depois
  `corerouter-cli --connect 127.0.0.1:7979 run queue.simple.add '{"name":"ana","target":"10.0.0.5","max_limit":"10M/50M","burst_limit":"20M/80M","burst_threshold":"8M/40M","burst_time":"16s"}'`,
  `corerouter-cli … run queue.simple.stats '{"id":"ana"}'` e, na GUI (`--connect`), Queues › duplo
  clique na fila. Medido: `queue.simple.stats` 2,2 µs com 10 mil e com 100 mil filas; histórico
  438 KiB por fila (10 mil marcadas = 4,18 GiB, não cabem: teto 4 GiB e 4096 séries).

- 2026-10-26 — processo: Três testes instáveis da fila (2026-10-26), cada um pela causa real:
  - `netns_pppoe_io` (bug de produção): os sockets `ETH_P_ALL` da porta PPPoE (`pppoe_io::bound` e
    o tap do `bng0`) recebem quadros de **todas** as interfaces, sem filtro, entre o `socket()` e o
    `bind`; o BNG lia esses quadros como PPPoE da porta (no CI, um relatório MLD de outra porta).
    Agora a porta descarta o que ficou na fila depois do filtro e do bind, como os sockets do DHCP e
    da captura já faziam. Teste novo `a_port_never_reads_another_interface`: abre a porta 50 vezes
    com outra veth inundada de PPPoE. Sem a correção, 3.500 a 4.900 quadros alheios por rodada;
    com ela, 0 (**medido**). O teste também passou a esperar a veth sair do qdisc `noop` (o caso 0
    não lia nada no CI: o quadro saía antes do carrier).
  - `netns` (`two_daemons_see_each_other`): o veth agora é apagado antes de o namespace de B
    acabar. O kernel destrói o namespace depois, numa workqueue, e leva o veth junto; o `ip link
    del` achava "Cannot find device". Com 300 ms entre os dois passos, a ordem antiga falha sempre
    (**medido**).
  - `netns_dns_zones`: o serviço DNS copia a config a cada 1 s, e o teste esperava o 3º de 5
    registros, então a AXFR podia ler 4 de 5. Agora ele espera o SOA servido trazer o serial
    confirmado (`ip.dns.zone.print`). Com uma pausa de 1,1 s depois do 3º registro, o teste antigo
    falha (3 de 5) e o novo passa (**medido**).

  Carga: 12 a 16 cópias em paralelo, com 32 núcleos ocupados. `netns_pppoe_io` foi de 1 falha em
  160 a 0 em 160; `netns` e `netns_dns_zones` deram 0 em 60 cada (**medido**).

- 2026-10-26 — G4.10a: Avisos ao assinante, parte 1 (modelo e comandos): `/ip subscriber-notice` com perfis (`block`,
  `notice`, `throttle`) ligados a uma address list do firewall, walled garden por domínio ou
  prefixo, páginas editáveis com variáveis (`{login}` `{plano}` `{valor}` `{vencimento}`
  `{link_pix}`), a tabela de sondas de detecção de portal de 21 hosts (Android, Chrome OS,
  Samsung/Xiaomi/Huawei, Apple, Windows, Firefox, NetworkManager), quem está sob um perfil agora
  (`active.list`, desde quando, se viu), visto/fim do aviso por tempo, log de visualizações,
  eventos para o webhook, "Testar como cliente" (`ip.subscriber-notice.test`, inclusive a regra de
  `input` que derrubaria o portal) e as ações "Block (com página)" do lease
  (`ip.dhcp-server.lease.notice`) e do secret (`ppp.secret.notice`, vale também para login do
  RADIUS). Pesquisa em `docs/subscriber-notices.md`. Testar:
  `cargo test -p corerouter-engine --test subscriber_notice` e
  `corerouter-cli run ip.subscriber-notice.profile.add '{"name":"atraso","mode":"block","address_list":"bloqueados"}'`.

- 2026-10-26 — G4.3hb: CoA e Disconnect-Request (RFC 5176) depois de uma tomada do par de BNGs (`docs/bng-ha.md` §2.11).
  O servidor RADIUS continua mandando ao nó que conhece. Quando nenhuma sessão desse nó bate com o
  pedido e ele não é o que atende (espera, cercado, cedendo), o pedido vai ao par pelo link de sync:
  - `proto-ha`: `Msg::Forward`/`ForwardReply`, até 64 KiB;
  - o recurso vai anunciado no Hello, nos bytes reservados do cabeçalho, que a versão anterior
    ignora.

  O par aplica o pedido nas sessões dele, sem encaminhar de novo. O nó antigo responde ao servidor
  com o que o par disse (a RFC 5176 §3.3 pede a resposta do endereço para onde o servidor mandou):
  - par sem a sessão: NAK 503;
  - par mudo por 2 s: NAK 505 (Other Proxy Processing Error);
  - sem link: NAK 503 na hora;
  - retransmissão do servidor enquanto o par responde: não é encaminhada de novo;
  - até 1024 pedidos em voo.

  `radius.incoming.get` ganha `forwarded` e `forward_answered`.

  Achado no caminho: o dono das sessões PPP varria a tabela inteira a cada CoA, debaixo do lock que
  os workers dividem: 16 ms por CoA com 100 mil sessões (debug, **medido**). Agora o CoA por
  Framed-IP-Address ou por Acct-Session-Id (o que os sistemas de cobrança mandam) vai pelos índices
  que já existiam: 2,2 µs (debug, **medido**). Os outros seletores (usuário, MAC, porta) continuam
  na varredura.

  Testes:
  - `proto-ha`:
    - o Forward e a resposta atravessam o link;
    - nada vai a um par sem o recurso ou sem link;
    - o Hello com recursos é lido igual pela versão antiga.
  - `radius_aaa_tests`, com um par em memória:
    - a sessão do par recebe ACK com a palavra dele;
    - o NAK do par vai como ele disse;
    - sem par: 503;
    - par mudo: 505 depois de 2 s, e a resposta atrasada não muda nada;
    - a retransmissão não é encaminhada duas vezes;
    - o pedido do par vai só aos donos locais.
  - `pppoe_bng::a_coa_by_address_or_session_id_does_not_scan_the_table`: 100 mil sessões, CoA pelos
    índices, e os outros atributos do seletor ainda conferidos.
  - `tests/netns_ha_pppoe.rs`, dois daemons reais e 200 CPEs: depois de um switchover, 20 CoAs de
    taxa mandados ao nó antigo são aplicados no novo. Um endereço que ninguém tem dá 503, e um
    Disconnect pelo nó antigo encerra a sessão no novo.
  - Laboratório `cargo xtask bng-lab --only ha`: depois da queda, o sync e a testemunha de A voltam
    (o acesso e o uplink não). A volta como espera, e o servidor manda a ele uma rajada de 1000
    CoAs. A mesma rajada vai direto a C, para comparar.

  **Medido**:
  - Debug, `netns_ha_pppoe`: CoA no ativo, 0,19 ms. Pelo nó antigo, mediana de 40 ms e máximo de
    50 ms. São as esperas dos laços (o read de 20 ms da conexão de sync, a volta de 10 ms do laço
    principal), não trabalho. Com o par em memória, 0,25 ms.
  - VM `corerouter-lab` (8 vCPUs, release, sem root, caminho lento, 2026-10-26), rajada de 1000
    CoAs de taxa:

  | Sessões | Ao nó antigo (ACK, aplicados em C, mediana, p99, total) | Direto em C |
  |---:|---|---|
  | 1 000 | 1000/1000, 1000, 247 ms, 406 ms, 0,46 s | — |
  | 10 000 | 1000/1000, 1000, 247 ms, 410 ms, 0,46 s | 1000/1000, 1000, 208 ms, 366 ms, 0,42 s |
  | 100 000 | 1000/1000, 1000, 256 ms, 419 ms, 0,47 s | — |

  O par soma ≈ 40 ms à rajada. O limite da rajada (≈ 2200 CoAs/s) é o caminho de CoA de C, que já
  existia, e não cresce com o número de sessões depois da correção dos índices.

- 2026-10-27 — G4.10b: Avisos ao assinante, parte 2 (plano de dados), em `crates/firewall/src/notice.rs`. As cadeias
  `notice_dstnat` e `notice_forward` ficam na própria tabela `inet corerouter`, então a lista do
  perfil é o conjunto da address list. Entrar e sair da lista é um elemento, e as regras nunca
  mudam por assinante. Cada perfil ganha um salto por família e gancho
  (`notice_nat4_<perfil>`, `notice_block4_<perfil>`):

  - no modo `block`, o walled garden (`sn-garden` e os prefixos fixos) e o DNS passam; TCP recebe
    RST e o resto ICMP *administratively prohibited* na hora;
  - a porta 80 vai para o portal: todo HTTP, ou só os IPs das sondas (`sn-probe`) com
    `intercept=probes`;
  - quem viu a página (`sn-seen-<perfil>`) fica livre no aviso e na redução;
  - o endereço do próprio roteador nunca é redirecionado (`fib daddr type != local`);
  - `portal_address` troca o `redirect` por `dnat` para um endereço fixo do roteador (PPPoE pelo
    XDP).

  O modo `throttle` vira uma fila dinâmica de origem `notice` por membro, que vence a do
  lease. A taxa da sessão PPPoE/IPoE fica para a G4.10f.

  `notice_tick` só compara membros quando a config ou as listas dinâmicas mudaram. O
  `queue_sync` só monta as filas de redução quando o plano é refeito.

  Os limites de entradas de address-list estáticas e dinâmicas sobem de 65 536 para 262 144.

  Como testar:

  ```sh
  COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_notice
  ```

  Esse teste cobre:

  - o membro tem a porta 80 levada ao portal com o próprio endereço de origem;
  - o 443 é recusado em menos de 200 ms;
  - a liberação vale no próximo pacote;
  - no modo `notice`, só o IP da sonda é desviado e nada é recusado;
  - quem já viu fica livre.

  Testes do motor: `cargo test -p corerouter-engine --test subscriber_notice`.

- 2026-10-27 — G4.10c: Avisos ao assinante, parte 3: o serviço `subscriber-notice` do daemon
  (`apps/corerouter-daemon/src/service/notice.rs`).

  O portal escuta na porta 8880, em IPv4 e IPv6. Uma thread de aceite entrega cada conexão a
  4 workers por uma fila limitada a 256; com a fila cheia, a conexão fecha na hora. Cada
  requisição é tratada como hostil: cabeçalho de até 8 KB lido em até 5 s, só `GET`/`HEAD`, nada
  devolvido sem escape. O worker responde lendo o retrato (`Session::notice_snapshot`, refeito
  pelo tick a cada 2 s), sem o lock da sessão; só uma visualização de página o toma, uma vez.

  Respostas:

  - **sonda do sistema de um membro:** `302` para a página, que é o que todo SO lê como portal.
    A sonda nunca recebe 511, porque o Android trata 4xx/5xx como "sem internet".
  - **outro HTTP:** `511` com a página no corpo (RFC 6585 §6), `Cache-Control: no-store`.
  - **quem não é membro:** a resposta esperada de cada sistema (204, `Success`,
    `Microsoft Connect Test`, …), para o SO sair do estado de portal na hora.
  - **`/captive-portal/api`:** o JSON da RFC 8908.

  O serviço também cuida de:

  - opção DHCP 114 com `capport_url` (RFC 8910 §2.1: só a quem pede, e a opção 114 do operador
    tem precedência);
  - walled garden e nomes das sondas resolvidos pelo DNS do roteador a cada 5 min, gravados em
    `sn-garden` / `sn-probe` com 15 min de vida;
  - webhook com POST JSON por evento `entered`/`left`, fila de 1024 e 3 tentativas com espera
    de 1, 2 e 4 s.

  Como testar:

  - `cargo test -p corerouter-daemon --bin corerouter-daemon notice`: as 21 sondas, a página e
    o log, a resposta de quem não é membro, a API e as requisições hostis;
  - `cargo test -p corerouter-proto-dhcp capport`.

- 2026-10-27 — G4.10d: Avisos ao assinante, parte 4: a janela IP › Subscriber Notices (`crates/ui/src/subscriber_notice.rs`).
  Ela segue o padrão de lista com modal (G0.24). As abas são:

  - **Profiles:** nome, selo do modo (block vermelho, notice âmbar, throttle azul), selo da
    address list colorido pela chave, Behaviour e membros.
  - **Walled Garden.**
  - **Pages:** editor do modelo com a prévia ao lado, desenhada a partir do preenchimento do
    próprio motor (`page.preview` devolve título, parágrafos e botão já preenchidos). A página
    embutida é só de leitura e vira página nova com um nome.
  - **Active:** quem está sob um perfil, a origem, desde quando e se viu a página, com
    **Testar como cliente**.
  - **Log:** cada visualização, com o sistema que trouxe o assinante.

  Os modais de perfil e de walled garden ganham pré-visualização no motor
  (`profile.preview`, `walled-garden.preview`).

  O menu "Block (com página)" aparece nos leases do DHCP e nos secrets do PPP, com a lista de
  perfis e "Desbloquear".

  Testar: `cargo test -p corerouter-ui subscriber_notice`, `cargo test -p corerouter-engine --test
  subscriber_notice`; capturas da GUI real (Xvfb) olhadas.

- 2026-10-27 — G4.10e: Avisos ao assinante, parte 5: `apps/corerouter-daemon/tests/netns_notice.rs`, o teste de ponta a
  ponta (detalhes em `docs/subscriber-notices.md`, "Laboratório"). Ele cobre:

  - as 21 sondas, para o assinante direto e para o celular atrás do NAT da CPE;
  - o HTTPS recusado na hora;
  - o DNS liberado;
  - o 511 para outro site HTTP;
  - a página e o Log;
  - a liberação;
  - o aviso e a redução;
  - 100 mil assinantes na lista.

  Testar:

  ```sh
  COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-daemon --test netns_notice -- --test-threads 1 --nocapture
  ```

  Medidas (build de depuração, namespace):

  | Medida | Tempo |
  |---|---|
  | liberação, do comando ao próximo pedido sair | 39 ms |
  | carga de 100 mil (10 lotes de 10 000, commit e kernel) | 7,9 s |
  | sonda de um membro respondida pelo portal, com 100 mil | 10 ms |
  | HTTPS recusado | 34 µs |
  | uma entrada dinâmica entrar e sair | 31 ms |

  O roteiro manual com celular está em `plan/hw-lab.sh notice` (só imprime) e no doc.

- 2026-10-27 — G4.3hd: IPoE (G4.3f) no par de BNGs em hot standby (`docs/bng-ha.md` §2.12).

  O que entrou:
  - **Publicar.** O ativo publica cada sessão IPoE com a concessão DHCP dela (`SessionRecord` de
    `Kind::Ipoe`). Os TLVs novos `LEASE*` levam o fim, a duração, a opção 61, a opção 82, `hw` e o
    nome. O registro vai na subida e a cada renovação, e os contadores a cada 10 s.
  - **Calar o standby.** O DHCP do standby fica mudo nas portas dos servidores com sessões
    (`IpoeBackend::answering`, no engine). As portas IPoE do standby ganham `arp_ignore=8`
    (`hal-linux::ha_io::arp_quiet`): os dois nós têm o endereço do gateway.
  - **Tomar.** O nó que assume adota as sessões antes de responder. Elas ficam com o mesmo
    Acct-Session-Id, o Class, a taxa e as rotas, a entrada no XDP e um Interim com os contadores,
    sem Start. As concessões entram no servidor DHCP: `proto-dhcp` `Server::adopt`, aditivo, com
    journal. As concessões que só o nó tinha terminam. Um ARP ping a cada assinante, do endereço do
    gateway, aponta o ARP do CPE para o nó novo (RFC 826).
  - **Entregar.** Quem perde o papel encerra sem Stop (no modo stateless, com Stop).

  Achados no caminho:
  - `arp_reply` do IPoE procurava a sessão varrendo todas: O(n) por resposta, e a tomada pinga
    todos. Agora vai pelo endereço.
  - O CoA do IPoE por endereço ou Acct-Session-Id vai pelos índices, como o do PPPoE (G4.3hb).
  - Os workers do PPPoE ignoram os registros IPoE da tomada (antes contariam como "não couberam").

  Testes:
  - `proto-ha`: o registro IPoE com a concessão e um client id de 255 B, e o limite.
  - `ipoe_bng_tests::the_standby_is_silent_and_adopts_the_ipoe_sessions_with_their_leases`:
    - o standby não dá concessão nem pergunta ao RADIUS;
    - a adoção (uma vez só) faz as duas sessões, as concessões no DHCP e um ping a cada uma;
    - 700 s depois, as mesmas sessões, nenhum Start nem Stop, um Interim de cada com o mesmo id e o
      Class;
    - o nó antigo encerra sem Stop.
  - Laboratório `env BNG_LAB_HA_IPOE=1 cargo xtask bng-lab --only ha` (novo modo, uma porta, lease
    de 2 min), com a coluna nova "Todas no nó novo". As variáveis `BNG_LAB_HA_START_RATE`,
    `BNG_LAB_HA_OUTSTANDING` e `BNG_LAB_HA_ARP_S` ajustam o BNG Blaster.

  **Medido**:
  - Release, `cargo bench -p corerouter-daemon --bench ipoe_bng -- ipoe_ha`, Ryzen AI Max+ 395,
    2026-10-27:
    - adoção de 10 mil em 29,7 ms (3,0 µs/sessão) e de 100 mil em 623 ms (6,2 µs);
    - concessões no DHCP: 2,6 ms e 74 ms;
    - registro de 123 B.
  - O lock do núcleo IPoE vai em lotes de 1024 (≈ 8 ms). A primeira versão o segurava 774 ms com
    100 mil. Reservar as tabelas antes deu −8 %.
  - Laboratório na VM `corerouter-lab` (release, sem root, 2026-10-27), A perde a energia:
    - 1 000 sessões IPoE: tomada em 1,03 s, todas no nó novo em 1,14 s, 0 perdidas, 1 000 Starts,
      0 Stops, 1 000 com Interim do novo, todas renovaram no novo;
    - 3 000: 1,23 s e 1,35 s, 0 perdidas, 3 000 Interims;
    - o CoA mandado ao nó antigo, que voltou como espera, chega às sessões IPoE em C (1000/1000).

- 2026-10-27 — G2.1c: Firewall, tabela raw (`/ip firewall raw` do RouterOS): `ip.firewall.raw.{add,set,remove,move,list}`
  nas chains `prerouting` e `output`, ações `accept`, `drop`, `notrack`, `jump`, `return`, `log`,
  `passthrough` e `add-*-to-address-list`; `notrack` termina a chain (como no RouterOS) e vira
  `notrack accept` na chain base de prioridade `raw` (-300, antes do conntrack). Sem matchers de
  conexão (o validador recusa `connection_*` e `routing_mark` na raw). O aviso de lockout passa a
  conexão de gerência pela raw e, se ela leva `notrack`, testa o filter como `untracked`. Modelo
  pronto `ip.firewall.template.raw-bogons` (origens reservadas da RFC 6890 e porta 0 vindas da WAN,
  descartadas antes do conntrack; `private` acrescenta RFC 1918/6598/4193). GUI: aba Raw, assistente
  "Drop Bogons Before Conntrack", ⓘ nas abas da janela Firewall (`docs/firewall.md` §13).

  Como testar: `cargo test -p corerouter-engine --test firewall_raw`; no lab,
  `corerouter-cli run ip.firewall.raw.add '{"action":"notrack","protocol":"udp","dst_port":"53"}'`
  e IP › Firewall › Raw. Kernel real: `cargo xtask netns` (`netns_nft.rs` carrega a raw do golden).

  Desempenho (**medido**): `notrack` +5 % de pps encaminhados (1,17 → 1,24 Mpps) e drop na raw
  +32 % sobre o drop no filter (1,17 → 1,55 Mpps), 4096 fluxos UDP de 64 bytes num netns.

- 2026-10-27 — G2.7: CGNAT sem portas (G2.7). Antes, um assinante sem porta livre tinha a conexão descartada em silêncio:
  o kernel só contava `insert_failed`. Agora, pela RFC 6888 REQ-11, a conexão é descartada e o
  assinante recebe um ICMP *destination unreachable*, código 1 (*host unreachable*), que cita o pacote
  como ele o mandou (IP e porta privados). Há limite de `icmp_rate` por assinante (padrão 2/s) e de
  1000/s no roteador.

  - **Mecanismo** (`docs/cgnat.md` §1.9). A NAT do kernel nunca falha: sem porta livre ela fica com uma
    tupla em uso, e o `confirm` derruba a conexão depois de todo gancho. Por isso nem um `reject` no
    nftables nem XDP/TC enxergam a falha.
    - O tick põe no conjunto `full` quem passou de 80 % da faixa.
    - Logo depois da NAT, só as conexões novas desses assinantes vão a quatro filas (`queue num
      7423-7426 bypass`).
    - O serviço `cgnat-icmp` (uma thread por fila, sem o lock do `Session`) consulta a tupla de
      resposta no conntrack: tomada, descarta e manda o ICMP; livre, deixa seguir.
  - **Modo blocos:** a fila 7422 também responde com o ICMP quando não há bloco.
  - **REQ-8:** a quarentena de 120 s passou a ser por faixa de portas do IP público e vale também
    quando a geometria do pool muda (antes, a mudança pulava a quarentena). A busca da quarentena
    deixou de ser linear.
  - **Comandos:**
    - `ip.firewall.cgnat.set {icmp_unreachable?, icmp_rate?}`;
    - `alert.list` traz `refused`, `icmp_sent`, `icmp_limited` e `full`, e por assinante `refused`,
      `icmp` e `last_refused`;
    - uma linha `no free port: …` no log por assinante (no máximo uma por minuto);
    - janela CGNAT › Alerts com selos, coluna Refused e ⓘ.
  - **Como testar:**
    - `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_cgnat icmp`:
      10 fluxos além das 64 portas dão 10 recusas e exatamente 5 ICMP (a rajada), cada um com o IP e a
      porta privados; o vizinho com portas sai normalmente;
    - `cargo test -p corerouter-engine --test cgnat_blocks`.
  - **Números (medido, 2026-10-27):**
    - custo no caso normal: dentro do ruído (280 557 × 285 774 conexões novas/s, sem × com a chain);
    - latência até o ICMP: 125 µs;
    - tempestade: 188 mil recusas/s atendidas sem perda;
    - 14 ICMP em 20 mil recusas.

- 2026-10-27 — G3.1: FRR como motor de roteamento. A cada commit que muda `routing`, o `hal-frr` faz três coisas.
  Primeiro, renderiza a config pelos `proto-*`. Depois, lê o que cada daemon roda (`show
  running-config` no socket `/var/run/frr/<daemon>.vty`). Por fim, digita só a diferença entre
  `XFRR_start_configuration` e `XFRR_end_configuration`, com os daemons em paralelo. Se o FRR
  recusar uma linha, o que foi digitado é desfeito, o engine desfaz o `Hal::apply` e o commit
  falha com a linha e a mensagem do FRR. Não há processo externo e o FRR nunca é reiniciado:
  sessões que o commit não muda continuam de pé.

  O que entrou:
  - O diff é contra a config que o daemon roda, então o mesmo caminho ressincroniza depois de um
    restart do FRR. O serviço `frr` percebe o restart pelo PID dos daemons, mesmo quando ele cabe
    entre duas leituras.
  - Estado: `routing.bgp.session.list` (campos do `/routing bgp session print` do RouterOS v7) e
    `routing.backend.get`. Os dois vêm da amostra que o serviço lê a cada 2 s numa thread
    própria, fora do lock do `Session`. No laboratório virtual a lista fica vazia.
  - O trait `RoutingDaemon` recebe configs inteiras, então um backend mgmtd ou holo (G3.8) cabe
    sem mudar engine, comandos, UI ou MCP.
  - Instâncias com nome diferente de `default` viram `router bgp <AS> view <nome>` até a G3.2
    dar VRF às instâncias.
  - RFC 8212: o `bgp ebgp-requires-policy` do FRR fica ligado.
  - Para a G3.2: um filtro compartilhado (prefix-list, route-map) vai ao mgmtd, com `configure
    terminal file-lock`, e a cada daemon de roteamento ainda não convertido. Esquecer um daemon
    deixa uma cópia velha que o `vtysh` esconde.

  Como testar:
  - `cargo test -p corerouter-hal-frr` e `cargo test -p corerouter-engine routing`.
  - Com FRR real, na VM (root só lá dentro): `cargo xtask vm-lab run -- scripts/frr-live.sh`. O
    script sobe um par BGP num namespace e confere quatro coisas:
    - a sessão estabelecida segue de pé depois de acrescentar e tirar 2000 entradas de
      prefix-list e um vizinho;
    - o rollback de um comando recusado volta exatamente à config anterior;
    - a render é canônica (o diff de volta é vazio);
    - de ponta a ponta, o daemon com `--frr` leva um commit da CLI ao bgpd e reinstala a config
      depois de `systemctl restart frr`.
  - Comparação das formas de falar com o FRR: `cargo xtask vm-lab run -- scripts/frr-compare.sh`.

  Números (**medidos**, FRR 10.7.1, VM do laboratório com 8 vCPUs, release):

  | Medida | socket vty em Rust | `frr-reload.py` / `vtysh -c` |
  |---|---|---|
  | mudança pequena | 1,1–7,2 ms | 0,14–0,98 s |
  | 10 mil entradas de prefix-list | 1,65–1,77 s | 3,7–4,1 s |
  | ler 100 sessões | 2,3–2,6 ms | 10–12 ms |

  - O apply em paralelo (um thread por daemon) tirou 50–65 % do tempo da mudança grande.
  - A memória do processo que aplica ficou em 4–16 MiB, contra 18–36 MiB.

- 2026-10-27 — G1.6a: Imagem do sistema, parte 1: a imagem que boota. `os/` é uma árvore `BR2_EXTERNAL` do Buildroot
  2025.02.19 (LTS, fixado por versão e SHA-256 em `os/buildroot.lock`), com toolchain Bootlin
  glibc, kernel 6.18.59 LTS (SHA-256 do `sha256sums.asc` assinado do kernel.org, conferido pelo
  Buildroot e de novo pelo xtask) e tudo que o roteador usa compilado dentro: eBPF/XDP com BTF,
  nftables completo, VRF, MPLS, bonding, VLAN, bridge, PPPoE, WireGuard, filas e as placas
  ixgbe/i40e/iavf/ice/mlx5/virtio. O `cargo xtask os build` confere que os 154 `=y` do fragmento
  sobreviveram (pegou dois na primeira rodada: `SQUASHFS_DECOMP_MULTI_PERCPU` e `IAVF`, que no
  6.18 se ligam por outros nomes). Disco GPT com GUIDs fixos: ESP com o kernel como
  `BOOTX64.EFI` (sem bootloader), `rootfs-a` squashfs zstd só de leitura, `rootfs-b` vazio para o
  G1.6b e `config` ext4. O PID 1 é o crate novo `apps/corerouter-init` (Rust, sem `unsafe`):
  monta o sistema, sobe o `lo` por netlink, monta `/config` (tmpfs com aviso se faltar), supervisiona
  o daemon com backoff, registra quando o canal de controle responde e a memória ociosa, e
  desliga limpo pelos sinais do busybox `reboot`/`poweroff`. Sem shell, a não ser com
  `corerouter.shell=ttyS0` na linha de comando do kernel. Pesquisa (MikroTik, VyOS, Junos,
  Talos, Flatcar, RAUC × atualizador próprio) e decisões em `docs/os-image.md`.

  Como testar: `cargo xtask os build` (frio: 15 min e ~360 MB de download na primeira vez),
  `cargo xtask os boot-test` (KVM do usuário, sem root; `--tcg` sem KVM; `--efi` pelo OVMF e o disco
  inteiro) e `cargo xtask os check` (também roda no `cargo xtask ci`, pelo teste
  `os_tree_is_consistent`, sem baixar nada).

- 2026-10-27 — G2.1c: Firewall, diagnóstico (PR 2 de 2, sobre a tabela raw):

  - **Testador** `ip.firewall.test`. Mostra o caminho de um pacote inventado pela raw, mangle, NAT,
    decisão de rota e filter, na ordem das prioridades do netfilter (`corerouter_firewall::path`).
    Mostra também as regras casadas e a que decide. O modelo inclui `notrack` (vira `untracked`), NAT
    só no primeiro pacote e `dst-nat` antes da rota, com `connection-nat-state=dstnat` depois. Usa a
    config candidata, ou a em execução com `running`.
  - **Contadores ao vivo.** São `ip.firewall.counters` e as colunas Packets/Bytes/Rate/Last Used.
    - O serviço `fw-diag` do daemon faz **um** dump nfnetlink da tabela, fora do lock e só enquanto
      alguém olha (a cada 2 s, no máximo).
    - Os totais continuam depois de um commit.
    - Uma regra sem uso há 30 dias ganha o selo `stale`.
    - `ip.firewall.<tabela>.reset-counters` zera a contagem.
  - **Rastreio de pacote real** `ip.firewall.trace.*`. Liga `meta nftrace` numa tabela própria, com
    filtro obrigatório, até 20 pacotes/s marcados no kernel, prazo de até 300 s e teto de até 10 000
    eventos. Os eventos `NFT_MSG_TRACE` são mapeados para as nossas regras.
  - **Prévia** `ip.firewall.preview`. É o diff do ruleset que o próximo commit carrega, com o
    `config.diff` ao lado.
  - **GUI.** Abas Test e Diff, colunas de contadores com ⓘ e Reset Counters (`docs/firewall.md` §14).

  Como testar: `cargo test -p corerouter-engine --test firewall_diag`; kernel real:
  `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_fw_diag`
  (contadores contam pacotes de verdade e batem com `nft -j`; o trace mostra o handle e o `drop` da
  regra). No lab: IP › Firewall › Test.

  Desempenho (**medido**): `test` com 10 000 regras em 122 µs; contadores de 10 000 regras em
  10,7 ms por nfnetlink, contra 190 ms com `nft -j` (17,7×).

- 2026-10-27 — G2.7: CGNAT, aba Capacity (G2.7b). Mostra quantas portas os assinantes usam de verdade e sugere
  `ports_per_subscriber`.

  - **Cartões:**
    - limite e assinantes por IP público;
    - pico p99 dos 7 dias com o %;
    - quantos bateram no limite em 24 h, com recusas e ICMP enviados.
  - **Distribuição** do pico por faixa.
  - **Sugestão:**
    - p99 + 25 %, em múltiplos de 64, nunca abaixo de 320;
    - 1,5 × o valor de hoje quando mais de 1 % ficou sem porta;
    - mostra o ganho em assinantes por IP e os IPs necessários.
  - **Prévia** (`ip.firewall.cgnat.capacity.preview`): remapeados, conexões derrubadas e se cabe, sem
    mudar nada.
  - **Aplicar com Safe Mode**, só depois da prévia do mesmo valor.
  - ⓘ em português em cada cartão, na distribuição, na sugestão e no aplicar.

  A leitura do conntrack para o CGNAT saiu do lock do `Session`:

  - o serviço novo `cgnat-scan` do daemon lê a tabela uma conexão por vez (`Hal::conntrack_scanner`);
  - monta um vetor ordenado de 12 bytes por conexão;
  - só depois pega o lock;
  - os picos de 7 dias (anel de 20 bytes por assinante) e as recusas por hora vão ao journal
    `journal-cgnat-capacity.log` a cada 10 min e voltam no boot.

  **Como testar:**

  - `cargo test -p corerouter-engine --test cgnat_capacity`;
  - `cargo test -p corerouter-ui cgnat`;
  - na GUI com o laboratório, IP › Firewall › CGNAT › Capacity.

  **Números (medido, 2026-10-27, 64 Ki assinantes, 1,3 milhão de conexões):**

  - montar o uso fora do lock: 51 ms (antes, com conjuntos e dentro do lock: 75 ms);
  - lock segurado: 5,6 ms;
  - consulta: 4,1 ms;
  - picos: 2,8 MiB.

- 2026-10-27 — G1.26h: Tuning › Boot na imagem A/B. `system.tuning.boot.apply {confirm?, timeout?, reboot?, drill?}`
  põe na fila a cópia da imagem em uso para o slot inativo (kernel + rootfs conferidos contra o
  manifesto assinado; pulada quando o slot já tem a mesma imagem) e grava os parâmetros de
  `system.tuning.boot` na linha de comando da entrada UEFI desse slot, que boota em teste. A linha
  do slot em uso não muda; um parâmetro que impede o boot (pânico, `panic=10` sempre por último)
  volta sozinho ao slot anterior. `drill=true` acrescenta um `init=` que não existe: prova a volta
  numa caixa real. `system.tuning.boot.parameter.print` traz `image_ab`, o motivo quando não há, e
  `slots` (os parâmetros de cada slot); a aba Boot mostra os dois slots e o botão "Apply on slot X
  and reboot". Uma atualização (System › Packages) também leva os parâmetros ao slot novo.

  Como testar: `cargo xtask os ab-test --scenario bad-param` (QEMU: `intel_idle.max_cstate=1` +
  drill, o kernel de B entra em pânico e A volta em 11,6 s, **medido**); clonar o slot: 39 ms de
  gravação e 13 ms de conferência.

- 2026-10-27 — G1.6b: Imagem A/B e atualização segura. Cada slot boota pela sua entrada UEFI (`Boot####` com
  `dm-mod.create`: raiz por dm-verity, sem initramfs); o teste é um `BootNext` (o firmware o apaga
  ao usar: qualquer falha volta ao slot confirmado); confirmar reescreve o `BootOrder`. Pacote
  `.crpkg` com manifesto assinado (Ed25519; a imagem só leva a chave pública, a privada fica fora
  do repositório, `os/out/keys/` em desenvolvimento), gravado em fluxo com SHA-256 no caminho e
  relido do disco com a árvore do verity recalculada. A configuração é copiada (com o
  `format_version`) antes da troca e volta sozinha num teste que falha; um downgrade boota a cópia
  do slot antigo. Comandos `system.package.print/update/downgrade/confirm/cancel/check/scrub`
  (confirmação `auto`: daemon de pé há 10 s e as interfaces de gerência rodando; `manual`: pelo
  operador, prazo de 30 a 3600 s). Janela System › Packages. Laboratório virtual com o mesmo
  código (`--backend virtual --config-dir`). ESP passou de 32 para 128 MiB (dois kernels).
  `docs/os-image.md` ("A/B e atualização segura"), `docs/architecture.md` §1.1.2.

  Como testar: `cargo xtask os build && cargo xtask os ab-test` (QEMU como usuário, OVMF): A→B
  confirmado; B que não confirma volta para A com a config; pacote de chave desconhecida e pacote
  adulterado recusados; parâmetro de boot que impede o boot volta sozinho. 4 cenários, 13 boots,
  94,5 s (**medido**, KVM). `cargo test -p corerouter-sysupdate` faz o ciclo inteiro em diretório.

  Números (**medidos**, KVM, 2026-10-27): pacote 34,1 MiB; gravar 36–53 ms; reler e conferir
  12–17 ms; `update` inteiro 115–143 ms; daemon pronto 0,70–0,73 s depois do kernel com verity
  (0,72 s sem); teste confirmado 14,5 s depois da partida do QEMU (10 s de carência).

- 2026-10-27 — G2.8: Firewall por nfnetlink, sem o programa `nft`. O mesmo `build` do texto de "Ver regras" monta
  `program::Table` (expressões da VM do nf_tables em `corerouter_firewall::bytecode`, byte a byte
  iguais às do `nft --debug=mnl`), e o `hal-linux` (`firewall.rs`) aplica num lote atômico:

  - **commit por diferença:** lê os handles do kernel (`nft_read.rs`), confere que a tabela é a que
    carregamos e manda só as regras que saíram/entraram (diff de Myers por chain, `NEWRULE` com
    posição), elementos, chains e sets que mudaram; regra igual mantém handle e contadores;
    tabela mexida por outro → troca inteira, com as entradas dinâmicas relidas e recolocadas;
  - **entradas dinâmicas** (`address-list.add timeout=…` e `address_list_dynamic_many`): um lote de
    `NEWSETELEM`/`DELSETELEM`; sobreposição recusada pelo kernel → o set é lido, mesclado e
    reescrito num lote;
  - **leitura** (`nft_read.rs`): chains, sets, elementos e regras decodificados de volta para
    `program`; substitui o `nft -j`, e a imagem perde o jansson;
  - listas de portas viraram sets nomeados compartilhados (`ports_22_80_443`) e `ct state {a, b}`
    virou máscara (`ct state a,b`): um set anônimo por regra custava ao kernel O(sets) cada;
  - `nfnl.rs`: ACK só na última mensagem do lote (um ACK por mensagem estourava o buffer com
    milhares de mensagens: ENOBUFS), sets anônimos com nome explícito, ordem de atributos do nft.

  Testes: `cargo test -p corerouter-firewall` (vetores do bytecode), `cargo test -p
  corerouter-hal-linux --lib firewall_messages` (20 mensagens iguais às do nft), e em netns
  (`cargo xtask netns`): `netns_fw_nfnl.rs` carrega a mesma config pelo `nft -f` e por nós e compara
  o que o kernel guarda e o `nft list`; commit por diferença preserva handles; 1 000 entradas
  dinâmicas, sobreposição, IPv6; proptest de regras aleatórias (render → nfnetlink → leitura →
  igual, e igual ao que o nft carrega).

  Números (**medido**, abaixo): 10 000 regras carregam em 112 ms (antes 4,09 s), mudar uma em
  109 ms (antes 6,91 s), 100 000 entradas dinâmicas em 116 ms (antes um processo `nft` por entrada:
  2,4 s por 1 000; num script só, nem cabia no buffer).

- 2026-10-27 — G3.2a: BGP, parte 1 (`docs/bgp.md`). Templates (`routing.bgp.template.*`) e conexões
  (`routing.bgp.connection.*`) no modelo do RouterOS v7, com herança de vários templates (laço e
  template inexistente recusados), AS de 4 bytes, `local.role` com os papéis da RFC 9234,
  multihop, hold/keepalive (RFC 4271 §4.2/§10), chave TCP MD5 selada (nunca em config, journal,
  logs ou MCP), max-prefix por família com ação (`shutdown`, `warning`, `restart`), `afi`
  IPv4/IPv6, local address e nexthop-choice. Validação: AS reservado (0, 23456, 65535,
  4294967295), conexão sem família, template inexistente, laço de herança, iBGP com AS de fora,
  endereço repetido. `routing.bgp.session.list` traz o nome da conexão, os timers negociados, o
  último erro, as quedas, o BFD, as famílias e as políticas; `routing.bgp.session.refresh`,
  `resend` e `clear` agem na sessão. O render vai ao FRR pelo `hal-frr` só com a diferença: o diff
  agora define um vizinho novo antes das linhas dele nas famílias e remove um vizinho com um
  comando só. Janela Routing › BGP com as abas Sessions (detalhe e ações), Connections, Templates
  e Instances, no padrão de lista G0.24, com ⓘ em português.

  Como testar: `cargo test -p corerouter-proto-bgp -p corerouter-hal-frr -p corerouter-model`,
  `cargo test -p corerouter-engine routing_bgp`, `cargo test -p corerouter-ui bgp`; com FRR real,
  `cargo xtask vm-lab run -- scripts/frr-live.sh` (dois pares: eBGP e iBGP com MD5 e 20
  prefixos). Na GUI: Routing › BGP.

  Números (**medido**, 2026-10-27): no FRR 10.7.1 real da VM (8 vCPUs, nosso lado em debug),
  1 000 conexões aplicadas em 329 ms (5 006 comandos), uma mudada entre 1 000 em 28 ms (3
  comandos), todas removidas em 197 ms, leitura de 1 000 sessões em 135 ms fora do lock. No
  engine (release, criterion), mudar uma conexão entre 1 000 passou de 8,1 ms para 1,5 ms por
  commit com a seção `routing` em `CowArc` e o delta do histórico por conexão.

- 2026-10-27 — G1.27d: Vizinhos ARP/ND, parte a. O `hal-linux` lê a tabela de vizinhos por um socket rtnetlink
  síncrono (sem o crate `rtnetlink`/tokio): dump `RTM_GETNEIGH` das duas famílias e eventos do
  grupo `RTNLGRP_NEIGH`. O serviço `neighbors` do daemon (thread própria, sob o supervisor) aplica
  cada evento na tabela do motor, que tem trava própria (O(1) por mudança, nunca o lock do
  `Session`); `ENOBUFS` dispara um dump novo. Comandos: `ip.arp.list` e `ipv6.neighbor.list`
  (página no motor, busca por IP, CIDR, prefixo de MAC ou texto, filtros por interface, estado e
  origem, contagens da tabela inteira, uso × `gc_thresh3`), `ip.arp.add/set/remove` (journal e
  rollback), `ip.arp.make-static`, `ip.arp.flush`/`ipv6.neighbor.flush` (nunca o gateway de rota
  ativa nem o vizinho da gerência), `ip.arp.ping` (tarefa), `ip.arp.settings.print/set` (modos
  `enabled`, `disabled` = `IFF_NOARP`, `reply-only`, `proxy-arp`, `local-proxy-arp`, e
  `arp_timeout`; os arriscados pedem `confirm`, e cortar a gerência é recusado como lockout).
  `ip.route.list`/`page`/`detail` dizem `gateway_status = incomplete` quando o gateway não resolve
  (o kernel só avisa quando desiste, ~3 s: 3 solicitações × 1 s, RFC 4861 §10). Log com o tópico
  novo `arp`: "changed MAC" e "flip-flop" (arpwatch), e o aviso de 80 % do `gc_thresh3` com
  sugestão. Laboratório virtual coerente (`hal::lab_neigh`). Pesquisa em `docs/arp.md`.

  Como testar: `cargo test -p corerouter-engine --test arp`; em namespace,
  `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p
  corerouter-hal-linux --test netns_neigh` (5000 vizinhos, eventos, `apply` real de estáticos e
  modos, ARP ping contra um host noutro namespace). No laboratório real (`plan/lab-real.sh`,
  daemon `--backend linux`): o cliente aparece `stale`/`reachable` pelo feed, a rota por um
  gateway inexistente vira `incomplete`, trocar o MAC do cliente gera "changed MAC" no log,
  `reply-only` com o cliente estático continua pingando, ARP ping responde em ~0,05 ms (**medido**).

- 2026-10-27 — G4.4j: Log de NAT do CGNAT em IPFIX e transporte confiável do Traffic Flow:

  - **RFC 8158 do CGNAT:** blocos alocados e liberados (`natEvent` 16/17) com `natPoolId`, `vlanId`
    e `userName` (login PPPoE/IPoE pelo índice por endereço, fora do lock da sessão); pool sem bloco
    (3), assinante sem portas (13, cota por usuário, junto do ICMP do G2.7) e assinante acima do
    alerta (18, limiar por usuário), um por minuto por pool ou assinante (§5.2). Os templates seguem
    as Tabelas 5, 9, 13, 18 e 21, que viraram testes; o registro de bloco é conferido byte a byte.
  - **Fila própria no engine** (`nat_log.rs`, 262 144 eventos, descarte contado): antes os blocos
    vinham do log do roteador, cuja janela recente tem 1024 linhas.
  - **Comandos:** `ip.traffic-flow.set` ganhou `flows`, `nat_port_blocks`, `nat_limits` (e
    `nat_events` passou a vir desligado, como no RouterOS); `ip.traffic-flow.target.*` ganhou
    `transport` sctp/tls, `content` all/nat/flows, `nat_events_legacy`, `certificate`,
    `private_key` (secreta), `ca_certificate`, `server_name`; `records` aceita `type: nat-limit`; o
    CSV ganhou `user,vlan,pool,limit`. PEM colado numa linha só é reconstruído (RFC 7468 §2).
  - **Daemon:** cada coletor TCP/SCTP/TLS tem a thread `tf-send-<id>` com fila de 8 MiB; templates
    primeiro em toda conexão nova, com a sequência da mensagem seguinte; `src_address` também no
    TCP/SCTP/TLS (bind pelo `socket2`); sem fluxos nem sessões o conntrack nem é lido. O serviço
    `cgnat` serve os primeiros pacotes em lote: um lock e um `fdatasync` do journal por lote, e as
    filas do nfqueue pedem 4096 pacotes (a 7422 ficava no padrão de 1024).
  - **Janela:** IP › Firewall › CGNAT › Logging (interruptores com o `natEvent` de cada um, os
    coletores de NAT com transporte, conteúdo e códigos, aviso quando algum não é TLS, "Add
    Collector" abre o destino já em TLS/NAT/4740); IP › Traffic Flow com os campos novos. ⓘ em
    português e inglês.

  Como testar:

  ```sh
  COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-daemon --test netns_nat_ipfix -- --nocapture
  cargo test -p corerouter-proto-flow --test tshark_interop
  cargo bench -p corerouter-engine --bench cgnat_pba_storm
  ```

  O teste netns liga um CGNAT em blocos, três coletores (SCTP; TLS com certificados de uma CA de
  teste e autenticação mútua; UDP legado só NAT) e confere blocos, pool esgotado com limite de taxa,
  sessões 4 e 1, sequência sem buraco e uma tempestade de 20 mil assinantes. Precisa dos módulos
  `sctp` e `nfnetlink_queue` no host (`ci/kernel-modules/`).

  Desempenho e paralelismo (**medido**, release, AMD Ryzen AI MAX+ 395, kernel 7.0, 2026-10-27):
  100 mil eventos de criação NAT saíram pelo TCP 0,38 s após a rajada (~260 mil eventos/s), 1,6 µs de
  CPU por registro, sem descarte; tempestade de 20 mil blocos com 24 µs de CPU do daemon por bloco;
  alocação no engine 11 → 4,4 µs por bloco; group commit 632 → 3 411 blocos/s no build de teste.

- 2026-10-27 — G1.27d: Vizinhos ARP/ND, parte b: a janela IP › ARP (item próprio no menu, como no MikroTik; "IP ›
  Neighbors" segue sendo a descoberta LLDP/MNDP, decisão do usuário), com as abas ARP (IPv4), ND
  (IPv6) e Settings; IPv6 › Neighbors abre a lista ND. Barra + − ✓ ✗ 💬 para as estáticas e Make
  Static, ARP Ping e Flush (com confirmação); selos de estado e de interface com as contagens da
  tabela inteira que filtram com um clique; busca por IP, CIDR, prefixo de MAC ou texto feita no
  motor; página de 500 com ◀ ▶. Selo de identidade (G0.25, lugar `arp`) mostra o nome pela concessão
  DHCP ou pelo PTR das zonas locais. Clique numa linha abre o detalhe (`ip.arp.detail`: histórico
  de MACs, rotas que usam o vizinho, endereço do roteador na rede) com Make Static, Add to Address
  List, ARP Ping, Ping e Torch. Rodapé: vizinhos, estáticas/dinâmicas e "tabela do kernel X /
  gc_thresh3 Y", âmbar com sugestão a partir de 80 %. Aba Settings: modo `arp` e `arp_timeout` por
  interface (os arriscados confirmam) e os `gc_thresh` com atalho para System › Tuning. Modal de
  adicionar/editar com pré-visualização `ip.arp.check` (MAC de grupo, endereço do roteador, fora da
  rede da interface, host respondendo hoje com outro MAC). ⓘ em português em colunas, abas, campos
  e botões. Correções do laboratório: o serviço girava sem dormir com o feed do lab (CPU alta) e o
  "Last Seen" usava o relógio errado.

  Como testar: `cargo test -p corerouter-ui -- tests::arp`; GUI com o daemon do lab, IP › ARP.
  Screenshots claro/escuro na pasta de notas (`G1.27d-screenshots`).

- 2026-10-27 — G1.27d: Vizinhos ARP/ND, parte c: `ip.dhcp-server.add/set add_arp` (RouterOS `add-arp`, padrão não).
  Cada concessão vinculada por um servidor com `add_arp` vira uma entrada ARP permanente na
  interface do servidor, por uma operação O(1) no data plane (`Hal::neighbor_static`: um
  `RTM_NEWNEIGH` por concessão, nunca um apply inteiro), e sai quando a concessão termina (expira,
  é liberada ou removida) ou quando o servidor deixa de pedir (`add_arp` desligado, servidor
  removido, rollback). `ip.arp.list` mostra a origem `dhcp` (RouterOS flag H) e o filtro
  `source=dhcp`; a janela IP › ARP pinta o selo de verde e conta no rodapé. Com `arp=reply-only` na
  interface, é o antispoofing do RouterOS: só quem pegou concessão alcança o roteador (como o
  Dynamic ARP Inspection do Cisco com DHCP snooping). A opção "Add ARP For Leases" entrou no
  diálogo do servidor DHCP.

  Como testar: `cargo test -p corerouter-engine --test dhcp_server add_arp`.

  Corrigido também o teste `netns_neigh` (instável: 1000 entradas aprendidas perto do `gc_thresh3`
  de 1024 faziam o kernel recusar a entrada `incomplete` que o teste espera; agora são 200 e o teste
  espera a entrada com novas tentativas, 5 de 5 rodadas verdes, **medido**).

- 2026-10-27 — interfaces-lista: Interfaces: lista com ícones de tipo, estado em selo, resumo da seleção e
  colunas escolhidas pelo operador e guardadas nas preferências locais. Os
  contadores, gráficos e comentários em faixa continuam disponíveis. Para testar,
  abra Interfaces, escolha Columns, oculte MTU e reabra a GUI; teste também Inline
  Comments e os temas claro e escuro. O resumo usa consultas existentes da interface
  selecionada; disponibilidade depende da plataforma.

- 2026-10-27 — G1.27d: Vizinhos ARP/ND, parte d: o fabricante de cada MAC. A lista pública MA-L do IEEE (`oui.csv`,
  baixada em 2026-10-27, SHA-256 `e1a07d9a…5f24`, 3,9 MB) vira uma tabela compacta embutida
  (`crates/model/data/oui.bin`, 709 079 bytes, 40 410 atribuições, **medido**): registros de 6
  bytes ordenados (prefixo + deslocamento do nome) e nomes sem repetição, procurados por busca
  binária direto nos bytes. `cargo xtask oui <oui.csv> --date …` a gera. O usuário decidiu embutir
  com base na declaração do IEEE citada pelo Debian (`docs/third-party.md`). `ip.arp.vendors.update`
  pede ao serviço `oui` do daemon que baixe a lista atual (TLS conferido, até 16 MB, parser com
  proptest, troca atômica: arquivo temporário + rename em `<config-dir>/oui.bin`); a baixada vale
  mais que a embutida e é recarregada no início. `ip.arp.vendors.print` diz qual está em uso, a
  data e o SHA-256; a aba Settings de IP › ARP mostra isso e o botão "Update vendors". A coluna
  Vendor de IP › ARP passa a ter o nome, e a busca por texto acha pelo fabricante. Endereços
  localmente administrados ou de grupo não têm fabricante (bits U/L e I/G).

  Como testar: `cargo test -p corerouter-model oui`, `cargo test -p corerouter-engine --test arp
  vendors`; daemon com `--config-dir` e um DNS (`ip.dns.set servers=1.1.1.1`), depois
  `ip.arp.vendors.update` e `ip.arp.vendors.print`. Conferido assim: 40 414 atribuições baixadas,
  `oui.bin` gravado e ainda em uso depois de reiniciar o daemon (**medido**).

- 2026-10-27 — interfaces-refino: Interfaces: gráficos de tráfego mais largos usam a largura disponível a partir da
  primeira amostra conhecida, sem ligar as lacunas internas; ponto único aparece e
  sem dados não se inventa linha. A legenda informa Rx/Tx e até cinco minutos.
  Cabeçalhos ganham espaço para ⓘ; resumo da interface selecionada separa estado,
  enlace, duplex, MTU e taxas quando informadas. Comentários mantêm a faixa e as
  interações existentes. Testar: abrir Interfaces no lab, selecionar uma porta,
  comentar e ativar Inline Comments; verificar temas claro/escuro e ocultar Traffic.

- 2026-10-27 — G1.6c: Instalador e imagens de VM (G1.6c). `cargo xtask os build` agora grava também
  `corerouter-install.iso` (ISO 9660 + El Torito UEFI + GPT híbrida, escrita em Rust por
  `corerouter-image installer`: serve de CD e de pendrive), `corerouter.qcow2` e `corerouter.ova`.
  A ISO boota um segundo kernel (`os/package/corerouter-installer`: o mesmo kernel e `.config`,
  outra linha de comando, initramfs embutido com o `corerouter-init`, sem BTF); o instalador acha a
  mídia, confere o índice e o pacote (Ed25519), lista os discos (nunca oferece a mídia, o drive
  óptico, disco pequeno ou só de leitura), exige o nome do disco digitado, grava ESP, slot A e
  `/config` em fluxo, relê tudo (SHA-256 e árvore do dm-verity), escreve a GPT por último e cria a
  entrada `Boot####` "CoreRouter A" primeiro no `BootOrder`. Opções: manter a configuração de um
  CoreRouter instalado e um endereço de gerência para o primeiro boot (`corerouter.mgmt=`, aplicado
  uma vez por comandos). Sem endereço em nenhuma porta, o console oferece o assistente de primeiro
  boot (porta, endereço, gateway, senha do admin). FRR 10.3 do Buildroot entra na imagem; o init
  sobe os 8 daemons que o hal-frr usa e o daemon recebe `--frr /var/run/frr`; vtysh, bash, readline e
  ncurses ficam fora (sem GPL-3.0 na imagem). Núcleo em `crates/sysupdate/src/{gpt,iso,install}.rs`
  (testado sobre arquivos), docs em `docs/os-image.md` ("Instalador, imagens de VM e FRR").

  Como testar: `cargo xtask os build && cargo xtask os install-test` (instala de CD e de USB num
  disco virtual de 2 GiB, boota pelo disco: dm-verity, ping TLS no endereço de gerência, 8 sockets
  do FRR, BGP aplicado e lido do bgpd; reinstala mantendo a config; instalação interativa pela serial
  recusando a mídia e um nome errado; qcow2 com o assistente de console e ping TLS; OVA).

  Números (**medidos**, KVM, 2026-10-27): instalar 0,1–0,3 s (104 MiB gravados em 70–130 ms, relidos
  em 30–38 ms), QEMU ligado → desligado 2,1–3,3 s; ISO 96,2 MiB, qcow2 38,9 MiB, OVA 38,8 MiB;
  squashfs 19,3 MiB (+4,5 MiB do FRR), memória ociosa 93–98 MiB (era 48–58); kernel → daemon
  0,76–0,82 s e → FRR 0,77–0,78 s; `install-test` 33 s.

- 2026-10-27 — G3.2c: BGP, parte 3 (`docs/rpki.md`), mais o que faltava do G3.3.

  - **RPKI.** `routing.rpki.add/set/remove/list/preview` no modelo `/routing rpki` do RouterOS v7
    (endereço, porta 323, grupo, refresh/retry/expire com os limites da RFC 8210 §6, preferência).
    O render põe o nó `rpki` do FRR e o route-map `CR-RPKI-IN` (`match rpki invalid` → deny) com
    `soft-reconfiguration inbound` nos vizinhos iBGP; em eBGP só junto da política da G3.2b, para
    não furar o RFC 8212. Inválidas descartadas por padrão assim que existe um validador, com aviso
    no `add`, na prévia e na janela, e interruptor por conexão ou template
    (`routing.rpki.invalid.set`). Cliente RTR próprio (`proto_bgp::rtr`, sans-IO; serviço `rpki`
    do daemon, uma thread por validador): versão 1 com volta para a 0, Reset/Serial Query, Serial
    Notify, Cache Reset, troca de Session ID, timers e expiração; `routing.rpki.session.list`
    mostra estado, versão, Session ID, serial, VRPs por família e o estado do próprio bgpd.
    `routing.rpki.check` é o `rpki-check` do RouterOS. Validação RFC 6811 (com RFC 8481, RFC 6483
    §4/RFC 7607 para AS 0) numa árvore Patricia por família.
  - **Rotas por conexão.** `routing.bgp.route.list {connection, direction}`: o `hal-frr` lê
    `received-routes`/`advertised-routes`/`routes json` do bgpd em streaming para uma tabela
    compacta (24 B por rota, atributos internados), num job do runner fora do lock; o engine guarda
    até 4 tabelas ordenadas e validadas, e pagina e busca por prefixo (exact, longer, orlonger,
    covering), AS path (`^`/`$`), community, estado RPKI e recusadas (`filtered`).
    `routing.bgp.route.summary` dá a porcentagem de cada estado por sessão.
  - **"Por que essa rota?"** `routing.bgp.route.explain {prefix}`: todos os caminhos, o escolhido e
    o passo da decisão (ordem do `bgp_path_info_cmp` do FRR 10.x, com a seção da RFC 4271 §9.1 /
    RFC 4456 §9 em cada passo) que deixou cada um para trás, com os dois valores; avisa quando a
    escolha do daemon não se reproduz passo a passo.
  - **Histórico de quedas** (`routing.bgp.session.history`): down/up/flap das amostras de 2 s, com
    o motivo e quanto tempo esteve de pé; anel de 64 por sessão.
  - **GUI.** Routing › RPKI (lista G0.24 com modal e prévia, política, `RPKI Check`) e Routing ›
    BGP Routes (Received, Advertised, History; selos RPKI por linha, barra com a porcentagem de
    cada estado, páginas de 500, busca; modal "Why this route?" com o passo de cada caminho e a
    ordem dos passos, cada um com ⓘ em português). Botões Routes/History no detalhe da sessão
    (Routing › BGP) e "Why this route? (BGP)" no detalhe de IP › Routes.
  - **VM.** `xtask/src/vm_tools.rs` declara `frr-rpki-rtrlib` 10.7.1 (hash do `Packages` assinado)
    e `librtr0t64`; `scripts/frr-rpki-live.sh` é o teste com FRR real (validador local
    `rtr_server`, dois vizinhos iBGP: inválida descartada, explain por local-pref, interruptor,
    histórico).

  Como testar: `cargo test -p corerouter-proto-bgp -p corerouter-hal-frr`, `cargo test -p
  corerouter-engine routing_rpki routing_bgp_route bgp_history`, `cargo test -p corerouter-ui
  bgp_routes`, `cargo test -p corerouter-daemon rpki` (RTR por TCP com o servidor de teste); com
  FRR real, `cargo xtask vm-lab run -- scripts/frr-rpki-live.sh`. Na GUI: Routing › RPKI e
  Routing › BGP Routes.

- 2026-10-27 — G3.2c: RPKI e rotas BGP na GUI, no mockup aprovado (continuação do #315): as janelas Routing › RPKI e
  Routing › BGP Routes viraram as abas RPKI e Routes da janela Routing › BGP. O detalhe da sessão
  tem três colunas: erro e timers; "RPKI In" com os selos `valid`/`unknown`/`invalid` em
  porcentagem (verde, amarelo e vermelho) e as políticas; quedas e os links "received routes ·
  advertised · history · why this route?". Sem a tabela lida, "RPKI In" oferece "read the
  routes". O modal "Why this route?" aceita digitar o prefixo (o link do detalhe abre vazio).
  `unknown` passou de neutro a amarelo em todos os selos. Como testar: `cargo test -p
  corerouter-ui bgp_routes`; na GUI, Routing › BGP, selecionar uma sessão e as abas RPKI e Routes.

- 2026-10-27 — G3.3: Estado BGP: fechado pelas partes que já entraram. `routing.bgp.session.list` e a aba Sessions
  vieram na G3.2a; `routing.bgp.route.list` (recebidas e anunciadas, paginadas, com busca) e
  `routing.bgp.session.history` (quedas por sessão), na G3.2c.

- 2026-10-27 — G3.2b: Políticas BGP no modelo do `/routing filter` do RouterOS v7 (`docs/bgp-policy.md`):

  - **Modelo e comandos:** `routing.filter.rule.{add,set,remove,move,list,check}` (chain + texto da
    regra: `if (dst in bogons || dst-len > 24) { reject } set bgp-local-pref 150; accept`),
    `routing.filter.prefix-list.*` (formato `10.0.0.0/8 le 24`), `routing.filter.community-list.*`
    (RFC 1997 e RFC 8092 na mesma lista), `routing.filter.status`, `routing.filter.preview`,
    `routing.filter.impact`. Conexões e templates BGP ganham `input_filter`, `output_filter` e
    `keep_received` (`soft-reconfiguration inbound`, padrão sim).
  - **Linguagem:** matchers `dst`, `dst-len`, `afi`, `protocol`, `bgp-as-path` (regex do FRR),
    `bgp-communities`/`bgp-large-communities` (`includes`, `any`, `equal`, `-list`); `&&`, `||`,
    `not`, parênteses, `else if`; ações `accept`, `reject`, `return`, `jump`, `set bgp-local-pref`,
    `set bgp-med`, `set bgp-path-prepend`, `set|append|delete bgp-communities` (e large). Ação
    padrão reject (RouterOS). Erro com a coluna e "did you mean"; laço de `jump` recusado.
  - **FRR:** cada chain vira `route-map CR-<chain>` com testes `on-match goto` só para a frente,
    `jump` expandido e fim `deny 65535`; listas com nome pelo conteúdo (`CR-P-<hash>`); só contextos
    `CR-` são do CoreRouter. Forma canônica conferida no FRR 10.7.1 (segundo sync vazio).
  - **Prévia e impacto:** a chain pendente contra a em vigor nas mesmas rotas; no lab, 5 000 rotas
    de amostra reproduzível por conexão; com o FRR, as rotas recebidas (antes da política) ou as
    melhores (saída), lidas fora do lock pela thread do FRR do daemon. "this change withdraws N
    prefixes announced to AS X" por conexão e direção.
  - **RFC 8212:** eBGP sem chain não aceita nem envia (FRR `ebgp-requires-policy`); aviso na janela,
    no modal da conexão e em `routing.filter.status`.
  - **Janela Routing › Filters:** abas Rules (selos da chain por hash, condições, ações verde/
    vermelho/azul, ▲▼, Preview), Prefix Lists, Community Lists e Preview; aviso RFC 8212 e impacto do
    commit em cima; página Filters no modal da conexão BGP; ⓘ em inglês e português.

  Como testar: `cargo test -p corerouter-proto-bgp` (parser, avaliador, render, proptest de
  equivalência), `cargo test -p corerouter-engine --lib routing_filter`, `cargo test -p
  corerouter-ui --lib tests::routing_filter`; com FRR real na VM: `cargo xtask vm-lab run --
  scripts/frr-policy-live.sh` (RFC 8212 bloqueia e guarda as rotas; filtro descarta por lista,
  community e tamanho; prepend e community chegam ao par; forma canônica; uma regra mudada = 14
  linhas em 2,7 ms; prévia nas rotas lidas do bgpd = o que o bgpd fez — **medido**, 2026-10-27).
  Na GUI: Routing › Filters.

- 2026-10-27 — G3.4: OSPF, parte 1 (configuração, `docs/ospf.md`): `routing.ospf.instance`, `area`, `area.range`,
  `interface-template` (com `move` e o `check` do modal), `static-neighbor`, `keychain` e
  `keychain.key`, e `routing.ospf.impact`, no modelo do RouterOS v7. `proto-ospf` valida (RFC 2328
  §3.6, §C.3, §D.3, §15; RFC 3101; RFC 7166) e renderiza para o `ospfd`/`ospf6d` do FRR na forma
  canônica do FRR 10.7.1; o `hal-frr` passou a ser dono de `router ospf`, `router ospf6`, das
  linhas OSPF dos contextos `interface` (por daemon), de `key chain CR-` e dos filtros `CR-O2-`/
  `CR-O3-`. Chaves seladas (`auth_key`, `key_string` em `auth::SECRET_KEYS`, mascaradas no
  `hal-frr`), `sha256` por padrão quando só a chave é dada. O `check` mostra as interfaces que
  entram, o tipo sugerido (/30, /31, PPP → `ptp`), `passive` sugerido em interface de cliente,
  autenticação ausente ou fraca e as adjacências que caem (risco com Safe Mode).

  Como testar: `cargo test -p corerouter-proto-ospf -p corerouter-hal-frr`, `cargo test -p
  corerouter-engine routing_ospf`; na CLI, os exemplos de `docs/ospf.md`. O teste com FRR real na
  VM do laboratório (Full entre dois FRRs, sha256, rotação sem queda, MTU no Diagnose) vem com a
  G3.4b, quando a VM voltar.

- 2026-10-27 — G4.3ce: BNG, anúncio dos blocos de assinantes, parte OSPF: `routing.ospf.instance.set
  subscriber_pools=true` cobre cada faixa dos `/ip pool` dos perfis PPPoE e dos servidores DHCP
  IPoE pelo menor prefixo, agrega, e redistribui as rotas dos assinantes (conectada /32 do PPP,
  kernel do IPoE) por um prefix-list com `summary-address` no `ospfd`: um LSA tipo 5 por pool, que
  some quando o último assinante cai (`docs/ospf.md`).

- 2026-10-27 — G3.4: OSPF, parte 2 (estado, `docs/ospf.md` "Estado"): `routing.ospf.neighbor.list`,
  `interface.list`, `lsa.list`, `route.list`, `topology`, `path` e `neighbor.diagnose`. O serviço
  `frr` lê vizinhos e interfaces a cada poll e a LSDB sob demanda, em fluxo e fora do lock, para a
  tabela compacta `ospf_state::Lsdb`. `proto-ospf` ganhou o parser de pacotes OSPF v2/v3 (Hello e
  DD, com proptest), o Diagnose (RFC 2328 §10.4–§10.6, §C.1, §D.3; RFC 3101 §2.3), o grafo da
  LSDB com Dijkstra (§16.1, com a checagem de mão dupla), o layout por forças em threads e a
  amostra do laboratório virtual.

  Como testar: `cargo test -p corerouter-proto-ospf -p corerouter-hal-frr`, `cargo test -p
  corerouter-engine ospf`; no laboratório virtual, `routing.ospf.topology {"instance":"v2"}` depois
  dos exemplos de `docs/ospf.md`. Com FRR real: `cargo xtask vm-lab run --
  scripts/frr-ospf-live.sh` (escrito; a VM está com o disco cheio).

- 2026-10-27 — G3.6: BFD, parte 1 (G3.6a): CoreRouter's own BFD in pure Rust. Crate `proto-bfd` (L2, sans-IO, WASM):
  Control packet codec with the RFC 5880 §6.8.6 checks, the session machine (§6.8, Poll/Final,
  slow 1 s timers while not Up, jitter of §6.8.7, a peer's Demand mode honoured), Keyed SHA1 and
  Meticulous Keyed SHA1 (§6.7.4, erratum 7083), dampening (RFC 5882 §3.2), a timer wheel and
  per-session p99 histograms; proptest on hostile packets. Daemon service `bfd`: N named threads
  (`--bfd-threads`, auto: one per 500 sessions up to 4), each with its own sockets on 3784/4784 in
  a `SO_REUSEPORT` group steered by a classic BPF program (`Your Discriminator mod N`), its own
  timer wheel and no lock on the packet path; TTL 255 out, single hop accepts only 255 (RFC 5881
  §5), multihop a minimum TTL. Commands `routing.bfd.profile.*` (built-in `default` 300 ms × 3 and
  `fast` 50 ms × 3, dampening on), `routing.bfd.peer.*`, `routing.bfd.session.list` (jitter p99,
  rx gap p99, detect time, flaps in 24 h, CPU per thread) and `routing.bfd.history.list`. Docs:
  `docs/bfd.md`.

  Test: `cargo test -p corerouter-proto-bfd`; `cargo test -p corerouter-daemon --bin corerouter-daemon bfd::`
  (two engines over the loopback: up, then the peer gone and detected in 90–170 ms);
  `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-daemon --test netns_bfd`
  (two daemons over a veth: up in 1.4 s, the link cut detected in 118 ms with the 150 ms
  detection time, **medido**). Load bench: `docs/bfd.md` ("Desempenho e paralelismo").

- 2026-10-27 — G3.4: OSPF, parte 3 (janela, `docs/ospf.md`): Routing › OSPF deixou de ser um stub (`Win::Ospf` saiu de
  `windows.rs`; a janela é o painel `crates/ui/src/ospf.rs`). Abas Neighbors (estado em selo "Full ·
  DR", área em selo por hash, uptime, BFD, Diagnose com a seção da RFC), Instances, Areas, Interface
  Templates e Key Chains (lista G0.24 com o modal alimentado pela prévia do engine:
  `routing.ospf.instance.check`, `area.check`, `area.range.check`, `keychain.check`), LSDB
  (paginada, por tipo), Routes ("Por que esse caminho?" ao selecionar uma rota) e Topology (o mapa
  desenhado da LSDB, `ospf_topology.rs`: clique num roteador para ver o caminho, custo somado salto a
  salto, selo `agrees` quando confere com a rota do daemon). ⓘ em português em toda aba, coluna e
  campo; screenshots claro e escuro conferidos. A amostra do laboratório virtual ganhou um LSA do
  nosso roteador por área. O campo `bfd` dos templates agora é conferido contra os perfis da G3.6
  (`routing.bfd`) e deixou de ir ao FRR como `ip ospf bfd`: o BFD é nosso, não o `bfdd`; a ligação
  sessão → adjacência é a G3.6b.

  Como testar: `cargo test -p corerouter-ui ospf`; na GUI, Routing › OSPF depois dos exemplos de
  `docs/ospf.md` (o laboratório virtual mostra a amostra, com a segunda interface em ExStart).

- 2026-10-27 — G3.7: Simulador de rede, parte 1 (motor e comandos). O crate novo `crates/netsim` (L2, puro, compila
  para wasm) roda OSPFv2 (RFC 2328: hellos/dead, router-LSA, inundação, MinLSInterval, SPF com o
  throttle do FRR), BGP-4 (RFC 4271: OPEN/KEEPALIVE/UPDATE, hold, laço de AS, decisão na ordem do
  FRR conferida contra `proto_bgp::decision`, chains de `/routing filter` pelo avaliador do
  `proto-bgp`, RFC 8212) e BFD (RFC 5880, analítico) por eventos discretos num relógio virtual em
  µs, determinístico (mesma semente, mesma execução, com qualquer número de threads). Os roteadores
  avançam em paralelo dentro de janelas conservadoras (lookahead = menor latência de enlace), num
  pool de threads persistente; no navegador, uma thread.

  No engine, cada roteador virtual é um `Session` sobre o `VirtualHal`, configurado por comandos
  (`engine::netsim`). Os comandos são `tool.netsim.*`:
  - topologia: `new` (presets square/ring/mesh/star/grid até 500 roteadores), `node.add`,
    `link.add`, `link.set`;
  - execução: `node.run` (qualquer comando dentro de um roteador virtual), `clock` (play, pause,
    step, ×1..×3600), `tick`, `advance` (com orçamento de eventos);
  - falhas: `fault` (corte silencioso, perda de portadora, reparo, roteador fora/de volta,
    latência, perda);
  - leitura: `get` (com o selo "simulation — not the real network" e o resumo de convergência),
    `timeline`, `node.get` (rotas, vizinhos OSPF, sessões e tabela BGP, LSDB);
  - extras: `import` ("e se?" com a config deste roteador), `export`/`load` (o cenário com o
    `expect` vira teste: `crates/engine/tests/netsim_scenarios.rs` roda `tests/netsim/*.json`).

  Como testar:
  - `cargo test -p corerouter-netsim`: convergência em anel, malha, estrela e grade; corte com e sem
    BFD; perda de portadora; saída do upstream; roteador fora e de volta; RFC 8212; AS errado;
    determinismo com 1/4/8 threads; orçamento; proptest da decisão;
  - `cargo test -p corerouter-engine netsim`;
  - pelo CLI: `corerouter-cli run tool.netsim.new '{}'`, `… run tool.netsim.advance '{"ms":60000}'`,
    `… run tool.netsim.fault '{"kind":"link-cut","link":0}'`, `… run tool.netsim.advance '{"ms":5000}'`,
    `… run tool.netsim.get` (campo `convergence`).

  Corte silencioso R1–R2 no quadrado, com BFD: percebido em +0,79 s, OSPF reconvergiu em +0,80 s,
  nenhum prefixo BGP perdido (**medido**, `a_cut_link_reconverges_with_bfd`). Sem BFD, o dead
  interval decide em 30–40 s.

- 2026-10-27 — G3.6: BFD, parte 2 (G3.6b): CoreRouter's engine as the distributed data plane of FRR's `bfdd` (FRR 10.7.1
  `bfddp`, `--dplaneaddr unix:/var/run/frr/bfdd_dplane.sock`, set by the init): bfdd hands every
  session it creates (BGP `neighbor … bfd profile`, OSPF `ip ospf bfd profile`, the `routing.bfd`
  peers) to the engine and tells bgpd/ospfd what the engine reports, so BGP and OSPF go down with
  our BFD. Codec `proto_bfd::dplane` (proptest), the client `service/bfd/dplane.rs` (reconnect,
  bounded queue), counters and echo answered; auth, dampening and minimum TTL from our profile
  (bfddp has no auth). FRR render of the `bfd` block (profiles, peers); `bfd` profile on BGP
  connections and templates; commit checks (named profiles exist, multihop peers need a local
  address); `routing.bfd.attach` puts a profile on every BGP connection and OSPF template without
  one. Option (b), dropping neighbours over vty, was rejected: it cannot hold a neighbour down and
  does not cover OSPF (docs/bfd.md, "Ligação com o FRR").

  Test: `cargo test -p corerouter-daemon --bin corerouter-daemon bfd::` (`data_plane_for_a_fake_bfdd`:
  a fake bfdd hears Up, gets counters, and hears Down with Diag 1 ≤ 250 ms after the peer is gone,
  **medido**); `cargo test -p corerouter-proto-bfd`; `cargo test -p corerouter-engine --lib routing_bfd`.
  Interop and latency against the real bfdd: on the lab VM when it has disk again.

- 2026-10-27 — G3.7b: Janela Tools › Network Simulator (painel `crates/ui/src/netsim.rs`), sobre os comandos
  `tool.netsim.*` da G3.7. Tem:
  - barra com o selo âmbar "simulation — not the real network" (sempre visível), topologia pronta e
    New, relógio ⏮ (recomeça em t = 0) ⏯ ⏭ (próximo instante com evento) ×1/×10/×60/×600/×3600
    e o tempo virtual;
  - topologia desenhada: roteadores em selo com a cor pelo hash do AS (vermelho quando fora), enlaces
    verdes (OSPF Full), âmbar (OSPF subindo), azuis (só eBGP), vermelho tracejado (cortado), cinza
    tracejado (sem portadora), custo OSPF ao lado; clique seleciona roteador ou enlace;
  - roteador selecionado: AS, router id, vizinhos OSPF, sessões BGP e rotas, com Derrubar/Ligar;
  - enlace selecionado: estado, custo, latência, perda, Cortar/Sem portadora/Restaurar, custo e BFD;
  - editor: acrescentar roteador (AS) e enlace (a, b, custo), e "E se? Adicionar este roteador";
  - linha do tempo com selos por camada (fault, bfd, ospf, bgp) e, em cima, o resumo da última falha
    ("link-cut: detected +0.64 s, OSPF +0.64 s, BGP +0.65 s, 0 prefixes lost");
  - ⓘ em português em cada parte (`i18n/auto/netsim_{en,pt}.rs`), item no menu Tools com sinônimos
    (simulador, e se, convergência, gns3, batfish…).

  Rodando, a janela manda `tool.netsim.tick` a cada 0,5 s com o tempo de parede passado, como
  consulta (não enche o log de ações). Ícones novos do Phosphor: play, pause, skip-back,
  skip-forward (subconjunto refeito por `scripts/icons-subset.sh` a partir do `egui-phosphor`
  0.14.0 do crates.io, sha256 conferido).

  Como testar: `cargo run -p corerouter-gui -- --control 7979`, Virtual lab, Tools › Network
  Simulator, New, ⏯ e ×60; clique no enlace R1–R2, Cortar; a linha do tempo mostra o BFD em
  ~0,6–0,9 s e o OSPF indo por R3. `cargo test -p corerouter-ui netsim`.

- 2026-10-27 — G3.5: MPLS e LDP, parte 1 (`docs/mpls.md`):

  - **Comandos** com os nomes do RouterOS v7: `mpls.settings.*`, `mpls.interface.*`,
    `mpls.static.*` (LSP estático, Cisco/Junos), `mpls.ldp.*`, `mpls.ldp.interface.*`,
    `mpls.ldp.neighbor.*` (TCP MD5 selada, Hellos dirigidos) e `mpls.forwarding-table.page`.
    As listas modais têm prévias (`*.preview`) que mostram o que o `ldpd` recebe.
  - **Kernel:** `hal-linux/src/mpls.rs` fala netlink `AF_MPLS` próprio:
    - dump, `RTM_NEWROUTE`/`DELROUTE` em lotes de 64 KiB com tudo ou nada, e os sysctls;
    - os comandos que adicionam ficam desabilitados com o motivo sem o `mpls_router`;
    - `ci/kernel-modules/mpls_router` liga o teste em netns no CI completo. O módulo é `optional`: o kernel do Azure não o traz no pacote base. O setup tenta o `.ko` do `linux-modules-extra` (o cache do `vrf`); sem ele, o teste pula com aviso;
    - o kernel da imagem já tem `CONFIG_MPLS_ROUTING=y`.
  - **FRR:**
    - o `hal-frr` passa a ser dono de `mpls ldp` (no `ldpd`) e de `mpls label dynamic-block` (no
      zebra, quando a faixa não é a padrão);
    - põe `mpls ldp-sync` em `router ospf`, empilhado na G3.4;
    - lê vizinhos, ligações, interfaces e o sync a cada 2 s.
  - **Validação com a RFC no erro:**
    - RFC 3032 §2.1 (rótulos reservados; 3 nunca no fio);
    - RFC 5036 §3.5.2.1 (hello < hold);
    - RFC 7552 §6.1 (transporte IPv6 global);
    - um LSP estático dentro da faixa dinâmica é recusado.
  - **Janelas** MPLS › LDP (Neighbors, Interfaces, Settings) e MPLS › Forwarding Table, no mockup
    aprovado, com ⓘ em português, claro e escuro:
    - selo `MTU 1500 < 1504`;
    - Sync IGP em selo;
    - o motivo de cada FEC sem rótulo;
    - `implicit-null (pop)`.
  - **IP › Routes:** selo `MPLS <rótulo>` no gateway.

  **Como testar:**

  - `cargo test -p corerouter-proto-mpls -p corerouter-hal-frr -p corerouter-engine --test mpls`;
  - `cargo test -p corerouter-ui mpls`;
  - `cargo xtask netns` com o `mpls_router` carregado (`tests/netns_mpls.rs`);
  - na CLI: `mpls.ldp.add {"lsr_id":"10.255.0.1"}` e `mpls.ldp.interface.add {"interface":"ether1"}`,
    e a janela mostra o aviso de MTU do lab (1500).

- 2026-10-27 — G3.6: BFD, parte 3 (G3.6c): the Routing › BFD window, tabs Sessions (Peer with a multihop chip, Used
  by as name-coloured chips, State up/down/init/dampened/inactive, Tx/Rx, Detect Time, Jitter p99,
  Flaps 24h; + and − for peers, "Use BFD Everywhere"; footer with the engine's threads, CPU and
  steering), Profiles (list window pattern with the engine's preview `routing.bfd.profile.preview`:
  detection time, packets per second, CPU and multiplier warnings) and History (newest first,
  `down » dampened`, `dampened » up`). The peer modal uses `routing.bfd.peer.preview`. The BGP
  connection and template modal gained "BFD Profile". ⓘ on every column, tab and field, Portuguese
  and English. Screenshots light and dark checked (two daemons over a veth in a namespace, three
  link flaps dampened the session).

  Test: `cargo test -p corerouter-ui bfd` (sessions, attach, profile and peer modals through the
  preview, history, every ⓘ in both languages); `cargo test -p corerouter-engine --lib routing_bfd`.

- 2026-10-27 — G3.7d: Simulador de rede, parte 3: cada roteador virtual roda o OSPF da sua própria configuração
  (modelo da G3.4), não mais "OSPF em todo enlace":
  - **o que é lido**: a primeira instância OSPFv2 habilitada e as interfaces que os templates casam,
    pela mesma regra do render para o FRR (`proto_ospf::bind::bindings`: nome, interface list ou
    rede; o primeiro template vence), com o custo, o hello e o dead do template, `passive`
    (anuncia a rede, sem adjacência) e o perfil de BFD (liga o BFD da adjacência). Sem instância,
    sem OSPF; loopback só entra se um template a casar;
  - **o que muda nos roteadores**: os presets digitam em cada roteador a instância `default`, a área
    `backbone` (0.0.0.0), um template ponto a ponto com as portas dos enlaces OSPF e a loopback
    passiva; um enlace novo acrescenta o template da porta, um roteador novo já nasce com a
    instância; template sem custo usa o custo do enlace no editor;
  - **BFD do BGP** (G3.6b): uma conexão com perfil BFD (`bfd`, RouterOS `use-bfd`) cai com o BFD;
    sem perfil, um corte silencioso espera o hold timer. Os presets e o `link.add` põem o perfil
    embutido `default` no eBGP; a porta liga o BFD quando um vizinho de um salto o pede;
  - **"E se?"**: copia também instâncias, áreas e templates OSPF e os perfis BFD (as chaves de
    autenticação continuam seladas no roteador real);
  - **formato do cenário exportado**: passa a ser `corerouter-netsim/2` (os roteadores trazem os
    comandos OSPF). O formato 1 é recusado com o motivo ("export it again"), e o exemplo de
    `crates/engine/tests/netsim/` foi exportado de novo, com o mesmo `expect`.

  Como testar: `cargo test -p corerouter-netsim the_routers_own_ospf_config_decides`,
  `cargo test -p corerouter-engine netsim` (inclui `bgp_bfd_comes_from_the_connection`). Na janela: selecione R1,
  `tool.netsim.node.run {"node":"R1","id":"routing.ospf.interface-template.add","params":{"area":"backbone","interfaces":["ether1"],"type":"ptp","cost":100,"place_before":"*3"}}`
  e veja a rota de R1 para 10.255.0.2/32 passar por R3 com custo 20.

  Desempenho (**medido**, release, 32 CPUs com load ~15, 2026-10-27): montar o laboratório de 500
  roteadores, agora com 4 comandos OSPF a mais por roteador, levou 143 ms (150 ms antes); 60 s
  virtuais pelo `tool.netsim.advance`, 3,3 s. Ler o OSPF de um roteador é O(interfaces × templates
  que as citam), feito só quando a config dele muda.

- 2026-10-28 — G4.9b: `shaper_accuracy` (teste root do shaper, passo `xdp-root`) deixa de reprovar quando o runner não
  consegue oferecer carga. No lote do #326 (28/10), com 10 000 alvos, o gerador ofereceu só 1,2× a
  taxa ao alvo menos servido (a média era ~3,3×) mesmo depois das reduções, e o teste caiu em
  "not offered enough"; repetido, passou. Duas mudanças:

  - **Gerador equilibrado:** antes a thread `t` mandava só para os alvos `t, t+2, …`, e a thread mais
    lenta (dividindo a CPU com o softirq do roteador) definia o alvo menos servido. Agora cada thread
    percorre todos os alvos, cada uma a partir da sua parte do anel: uma thread lenta custa igual a
    todos os alvos. O PERF passa a mostrar a média ao lado do mínimo (`offered >= 3.2x (mean 3.3x)`).
  - **Skip com aviso:** se nem com a taxa no piso (8 kbit/s) o mínimo chega a 2× a taxa, o caso
    imprime `SKIP shaper_accuracy <n> targets: runner offered only X× (needs 2x) …` e segue. Com carga
    suficiente o erro de ±5% continua sendo cobrado. No piso o teste não repete mais rodadas inúteis
    (até 36 s a menos no runner).

  Como testar: `cargo xtask vm-lab run -- env COREROUTER_REQUIRE_XDP=1 cargo xtask xdp-root`.

  Números (**medido**): nas 22 rodadas anteriores do CI, o runner a 10 000 alvos ficou sempre no piso,
  com o mínimo entre 3,0× e 6,5× e normalmente a 85–95% da média; na que falhou, a 37%. Na VM do
  laboratório (8 vCPUs), o mínimo é igual à média com os dois geradores, porque o escalonador iguala
  as threads. `sendmmsg` em lotes de 64 e 3 ou 4 threads não ofereceram mais (1,52 contra 1,54 Mpps;
  4 threads 1,49 Mpps), porque o custo é o caminho do roteador, executado no softirq de quem envia.
  Por isso ficaram de fora.

- 2026-10-28 — G1.27f: Check-gateway em rotas estáticas, como o `check-gateway` do RouterOS v7. `ip.route.add/set`
  ganham `check_gateway` (`none | ping | arp | bfd`) e `bfd_profile`; a cada 10 s, 2 falhas e a rota
  sai do kernel (fica `inactive`, motivo `check-gateway-down`) e a de distância maior assume; na
  primeira resposta ela volta. Hold-down contra oscilação: a 2ª queda em 15 min espera 10 s
  respondendo, depois 20 s, 40 s… até 5 min. Rotas com o mesmo método, gateway e tabela dividem uma
  sonda. Comandos novos `ip.route.check.list` (alvos, rotas por alvo, estado, falhas, hold-down,
  flaps) e `ip.route.check.history`; `ip.route.list`/`ip.route.detail` trazem `status`,
  `hold_down_secs`, `bfd_profile` e o histórico do gateway. Engine: `gateway_check.rs` (estado
  `Health`, alvos, agenda `Schedule`), a mesma máquina de estado do cliente DHCP (G4.7c, refeito em
  cima dela); daemon: serviço `route-check` (`--route-check-interval`); hal: `ArpPinger::request`/
  `replies` (ARP em lote, um socket por interface). Janela IP › Routes: coluna **Check** (método +
  selo `reachable`/`unreachable`/`checking`/`not-checked`), campo **Check Gateway** com selos e
  **BFD Profile** no modal, detalhe com falhas, hold-down e trocas; ⓘ em português.

  Testar: `cargo test -p corerouter-engine --test route_check`; netns com daemon real (ping, arp e
  BFD contra um segundo daemon): `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net --
  cargo test -p corerouter-daemon --test netns_route_check` (8 s, **medido**). Screenshots em
  `side-session-notes/…/G1.27f-screenshots/`.

- 2026-10-28 — G3.5b: LSP ping e traceroute (RFC 8029 com a RFC 9570 e a errata 8788): `tool.mpls.ping.start` e
  `tool.mpls.traceroute.start` (terminal `/tool lsp-ping`, `/tool lsp-traceroute`), janela Tools ›
  LSP Ping (modos Ping e Traceroute, letras de retorno do Cisco como selos, rótulos por salto) e
  "LSP Ping…" no clique direito de uma FEC em MPLS › Forwarding Table. Codec e respondedor sans-IO
  em `hal/src/lsp/` (proptest de entrada hostil, exemplo de FEC Stack da RFC §3); envio por
  `AF_PACKET` com a pilha da rota da FEC (`RTA_ENCAP`), destino 127.0.0.1, TTL IP 1, sem Router
  Alert; respondedor no serviço `lsp-ping` do daemon (sockets por protocolo com BPF nas interfaces
  MPLS, códigos 1/2/3/4/5/6/8/10/11, DDMAP por próximo salto, limite de taxa `/mpls settings
  lsp-ping-rate`, padrão 100/s, ligado por padrão). O laboratório responde com o mesmo código
  (LSPs simulados, um quebrado em 10.255.9.9). Como testar: no laboratório, Tools › LSP Ping,
  FEC `10.255.0.4`, Ping e Traceroute; `cargo test -p corerouter-hal lsp`; na VM,
  `flock vm/root.lock cargo xtask vm-lab run -- scripts/lsp-ping-live.sh` (três roteadores com o
  ldpd do FRR). Custo por pedido: 117 ns para codificar, 363 ns para responder em trânsito com 100
  mil rótulos (**medido**, release). Na VM, com os rótulos do ldpd do FRR em três roteadores: 200/200
  pings com código 3, traceroute lsp2 (label switched, implicit-null) → lsp3 (egress); RTT do LSP
  ping 90 µs de mediana contra 17 µs do ICMP do kernel no mesmo caminho (build debug, **medido**).

- 2026-10-28 — G3.6g: Rotas estáticas com `check_gateway=bfd`: o `bfd` (G3.6) roda as sessões pedidas pelas rotas
  (`bfd::route_sessions`/`wanted_all`; um gateway com milhares de rotas é uma sessão, os usuários
  listam até 4 rotas e "and N more routes"); no modo data plane do `bfdd` as sessões das rotas
  continuam no nosso motor, exceto se o `bfdd` já tem sessão ao mesmo endereço. A mudança de estado
  chega ao engine no mesmo lock que grava o histórico do BFD (`route_check_bfd_event`), então a rota
  sai no tempo de detecção do perfil (`fast`: 150 ms). Perfil usado por rota não pode ser removido.
  Teste em netns contra um segundo daemon como par BFD (`netns_route_check`).

- 2026-10-28 — G0.26b: Travas da VM do laboratório, depois do impasse de 2026-10-28 (~40 min parados). O incidente teve três partes. Um `zebra` do FRR, subido por um teste, herdou o fd 9 da trava `/run/corerouter-lab.lock` e a segurou depois da rodada. Duas sessões embrulhavam o `run` em `flock vm/root.lock` e esperavam uma pela outra. E o `flock 9` esperava sem prazo. Correções em `xtask/src/vm_lab.rs`:
  - o comando roda num subshell com `9>&-`, então um daemon que ele sobe não leva a trava;
  - o `cd` para `src` fica numa linha própria: antes, `run -- 'a & b'` punha `cd && a` em segundo plano e rodava `b` fora de `src`;
  - cada processo da rodada leva `COREROUTER_LAB_ROUND=<pid>.<início>` do `vm-lab run` no host, e no fim o `run` avisa, com PID e comando, do que ficou vivo na VM (não mata sozinho);
  - a espera usa `flock -w` (`--lock-timeout`, `$COREROUTER_VM_LOCK_TIMEOUT`, padrão 30 min); ao estourar, sai com código 75 dizendo o dono, a idade e os processos que seguram ou esperam;
  - o `.lock.owner` passa a ter `worktree`, `round`, `host_pid` e `started`, e fica vazio quando a rodada termina normalmente;
  - `cargo xtask vm-lab unlock [--force]` mostra o dono, a idade e os processos; com `--force`, encerra (TERM e depois KILL) o que sobrou de rodadas cujo `run` não existe mais no host. Nunca mexe numa rodada viva nem em quem espera. Um dono no formato antigo conta como vivo enquanto houver um `vm-lab run` daquela worktree no host;
  - `status` mostra o dono e a idade, e também o que sobrou com a trava livre;
  - `snapshot` e `reset` recusam com a mesma descrição.

  Docs: `docs/vm-lab.md` ganhou a seção "Travas: regras e como destravar": para que serve cada trava, sessões sem `flock vm/root.lock`, `trap` para desligar daemons, diagnóstico e solução. O `AGENTS.md` ganhou uma linha.

  Como testar:
  - `cargo test -p xtask vm_lab` (12 testes): dois deles rodam o script gerado no bash local com uma trava em pasta temporária. Um confere que um `sleep 600 &` não segura a trava depois da rodada (o teste falha sem o `9>&-`, conferido). O outro confere que a espera desiste em 1 s e diz quem segura.
  - Na VM (**medido**, 2026-10-28):
    - `cargo xtask vm-lab run -- 'sleep 600 >/dev/null 2>&1 & …'`: avisou do `sleep` que sobrou; trava livre (`fuser` vazio); `unlock --force` o encerrou;
    - com uma rodada segurando a trava, um segundo `run --lock-timeout 10s` desistiu em 10,1 s com o dono e os processos; `unlock --force` recusou porque a rodada estava viva; `reset` e `snapshot` recusaram;
    - incidente simulado (processo sem marca segurando a trava, owner no formato antigo): `unlock` mostrou e `unlock --force` liberou.

- 2026-10-28 — G3.2c: RPKI e "Por que essa rota?" contra o FRR real na VM do laboratório
  (`cargo xtask vm-lab run -- scripts/frr-rpki-live.sh`, FRR 10.7.1 com `bgpd_rpki`, validador RTR
  local com VRPs fixos), **medido** em 2026-10-27: render canônico; o `bgpd` descarta a origem
  inválida 10.66.0.0/24 (ROA /16 com tamanho máximo 16); a lista recebida mostra 10.66.0.0/24
  `invalid` e filtrada, 10.30.2.0/24 `valid`, 10.20.1.0/24 `unknown` (resumo lido em 1 ms); o
  explain diz que o caminho do rr3 perdeu em local-pref (200 > 100), como o próprio `bgpd`;
  `rpki_invalid=accept` numa conexão deixa a inválida entrar e voltar a `reject` a tira. Nenhum
  defeito achado.

- 2026-10-28 — G3.4: OSPF contra o FRR real na VM do laboratório (`cargo xtask vm-lab run -- scripts/frr-ospf-live.sh`,
  FRR 10.7.1), **medido** em 2026-10-27: commit em 17,5 ms; Full com HMAC-SHA-256 (RFC 5709) em
  0,3 s; a rotação para a chave 2 mantém a adjacência Full por 20 s (2,5 intervalos de dead); o
  vizinho com MTU 1400 para em Exchange e o Diagnose aponta o RFC 2328 §10.6; LSDB lida com 2 LSAs
  e 5 ligações. Dois defeitos achados e corrigidos com teste: o Diagnose dizia "for 0 min" abaixo de
  um minuto (agora "for 12 s") e um template ponto a ponto **passivo** (a loopback, como o operador
  escreve) não tinha o /32 anunciado, porque o `ospfd` toma um /32 em interface point-to-point como
  enlace não numerado; o render agora escreve `broadcast` para template passivo ponto a ponto (sem
  vizinho, o tipo só decide o que se anuncia). O segundo apareceu no teste do LDP (a sessão LDP, com
  transporte no loopback, não subia).

- 2026-10-28 — G3.5: LDP contra o FRR real na VM do laboratório: `cargo xtask vm-lab run -- scripts/frr-ldp-live.sh`
  (teste `crates/hal-frr/tests/frr_ldp_live.rs`). Três LSRs em linha: R1 é o FRR da VM, configurado
  pelo `hal-frr` (OSPF + LDP); R2 e R3 são instâncias do FRR (`zebra`, `ospfd`, `ldpd`) em
  namespaces. **Medido** em 2026-10-27 (FRR 10.7.1): render canônico; sessão LDP operacional em
  6,0 s depois do commit; 10.255.0.3/32 sai do R1 com o rótulo do R2 (`encap mpls 17`), o R2 tira o
  rótulo (PHP, RFC 3032 §2.1) e o ping passa pelo LSP 6,1 s depois do commit (o tcpdump no R2 mostra
  o rótulo 17); sync RFC 5443 "achieved" em 10,1 s (o `ldpd` espera 10 s fixos depois da sessão).
  Corrigido: "Sync not required: non-p2p link" (loopback, broadcast) aparecia como "esperando" para
  sempre; o formato do `show ip ospf mpls ldp-sync json` foi confirmado e entrou como teste.

  O `tests/netns_mpls.rs` rodou pela primeira vez com o `mpls_router` (VM, kernel 7.0) e passou;
  `MPLS_LABELS` escolhe o tamanho da medição.

- 2026-10-28 — G3.6: O texto da linha G3.6 deixa de dizer "pendentes da VM": a G3.6i fechou a interoperabilidade e a
  comparação com o `bfdd` 10.7.1 (`docs/bfd.md`, "Contra o `bfdd` real").

- 2026-10-28 — G3.6b: A linha G3.6b ficou "aberto" depois do merge do #331: o fold registrou o status só na G3.6.
  Corrigido aqui, com o número do data plane medido na G3.6i.

- 2026-10-28 — G3.6c: A linha G3.6c ficou "aberto" depois do merge do #335: o fold registrou o status só na G3.6.

- 2026-10-28 — G3.6i: BFD contra o FRR real na VM do laboratório (FRR 10.7.1, build release, **medido** em
  2026-10-27). Roteiros novos: `scripts/frr-bfd-live.sh [interop|load|self|all]` (testes
  `#[ignore]` em `apps/corerouter-daemon/src/service/bfd/live_bfdd.rs`: o motor num namespace,
  `zebra` + `bfdd` noutro) e `scripts/frr-bfd-dplane-live.sh` (o daemon como data plane do `bfdd`
  da VM, com `bgpd` e um par eBGP com BFD num namespace).

  - **Interop:** Up em ~1 s; o Poll do `bfdd` (300 → 50 ms) aplicado em 242 ms e o nosso (200 ms)
    visto pelo `bfdd` em 8 ms, sem mudança de estado; SHA1 só do nosso lado cai e não volta (o
    `bfdd` 10.7.1 não implementa autenticação e descarta o bit A, RFC 5880 §6.8.6); o `bfdd`
    detecta o nosso silêncio com `control detection time expired` em 114–155 ms e nós detectamos o
    `bfdd` morto em 146 ms (50 ms × 3).
  - **Data plane com `bgpd`:** cinco cortes só dos pacotes BFD do vizinho (o TCP do BGP segue): o
    `bfdd` recebe o nosso `BFD_STATE_CHANGE` 110–140 ms depois do corte e o `bgpd` sai de
    Established 0,20–0,26 ms depois (logs do FRR com µs). O 0,2 ms substitui o "< 1 ms estimado" do
    `docs/bfd.md`.
  - **Carga** (50 ms × 3, 15 s): 1000 sessões, uma thread nossa 36,5 % × `bfdd` 32,7 % de um
    núcleo; com 4 threads, 15,4 % por thread; o nosso atraso de envio p99 mediano 69–108 µs; zero
    quedas falsas dos dois lados em 135 s. Nós contra nós na mesma VM: 32,4 % (no host, 10,1 %): o
    custo é a syscall, ~3× mais cara na VM. Números e leitura em `docs/bfd.md`; decisão revista em
    `docs/architecture.md` (mantida).
  - **Achado do `bfdd`:** a sessão de salto único é identificada pelo vizinho, não pelo endereço
    local (vários `peer X local-address …` viram uma); a bancada põe os endereços do nosso lado.
  - Um corte 0,5 s depois de o BFD subir não derrubou o BGP numa rodada (o BFD caiu, o `bgpd` ficou
    em Established); com 3 s de folga, cinco de cinco derrubaram. Não reproduzido de propósito: G3.6k.

- 2026-10-28 — G3.7c: Fidelidade do simulador com o FRR real na VM do laboratório
  (`cargo xtask vm-lab run -- scripts/frr-netsim-fidelity.sh`, teste
  `crates/netsim/tests/frr_fidelity.rs`). Cada cenário roda no simulador e como uma instância do FRR
  10.7.1 (`zebra`, `ospfd`, `bgpd`) por roteador, cada uma num namespace, um veth por enlace; cada
  roteador tem de ter as mesmas melhores rotas e sessões por 5 s seguidos. **Medido** em 2026-10-27:
  o quadrado (18 melhores rotas, 5 sessões), o anel de 5 com eBGP (55 rotas, 5 sessões) e o anel de
  4 com OSPF (20 rotas com ECMP) batem; o FRR convergiu em 9–13 s com timers curtos.

  Defeito achado e corrigido: o simulador escolhia um caminho BGP só, e o `bgpd` instala todos os
  iguais ao melhor até o custo IGP (`maximum-paths` 64 por padrão, que o nosso render não muda): no
  quadrado o R2 vai ao upstream por R1 e R3 e o R4 ao /16 do cliente pelos dois. O simulador agora
  soma os enlaces desses caminhos (mesmo tipo, local-pref, AS path inteiro, origin, MED e custo
  IGP, até 16); teste `bgp_multipath_like_frr`. Custo na bancada do simulador (criterion, host,
  release): +0,8 a +4,6 % (convergir 100 roteadores 88,8 → 90,4 ms, dentro do ruído; corte 92,3 →
  97,2 ms), o preço de reinstalar todo prefixo olhado (um membro do multipath pode entrar ou sair
  com o melhor no lugar).

- 2026-10-28 — G3.6h: BFD no par do BNG. O nosso motor BFD (G3.6) vira o terceiro sinal de vida nos dois caminhos do par
  (`ppp.redundancy.set bfd=fast access_bfd=fast access_peer=<ip>`). Só a expiração conta (RFC 5880
  §6.8.4, diagnóstico 1; errata 6926); AdminDown, não. A regra de maioria com a testemunha não
  muda: o espera só assume com o par mudo em todos os caminhos e com uma resposta da testemunha
  **posterior** à detecção. Sem ela, vale o intervalo morto dos hellos. Tabela de decisões em
  `docs/bng-ha.md` §2.1 e desenho em §2.13.

  O que entrou:

  - **Sem o lock do `Session` no caminho da decisão:** a thread do motor BFD avisa o `ppp-ha` por um
    tap nas `Options` do motor; o tap só enfileira e acorda o laço.
  - **Dampening por caminho:** usa o do perfil. Um alarme falso (BFD perdido com o hello passando)
    vale duas penalidades.
  - **Linha do tempo de cada tomada:** detectado, testemunha, ativo, anunciado, adotadas e 1º
    quadro, mais as sessões perdidas (`ppp.redundancy.monitor` → `takeovers`).
  - **`ppp.redundancy.test-takeover`:** roda as verificações e, com `confirm=takeover`, faz a tomada
    planejada (`failure` silencia também o BFD do par). O resultado é lido do par pelo link de sync.
  - **Alertas:** p99 do intervalo do BFD ≥ 2/3 da detecção, BFD saindo atrasado, caminho amortecido.
  - **Janela PPP › Redundancy:** campos de detecção, estado do BFD por caminho, idade da resposta da
    testemunha, alertas, linha do tempo e o botão **Testar tomada**, que pede para digitar
    `takeover`. ⓘ em português; capturas claro e escuro em `docs/changes/G3.6h-screenshots/`.

  Como testar:

  - `cargo test -p corerouter-proto-ha --release --test sim_bfd`;
  - `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-daemon --test netns_ha_bfd -- --test-threads 1 --nocapture`;
  - na VM: `cargo xtask vm-lab run -- env BNG_LAB_HA_BFD=fast cargo xtask bng-lab --only ha`.

  Números:

  - **Laboratório em memória:** a tomada leva 155 ms simulados, 0 de 20 000 sessões perdidas; em 300
    sementes de falhas aleatórias com BFD nunca houve dois ativos (**medido**).
  - **Dois daemons reais** (debug, namespace): ativo 150–154 ms depois do último sinal de vida do
    par, contra 1,16 s com só hellos (**medido**).
  - **Acordar o laço pelo evento** cortou 10 ms → 0–4 ms entre a detecção e a decisão (**medido**).
  - **VM com BNG Blaster** (o ativo perde a energia; caminho lento): a tomada leva 0,13–0,20 s com BFD,
    contra 0,96–1,18 s só com hellos. O tráfego de subida volta em 0,19 s com 1 mil sessões, 0,25 s com
    10 mil e 1,04 s com 100 mil. 0 sessões perdidas em todas as escalas (**medido**). Acima de ~10 mil, a adoção
    no caminho lento domina (100 mil levam ~0,75 s, com e sem BFD): gap abaixo.

- 2026-10-28 — G3.4f: Segment Routing MPLS sobre OSPFv2 (RFC 8665, 8660, 8402): `routing.ospf.segment-routing.{set,unset,check,database}`
  e `routing.ospf.prefix-sid.{add,set,remove,list,check}`, render para o `ospfd` na forma que ele
  imprime, remoção na ordem que o FRR aceita (prefixos, `segment-routing on`, `router-info`,
  `capability opaque`), bloco dinâmico do LDP movido para fora do SRGB/SRLB (24000–1048575 com os
  padrões), leitura do banco SR (`show ip ospf database segment-routing json`) junto com a LSDB, fora
  do lock, e a aba Routing › OSPF › Segment Routing (Este roteador, SIDs da rede, Roteadores SR,
  conflitos). Detalhes em `docs/ospf.md`, seção "Segment Routing (G3.4f)".

  Como testar: `corerouter-cli run routing.ospf.segment-routing.check '{}'` (prévia),
  `routing.ospf.segment-routing.set '{}'` (liga e dá SID às loopbacks),
  `routing.ospf.segment-routing.database`; na VM, `cargo xtask vm-lab run -- scripts/frr-sr-live.sh sr`.

  FRR 10.7.1 na VM, **medido** em 2026-10-28: commit em 15,4 ms, banco SR completo 5,8 s depois,
  ping pelo rótulo 16003, SRGB movido em 1,9 ms, SR desligado em 1,4 ms. Achados da VM: o `ospfd`
  recusa `ip ospf network` na `lo` do kernel (o render deixou de escrever) e recusa prefix SID numa
  interface dummy (vira a G3.4i).

- 2026-10-28 — G3.4d: TI-LFA (RFC 9855) sobre o SR da G3.4f: `ti_lfa` (`off`, `link`, `node`) em
  `routing.ospf.segment-routing.set`, render `fast-reroute ti-lfa [node-protection]`,
  `routing.ospf.fast-reroute.list` (cobertura, rotas com principal e reserva e pilha de rótulos, rotas sem
  proteção com o motivo) e `routing.ospf.fast-reroute.simulate` (o corte de um vizinho, sem tocar a
  rede). Os reservas vêm do zebra (`show ip route ospf json`, lido do socket em linhas tipadas); os
  motivos e a simulação, de `netsim::tilfa`, uma reprodução simplificada do `ospf_ti_lfa.c`. Aba
  Routing › OSPF › Fast Reroute. Detalhes em `docs/ospf.md`, "Fast Reroute: TI-LFA (G3.4d)".

  Como testar: `corerouter-cli run routing.ospf.segment-routing.set '{"ti_lfa":"link"}'`,
  `routing.ospf.fast-reroute.list`, `routing.ospf.fast-reroute.simulate '{"neighbor":"ether1"}'`; na VM,
  `cargo xtask vm-lab run -- scripts/frr-sr-live.sh frr`.

  FRR 10.7.1 na VM, **medido** em 2026-10-28 (UDP do iperf3, 2 000 datagramas/s, corte de R1–R2):
  perda de portadora 12,5 ms com TI-LFA e 13,5 ms sem; corte silencioso com BFD 3 × 10 ms 59,5 ms com
  TI-LFA e 51,0 ms só com BFD; segunda rodada 13,5 × 13,5 ms e 50,5 × 50,5 ms. A meta de < 50 ms não foi atingida no corte silencioso, e o TI-LFA não
  muda a perda no Linux. Fidelidade: onde os dois têm reserva, `netsim` e `ospfd` saem pelo mesmo
  vizinho; o `ospfd` não instalou o reserva que pede nó P ≠ nó Q (10.255.0.2/32 no quadrado).

- 2026-10-28 — G1.27d: Teste `netns_neigh::arp_ping_gets_an_answer_from_a_real_host` instável corrigido (só o teste; o
  `hal-linux` não mudou). Nos 7 runs da fila (Actions 40576264652, 40578661613, 40591681774,
  40616352446, 40628233128, 40634323743, 40640354947) a falha era sempre a mesma: o `expect("the far
  host answers")` (linha 424) dos 20 pings ARP, passando ao repetir sozinho. Não era limite de
  tempo apertado de latência: o pedido ARP é um quadro único, sem retransmissão, e o teste o enviava
  logo depois do `ip link set up`. O carrier do veth e o qdisc real vêm de trabalho adiado do
  linkwatch do kernel, que no runner carregado atrasa e o quadro se perde. Agora o teste espera o
  `/sys/class/net/nbd0/carrier` e repete cada ping até 30 s (o rtt guardado é o da tentativa que
  respondeu); o prazo de "never resolved" subiu de 3 s para 30 s. A conferência (a máquina remota
  responde, o silêncio dá `None`, vira vizinho `reachable` com MAC) é a mesma.

  Reproduzido sob carga (64 laços de CPU em 32 núcleos, 8 instâncias do teste em paralelo, cada
  uma num `unshare --user --map-root-user --net`; **medido**, 2026-10-28): antes da mudança 1 falha
  em 255 execuções, no mesmo `expect` (a taxa baixa é a do runner: 7 em poucas dezenas de lotes);
  depois, 0 falhas em 200. A espera pelo carrier usa `ip -o link show` e não `/sys/class/net`,
  porque o `unshare --net` sem mount namespace mostra o `/sys` do host.

- 2026-10-28 — G3.4i: SR na `lo` do kernel: o `ospfd` do FRR só aceita prefix SID numa interface IFF_LOOPBACK, e as
  loopbacks do CoreRouter são `dummy` no Linux. Agora a loopback **chamada `lo`** (módulo
  `corerouter_model::os_loopback`) é a `lo` do sistema: `interface.loopback.add name=lo` funciona
  mesmo com a `lo` do kernel fora do CoreRouter (também numa transação, antes do commit), o
  `owner` a classifica como gerida só com essa declaração, o `plan`/`repair` do hal-linux só deixam
  passar endereços e rotas nela, o snapshot de drift ignora estado/MTU dela e os endereços do SO, e
  o RA e a descoberta de portas a deixam de fora. Desativar a `lo` tira os nossos endereços sem
  derrubar a `lo` do kernel; tirá-la da config não a apaga. A validação recusa 127.0.0.0/8 e ::1 na
  `lo`, outro tipo de interface com o nome `lo` e a `lo` em VRF, bridge ou bond. Outra loopback
  continua `dummy`, e a prévia do SR segue avisando quando o prefix SID está nela (texto com o
  comando para criar a `lo`).

  Como testar: `corerouter-cli run interface.loopback.add '{"name":"lo"}'`,
  `ip.address.add '{"address":"10.255.0.1/32","interface":"lo"}'`, depois `ip -o addr show dev lo`
  (127.0.0.1/8 e ::1 continuam). Testes: `cargo test -p corerouter-engine --test os_loopback`,
  `cargo xtask netns` (`netns_os_loopback`: aplicar, drift + reconcile, desativar, tirar da config,
  apply com falha e rollback, sempre com a `lo` up, MTU 65536, 127.0.0.1/8 e ::1), e na VM
  `cargo xtask vm-lab run -- scripts/frr-sr-live.sh sr` (o `live_sr` põe a `lo` pelo `LinuxHal`).

  Números **medidos** em 2026-10-28, build debug:
  - no namespace (host), o apply de `lo` + um dummy com 3 endereços leva ~2 ms;
  - na VM (FRR 10.7.1), o `LinuxHal` põe `lo` + `crsr-lo` em 5,4–7,2 ms (duas rodadas) e o commit
    do FRR leva 16,2 ms;
  - o `ospfd` aceita o prefix SID 10.255.0.1 (índice 1) na `lo`: R2 comuta o 16001 (PHP, pop para
    o R1) e R3 o troca para o R2;
  - ping R1 → R3 pelo 16003 e R3 → R1 pelo 16001, e o caminho SR fica utilizável 6,1 s depois do
    commit;
  - o SID num dummy (`crsr-lo`) continua recusado (`interface crsr-lo is not a Loopback`).

  Na primeira rodada, o `ospfd` dos vizinhos R2/R4 do roteiro abortou com o assert da G3.4l
  (TI-LFA ligado neles), sem relação com esta mudança; a segunda passou.

- 2026-10-28 — G4.3hh: Adoção em lote na tomada do par BNG. O perfil mostrou que o tempo não ia nas rotas, como se
  supunha: os 8 workers faziam fila no lock da tabela ativa, um por sessão (300 de 310 ms), e
  `Ppp::effective` clonava três perfis por sessão. Agora:

  - **Duas fases.** O worker indexa a sua parte da réplica, adota o primeiro bloco de 1024
    (`Server::import`, o `Sub`, pool, tabela do caminho lento, XDP ou rota) e responde. Um quadro de
    sessão ainda não adotada a adota na hora (nunca leva PADT); o resto vai um bloco por rodada,
    com os quadros entre eles. Depois, a tabela ativa, o histórico, o Interim, a address-list e a
    publicação, também em blocos, um lock da tabela por bloco. Uma sessão que acaba antes ganha a
    linha primeiro (o Stop leva os contadores herdados).
  - **Rotas em lote numa thread** (`pppoe-routes`): até 64 KiB de pedidos por `sendmsg`, ACK só no
    último, repetição só do recusado, a contagem conferida e publicada na linha do tempo
    (`routes`, `routes_refused`). Oito threads em lote eram mais lentas que uma (o kernel serializa
    pelo RTNL do namespace). `COREROUTER_SLOW_ROUTES=each` volta ao `rtnetlink` uma a uma.
  - **A réplica decodificada em até 8 threads**; o índice de secrets montado no `configure`; o
    `effective` em cache por par de perfis.
  - **Linha do tempo:** `handed_ms`, `answering_ms` e `routes_ms` no `ppp.redundancy.monitor`; o
    selo "rotas" na janela PPP › Redundancy.
  - **Laboratório:** "subida de volta" medida de verdade, pelo primeiro pacote de 32 sessões-sonda
    na porta da rede (antes era a tabela de C).

  Como testar: `cargo test -p corerouter-daemon --bin corerouter-daemon pppoe_ha_tests` (inclui a
  sessão adotada na hora e a que cai antes da contabilidade);
  `COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_routes_batch`;
  `cargo xtask vm-lab run -- env BNG_LAB_HA_BFD=fast cargo xtask bng-lab --only ha --scales 10000,100000`.

  Medido na VM `corerouter-lab` (8 vCPUs, release, BNG Blaster, sem root, BFD `fast`), 100 mil
  sessões: subida de todas as sondas de volta em **0,244 s** (antes 1,20 s), todas adotadas em
  273 ms do último sinal de vida (antes 1102 ms), rotas no kernel em 308 ms, 0 perdidas. 10 mil:
  0,203 s, igual à `main` (a adoção já cabia na detecção). Detalhes em `docs/bng-ha.md` §2.14.

- 2026-10-28 — G3.6h: Três testes instáveis do BFD corrigidos (`netns_bfd`, `netns_ha_bfd`, `bfd::tests::data_plane_for_a_fake_bfdd`),
  um deles com **bug real no serviço** (`ppp_ha`). Status da G3.6h não muda.

  - **`netns_ha_bfd` (bug de código).** O evento "BFD subiu" de um caminho do par que sobe antes da
    configuração do `ppp.redundancy` ser aplicada não entra na fila (o `tap` só enfileira os pares
    já configurados), e o `bfd_sync` (que a documentação diz rodar "uma vez por segundo") só rodava
    na aplicação da configuração, com o instantâneo de até 500 ms. Resultado: a máquina de papéis nunca
    soube que o caminho estava `up`, a perda por BFD (`was_up && expired`) era ignorada e a tomada
    saía por `dead-interval` (1,2 s) em vez de `bfd` (~150 ms), com o `test-takeover` já dizendo
    "bfd-sync: up" (a lista de verificação lia o instantâneo do serviço). Agora `bfd_sync` roda a cada
    200 ms (só preenche o que nenhum evento disse nos últimos 1000 ms, para o instantâneo velho não
    apagar uma perda recente) e a lista de verificação só dá `ok` ao `bfd-*` quando a máquina de papéis
    também sabe que está `up`. O teste passou a esperar o BFD `up` com `detect_ms == 150` (timers
    rápidos, depois do Poll Sequence).
  - **`netns_bfd` (teste).** (1) `session(B)` vinha `inactive` logo depois de A subir: a linha de B é
    do instantâneo do serviço, copiado a cada 500 ms; agora espera por condição. (2) Os 2 s "sem down
    falso" com detecção de 150 ms caem de verdade quando a máquina deixa um daemon parado por 150 ms
    (B declara down e avisa A: `neighbor-signaled-session-down`): a janela de 2 s pode ser repetida
    até 5 vezes, voltando antes para `up` com timers rápidos; um bug que oscila nunca acha janela
    limpa. (3) O limite de detecção passou de 200 ms para 1000 ms (o `ip link set down` roda no meio
    e a máquina carregada o atrasa); ainda separa os timers rápidos (150 ms) dos lentos (3 s).
  - **`data_plane_for_a_fake_bfdd` (teste).** O cronômetro dos ≤ 250 ms agora começa depois do
    `drop(b)` (o drop junta as threads do par) e o limite passou a 1500 ms (ainda abaixo dos 3 s dos
    timers lentos; o laço espera até 2 s). Não reproduzi a falha (0 em 165 execuções sob carga): a
    folga de 100 ms sobre os 150 ms + leituras de 20 ms é a causa provável.

  Reprodução (**medido**, 2026-10-28, 32 núcleos, cada instância num `unshare --user --map-root-user
  --net`, TMPDIR próprio; as três instâncias do teste de cada rodada em paralelo, rodadas de 15):
  - carga moderada (16 laços de CPU + 3 instâncias de cada teste ao mesmo tempo): antes `netns_bfd`
    16 falhas em 45, `netns_ha_bfd` 8 em 45, unitário 0 em 45; depois 0, 0 e 0 em 45 cada;
  - carga extrema (64 laços de CPU + 8 instâncias de cada): antes `netns_bfd` 9 em 40 (8 no
    `session(B)==up`, 1 no "sem down falso"), `netns_ha_bfd` 5 em 40; depois `netns_bfd` 0 em 48 (e
    0 em 48 na segunda rodada), `netns_ha_bfd` 2 em 48. As falhas que sobram a 3× de sobrecarga de CPU são o
    caso em que um hello chega depois da perda do BFD (a máquina de papéis trata como "o par está
    vivo": comportamento desejado contra alarme falso) e não são corrigíveis no teste.

- 2026-10-28 — G1.6k: A imagem instalável passa a levar o **FRR 10.7.1** com a **libyang 3.13.6**, as versões da VM
  do laboratório onde OSPF, LDP, Segment Routing, TI-LFA e o BFD distribuído foram validados (o
  Buildroot 2025.02.19 trazia o 10.3 e a libyang 2.1.148). `os/buildroot-patches/` porta para o
  2025.02.19 as receitas do `master` do Buildroot (FRR 10.7.0 → 10.7.1, libyang 3.13.6), com o
  hash de cada tarball conferido pelo Buildroot; o `cargo xtask os build` aplica os patches à
  árvore extraída e a extrai de novo quando eles mudam, e o `os check` recusa patch fora de
  `package/`. Mesmos daemons e opções (sem `vtysh`, scripts nem bash). Novo `cargo xtask os
  frr-test`: dois roteadores da imagem no QEMU (sem root, enlace por socket UDP do QEMU),
  configurados só por comandos, com vizinho OSPF `Full`, prefix SID do outro com rótulo, LDP
  operacional, BFD `up` pelo data plane do `bfdd`, rótulos MPLS no kernel, ping entre as
  loopbacks e a versão do FRR igual à do patch (25 s, **medido**).

  Como testar: `cargo xtask os build`, `cargo xtask os frr-test`, `cargo xtask os boot-test --efi`,
  `cargo xtask os install-test`.

  Números (**medidos**, 2026-10-28, KVM, builds limpos): rootfs 21,4 → 21,7 MiB; RSS dos 8
  daemons do FRR com OSPF+SR+LDP no ar 85,7 → 88,5 MiB; boot e convergência iguais (kernel → FRR
  0,75 s, OSPF `Full` 1,5 s, LDP 11,5 s); dois builds limpos com `-j` diferente deram imagens
  idênticas, menos o OVA (o `CID` aleatório que o `qemu-img` grava no VMDK, que já existia: G1.6l).

- 2026-10-28 — G3.6l: O perfil `bfd` do interface-template OSPF chega ao `ospfd` (`ip ospf bfd` + `ip ospf bfd profile
  P`), e o vizinho OSPF cai pelo BFD do CoreRouter (data plane do `bfdd`). Achado em paralelo pela
  G1.6k e pela G3.9 (contra o RouterOS); corrigido na G3.9. Números em `docs/changes/G3.9.md`.

- 2026-10-28 — G3.6m: O bloco `bfd` do render é a forma que o `bfdd` 10.7.1 imprime: sem os valores padrão e com
  transmit antes de receive. O hal-frr não o redigita mais a cada sync. Corrigido na G3.9.

- 2026-10-28 — G3.9: Interoperabilidade com RouterOS v7: um RouterOS 7.25 CHR (imagem oficial, SHA-256 publicado
  conferido) roda em QEMU/KVM aninhado dentro da VM do laboratório, ligado ao CoreRouter
  (`--backend linux`, FRR 10.7.1 `-N crcore` num namespace, `bfdd` com o nosso motor como data plane)
  e a dois FRR (R3, R4) para tráfego de ponta a ponta. `scripts/routeros-interop.sh` é o roteiro
  repetível (`cargo xtask vm-lab run -- scripts/routeros-interop.sh [casos]`, ~15 min); o caso `prod`
  aplica os blocos de `docs/producao-core.md` como estão, num CoreRouter reiniciado do zero, e
  confere Full, BFD, LDP e que o MikroTik só manda ao CoreRouter a loopback e a sub-rede de teste.

  Interopera (**medido**, VM do laboratório, 2026-10-28): OSPFv2 ptp (Full 1,8–7,6 s com hello 1 s;
  o CHR fica até ~4 s em Loading) e broadcast com prioridade 0 (CHR DR, CoreRouter DROther); md5 e
  sha256; áreas normal, stub e NSSA (tipo diferente não forma); MTU diferente fica em
  ExStart/Exchange e o `neighbor.diagnose` aponta o MTU, `mtu_ignore` só do nosso lado resolve;
  redistribuição só do pedido; custo 65535 tira o CoreRouter do trânsito sem tirar a sub-rede dos
  clientes; LDP (sessão em 1–2,5 s, rótulos nos dois sentidos, ping R3 → R4 rotulado através do CHR
  e do CoreRouter); BFD 300 ms × 3 e × 4 (× 4 recomendado com RouterOS: nenhuma queda extra na volta
  de um corte); OSPFv3 ptp.

  Corrigido nesta entrega (fecha também a G3.6l e a G3.6m, abertas pela G1.6k):
  - o `bfd` do interface-template OSPF nunca chegava ao FRR (faltava `ip ospf bfd profile P`): num
    corte silencioso o OSPF esperava o dead interval; agora o CHR derruba a adjacência em 0,7–1,1 s
    e o buraco no tráfego é de 1,2–1,6 s (300 ms × 3 a × 4);
  - o `hal-frr` dava como aplicado um batch que o northbound do FRR recusava (`XFRR_end_configuration`
    responde sucesso com "% Configuration failed"): sha1/384/512 deixavam o `ospfd` sem key chain,
    mandando MD5 com key id 0; agora o commit falha com a mensagem do FRR;
  - tirar o OSPF de uma interface mandava `no interface X`, que o FRR recusa enquanto o link existe:
    o commit inteiro falhava; agora a interface é esvaziada linha a linha;
  - o bloco `bfd` era redigitado a cada sync (o `bfdd` omite os valores padrão e imprime transmit
    antes de receive): o render agora é a forma canônica.

  Números de queda (R3 pinga R4 a cada 10 ms; o caminho volta pelo enlace direto CHR—R4):
  corte silencioso com BFD 300 ms × 3: CHR derruba a adjacência em 0,7–0,8 s, buraco de 1,16–1,29 s;
  com × 4: 1,08 s e 1,55 s; perda de portadora: buraco de 0,6–0,7 s; sem BFD (dead 4 s): adjacência
  cai em 3,2–3,5 s; a volta do CoreRouter não abre buraco (< 0,1 s). Sair: template passivo tira o
  tráfego sem perda em nenhuma rodada, desligar a instância abre 0,44–1,4 s.

- 2026-10-28 — G1.27h: Rota do DHCP escondida (achado do usuário numa VM com `--backend linux`, 2026-10-28): com uma
  estática `0.0.0.0/0` distância 1 e um cliente DHCP com `default_route_distance=1`, a rota do lease
  sumia de `ip.route.list` (nem inativa), do kernel e do log; só aparecia ao desativar a estática.
  Causa: `Session::effective` (G4.7a, anterior ao ECMP do G1.27a) descartava a rota do lease quando
  uma estática tinha a mesma tabela, destino e distância ("o kernel fica com uma"); o mesmo no cliente
  DHCPv6. Agora a rota do lease sempre entra: com a mesma distância as duas formam ECMP (`+`, uma rota
  multipath no kernel, como `docs/routes.md` já prometia e como o RouterOS v7 faz); com distância
  maior ela fica em standby com o motivo ("loses to distance 1 (route *1 via …)"). `ip.dhcp-client.list`
  e `ipv6.dhcp-client.list` ganham `route_states` (`route`, `state`, `ecmp`, `reason`) e uma nota por
  rota que não está sozinha no encaminhamento. Testar: `cargo test -p corerouter-engine --test
  dhcp_client a_static_route_at_the_same_distance` (e `--test dhcp6_client`, `--lib route_table`).
  Desempenho: a busca do estado de cada rota do lease é por busca binária no grupo (O(log n) numa
  tabela de 1 M rotas); o filtro antigo era O(rotas × rotas do lease) a cada `effective`.

- 2026-10-28 — G4.6i: NTP desligado deixa de ser aviso num roteador novo (achado numa VM recém-instalada: "1 warning"
  logo na primeira tela, com um cliente DHCP `use_peer_ntp=yes` que é o padrão).

  - **Padrão de fábrica mantido: cliente NTP desligado**, como o RouterOS v7 (`/system ntp client`
    `enabled=no`; ele só acrescenta os servidores do DHCP quando o cliente é ligado). Ligar de fábrica
    com `pool.ntp.org` mudaria o `NtpClient::default()` e, pelo `serde(default)`, também as configs
    já salvas sem o campo, e faria o roteador falar com a internet sem o operador pedir. VyOS
    (`time.cloudflare.com` etc. de fábrica) e OPNsense (pool) ligam; Junos não liga. Fica como opção
    futura, só para config nova, se o operador preferir.
  - **Aviso só quando importa:** a verificação de saúde `ntp` vira Warning com o cliente desligado
    somente se há servidor RADIUS em uso (Event-Timestamp e contabilidade dependem do relógio). Sem
    isso, fica Ok com o texto "desligado (padrão de fábrica)" apontando System › NTP Client.
    Cliente ligado sem resposta continua Warning.
  - Testes: `every_rule_by_table` (desligado sem dependência = Ok; com RADIUS = Warning),
    `new_router_has_no_ntp_warning` (laboratório novo não loga aviso de NTP).
  - Sem mudança em config existente. Caminho não quente (verificação a cada leitura de saúde, O(servidores RADIUS)).

- 2026-10-28 — G1.6m: Primeiro boot da imagem numa VM libvirt (UEFI, 3 placas virtio), seis achados do usuário
  (`docs/os-image.md`, seção G1.6m):

  - **Nomes de porta:** o init renomeia `eth0…` para `ether1…` antes do daemon, na ordem do
    barramento PCI (não do probe), com o nome preso ao MAC em `/config/.port-names` (placa nova
    ganha o próximo número; placa trocada no mesmo slot herda o nome; configuração de antes sem
    mapa mantém os nomes do kernel). `corerouter.mgmt=eth0,…` antigo vale para a mesma placa
    renomeada. O instalador lista as portas com esses nomes, link e MAC, e recusa porta que não
    existe.
  - **Assistente de console:** diz que não há terminal de comandos e o que usar (GUI/CLI pela
    rede); convite de novo a cada 5 min e pergunta pendente de novo a cada 30 s (console serial
    conectado depois); porta pelo número com confirmação (`Use ether1 (link up, 52:54:…)? [y/N]`),
    sem padrão que um Enter perdido aceite; resumo e `Apply? [y/N]`. Com endereço, Enter mostra o
    status e como conectar.
  - **Interfaces do kernel** (`bond0`, `dummy0`, `gre0`, `gretap0`, `erspan0`, `ip6gre0`,
    `ip6tnl0`, `sit0`, `tunl0`): `bonding.max_bonds=0 dummy.numdummies=0` na linha de comando
    embutida e um patch de uma linha no kernel (padrão do `fb_tunnels_only_for_init_net` = 2: o
    sysctl pela linha de comando chega depois dos initcalls). O `os build` reaplica patches do
    kernel quando mudam.
  - **Shell de manutenção que parava:** a causa era sair do shell, não reconectar o console. O
    PID 1 colhia filhos com `waitpid(None)` do rustix 1.x, que é `wait4(0)` (só o próprio grupo
    de processos): o shell (`setsid`) virava zumbi e nunca voltava; órfãos com grupo próprio
    também. Agora `wait4(-1)`.
  - **NVRAM herdada:** o `corerouter.mgmt=` aplicado é anunciado nos consoles (endereço, porta,
    origem, `--reset-nvram`); o marcador `/config/.installer-mgmt-applied` é gravado com fsync
    (o daemon sincroniza a configuração, o marcador não: uma VM desligada à força logo depois
    ficava com o endereço e sem o marcador).
  - **Roteiro** `docs/producao-core.md`: primeiro boot com o assistente real, nomes `etherN` e
    NVRAM nova no Proxmox/libvirt (o caso `prod` do `routeros-interop.sh` usa só os blocos
    `lab:`, sem mudança).

  Como testar: `cargo xtask os build`, `cargo xtask os install-test` (instalação com o
  `corerouter.mgmt=eth0,…` antigo aplicado em `ether1` e anunciado; disco com 3 placas:
  `ether1 ether2 ether3 lo` e nada mais em `/sys/class/net`; marcador e mapa gravados; `exit` no
  shell e ele volta sem zumbi; instalador recusa `eth9`; assistente do qcow2 pelo número, com
  confirmação e resumo), `cargo xtask os boot-test`, `ab-test`, `frr-test` (agora em `ether1`).

- 2026-10-28 — G0.3d: Acesso sem senha como no RouterOS CHR (G0.3d, parte a). No teste da imagem numa VM o usuário
  pulou a senha no assistente e ficou trancado: o `admin` sem senha só entrava de `127.0.0.1` e
  todo login pela rede era recusado (G0.3b), sem shell no console para definir a senha. Decisão
  do usuário: aceitar a senha vazia de qualquer rede, como o CHR, sem forçar troca nem limitar
  comandos, mas avisando sempre.

  - **Control (`auth.login`):** a conta sem senha entra com a senha vazia de qualquer endereço
    (fora do loopback é sempre TLS); a recusa `NO_PASSWORD_REMOTE` saiu (a constante fica para
    os clientes reconhecerem roteadores entre G0.3b e G0.3d). Cada login sem senha é um aviso no
    log do roteador (`log.print`, tópicos `system,account,warning`, origem `auth`) com usuário,
    endereço de origem e canal, e uma linha `WARN` no log do daemon.
  - **Saúde:** verificação nova `auth.no_password` ("Admin password"), `warning` enquanto uma
    conta `full` ativa não tiver senha; entra no selo "1 warning" e no System › Resources (ⓘ em
    inglês e português).
  - **GUI:** selo âmbar `admin: no password` na barra de cima com o botão **Set password** e o ⓘ
    (modal explicando o risco, catálogo `i18n/auto/first_login_*.rs`), em todo login e toda
    janela; o diálogo de primeiro acesso diz que a senha vazia vale pela rede ("Not now" segue).
  - **CLI e MCP:** uma linha `WARNING: user(s) admin of group full have no password…` no login
    (stderr); no MCP o aviso vai também na descrição do backend nas instruções do servidor. O
    terminal (`corerouter-cli shell`, New Terminal) diz o mesmo antes de perguntar a senha.
  - **Daemon e assistente de primeiro boot:** saiu "every network login is refused until a
    password is set"; o assistente (`apps/corerouter-init/src/setup.rs`) mantém a senha opcional
    e termina dizendo que dá para entrar pela rede com a senha vazia e defini-la depois.
  - Docs: `CLAUDE.md`/`AGENTS.md`, `docs/control-protocol.md`, `docs/producao-core.md` e o
    critério da G0.3b em `docs/gaps.md`.

  Como testar: `cargo nextest run -p corerouter-control auth::tests::no_password_admin_logs_in_from_anywhere_and_is_logged`,
  `-p corerouter-daemon network_listener_takes_the_empty_password_with_a_warning`,
  `-p corerouter-engine admin_without_password_warns_until_set`, `-p corerouter-ui first_login`.
  Na mão: `corerouter-daemon --control 7311 --config-dir /tmp/cr`, a GUI com `--connect
  127.0.0.1:7311` mostra o selo e "1 warning"; `corerouter-cli --connect 127.0.0.1:7311 run
  system.identity.get` imprime o aviso.

- 2026-10-28 — G0.28: Gerenciador instalável como o WinBox: `cargo xtask package gui` gera o `.deb` `corerouter-gui`
  com a GUI e a CLI em `/usr/bin` (perfil `dist`: release sem símbolos, commit embutido), a
  entrada do menu (Network › RemoteAccess), o ícone desenhado por código em todos os tamanhos do
  hicolor + SVG, e o handler de links `corerouter://[usuário@]host[:porta]`, que abre a GUI já
  conectando pelo mesmo caminho do botão Connect (certificado confirmado na primeira vez; senha só
  do chaveiro, nunca do link nem do ambiente; texto tratado como hostil). O `.deb` é escrito em
  Rust no xtask (`ar` + `ustar` + gzip), reproduzível, e as dependências vêm do `ldd` mais as
  bibliotecas que o winit/wgpu abrem por `dlopen`. Como testar: `cargo xtask package gui`,
  `dpkg-deb --info/--contents` no arquivo e `sudo apt install ./target/package/corerouter-gui_*.deb`;
  o teste do xtask instala e remove um pacote num diretório descartável sem root. Detalhes em
  `docs/install-gui.md`.

- 2026-10-28 — G0.3d: Certificado trocado sem editar arquivo à mão (G0.3d, parte b). Depois de reinstalar o roteador,
  a GUI recusava o certificado novo e mandava apagar a linha do `known_hosts`.

  - **control:** o `known_hosts` grava quando cada certificado foi aceito (terceira coluna,
    segundos unix; linhas antigas sem ela seguem valendo) e `format_since` mostra a data. O
    `dial` pergunta ao `Trust` o que fazer com um certificado trocado (`Decision::{Cancel, Once,
    Update}`, padrão Cancel): uma vez conecta fixando o novo sem gravar, atualizar troca a linha.
    Nada é enviado ao roteador antes da decisão (a segunda conexão é fixada no certificado que
    o operador viu). `AcceptNew` aceita e grava; `Expect(fp)` aceita a troca só se o novo for
    exatamente o dado.
  - **GUI nativa:** modal (`egui::Modal`) com o fingerprint guardado e quando foi aceito, o novo
    (em duas linhas de 16 bytes, fáceis de comparar), o texto "reinstalação × interceptação", ⓘ
    com a explicação (EN/PT) e três botões: **Cancel** (com foco; Enter e Esc cancelam),
    **Connect once** e **Trust and update**. O primeiro uso abre o mesmo modal (Cancel, Connect
    once, Trust and connect). Rótulos em português no catálogo `i18n/auto/connect_pt.rs`.
  - **CLI:** num terminal pergunta `[c]ancel, connect [o]nce, trust and [u]pdate?` (linha vazia
    cancela); sem terminal recusa com a mensagem e cita `--accept-new-cert` (novo) e
    `--fingerprint`. **MCP** (`corerouter-cli mcp`): igual à CLI sem terminal.
  - Docs: `CLAUDE.md`/`AGENTS.md`, `docs/control-protocol.md`, `docs/mcp.md`.

  Como testar: `cargo nextest run -p corerouter-control -E 'test(known) | test(tls_endpoint) | test(dates)'`
  (trocar, uma vez, cancelar, `--accept-new-cert`), `-p corerouter-cli` (sem terminal: recusa e
  `--accept-new-cert` grava; `run` e `mcp`), `-p corerouter-ui a_changed_certificate_asks_with_cancel_as_the_default`.
  Na mão: daemon com `--listen 127.0.0.1:8739 --config-dir /tmp/cr2`, um `known_hosts` temporário
  (`COREROUTER_KNOWN_HOSTS=/tmp/kh`) com outra impressão para `127.0.0.1:8739`, e
  `corerouter-gui --connect tls://127.0.0.1:8739 --user admin`: abre o modal (screenshot conferido).

- 2026-10-28 — flaky: Dois testes instáveis do `cargo xtask ci` (2026-10-28) corrigidos:

  - **`service::iperf::tests::udp_send_gets_the_far_ends_numbers`**: não era o teste, era uma
    corrida no servidor de bandwidth test (iperf3) do daemon. O servidor mandava `CREATE_STREAMS`
    e só depois abria o socket UDP; com vários streams, também abria o socket do próximo depois de
    responder o anterior. O datagrama do cliente que chegasse antes achava a porta fechada (ICMP
    port unreachable → "Connection refused"). Agora o listener é aberto antes do `CREATE_STREAMS`
    e o do próximo stream antes da resposta, como o iperf3 (`iperf_udp_accept`). Teste novo
    `udp_with_several_streams_never_hits_a_closed_port` (4 streams, 5 vezes): com o código antigo
    falhou 1 de 3 rodadas com o mesmo erro, sem carga; com a correção, 10 de 10, metade com as 32
    CPUs ocupadas (**medido**).
  - **`neighbors::tests::recording_into_a_full_table_is_cheap`**: trava de tempo de uma medição só
    (10 000 inserções < 500 ms em debug) estourava com a máquina carregada. Agora julga a rodada
    mais rápida de 7 (2000 inserções cada, < 100 ms): carga passageira atrasa algumas rodadas,
    nunca todas, e o caminho O(n) antigo (~120 µs por inserção) dá > 200 ms em todas. Medido em
    debug: 11 ms por rodada.

- 2026-10-28 — G1.27j: Rota do DHCP em ECMP silencioso (achado do usuário na VM depois da G1.27h): com uma estática
  `0.0.0.0/0` distância 1 e um cliente DHCP com `default_route_distance=1` (o padrão do RouterOS), as
  duas viravam ECMP e o tráfego passava a sair por fluxo por duas saídas com IPs públicos diferentes,
  sem aviso nenhum. Agora:

  - **Distância 254 para cliente novo** (`ip.dhcp-client.add`/`ipv6.dhcp-client.add` sem
    `default_route_distance`, e os formulários "New" da GUI), a AD do Cisco para a default aprendida
    por DHCP: sozinha ela é a rota em uso; ao lado de uma estática, OSPF ou BGP fica de reserva.
    Config gravada mantém o valor (o campo é sempre gravado; arquivo sem ele lê 1, como antes). A rota
    de RA continua em 255, atrás da do DHCPv6.
  - **Aviso sempre que houver ECMP**: `notice` em cada rota ativa do grupo no `ip.route.list` (info:
    caminhos de uma origem só; warning: origens misturadas, dois clientes DHCP ou a rota padrão, com o
    comando pronto no `fix`); selo `ECMP` âmbar + `warning`, texto no Motivo, contagem no rodapé e
    linha "ECMP" com "Copy command" no detalhe da janela Routes (ⓘ do Motivo explica); check de saúde
    `routes.ecmp` (conta no "N warning" da barra); `notes` e `route_states[].notice` em
    `ip.dhcp-client.list`/`ipv6.dhcp-client.list`; `summary.ecmp_warning/ecmp_info` no
    `ip.route.page`.

  Testar: `cargo test -p corerouter-engine --lib route_table` (warning misto com o fix, info do mesmo
  protocolo, rota padrão, desfazer o empate limpa o aviso, 100 000 rotas em ECMP numa passada),
  `--test dhcp_client a_static_route_at_the_same_distance a_new_client_is_a_backup`, `-p
  corerouter-model` (254 no cliente novo, 1 preservado), `-p corerouter-ui --lib route_view`. Na GUI
  (lab virtual): estática `0.0.0.0/0` + cliente DHCP em ether1 com distância 1 → linha ECMP âmbar e
  "1 ECMP warning"; o comando do aviso deixa a do DHCP em standby e o aviso some.

  Desempenho: o aviso é decidido em `select_group`, na mesma passada que já decide os estados (os
  grupos são runs da tabela ordenada): O(tamanho do grupo) por grupo, O(n) na tabela; a contagem vai
  no `Summary` guardado com as linhas, e a saúde só a lê.

- 2026-10-28 — G1.6e: Pacote pela rede, parte 1: o `.crpkg` vai pelo canal de controle (TLS, ou o canal local da GUI)
  em blocos de 1 MiB e é gravado no slot inativo enquanto chega, sem cópia em RAM (fila de 8
  blocos; cheia responde `busy`). Comandos `system.package.upload.start/chunk/abort`; o serviço
  `package` lê a fila como um fluxo (`sysupdate::upload::ChunkReader`) e usa a mesma instalação de
  um arquivo (`Platform::install_from`): assinatura antes do primeiro byte, hashes e dm-verity antes
  de ativar, boot de teste com volta automática. Interrompido, adulterado ou abandonado (60 s sem
  bloco) não muda nada. GUI: System › Packages › From this computer (caminho ou arquivo solto na
  janela, progresso, Abort); o navegador ainda não lê arquivos locais. CLI: `corerouter-cli upload
  <arquivo> [params] --wait` espera o reboot e a confirmação. Ciclo de teste da imagem sem
  recriar a VM: `cargo xtask os build --only crpkg` (sem disk.img, ISO, qcow2, OVA) e `cargo xtask
  os push --to 127.0.0.1:7990` (build, envio, reboot, confirmação, tempo de cada etapa).
  `cargo xtask os ab-test --scenario push`: envio por TLS no QEMU mantém `/config`, senha e
  certificado; um pacote ruim enviado do mesmo jeito volta sozinho. Como testar: `cargo test -p
  corerouter-daemon --test package_upload`, `cargo test -p corerouter-sysupdate`, `cargo xtask os
  ab-test --scenario push`. Números em `docs/os-image.md` ("Pacote pela rede").

- 2026-10-28 — G1.6e: Pacote pela rede, parte 2: `system.package.download {url, check?, downgrade?, ssl_verify?,
  confirm?, timeout?, reboot?}` — o próprio roteador baixa o `.crpkg` de um endereço HTTP(S) (thread
  `pkg-download`, cliente HTTP do daemon com o corpo entregue em pedaços de 256 KiB, `get_to`) pela
  mesma fila limitada do envio até a instalação em fluxo: nunca inteiro na memória, assinatura antes
  do primeiro byte gravado. Na GUI, um endereço no campo Package file faz Check e Install baixarem.
  Como testar: `cargo test -p corerouter-daemon --test package_upload` (servidor HTTP local: 404,
  pacote adulterado, check, instalação e boot de teste).

- 2026-10-28 — G1.6o: Acesso web de fábrica, como o WebFig: na imagem, `https://<roteador>/` abre a GUI e pede o login.
  Comandos `ip.service.www-ssl.set/get` (HTTPS + WSS com o certificado do roteador) e
  `ip.service.www.set/get` (HTTP só para `301` → HTTPS), com `enabled`, `address`, `port` e
  `available_from` (o `address` do `/ip service`: quem não está na lista cai antes do TLS, contado
  em `refused`). O serviço `web` do daemon segue a config em execução: um commit abre, move ou
  fecha a porta sem reiniciar, e as conexões abertas continuam. O padrão de fábrica (`www-ssl` na
  443) vale só para config nova (`--web-factory-on`, passado pelo init), então um roteador
  atualizado não ganha porta nova. O `cargo xtask os build` compila a GUI com trunk em release,
  com `wasm-bindgen` e `wasm-opt` em versões fixas conferidas por SHA-256 e guarda o `.wasm` e o JS
  só como `.gz`, que o daemon serve com `Content-Encoding: gzip` (32 → 11 MiB na rede). Respostas estáticas ganham `X-Frame-Options: DENY` e
  `Referrer-Policy: no-referrer`. Detalhes, pesquisa e números em `docs/os-image.md` ("Acesso web
  de fábrica").

  Como testar: `cargo xtask os build && cargo xtask os boot-test` (a linha "web access" mostra a
  página, o `.wasm` e o login por WSS); fora da imagem,
  `corerouter-daemon --config-dir /tmp/cr --web-files <dist> --web-factory-on` e
  `corerouter-cli --connect 127.0.0.1:7979 run ip.service.www-ssl.set '{"port":18443}'`, depois
  `https://127.0.0.1:18443/`.

- 2026-10-29 — G0.3e: Senha salva sem esconderijo na tela de conexão (defeito de 2026-10-29: numa VM reinstalada com
  `admin` sem senha, a GUI nativa mandava em silêncio a senha guardada no chaveiro para a VM antiga
  quando o campo Password ficava vazio, e o login falhava com "Invalid user or password"). Agora a
  GUI manda exatamente o que o campo tem: ao mudar Connect to ou Login, ela procura a senha salva
  (`usuário@endereço` normalizado, serviço `corerouter`) e, se existir, a põe no campo (mascarada)
  com o selo azul `saved password`, o ⓘ (`connect.saved_password`, pt/en) e "Forget"; campo apagado =
  senha vazia, e o selo vira `saved password unused`. Login recusado com a senha salva diz "The saved
  password for this router did not work…" com o botão "Forget saved password". "Trust and update"
  num certificado trocado (G0.3d) traz a caixa "Also forget the saved password of admin", marcada
  por padrão (reinstalação = admin novo), e conecta sem ela. Duplo clique num vizinho conecta só
  depois de a senha salva estar no campo. O exemplo de Connect to virou `e.g. 192.168.88.1:8729` em
  itálico (não o último endereço usado: isso pediria estado novo e, com a senha agora preenchida,
  um Enter ao abrir entraria no último roteador sem escolha; a aba Saved já cumpre esse papel).
  `--connect` segue o mesmo caminho do botão. Código: `crates/ui/src/connect.rs`
  (`wants_saved_password`/`set_saved_password`, `ConnectAction::ForgetPassword`,
  `Trust.forget_password`, `Credentials.saved`), `apps/corerouter-gui/src/native.rs` (trait
  `Secrets`: chaveiro do sistema ou um mapa nos testes). Testes: 4 da tela (senha mostrada e campo
  vazio, recusa com Forget, Trust and update, vizinho com duplo clique e exemplo) e 2 nativos com
  servidor de controle de teste e cofre falso (o defeito reproduzido: senha velha recusada,
  esquecida, senha vazia entra; Remember/forget por conta). Screenshots em
  `docs/changes/G0.3e-screenshots/` (GUI real num D-Bus isolado com gnome-keyring descartável).
  Busca no chaveiro: ≤ 5,5 ms por troca de endereço/Login (**medido**, 100 `secret-tool lookup`
  com o processo incluído, 2026-10-29), fora de qualquer caminho quente.

- 2026-10-29 — G0.29: Portão local mais rápido para várias sessões em paralelo (pedido do usuário, 2026-10-29), partes
  A e D; a B (sccache) foi medida e ficou de fora:

  - **A. `cargo xtask ci --affected`** (`xtask/src/affected.rs`): os arquivos mudados desde a
    base com a `origin/main` (commit, índice, árvore e não rastreados; `--base <ref>` muda a base)
    dão os crates alterados, por diretório, e os que dependem deles (dependências normais, de dev
    e de build, via `cargo metadata`). fmt, clippy e test rodam com `-p` só nesses;
    `bench-check` e `netns` só nos crates alterados que têm benches/testes `netns*` (os dos
    dependentes ficam para o completo da fila: rodá-los a cada mudança no `engine` custava
    ~3 min), `wasm` só nos crates WASM do conjunto, `layers` quando muda um `Cargo.toml` de
    crate, `docs` quando muda `docs/`, `agents-sync` quando muda `AGENTS.md`/`CLAUDE.md`,
    `ebpf-check` quando muda `crates/dataplane-ebpf*`. Arquivo de workspace
    (`Cargo.toml`/`Cargo.lock` da raiz, `xtask/`, `.cargo/`, `.config/`, `build-support/`,
    `clippy.toml`, `rustfmt.toml`, toolchain) ou arquivo em `crates/`/`apps/` fora de qualquer
    pacote roda tudo. Arquivos lidos de fora do pacote (`fuzz/`, `docs/analytics.md`, o objeto
    XDP) selecionam quem os lê. Vira o portão local do `CLAUDE.md` e do `AGENTS.md`; o completo
    segue no lote da fila e na `main` (`scripts/land.sh` sem mudança).
  - **D. 2 vagas de CI na máquina** (`xtask/src/slots.rs`): o `ci` que compila pega uma vaga
    (`flock` em `$XDG_RUNTIME_DIR/corerouter-ci/slot-<i>.lock`, solta quando o processo morre;
    o fd é close-on-exec, nenhum filho a herda) e espera com "esperando vaga (N rodando: pid … em
    …)"; depois confere o disco do target e espera (até 20 min) enquanto houver menos de 30 GB
    livres. `--no-wait` só avisa; `COREROUTER_CI_SLOTS` e `COREROUTER_CI_MIN_FREE_GB` mudam os
    limites. No GitHub Actions não há vaga (um job por runner).
  - **B. sccache: medido, sem ganho, fora.** A chave de cache do sccache 0.18 para Rust inclui a
    pasta da worktree (o `cwd` que o cargo dá ao rustc) e o caminho do target: a mesma crate do
    registro deu chaves diferentes em outra worktree e em outro `CARGO_TARGET_DIR` da mesma
    worktree, e `SCCACHE_BASEDIRS` não mudou a chave. Uma segunda worktree com o cache quente
    teve 0 acertos de Rust (845 erros; só 31 acertos de C/assembly) e a compilação fria ficou
    ~14% mais lenta com o sccache. Fica como G0.29b.

  Como testar: `cargo test -p xtask` (seleção do afetado com metadata falsa; o semáforo com dois
  processos-filho segurando as vagas, a morte de um libera, a trava não passa para filhos);
  `cargo xtask ci --affected` numa branch com uma mudança pequena.

- 2026-10-29 — G0.29: Parte C: os testes de integração de cada crate viram um executável só, `tests/it/main.rs` com um
  `mod` por arquivo (106 arquivos de 9 crates: engine, daemon, dataplane-ebpf-common, shell,
  proto-pppoe, proto-radius, control, mcp, proto-ha). Os nomes das funções não mudam; o nome
  completo ganha o módulo do arquivo (`cgnat::...`), e o `.config/nextest.toml` casa com ou sem
  ele. Ficam em `tests/<nome>.rs`, binário próprio, os que precisam do processo deles: `netns*`
  (o `cargo xtask netns` dá um namespace novo por binário, descoberta sem mudança), `*_root`
  (`cargo xtask xdp-root`), `*_live` (scripts do FRR), `bng_lab*` (`cargo xtask bng-lab`), os que
  se reexecutam pelo nome (`current_exe() --exact`) e o `discovery/tests/warnings.rs`, que
  instala o logger do processo. O `cargo xtask fmt` reprova um `tests/it/<nome>.rs` sem o `mod`
  no `main.rs` (ficaria sem compilar, em silêncio). `CLAUDE.md`/`AGENTS.md`: a regra do arquivo
  novo de teste.

  Benches (77): não juntados. A medição dos testes mostrou que juntar não muda o tempo (o link
  já roda em paralelo nas 32 threads) e só reduz disco; nos benches seriam ~2,4 GB, ao custo de
  renomear os alvos que `cargo bench --bench <nome>`, o `SLOW_FIRST` do bench-check e os
  comandos do `docs/perf.md` usam.

  Como testar: `cargo nextest run --workspace` (3487 testes); `cargo test -p corerouter-engine
  --test it cgnat::` (um arquivo); `cargo xtask netns`; `cargo test -p xtask it_mods`.

- 2026-10-29 — G0.30: Orçamento de testes, parte A: o relatório dos mais lentos. O passo `test` do `cargo xtask ci`
  grava o JUnit do nextest (`.config/nextest.toml`, `target/nextest/default/junit.xml`) e o xtask
  imprime, depois do resumo, o total de tempo de teste, quantos passam de 1 s e de 5 s e os 20
  mais lentos (`xtask/src/slowest.rs`); aparece no fim de todo `cargo xtask ci` e no log de cada
  parte do job `test` no GitHub. Como testar: `cargo xtask ci --only test` e ler o fim da saída.

- 2026-10-29 — G0.30: Orçamento de testes, parte B: camadas de teste e proptest por camada. A camada **rápida** (o
  portão da sessão `cargo xtask ci --affected`, o `--fast` e o job `test` do PR no GitHub) roda
  tudo menos os testes cujo nome começa com `slow_` (perfil `quick` do `.config/nextest.toml`) e
  com `PROPTEST_CASES=32`; a **completa** (lote da fila e `main`) roda todos com os casos de cada
  proptest; o **CI noturno** novo (`.github/workflows/nightly.yml`, 06:17 UTC) roda a completa com
  `PROPTEST_CASES=4096` (o maior caso escrito hoje é 3000) em 4 partes, mais os namespaces, e abre
  ou comenta a issue "CI noturno quebrado" (rótulo `noturno-quebrado`) ao falhar, fechando-a no
  verde, como o `main-red`. O `--affected` deixa de rodar o `netns` (camada lenta) salvo com
  `--only netns`. `COREROUTER_TEST_LAYER=quick|full` escolhe à mão.

  Na camada lenta (`slow_`, cada um com uma linha de doc dizendo por quê): a simulação de 100 mil
  sessões PPPoE, a reconexão em massa de 20 mil, os 20 mil Service-Names em QinQ, a reconexão de
  6000 CPEs contra um RADIUS lento, as 100 mil requisições RADIUS e o aviso do discovery (agentes
  em sockets reais, intervalo de 1 s). Os dois testes do journal da config que percorriam de 5 a
  2100 commits num laço viraram dois cada: os casos pequenos ficam na camada rápida e os da borda
  do checkpoint (1023–1025, 1030 e 2100 commits) na lenta, um teste por contagem para rodarem
  lado a lado no lote. Nada do que os testes conferem mudou. O `priority` do nextest passa a
  começar primeiro todos os `slow_`, sem lista de nomes.

  As regressões gravadas do proptest (`proptest-regressions/`) rodam antes dos casos novos com
  qualquer `PROPTEST_CASES` (proptest 1.12, `run_in_process_with_replay`); o risco era outro: o
  arquivo é achado pelo caminho do teste, e um teste movido (como na ida para `tests/it`, G0.29)
  deixa as sementes para trás sem aviso. O passo `test` agora reprova regressão órfã
  (`xtask/src/regressions.rs`).

  Como testar: `cargo xtask ci --affected` (a linha "test layer: quick …" e o relatório no fim);
  `COREROUTER_TEST_LAYER=full cargo xtask ci --only test` roda os `slow_`;
  `cargo nextest list --profile quick | grep -c slow_` dá 0.

- 2026-10-29 — G0.30: Orçamento de testes, parte C: relógio simulado nos piores e o teto.

  - `corerouter_engine::tasks::SimClock`: um `Clock` cujo `sleep` só avança o tempo (sem
    threads, compila para WASM). Os testes de ferramentas do engine (`test_runner::sim()`) e os da
    GUI e do engine que usavam relógio de parede (traceroute, ping, torch, bandwidth, RADIUS, LSP
    ping, cable test, ARP) passam a usá-lo: os timeouts do laboratório não custam nada. Ficam no
    relógio de parede, com o motivo no teste, os dois que precisam dele: parar um ping contínuo
    ainda rodando e esperar a resposta do backend RADIUS de outra thread.
  - Serviços `metrics`, `dns_server` e `dns` do daemon: o `TICK` que relê a config é 50 ms nos
    testes de unidade (`cfg!(test)`), 1 s em produção.
  - `command_sweep` (todo comando com parâmetros lixo; cresce com cada comando novo) dividido
    pelos núcleos com `thread::scope`; cada entrada continua num laboratório novo. O teste de
    corrida do iperf roda as 5 rodadas de 1 s ao mesmo tempo, cada uma com o seu servidor.
  - `[profile.dev.package.*]` com `opt-level = 3` para a pilha do egui e do texto (egui, epaint,
    harfrust, skrifa, vello…) e para serde_json, regex, memchr e sha: os testes da GUI desenham
    quadros de verdade e gastavam o tempo nesse código sem otimização. Nosso código continua sem
    otimização (compila rápido e depura igual).
  - Camada lenta: a tempestade DHCP de 70 mil clientes (`slow_`).
  - Teto (`xtask/src/slowest.rs`, `budget` no `xtask/src/main.rs`): teste fora da camada lenta
    acima do teto reprova o job `test` do PR no GitHub, onde o teto é 10 s (o runner de 4 vCPU
    leva 1,5–2× o tempo daqui nos testes que gastam CPU, **medido** no #389); no local, acima de
    5 s é aviso, e o `--affected` lista os testes acima de 1 s dos pacotes mudados
    (`COREROUTER_TEST_CEILING_SECS` muda o teto). O teto vale
    na camada rápida (a do PR): no lote, os proptests rodam com os casos escritos (até 3000) e a
    camada lenta é lenta de propósito.

  Como testar: `cargo xtask ci --affected` (fim da saída: relatório e avisos);
  `COREROUTER_TEST_CEILING_SECS=0.5 GITHUB_ACTIONS=1 cargo xtask ci --only test` reprova.

- 2026-10-29 — G0.31: Auditoria de desempenho, parte 1: `config.diff` e `state.inspect` (o `pending_changes` do resumo
  usa o mesmo diff) serializavam a config inteira dos dois lados, mesmo sem nada pendente. Com uma
  config de ISP (1000 VLANs, 10 000 regras de filtro, 100 000 entradas de address-list, 60 000
  rotas), cada um segurava o lock do `Session` por ~1,4 s; a GUI pede os dois a cada segundo
  (`REFRESH_SECS`), então uma GUI aberta deixava o lock ocupado quase o tempo todo e DHCP, PPPoE,
  métricas e os outros clientes esperavam. Agora `diff_configs` retorna na hora quando as configs
  são iguais (as seções compartilhadas comparam por ponteiro) e só serializa as seções que mudaram
  (`Config`, `Ip` e `Firewall`, desestruturados por inteiro: campo novo sem tratamento não compila).
  Teste: `store::tests::skipping_equal_sections_gives_the_same_diff` compara com o diff antigo.
  Benchmark novo `crates/engine/benches/lock_hold.rs`: varre todas as consultas que aceitam `{}`
  na config grande e imprime as mais lentas, e mede `state.inspect`/`config.diff` com e sem
  mudança pendente. Números na seção perf (**medido**).

- 2026-10-29 — G0.31: Auditoria de desempenho, parte 3: o encaminhador DNS da LAN lia cada socket UDP numa thread só.
  Sob carga, essa thread `dns-udp` ficava a 100 % de um núcleo com os outros 31 livres e o
  encaminhador parava em ~340 mil respostas/s. Agora cada socket tem até quatro leitores (metade dos
  núcleos, de 1 a 4), todos no mesmo socket: o kernel entrega cada datagrama a um leitor que está
  esperando, então não há porta nova nem opção de socket nova. Os locks da cadeia (estatística,
  limite por cliente, cache) deixam escalar: 4 threads dão 964 mil respostas/s, com p99 de 229 µs
  (eram 626 µs). O limite `max_queries_per_client` continua valendo para o conjunto, porque a tabela
  de baldes é a mesma. A G3.9h também testa o DNS nesta rodada; esta mudança só mexe em
  `open()`/`udp_threads()` de `apps/corerouter-daemon/src/service/dns_server.rs`. Números na seção
  perf (**medido**).

- 2026-10-29 — G0.31: Auditoria de desempenho, parte 2: `ip.firewall.<tabela>.list` era O(n²). Para cada regra o
  `rule_issues` montava de novo o grafo de jumps da tabela inteira, e o `shadowed` percorria todas
  as regras anteriores de todas as chains e recalculava a família dos dois lados a cada par. Agora
  `corerouter_firewall::table_issues` monta o grafo uma vez por tabela (como o `validate` já fazia
  desde o audit-net) e o `shadowed` guarda, por chain, as regras anteriores que decidem, com a
  família calculada uma vez: as mesmas comparações na mesma ordem (o teto `MAX_COMPARISONS` corta
  no mesmo ponto). Com 10 000 regras em 50 chains, 372 → 38 ms sob o lock do `Session` (a janela
  Firewall pede a lista a cada segundo). Teste: `table_issues_are_the_issues_of_each_rule`
  (`crates/firewall/tests/render.rs`) e os testes do `shadow`. Números na seção perf (**medido**).

- 2026-10-29 — G0.31: Auditoria de desempenho, achado de passagem: os serviços `frr`, `mpls` e `neighbors` ociosos
  (daemon sem `--frr`, laboratório virtual) davam heartbeat a cada 60 s, mas o supervisor acusa
  "no heartbeat for 30 s (stuck?)" depois de 30 s. Todo daemon sem FRR logava esse aviso falso e
  mostrava o motivo "no heartbeat" em `system.service.print`. Agora os três chamam
  `Health::idle_until_shutdown`, que bate a cada `IDLE_BEAT` (10 s); o teste
  `an_idle_service_beats_before_it_counts_as_stuck` mantém o intervalo abaixo da metade do limite.

- 2026-10-29 — G1.6q: Teste de produção da imagem instalada, parte 1 (o soak de 8 h vem num PR seguinte,
  `G1.6q-soak`). Na VM `corerouter-teste` (libvirt, imagem de 28/10, `3d79961`) só por leitura e
  pelo canal 7990 da GUI do usuário; os testes que mudam config, reiniciam ou derrubam a VM
  rodaram em duas cópias locais da **mesma imagem** (`corerouter.qcow2` de 28/10) num QEMU de
  usuário, só com a rede NAT do slirp (nada na rede física).

  Quatro defeitos achados e corrigidos:

  - **`virsh shutdown`, o "Shutdown" do Proxmox e o botão de energia não faziam nada**: o kernel
    6.18 com `ACPI_BUTTON` não criou dispositivo de entrada para o botão fixo do q35, e ninguém o
    ouvia. Agora o `CONFIG_ACPI_TINY_POWER_BUTTON` manda SIGUSR2 ao PID 1, que já desliga limpo.
    Botão → QEMU fora: **0,41 s** (antes: nada em 64 s; **medido**).
  - **`system.resource.process.print` voltava `[]`** numa chamada avulsa (CLI/MCP, ninguém olhando
    a janela) e, depois, a lista de até 15 s antes. Agora lê na hora quando a do serviço não é da
    última leitura (teste `a_one_shot_call_gets_the_processes_of_now`).
  - **Descritores abertos por processo** não apareciam em lugar nenhum: `fds` na lista de
    processos (`/proc/<pid>/fd`, até 65 536 contados; teste `open_descriptors_are_counted`).
  - **Cada GUI aberta puxava ~300 KB/s da gerência**, parada (4,2 GB em 3h48 numa delas, na VM
    real): o catálogo de comandos (`engine.list`, 309 KB) ia junto em toda atualização de 1 s.
    Agora a GUI pede `engine.list {if_none_match: <etag>}` e o roteador responde `{etag,
    unchanged: true}` quando nada mudou (FNV-1a do JSON do catálogo, razões de desabilitado
    incluídas, então um botão que acende vem na atualização seguinte). Sem o parâmetro (CLI, MCP,
    GUI antiga) a resposta continua o array; roteador antigo ignora o parâmetro e a GUI aceita o
    array. **294 → 8 KiB/s** por GUI ociosa (**medido**, mesmo daemon, 60 s; testes
    `the_catalogue_is_not_sent_again_unchanged` e `the_catalogue_comes_again_only_when_it_changed`).

  Funcional na imagem (cópias locais, KVM, 2 vCPUs, 2 GiB, **medido** em 2026-10-29):

  - 298 comandos de consulta com `{}`: nenhum pânico, nenhum erro fora de "parâmetro obrigatório"
    ou "nada configurado" com o comando que resolve; os mais lentos: `log.os.print` 7,8 ms.
  - Transacional: loopback, bridge sobre `ether2`, VLAN 100, endereços e identity num
    `config.commit` (revisão 5), `config.drift.list` em sincronia, `config.rollback` para a 4.
  - Safe Mode: a sessão caiu, as mudanças foram desfeitas ("undone (the owner's connection
    closed)"); `config.safe-mode.exit` confirmou.
  - Reset forçado (`system_reset`, queda de energia): config inteira de volta; **3,7 s** do reset ao
    TLS respondendo, kernel → daemon pronto 1,25 s; boot a frio da imagem nova 2,78 s (com o
    firmware).
  - A/B: 3d79961 → imagem nova em **18 s** (envio 0,3 s a 172 MiB/s, volta em 10,5 s, confirmada
    em 17,5 s), config, certificado e `admin` sem senha mantidos; `system.tuning.boot.apply
    drill=true` (slot de teste que não boota): kernel panic e volta sozinha ao slot anterior,
    `rolled-back`, em menos de 20 s.
  - Web: `https://…/` 200, `.wasm` de 11,5 MB em gzip em 0,17 s; métricas (`ip.service.metrics`)
    171 linhas em 15 ms; NTP sincronizado em menos de 5 s (stratum 2, −3,8 ms); DNS pelo
    servidor configurado.
  - Gerência sob carga (cópia local, 2 vCPUs): 1 conexão 2 405 consultas/s (p50 0,38 ms, p99
    0,96 ms), 4 conexões 4 712/s (p99 2,08 ms), o daemon em ~1,2 das 2 vCPUs.

  Na VM real: atualizada pelo canal 7990 (`corerouter-cli upload --wait`, o que o `cargo xtask os
  push` faz) para esta branch (`f694e065`): 17,6 s, volta em 7,5 s; config (13 revisões), endereço
  DHCP da `ether1`, certificado (SHA-256 igual) e `admin` sem senha mantidos, as duas GUIs
  reconectaram. Ela rodava desde 28/10 **sem dm-verity** (primeiro boot de imagem de VM pelo
  fallback da UEFI, documentado em `docs/os-image.md`); agora o slot `b` está com `"verity":
  true`. O roteiro (`docs/producao-core.md`) ganhou o passo "reiniciar uma vez".

  FRR ocioso: **103,3 MiB** somando os 8 daemons (10 processos; o `ldpd` tem 3), contra os ~88 MiB
  da G1.6i; `mgmtd`+`zebra`+`staticd` são 33,4 MiB: a G1.6i economizaria ~70 MiB (**medido**, VM
  real, 4 h de uptime).

- 2026-10-29 — G3.9h: QinQ 802.1ad como o RouterOS monta: `interface.vlan.add` ganhou `use_service_tag` (o
  `use-service-tag` do RouterOS), que cria a VLAN com TPID 0x88a8 (S-tag do IEEE 802.1ad) em vez
  de 0x8100. Antes o CoreRouter só empilhava 802.1Q sobre 802.1Q, e uma C-VLAN sobre uma S-VLAN
  do RouterOS ou de uma OLT não conversava. Uma S-VLAN e uma C-VLAN podem ter o mesmo id na
  mesma porta (TPIDs diferentes, como no Linux e no RouterOS); duas S-VLANs com o mesmo id, não.
  O `interface.list` mostra `use_service_tag`, o `/export` escreve `use-service-tag=yes` só onde
  está ligado, e a config de uma VLAN comum não muda (o campo só é gravado quando verdadeiro). No
  kernel: `IFLA_VLAN_PROTOCOL` na criação e na leitura (uma VLAN existente com outro TPID não é
  adotada). Teste: `cargo test -p corerouter-engine --test it -- vlan_add_service_tag_for_qinq` e o
  teste de namespace `vlan_bridge_loopback_and_addresses` (`cargo xtask netns`), que cria
  `802.1ad id 10` + `802.1Q id 7` em cima e confere no `ip -d link`.

- 2026-10-29 — G4.3hk: O `netns_ha_pppoe` caía uma vez a cada tantos lotes da fila, cada vez num ponto. A causa
  eram **dois defeitos do produto**. O teste estava certo.

  - **Um nó do par atendia assinantes sem a config do par.** O laço `ppp-ha` e os serviços
    PPPoE/IPoE releem a config cada um no seu segundo. Logo depois de `ppp.redundancy.set`, o
    HA já dizia `standby` (ou `active`) e os workers ainda rodavam sem redundância
    (`serving()` = `!cfg.redundancy.enabled || …` = sim). O nó respondia PADI pela MAC
    própria em vez da virtual, e um standby atendia CPEs que depois abandonava em silêncio.
    Comprovado no laboratório: as CPEs subiram em 25 ms com MAC de AC errada, e o B registrou
    `down admin` de sessões que um standby não devia ter. Correção:
    `pppoe_bng::ha_may_answer`. Sem par nem no HA (`HA_PAIRED`, que o `ppp-ha` grava) nem na config, o nó
    atende como antes. Com par em qualquer um dos dois, só atende quando é o ativo **e** a
    config dele já tem o par (a VMAC). O IPoE usa a mesma trava, no DHCP e no ARP calado.
  - **CoA-ACK antes de a mudança aparecer** (RFC 5176 §3: o ACK diz que a mudança foi feita).
    O PPPoE punha a taxa na fila dos workers e respondia ACK; o `ppp.active.list` só mostrava
    a taxa na volta seguinte do worker (até 20 ms ocioso, mais sob carga). Comprovado: logo
    após os 20 ACKs uma sessão estava sem a taxa, e 2 s depois tinha. Agora a taxa entra na
    sessão sob o mesmo lock, antes do ACK, como no IPoE. O plano de dados é programado na
    volta seguinte do worker, como já era.

  O teste ganhou diagnóstico permanente: quedas das CPEs por motivo, o maior intervalo sem
  atendimento e, na falha, o monitor e o histórico dos dois nós, o log do roteador (papéis
  e partidas do PPPoE) e o fim dos logs dos daemons, que agora ficam na pasta de config.
  Duas hipóteses foram descartadas com medida. **(a)** As CPEs sem atendimento entre as
  consultas ao B ficaram até 1,4 s (**medido**), longe do `keepalive_timeout` de 10 s.
  **(b)** Um split brain por hello perdido também não: congelar o B ou o A por 3 s
  (SIGSTOP) com 200 sessões não derrubou nenhuma.


  Como testar: `cargo test -p corerouter-daemon --bin corerouter-daemon -- a_node_answers_only coa_rate_is_on`
  (determinísticos: o primeiro fixa a tabela da trava, o segundo reprovava sem o ACK novo) e
  `cargo xtask netns` (o teste inteiro).

  Números (**medidos**, 2026-10-29, AMD Ryzen AI Max+ 395, 32 threads, build debug), várias
  cópias do teste em paralelo, cada uma no seu namespace:

  | Carga | Antes | Depois |
  |---|---|---|
  | 8 cópias × 6 rodadas | 6 falhas em 48 (5× MAC de AC errada, 1× taxa do CoA) | 0 em 48 |
  | 12 cópias × 4 rodadas | 7 falhas em 48 (todas MAC de AC errada) | 0 em 48 |
  | 12 cópias × 3 rodadas (código final) | — | 0 em 36 |

  Só CPU não reproduz: 0 falhas em 7 rodadas do `cargo xtask netns` inteiro preso em 4 e em
  2 núcleos com laços de carga, e 0 em 5 do teste sozinho sob carga. A janela aparece quando
  vários daemons sobem e são configurados ao mesmo tempo, como no passo `netns` do CI.

- 2026-10-29 — G3.9f: Interoperabilidade BGP, parte 1: CoreRouter × CoreRouter e FRR 10.7.1, sem root e sem a VM do
  laboratório (presa a noite toda). `scripts/bgp-crcr-userns.sh` monta dois CoreRouters (backend
  linux, cada um com o seu FRR) e dois FRR num namespace de usuário + rede + montagem
  (`unshare --user --map-root-user`), com os pacotes oficiais do FRR 10.7.1 (deb.frrouting.org,
  SHA-256 do índice conferido) extraídos no target, nunca instalados; 12 casos, 50 OK, 0 FAIL e nenhum
  aviso "FRR prints … differently" na última rodada (**medido**, AMD Ryzen AI Max+ 395, 32 threads, release, 2026-10-29). O roteiro contra o RouterOS 7.25
  CHR, `scripts/routeros-interop-bgp.sh` (17 casos: eBGP/iBGP v4/v6, MP-BGP, multihop, MD5,
  communities normal/large/extended, filtros nos dois sentidos, next-hop-self, refletor nos dois
  sentidos, max-prefix, reinício, BFD, convergência, 100 mil prefixos, CoreRouter × CoreRouter),
  está pronto e roda na próxima janela da VM (`G3.9f-routeros`).

  Defeitos achados e corrigidos (cada um com teste):

  - **O BFD do BGP desligava a cada commit.** O `bgpd` 10.7.1 imprime `neighbor X bfd` e
    `neighbor X bfd profile P`; o render só tinha a segunda, e todo sync digitava
    `no neighbor X bfd` (o aviso "FRR prints … differently" em cada commit). Num corte silencioso
    com duas sessões, a troca de caminho levava 7,8 s (o hold time) em vez de 0,3 s. Agora as duas
    linhas, com a do perfil apagada antes (`hal-frr`), como o OSPF já fazia (G3.6l). Depois:
    **314–420 ms** (BFD 100 ms × 3, duas rodadas, **medido**).
  - **Um `bgpd` reiniciado ficava vazio.** `Frr::incarnation` virava `None` quando qualquer daemon
    que o CoreRouter configura não tinha `.pid` (aqui `ospf6d` e `ldpd` não subiam; a G1.6i quer
    justamente subir só os usados): o serviço `frr` nunca via o reinício. Agora o ausente conta
    como `-`; o `bgpd` morto e subido de novo recebe a config em 5,9 s (**medido**).
  - **O BGP não anunciava nada do próprio roteador.** Faltava o `output.network` e o
    `output.redistribute` do RouterOS: entraram `output_network` (address-list) e
    `output_redistribute` (`connected`, `static`, `ospf`) nos templates e conexões, e o papel
    `ibgp-rr` (refletor, RFC 4456). As estáticas do CoreRouter são rotas *kernel* para o `zebra`
    (o backend linux as instala com `proto static`): `static` vira `redistribute kernel` com um
    route-map dos prefixos estáticos. Um commit que muda só a address-list ou só as estáticas
    agora chega ao FRR (antes só um commit de `routing` chegava): ~0,12 s da entrada nova até o
    vizinho (**medido**).
  - **`corerouter-cli … | head` dava panic** (`println!` com stdout fechado): agora sai com 141,
    como um pipe.

  | Caso (host, FRR 10.7.1) | Resultado (**medido**) |
  |---|---|
  | eBGP IPv4 CR1 (65000) × CR2 (65002) | Established 5,4 s depois da config; rotas no kernel 1–3 ms depois; ping entre os gateways dos clientes |
  | `output_network` | entrada nova da lista no vizinho em 118–131 ms, retirada em 133–205 ms; rede sem rota não sai e sai 210 ms depois de surgir a estática |
  | `output_redistribute=static` | no vizinho em ~4 s |
  | eBGP IPv6 (transporte e NLRI) | Established 4,5 s; next hop link-local no kernel |
  | MP-BGP (IPv4 + IPv6 numa sessão IPv4) | IPv6 instalado; next hop global `fd39:5::1` + link-local (RFC 2545 §3) |
  | TCP MD5 | Established; chave selada no disco; chave errada derruba e mantém caída; corrigida volta em ~1 s |
  | Filtros e communities | MED 77, prepend 2, community 65000:10 + no-export, large 65000:0:10, community-list → local-pref 300; no-export respeitado; chain alterada aplica em ~5 s sem reset |
  | next-hop-self (eBGP de um FRR → iBGP) | sem `force-self` o CR2 não instala (next hop inalcançável, RFC 4271 §5.1.3); com ele, instala 221 ms depois do commit |
  | Refletor (CR1 RR, clientes CR2 e FRR) | ORIGINATOR_ID e CLUSTER_LIST corretos nos dois sentidos; sem o papel o cliente perde a rota em 139 ms |
  | max-prefix | 6 > 3 com `shutdown`: sessão `idle`, "Reached received prefix count"; o FRR do outro lado recebe Cease/Maximum Number of Prefixes Reached (`0601`, RFC 4486); `warning` mantém os 6 |
  | Reinício | `corerouter-daemon` reiniciado (responde em 210 ms) não toca a sessão; `bgpd` morto: o vizinho retira em 106 ms (sem graceful restart, G3.9ff) e a config volta em 5,9 s |
  | BFD 100 ms × 3 | sobe com o BGP; perda total silenciosa retira a rota em 313–416 ms (hold 180 s) |
  | Convergência (2 sessões, hold 9 s) | corte silencioso: 8,8–9,0 s pelo hold, **314–420 ms** com BFD (7,8 s antes da correção); link down: 1–2 ms |
  | 100 mil prefixos | FRR → CR1 no kernel em 3,5–4,5 s; CR1 → CR2 em 3,6–3,9 s; `session.clear` ressincroniza em 4,7–5,0 s; retirada total em 1,3 s |

  Desempenho e paralelismo (100 mil prefixos, **medido**): o `corerouter-daemon` fica em ~0 % de
  CPU durante a carga e parado (nenhuma thread passa de 0,2 s em 300 s; RSS 71 → 79 MiB depois de
  listar a tabela), então o caminho quente é do FRR: `bgpd` 0,4–0,5 s de CPU numa thread
  (116 MiB), `zebra` 0,8–1,0 s na principal + 0,5–0,6 s na `zebra_apic` + 0,1–0,2 s na
  `zebra_dplane` (69 MiB). Nada serializado do nosso lado a dividir; o `bgpd` de uma thread
  principal é do FRR (decisão G3.1). Comandos com 100 mil rotas: `session.list` 3 ms,
  `route.list` (primeira página, lendo o `bgpd`) 767 ms, um prefixo com a tabela em cache 2 ms,
  `route.summary` 2 ms, `ip.route.page` 3 ms. O custo novo do render é O(conexões + entradas das
  listas nomeadas + estáticas), só quando uma conexão anuncia; o gatilho do commit é O(1) quando
  lista e estáticas não mudaram (cópias compartilhadas).

  Como testar: `scripts/bgp-crcr-userns.sh` (ou só alguns casos: `… filters bfd`), sem root;
  `cargo test -p corerouter-proto-bgp origination static_redis`,
  `cargo test -p corerouter-hal-frr bfd incarnation`.

- 2026-10-29 — G3.9fe: OSPF `redistribute=static` não anunciava nada: o backend linux instala as estáticas do
  CoreRouter direto no kernel (`proto static`) e o `zebra` as lista como *kernel*, então o
  `redistribute static` do `ospfd` (que é o do `staticd`) não achava nenhuma — o mesmo defeito
  achado no BGP na G3.9f, reproduzido em `scripts/bgp-crcr-userns.sh ospf-static` (antes: FAIL,
  "zebra on CR1 sees [kernel]"). Agora `static` sai como `redistribute kernel route-map
  CR-O2-<inst>-kernel`, cujo `deny 2` casa a prefix-list `…-NOTSTATIC` (cada estática do main em
  `deny`, o resto em `permit 0.0.0.0/0 le 32`; IPv6 no v3), depois dos pools de assinantes e antes
  da chain do `out_filter_chain` — a forma que o `ospfd`/`ospf6d` 10.7.1 imprimem (nenhum aviso de
  redigitação). Com `kernel` pedido também, vai o kernel inteiro, sem a lista. Um commit que só
  muda `/ip route` agora chega ao FRR quando uma instância redistribui estáticas (gatilho O(1)
  quando as rotas não mudaram).

  Laboratório no host (**medido**, FRR 10.7.1, 2026-10-29): estática anunciada a CR2 por OSPF;
  uma rota kernel de outro programa (`proto boot`) fica de fora com `static` e entra com
  `kernel` em 106 ms; uma estática nova chega ao vizinho 118 ms depois do comando. Como testar:
  `scripts/bgp-crcr-userns.sh ospf-static`, `cargo test -p corerouter-proto-ospf static_redistribution`.

  Desempenho: a lista custa O(estáticas) no render, só com `static` pedido; o gatilho do commit
  compara as listas de rotas só quando elas não são a mesma cópia.

- 2026-10-29 — G0.31: Auditoria de desempenho, parte 5: com o backend linux, todo commit que acrescentava uma rota lia a
  tabela inteira do kernel (`load_hops`, um dump `RTM_GETROUTE`) antes do primeiro `add`, só para
  saber se já havia rota igual (nossa depois de um reinício, irmã de ECMP ou de outro programa).
  Com 60 000 rotas o dump custava 76 ms por commit, sob o lock do `Session`. Agora o `add` (que já
  vai com `NLM_F_EXCL`) é tentado primeiro, e a tabela só é lida quando o kernel responde `EEXIST`;
  nesse caso seguem as mesmas regras de antes (adota, junta ao ECMP ou recusa). Uma rota a mais com
  60 000 instaladas: 140 → 60–70 ms (**medido**). Teste novo
  `a_route_of_someone_else_is_refused_not_replaced` (`crates/hal-linux/tests/netns_routes.rs`): a
  rota alheia fica intocada e a rota anterior do mesmo commit é desfeita. Os testes de ECMP e de
  adoção continuam passando.

  Também medido nesta auditoria e registrado aqui (os PRs #395 e #399 já tinham entrado):
  `config.diff` e `state.inspect` de ponta a ponta no daemon, o canal de controle com 1, 8, 16 e 64
  conexões, e o conntrack com 250 mil entradas. As gaps G0.31b–e saem desses números.

- 2026-10-29 — G3.9h: Interoperabilidade de L2 e serviços, parte 2: o roteiro `scripts/routeros-interop-l2.sh` (casos
  wire, vlan, qinq, mtu, lldp, arp, tools, dhcp, dhcp-client, dhcp-relay, dhcp6, dhcp6-client,
  ra, ntp, dns, nat, cgnat, bond, cr-dhcp, cr-bond, storm e dns-qps). Roda na VM do laboratório
  contra o RouterOS 7.25 CHR (`cargo xtask vm-lab run -- scripts/routeros-interop-l2.sh
  [casos]`) ou, com `NO_CHR=1`, só os casos CoreRouter × CoreRouter num namespace descartável sem
  root, no host. Detalhes da montagem:

  - as portas do CHR ficam no namespace raiz, ligadas por veth + `tc mirred` ao namespace do
    CoreRouter, porque o daemon não adota um tap criado fora dele e uma bridge não passa LACP;
  - o roteiro tem um vigia de 30 min e só usa `wait <pid>`; o `wait` sem argumento esperava os
    daemons e prendeu a VM numa rodada de 2026-10-29;
  - sem BNG Blaster, a tempestade usa um gerador DHCP em Python num socket AF_PACKET.

  Resultados CoreRouter × CoreRouter (**medido**, 2026-10-29, host de 32 núcleos, release, veth
  num namespace sem root):

  - **DHCP sobre VLAN 50:** B pega o lease de A com gateway, DNS e domínio certos.
    - O release chega a A, que libera o lease, e B volta a pedir. É o mesmo do RouterOS: o
      `/ip dhcp-client release` de lá diz "release current binding and restart DHCP client". O
      roteiro esperava o lease livre e foi corrigido.
  - **802.3ad entre os dois kernels:**
    - um agregador só, com os dois membros, em ~415 ms;
    - vazão clientes → A (roteando) → bond → B: 88 Gbit/s com 1 fluxo e 354–380 Gbit/s com 4
      fluxos (veth: limitado por CPU, não é número de placa);
    - um membro cortado com queda de portadora não perde nada;
    - corte silencioso do membro que leva o tráfego (portadora em pé, quadros descartados com
      tc): 1,83 s perdidos até o timeout do LACP tirar o membro do agregador. Bate com a
      IEEE 802.1AX: com `lacp_rate` fast, 3 × 1 s contados desde o último LACPDU.
  - **Tempestade DHCPv4:** o servidor acompanha o gerador até 10 mil DISCOVER/s.
    - 20 000 clientes: 99 % ligados em 1,99 s (9 969 leases/s), latência de 1,6–3,2 ms no
      histograma do servidor e a thread `svc-dhcp-server` a 14 % de um núcleo;
    - a 40 mil/s quem cai é o gerador em Python: ele perde OFFERs e reenvia tudo a cada segundo, o
      que um cliente real não faz (RFC 2131 §4.1: 4, 8, 16… s). O teto do servidor fica para o BNG
      Blaster na VM.
  - **DNS QPS:** nomes estáticos e em cache, de 1, 4 e 8 clientes com 32 consultas em voo. Com 1
    leitor UDP: 376 mil respostas/s com a `dns-udp` a 100 % de um núcleo, e mais clientes não davam
    mais. Isso confirma a G0.31 (#400), que entrou na `main` em paralelo com os mesmos 4 leitores
    por socket. Com 4 leitores: 1,12 milhão/s a 400 %; com 8, 1,33 milhão/s a 760 % (rendimento
    por núcleo cai de 281 para 175 mil/s). Este PR acrescenta o teste
    `parallel_clients_share_the_udp_readers`: clientes em paralelo recebem cada um a sua resposta,
    e desligar o encaminhador para todos os leitores.

  Os casos contra o CHR (VLAN/QinQ/MTU, LLDP/MNDP, ARP, ferramentas, DHCPv4/v6, RA, NTP, DNS,
  NAT/CGNAT e bonding com o RouterOS) esperam a VM, presa desde 2026-10-29 por uma rodada antiga
  deste roteiro.

  Teste:

  ```sh
  unshare --user --map-root-user --net --mount -- sh -c 'mount -t tmpfs none /run && mkdir /run/netns && W=/tmp/crw NO_CHR=1 BIN=$PWD/target/release scripts/routeros-interop-l2.sh'
  cargo test -p corerouter-daemon --bin corerouter-daemon -- dns_server::
  ```

  O primeiro pede `jq` e `iperf3` no PATH.

- 2026-10-29 — G0.31: Auditoria de desempenho, parte 6: buffer de recepção dos sockets que recebem rajadas (DHCP e
  DNS). O servidor DHCPv4 lê os pedidos por um socket `AF_PACKET`
  (com filtro BPF) que ficava com o buffer de recepção padrão (`rmem_default`, 208 KiB, ~100
  quadros pequenos). Numa tempestade de DISCOVER/REQUEST, depois de uma queda de energia, o buffer
  enchia entre duas rodadas, e os clientes descartados só voltavam na retransmissão (4 s ou mais,
  RFC 2131 §4.1). A thread do DHCP ficava ociosa (1–14 % de CPU) enquanto o kernel descartava.
  Agora os sockets dos servidores DHCPv4 e DHCPv6 e os uplinks dos relays pedem 4 MiB por
  `l2::rcvbuf` (`SO_RCVBUFFORCE`, ou `SO_RCVBUF` até `rmem_max`), como o PPPoE já fazia. Com 20 000
  clientes e 1024 transações em voo: 2,5 mil → 35 mil concessões/s, 1808 → 0 retransmissões, 99 %
  servidos em 6,06 → 0,56 s (**medido**). O mesmo vale para os sockets UDP do encaminhador DNS da
  LAN (`apps/corerouter-daemon/src/service/dns_server.rs`): com 4096 consultas em voo, o kernel
  descartava 27 392 consultas em 6 s, e agora não descarta nenhuma (**medido**). A G3.9h também
  testa DHCP e DNS nesta rodada; esta mudança só mexe na abertura dos sockets.

- 2026-10-29 — G0.31: Auditoria de desempenho e paralelismo do daemon, fechamento. Tabela por área (tudo **medido**,
  release, AMD Ryzen AI MAX+ 395, namespaces sem root; números completos em `docs/perf.md` e o
  painel em `docs/desempenho.md`):

  | Área | Gargalo | Número | Resultado |
  |---|---|---|---|
  | Canal de controle | lock do `Session` serializa as consultas; `config.diff`/`state.inspect` serializavam a config inteira | 1,4 s sob o lock por chamada; com uma GUI aberta os outros clientes ficavam com p50 de 672 ms | corrigido (#395): 2–24 µs, vizinhos com p50 de 72 µs |
  | Canal de controle | 1/8/16/64 conexões | 21,9 / 79,6 / 72,9 mil pedidos/s, p99 86 / 214 / 622 µs; 48 de 64 recusadas ("too many connections") | sem mudança: a vazão para no lock (~13 µs por consulta); consultas grandes fora do lock são a G0.31b |
  | Firewall | `ip.firewall.*.list` O(n²) (grafo por regra, sombra contra todas as chains) | 372 ms com 10 000 regras | corrigido (#399): 38 ms |
  | Firewall | mudar 1 regra entre 10 000 relê o kernel e remonta tudo | 109 ms (G2.8) | gap G0.31f |
  | DNS | uma thread `dns-udp` por socket a 100 % | 336 mil respostas/s | corrigido (#400): 964 mil/s com 4 leitores |
  | DNS | buffer de recepção padrão | 28 160 consultas perdidas em 6 s com 4096 em voo | corrigido (#412): 0 |
  | DHCP | buffer de recepção padrão descarta a tempestade; a thread fica ociosa | 2,5 mil concessões/s e 99 % servidos em 6,06 s (1024 em voo) | corrigido (#412): 35 mil/s, 0,56 s, 0 retransmissões |
  | Rotas | commit de uma rota fazia dump da tabela do kernel | 140 ms com 60 000 rotas | corrigido (#408): 60–70 ms; o resto do commit O(n) na G0.31e e a checagem de duplicata O(n) na G0.31d |
  | Rotas | `ip.route.list` inteiro sob o lock | 771 ms, lock até ~190 ms | gap G0.31b (`ip.route.page` já existe: 2,4 ms) |
  | Conntrack | dump e filtro sob o lock | ~150 ms a cada 2 s com 250 000 entradas; 3 ms por chamada em cache | gap G0.31c |
  | `config.diff` com uma rota pendente | serializa a lista de rotas inteira | 523 ms | gap G0.31a |
  | Log/syslog, traffic-flow | filas | limitadas, descarte contado (`traffic_flow_link`, `remote_log`) | sem achado |
  | Métricas | `system.metrics` sob o lock | 1,5–1,9 ms com 1000 VLANs | sem achado |
  | Ferramentas `tool.*` | tarefas | fora do lock, no máximo 8, anel de eventos limitado | sem achado |
  | Supervisor | `frr`/`mpls`/`neighbors` ociosos marcados como "stuck" | heartbeat de 60 s com limite de 30 s | corrigido (#401) |

  Fora daqui: XDP precisa da VM (a fila das frentes de interop estava ocupada); o DHCP fica numa
  thread só, que ainda tem folga a 35 mil concessões/s, até haver um gerador mais rápido (BNG Blaster
  na VM).

- 2026-10-29 — G3.9fd: Janela Routing › BGP: a página Filters do modal de conexão e de template ganhou Output Network
  (o nome da address-list, `output_network`) e Redistribute (`connected,static,ospf`,
  `output_redistribute`), os parâmetros da G3.9f, cada um com o ⓘ (português e inglês) que diz o
  que o RouterOS chama assim e que o FRR anuncia por instância. Editar mostra de volta o que foi
  digitado. Teste: `cargo test -p corerouter-ui tests::bgp` (o novo
  `the_filters_page_sets_what_the_connection_announces` cria pela página e confere os parâmetros).
  Falta o screenshot (claro e escuro) da página Filters: a GUI não foi dirigida nesta sessão.

- 2026-10-29 — G3.9g: Interoperabilidade do BNG PPPoE com o RouterOS 7.25 CHR (parte 1): roteiro novo
  `scripts/routeros-interop-pppoe.sh` (CHR em QEMU/KVM na VM do laboratório, CoreRouter com o backend
  linux e XDP genérico num namespace, FreeRADIUS num segundo namespace) e duas divergências
  corrigidas.

  - **Keepalive pelo último pacote.** O servidor contava as faltas nas batidas do eco (`T/2`, duas
    faltas), então um assinante mudo caía entre `T` e `1,5 T` depois do último pacote: com
    `keepalive_timeout=30` o CHR mudo caiu em 42,0 s (**medido**); o RouterOS derruba em `T`. Agora
    a sessão guarda quando ouviu o assinante pela última vez e cai em `T` depois disso. Os ecos saem
    a cada `T/3` (com as duas faltas padrão), para caberem dois ecos e as respostas antes do prazo:
    um eco perdido não derruba a sessão (RFC 1661 §5.8); com o período antigo de `T/2` o segundo eco
    caía no próprio prazo e a simulação com perda (`slow_many_service_names_over_qinq_vlans`)
    perdia 5 sessões. Teste `keepalive_drops_a_silent_subscriber_after_the_timeout_not_later`
    (`proto-pppoe`, corte em 15 pontos entre as batidas; o código antigo reprova).
  - **AC-Name = `/system identity`.** O PADO levava sempre "CoreRouter"; o RouterOS manda a
    identity, e é ela que o `ac-name=` do cliente RouterOS compara. Teste
    `pado_ac_name_is_the_system_identity` (daemon).

  O que passou contra o CHR (rodadas r2, 2026-10-29, **medido**): PAP, CHAP, MS-CHAPv1 e
  MS-CHAPv2 (cada um sozinho e os quatro oferecidos: os dois lados ficam em mschap2, como o RouterOS),
  senha errada e método sem interseção recusados com o motivo no `ppp.why`; MTU 1480 e 1492 com
  ping DF do tamanho exato passando e ICMP "frag needed" um byte acima, 1500 só com
  `max_payload=1500` e quadros de 1508 (RFC 4638) e 1492 sem ele; DNS no IPCP (RFC 1877) e o
  `local_address` do perfil como endereço do BNG; PADT nos dois sentidos (o CHR vê a remoção em
  121 ms, o BNG vê o CHR desligar em 13 ms); Service-Name certo, vazio e errado (sem PADO); `ac-name`
  certo e errado. Keepalive com corte silencioso: servidor 10 s cai em 12,1 s; o cliente RouterOS
  cai em 2 × o dele (22 s com 10 s, 122 s com 60 s). Cada sessão do CHR leva ~3,1 s da habilitação
  ao Up, a investigar com o caso `timeline` (captura com tempos).

  Escala sem a VM (namespace sem root no host, `netns_pppoe` com 20 mil CPEs simulados do
  `proto-pppoe`, debug, Ryzen AI Max+ 395 com 32 CPUs, 2026-10-29, **medido**): 20 000 sessões
  Opened em 9,64 s = 2075 sessões/s; reconexão em massa em 34,8 s com `new_session_rate=1000`;
  ≈ 6,3 KB de RSS por sessão. CPU por thread (amostras de `/proc/<pid>/task` a cada segundo): os 8
  workers do daemon (`auto` = CPUs − 2, no máximo 8) dividem a subida, 10–20% cada; o leitor
  `svc-pppoe` fica em 9–22%; a thread saturada é a do próprio simulador de CPEs (≈ 75%, uma só).
  O plano de controle preso num núcleo a 98% (2026-10-25) não se repete; o que ainda serializa é o
  leitor único, que já é a G4.3ga. O teste contava os `replaced` do `ppp.history` (no máximo 10 000
  linhas) contra `n`, e reprovava acima de 10 mil sessões; agora compara com `min(n, 10 000)`.

  Como testar: `cargo xtask vm-lab run -- scripts/routeros-interop-pppoe.sh [casos]` (casos `auth
  mtu ipcp-dns ipv6 keepalive padt service-name mac-limit multi radius coa import client timeline`).
  Os casos IPv6, várias sessões, RADIUS/CoA, import e o resto ficam para a parte 2 (a VM ficou presa
  nesta noite).

- 2026-10-29 — fix-nightly-netsim: CI noturno verde de novo (issue "CI noturno quebrado", #393): o proptest
  `corerouter-netsim tests::decision_matches_proto_bgp` descartava com `prop_assume!` os pares em
  que os dois lados são rotas locais (~1 caso em 4). Com os 4096 casos do noturno isso passa do
  limite de 1024 descartes globais do proptest e o teste aborta sem achar divergência nenhuma. O
  filtro foi para a estratégia (`prop_filter`, que conta como descarte local, limite 65 536). Testar:
  `PROPTEST_CASES=4096 cargo test -p corerouter-netsim --lib decision_matches_proto_bgp` (passa,
  **medido**, 0,17 s).

- 2026-10-29 — fix-test-ceiling-journal: Dois testes da camada rápida passavam do teto de 10 s no runner do GitHub e reprovavam PRs que
  nem tocavam no motor (o #406): `config_journal::the_shutdown_checkpoint_loses_no_journal_line`
  (10,12 s) e o proptest `the_journal_saves_what_the_slot_would` (10,03 s). O caso de 1100 commits
  do primeiro virou `slow_the_shutdown_checkpoint_loses_no_journal_line_after_1100_commits` (a
  camada rápida fica com 3 e 40); o proptest passa a respeitar o `PROPTEST_CASES` (32 na camada
  rápida), com no máximo os 48 de antes no lote e no noturno.

- 2026-10-29 — G3.9g: Interoperabilidade do BNG PPPoE com o RouterOS 7.25 CHR, parte 2: o resto dos casos do roteiro
  `scripts/routeros-interop-pppoe.sh` e duas correções que tiram ~3 s da subida de cada sessão.

  - **LCP sem a espera de 3 s.** Nosso Configure-Request saía junto com o PADS, ~70 ms antes de o
    cliente RouterOS abrir o LCP; ele o descartava e cada sessão esperava o timer de reinício de
    3 s (RFC 1661 §4.6) pela retransmissão: 3,1–3,2 s da habilitação ao Up no CHR (**medido**, caso
    `timeline`). Agora o primeiro Configure-Request do assinante faz o nosso sair de novo na hora.
    Teste `a_configure_request_lost_before_the_client_listens_is_resent_at_once` (o código antigo
    sobe em 3100 ms na simulação).
  - **Primeiro Challenge repetido em 300 ms.** O cliente RouterOS às vezes descarta o Challenge do
    CHAP que chega microssegundos depois do Configure-Ack dele; a repetição só vinha em 3 s. Agora a
    primeira repetição sai em 300 ms (as outras seguem em 3 s, RFC 1994 §4.1 deixa o timer ao
    autenticador) com o mesmo valor, e uma Response ao Identifier anterior também vale. Teste
    `a_lost_first_challenge_is_repeated_early` (CHAP, MS-CHAPv1 e v2; o timer antigo dá 3100 ms).
    Contra o CHR (r5, **medido**): MS-CHAPv2 243 ms, MS-CHAPv1 223 ms, CHAP 439 ms, PAP 112 ms da
    habilitação ao Up; antes, ~3,1 s em todos (r2).

  Rodadas r3–r8 (2026-10-29, **medido**): IPv6CP + RA (endereço global no CHR 4,2 s depois do Up,
  o tempo do SLAAC do RouterOS) e DHCPv6-PD (/56 preso 6 ms depois), tráfego IPv6 pelo BNG; limite
  por MAC (`one_session_per_host` sim: no máximo uma sessão do MAC; não: as duas); 32 clientes do
  CHR, um MAC cada (macvlan), todos Up em 1,55 s, 32 endereços distintos, e o BNG volta a 0 sessões
  217 ms depois de o CHR desligar todos; FreeRADIUS: Framed-IP-Address, Mikrotik-Rate-Limit,
  Accounting-Start com o Class (RFC 2865 §5.25), Interim-Update aos 60 s do Acct-Interim-Interval,
  Session-Timeout 30 encerrando em 29,98 s com Acct-Terminate-Cause Session-Timeout, Access-Reject
  sem sessão; CoA (RFC 5176): 498 kbit/s medidos de um fluxo de 2 Mbit/s com 512k, CoA-ACK e 256
  kbit/s depois do CoA de 256k, Disconnect-ACK e o CHR vendo a queda em 118 ms, Disconnect-NAK para
  sessão desconhecida; import de `/ppp export show-sensitive` do CHR: 4 secrets e o perfil
  `imp-10m` (10M/20M) criados, `cpe1` existente pulado, caller-id mantido e a senha com espaço, `;`
  e `"` entrando por CHAP. Sem divergência nesses casos. Correções do roteiro: o `/rest/execute` do
  RouterOS volta antes de um script longo acabar (o `multi` habilitava só os 2 primeiros clientes);
  os casos RADIUS/CoA desligam o `one_session_per_host` (todos discam do mesmo MAC do CHR e se
  substituíam em ciclo, comportamento igual ao do RouterOS).

  Escala sem a VM (namespace sem root no host, `netns_pppoe` com 20 mil CPEs simulados do
  `proto-pppoe`, debug, Ryzen AI Max+ 395 com 32 CPUs, 2026-10-29, **medido**): 20 000 sessões
  Opened em 9,64 s = 2075 sessões/s; reconexão em massa em 34,8 s com `new_session_rate=1000`;
  ≈ 6,3 KB de RSS por sessão. CPU por thread (amostras de `/proc/<pid>/task` a cada segundo): os 8
  workers do daemon (`auto` = CPUs − 2, no máximo 8) dividem a subida, 10–20% cada; o leitor
  `svc-pppoe` fica em 9–22%; a thread saturada é a do próprio simulador de CPEs (≈ 75%, uma só).
  O plano de controle preso num núcleo a 98% (2026-10-25) não se repete; o que ainda serializa é o
  leitor único, que já é a G4.3ga. O teste contava os `replaced` do `ppp.history` (no máximo 10 000
  linhas) contra `n`, e reprovava acima de 10 mil sessões; agora compara com `min(n, 10 000)`.

  Como testar: `cargo xtask vm-lab run -- scripts/routeros-interop-pppoe.sh [casos]` (casos `auth
  mtu ipcp-dns ipv6 keepalive padt service-name mac-limit multi radius coa import client timeline`).

  Como testar: `cargo xtask vm-lab run -- scripts/routeros-interop-pppoe.sh [casos]`; os testes novos
  rodam no `cargo test -p corerouter-proto-pppoe`.

- 2026-10-29 — G3.9f: Interoperabilidade BGP, parte 2: `scripts/routeros-interop-bgp.sh` contra o RouterOS 7.25 CHR
  (licença free) na VM do laboratório, com dois CoreRouters (backend linux + FRR 10) e dois FRR
  puros (R3, R4) em namespaces. Rodar: `cargo xtask vm-lab run --lock-timeout 2h --
  scripts/routeros-interop-bgp.sh [casos]` (cinco rodadas de 1,5 a 18 min, **medido**).

  | Caso | Resultado (**medido**, VM `corerouter-lab`, 2026-10-29) |
  |---|---|
  | ebgp4 | OK: Established 5,2 s após as duas configs; rotas nos dois sentidos; remoção da conexão tira a rota do kernel em 109 ms |
  | ebgp6 | OK: transporte e NLRI IPv6 em 2,1 s; o CHR usa o link-local do CR1 (RFC 2545 §3) |
  | mpbgp | IPv4+IPv6 numa sessão IPv4: o CHR instala o IPv6 do CoreRouter; o IPv6 do CHR não entra no kernel do CR1 (next hop `::ffff:10.39.1.1` do CHR: divergência do RouterOS, RFC 2545 §3; a prévia da conexão agora avisa) |
  | multihop | OK: loopbacks com `update_source`, 1,8 s |
  | md5 | OK: Established em 2,9 s; chave errada derruba e mantém caída; chave corrigida volta em 0,96 s; a chave não fica em claro |
  | communities | OK: RFC 1997, 8092 e 4360 do CHR; append do CoreRouter (normal e large) chega ao CHR; lista de communities na entrada derruba em 108 ms |
  | filters | OK: local-pref, MED, prepend e reject nos dois sentidos; regra mudada vale em 5,1 s sem reset |
  | ibgp | OK: entre loopbacks, LOCAL_PREF 100 |
  | nexthop-self | OK: sem ele o CR2 não instala (next hop inalcançável); `force-self` instala em 211 ms |
  | rr | OK: CoreRouter como refletor, CHR → R4 e R4 → CHR com ORIGINATOR_ID e CLUSTER_LIST; sem o papel, split horizon em 122 ms |
  | rr-chr | OK: CHR como refletor nos dois sentidos, next hop mantido; o CHR põe o próprio ID no ORIGINATOR_ID (divergência, RFC 4456 §8) |
  | maxprefix | OK: 6 > 3 com `shutdown` fecha com Cease 6/1 (o CHR registra `prefix limit reached`); `warning` mantém |
  | restart | OK: reinício do daemon não mexe na sessão (volta em 211 ms); `bgpd` morto volta com a config em 5,8 s |
  | bfd | OK: BFD com o CHR para a sessão BGP |
  | convergence | OK: corte silencioso no lado do CHR: hold 9 s → 8,5 s; BFD 300 ms × 3 → 0,83 s; o CR1, que perde a portadora, troca em 2–3 ms |
  | scale | OK: 100 000 prefixos do CHR no kernel do CR1 em 3,5 s; CR1 → CR2 (iBGP) em 3,5 s; clear em 4,5 s; retirada em 1,2 s |
  | crcr | OK: eBGP com MD5 e IPv4+IPv6, communities, BFD 100 ms × 3 (perda em 418 ms), iBGP com refletor |

  Corrigido no mesmo PR: a prévia de `routing.bgp.connection.check` avisa (`mpbgp-nexthop`) quando
  a conexão leva IPv6 numa sessão IPv4. O roteiro lê os atributos BGP do CHR em `/routing/route`
  (o `/ip/route` não os mostra), aceita o next hop link-local, sobe o `mgmtd` antes do `staticd`
  (FRR 10) e mede a convergência de cada lado separado.

- 2026-10-29 — G3.9h: Interoperabilidade de L2 e serviços, parte 3: os casos contra o RouterOS 7.25 CHR, na VM do
  laboratório (`cargo xtask vm-lab run -- scripts/routeros-interop-l2.sh [casos]`), em rodadas de
  até 25 min. Nenhum caso achou defeito do CoreRouter; os FAIL das primeiras rodadas eram da
  montagem ou do roteiro, todos corrigidos:

  - **Soma de verificação no fio do laboratório:** um veth deixa a soma UDP/TCP dos sockets do
    próprio kernel para a placa preencher (`CHECKSUM_PARTIAL`); pelo `tc mirred` até o tap do CHR
    ela chega vazia e o RouterOS descarta. Caía a renovação DHCP unicast (T1), e cairiam DNS e NTP.
    O roteiro desliga o `tx` checksum nos veth do fio (`ethtool -K`); uma placa real preenche.
  - **`/rest/execute` do RouterOS sem `as-string`** roda o script como tarefa em segundo plano e
    volta na hora: dois comandos seguidos disputavam (o endereço da VLAN 30 antes de a VLAN
    existir). Era a falha intermitente da VLAN 30.
  - **Bonding 802.3ad:** o virtio-net do QEMU informa velocidade e duplex desconhecidos, e o
    802.3ad do CHR não liga o LACP nessas portas (nenhum LACPDU sai). O roteiro dá
    `speed=1000,duplex=full` às portas do bond.
  - **Conflito DHCP:** um "invasor" no próprio CHR não serve. O Linux responde ARP de qualquer
    endereço seu com o MAC da porta que perguntou, e um probe respondido pelo MAC do próprio
    cliente é o cliente com o endereço dele (RFC 5227): o servidor o oferece de novo, de
    propósito. O caso novo `dhcp-conflict` põe o invasor num namespace com MAC próprio: o servidor
    marca .50 `conflict` com o MAC do invasor e entrega .51 (RFC 2131 §4.4.1, o
    `conflict-detection` do RouterOS). Roda também com `NO_CHR=1`.
  - **CGNAT:** o CHR reaproveita o id ICMP e a porta TCP de origem, e o conntrack mantém o NAT de
    uma entrada que já existe (a masquerade do caso `nat`), como no RouterOS. O caso `cgnat` usa
    um destino próprio em B.

  Resultados contra o CHR (**medido**, 2026-10-29, VM `corerouter-lab`, release):

  - **VLAN e MTU:**
    - 802.1Q vid 30 nos dois sentidos, com a tag 0x8100 conferida no fio; a vid 31, só no CHR,
      não vaza para a porta sem tag;
    - 802.1ad S-tag 100 + C-tag 200 nos dois sentidos (0x88a8 por fora no fio); 802.1Q empilhado
      101/201;
    - 1500 bytes com DF sobre a VLAN; jumbo 9000 com DF nos dois sentidos; `tool.ping.mtu` acha
      9000.
  - **LLDP/MNDP:** o CoreRouter vê o CHR por LLDP em 415 ms (identidade, versão, porta remota,
    endereço) e por MNDP (só recebe); o CHR vê o CoreRouter.
  - **ARP:**
    - aprendizado nos dois sentidos;
    - proxy ARP (`published`) de um endereço roteado por outra interface, nos dois sentidos;
    - `published` dentro da própria sub-rede da porta: nem o CoreRouter nem o RouterOS respondem
      (o Linux só responde quando a rota sai por outra interface). Comportamento igual, sem
      divergência; o `ip.arp.check` já avisa;
    - a resposta publicada do CHR vem com 136–376 ms (o `proxy_delay` do Linux).
  - **Ferramentas:** ping, traceroute ICMP/UDP/TCP e MTR até o CHR.
  - **DHCPv4, CoreRouter servidor:**
    - o CHR liga em 1,05 s;
    - instala a opção 121 (10.99.0.0/16 e 0/0, RFC 3442) e o DNS da opção 6;
    - renova 30,0 s depois do ACK (T1 = 0,5 × 60 s, RFC 2131 §4.4.5);
    - o release chega ao servidor, e o CHR liga de novo em 9 ms.
  - **DHCPv4, CoreRouter cliente do CHR:**
    - liga em 2,1 s com as opções 15, 42 e 121 (rotas no kernel);
    - renova por unicast 30,3 s depois de ligar;
    - o release some do CHR ("deassigned"), e o cliente liga de novo em 211 ms.
  - **DHCP relay:** o CHR liga pelo relay em 1,05 s, com a opção 82 (RFC 3046).
  - **DHCPv6:**
    - **CoreRouter servidor:** endereço e prefixo /56 em 1,7 s, rota para o prefixo delegado e
      DNS (opção 23) no CHR;
    - **CoreRouter cliente:** endereço e /56 do CHR em 4,4 s, com endereço do pool delegado na
      ether8.
  - **RA:** SLAAC no CoreRouter pelo RA do CHR em 4,5 s (RFC 4862 §5.5.3). O CoreRouter ainda
    não envia RA (G3.9ha).
  - **NTP:** o cliente sincroniza com o CHR em 1 s (round trip 1,1 ms). O CoreRouter ainda não é
    servidor NTP (G4.6c).
  - **DNS:** o CHR resolve pelo CoreRouter um nome estático, um CNAME e um nome encaminhado a B,
    que fica no cache.
  - **NAT/CGNAT:**
    - masquerade com ping e HTTP; o conntrack mostra os fluxos do CHR; um filtro de forward
      bloqueia o ping;
    - CGNAT determinístico com ping e HTTP: as conexões saem como 198.51.100.0 dentro do bloco
      de portas do assinante; `cgnat.lookup` e `who-was` respondem.
  - **Bonding com o CHR:**
    - 802.3ad com `lacp-rate=1sec`: os dois membros no agregado em 433 ms, com o mesmo parceiro
      dos dois lados;
    - corte do link de uma porta do CHR (sem portadora em A): 0 ms perdidos;
    - ether2 de A desligada com a portadora do CHR em pé: 2,39 s perdidos, o tempo do CHR tirar a
      porta pelo timeout do LACP (802.1AX: 3 × 1 s);
    - active-backup e balance-xor: 230 e 320 ms perdidos no corte de um membro (mii 100 ms).
  - **Tempestade com o BNG Blaster na VM:** 20 000 clientes ligados, um DISCOVER, um REQUEST e um
    ACK por cliente, sem NAK nem reenvio; pico de 1 800 ACKs/s e quase todos abaixo de 6,4 ms.
    Quem limita é o próprio BNG Blaster na VM (~210 sessões/s); o teto do servidor continua o
    medido no host (9 969 leases/s a 14 % de um núcleo, G3.9h-crcr).

  Gap nova:


  Teste:

  ```sh
  cargo xtask vm-lab run -- scripts/routeros-interop-l2.sh
  unshare --user --map-root-user --net --mount -- sh -c 'mount -t tmpfs none /run && mkdir /run/netns && W=/tmp/crw NO_CHR=1 BIN=$PWD/target/release scripts/routeros-interop-l2.sh dhcp-conflict'
  ```

- 2026-10-29 — G1.6q: Teste de produção da imagem instalada, parte 2: o soak de 8 h e os testes funcionais na VM real
  (`corerouter-teste`, já com a imagem da parte 1, `f694e065`, slot `b`, dm-verity ativo).
  Gráfico: `docs/changes/G1.6q-soak-screenshots/soak.png`.

  Soak, uma amostra a cada 10 min (`system.resource.print`, `system.resource.process.print`,
  `system.health.check`, `log.print` dos avisos novos), **medido** em 2026-10-29:

  - **VM real, imagem nova**, pelo canal 7990 da GUI do usuário (uma conexão fixa): 38 amostras de
    04:20 a 10:30 (6,2 h). Às ~10:35 a GUI do 7990 fechou e as amostras seguintes falharam; uma
    amostra final às 12:21 pelo login TLS autorizado fecha as **8 h** de uptime. Daemon 46,3 →
    49,3 MiB: +2,7 MiB nos primeiros 30 min (caches, primeiro uso), depois **+0,03 MiB/h** (49,06 →
    49,31 MiB de 04:50 a 12:21). Threads 57 e descritores 24 fixos (56/23 no fim, sem a conexão do
    7990). FRR 102,8 → 103,2 MiB (+0,4 MiB uma vez na 1ª hora, depois plano), 25 threads.
    `MemAvailable` 1 837,7 → 1 831,4 MiB (−0,8 MiB/h, cache de página). `/config` 4,86 → 4,89 MiB
    (uma revisão de teste). Saúde sempre `warning` só pelo `admin` sem senha; nenhum erro novo no
    log em 8 h, e os únicos avisos novos são os "Login sem senha" das próprias amostras por TLS.
    Consulta completa de 17–40 ms.
  - **Cópia local A, imagem de 28/10** (`3d79961`), por TLS com ~5 logins por amostra: 48 amostras
    em 7,8 h. Threads 55, FRR 102,5 MiB e `/config` fixos. O daemon foi de 40,8 a 54,2 MiB, cada
    vez mais rápido: **não é vazamento**. Cada amostra gravava 5 avisos "Login sem senha" no log
    (teto de 1 000 entradas), e a resposta do `log.print {level: warning, limit: 2000}` crescia
    junto até ~450 KB; o alocador guarda o pico. Reproduzido na cópia B (imagem nova): 600
    `log.print` de 450 KB levam o daemon de 42,6 a **59,8 MiB e param aí** (59,32 → 59,81 → 59,82
    em rodadas de 200), e 60 s depois ele está em 56,0 MiB. 300 logins TLS seguidos e 200 de cada
    uma das outras consultas não mudam o RSS (±0,4 MiB), nas duas imagens.
  - **Observação pelo host** (`virsh domstats`, HTTPS e TLS a cada 10 min, 48 amostras, 7,8 h): VM
    `running` o tempo todo, HTTPS 200 em 2–3 ms, TLS em 15–17 ms, QEMU com 416–439 MiB. A gerência
    mandou **~335 KiB/s** o tempo todo para as GUIs do usuário (12,7 GB na noite), que ainda são
    binários anteriores ao etag do `engine.list` da parte 1. Com GUI nova a conta cai para ~8 KiB/s
    por GUI.

  Funcional na VM real pelo canal 7990 (imagem `f694e065`, **medido** em 2026-10-29, tudo desfeito
  no fim; revisões 15–22 do histórico):

  - `ping 1.1.1.1` pela `ether1` (cliente): 4/4, média 39,4 ms, jitter 0,03 ms.
  - NTP (`pool.ntp.org`): sincronizado em 3 s, stratum 2, offset −58,6 ms (o relógio vinha do
    RTC), RTT 56,9 ms; desligado de novo, como estava.
  - Transacional: loopback com 192.0.2.99/32, bridge com a `ether2` (sem cabo), VLAN 999 com
    198.51.100.99/24: diff de 32 linhas, commit na revisão 15, drift em sincronia; o rollback para a
    14 fica pendente em modo transacional até o commit (revisão 16), como no Junos; volta ao modo
    `immediate`, interfaces e endereços como antes.
  - Safe Mode: a queda da sessão MCP desfez as mudanças (revisão 20), e o `config.safe-mode.cancel`
    também (revisão 22).

- 2026-10-29 — G0.31a: `config.diff` só serializa, nas listas grandes, os blocos do `CowList` que o candidato e a config
  em execução não compartilham. Vale para as dez listas em blocos: endereços, rotas, filter/nat/
  mangle/raw, address-lists, PPP secrets, simple queues, leases estáticos do DHCP e DNS estático.
  Todas são indexadas por `id` no diff (o caminho é `ip.routes[*1F].distance`, não a posição), então
  tirar os itens iguais não muda nenhum caminho. Um lado que ficaria vazio guarda um item
  compartilhado nos dois, porque a lista vazia é uma linha própria (`ip.routes: []`) que as listas
  inteiras não dariam. `CowList::unshared` e `CowList::any_shared` são novos; a G0.31e pode
  reaproveitá-los no plano do commit.

  Como testar: `cargo test -p corerouter-model --lib store::` (o teste
  `skipping_shared_blocks_gives_the_same_diff` compara com o diff ingênuo das listas inteiras em 11
  edições: acrescentar, mudar, apagar, inserir no meio, `retain`, esvaziar, address-list, secret e
  duas seções ao mesmo tempo, nos dois sentidos). Bench: `cargo bench -p corerouter-engine --bench
  lock_hold`.

- 2026-10-29 — G0.31b: Consultas grandes fora do lock do `Session`. Sob o lock, o handler pega um snapshot: a config
  clonada (só contadores de referência) e `Arc`s do estado vivo. Em seguida chama `s.defer(closure)`.
  O canal de controle (`Host::with_session_reply`, no daemon e na GUI local) solta o lock e só
  então monta as linhas e o JSON (`Reply::finish`). Os outros chamadores (`Session::execute`: GUI no
  processo, CLI sem daemon, lotes, testes) recebem a resposta pronta, como antes. Só o comando
  pedido como resposta adia; um comando executado dentro dele responde no lugar.

  Adiam: `ip.route.list`, `ip.firewall.{filter,nat,mangle,raw}.list`,
  `ip.firewall.address-list.list`, `ip.firewall.preview` e `config.drift.list`. No drift, a leitura
  do kernel continua sob o lock. O estado vivo que eles leem passou a `Arc`, copiado só quando
  alguém escreve com um closure vivo:
  - `RouteWatch` (estados, `RouteWatch::changed`). A olhada é pulada quando a tabela de linhas é o
    mesmo `Arc` da última, porque nenhum estado pode ter mudado; antes, cada lista percorria as
    60 000 rotas sob o lock;
  - os contadores do firewall (`FwDiag::live`);
  - as entradas dinâmicas das address-lists (`DynamicLists::shared`);
  - o estado do LDP (`mpls::ldp_state`).

  O mecanismo está em `docs/architecture.md` ("Consultas fora do lock do `Session`") e serve à
  G0.31c: uma thread publica o dump do conntrack num `Arc`, e o handler chama `s.defer`.

  Como testar: `cargo test -p corerouter-engine --lib off_lock` (adia e termina com a mesma
  resposta; um comando dentro de outro responde no lugar; um erro não deixa nada pendente) e
  `cargo test -p corerouter-engine --test it off_lock` (as 11 combinações de consulta e parâmetros
  dão a mesma resposta com e sem adiar; um lote nunca adia). Bench: `cargo bench -p
  corerouter-engine --bench lock_hold`, coluna `held` da varredura e grupo `held/*`.

- 2026-10-29 — G1.6qf: Safe Mode na chamada avulsa da CLI: `corerouter-cli run config.safe-mode.enter` agora é recusado
  antes de conectar, com o motivo (a conexão fecha quando o comando volta, o roteador desfaria o
  Safe Mode na hora e o `run` seguinte mudaria a config sem proteção) e os clientes que mantêm a
  conexão (`corerouter-cli shell` com Ctrl+X, `corerouter-cli mcp`, GUI). A lista dos comandos
  presos à conexão fica no engine (`safe_mode::NEEDS_OPEN_CONNECTION`), perto do `hang_up` que a
  justifica. Teste do caso reproduzido na VM: `apps/corerouter-cli/tests/local.rs`
  (`run_refuses_safe_mode_which_would_end_with_its_connection`: recusa com e sem `--connect`, o
  roteador nunca entrou em Safe Mode e os outros comandos seguem).

- 2026-10-29 — G3.9hb: Terminal: `/interface vlan add interface=ether1 vlan-id=10 name=v10` funciona como no RouterOS, e o
  `/import` do `/interface vlan export` de um MikroTik entra como veio. O `CommandSpec` ganhou
  `key_alias(&[("interface", "parent")])`, que sai no `engine.list` como `key_alias`; o terminal
  troca o sinônimo pela chave antes de enviar (o `params` não muda; o engine continua recusando
  `interface`), oferece `interface=` no Tab ("same as parent") e completa o valor com os nomes de
  interface. O `interface.vlan.add` aceita `disabled` (o RouterOS exporta `disabled=yes`).
  `use-service-tag`, `mtu`, `vlan-id` e `comment` já batiam. Caso novo `rsc` em
  `scripts/routeros-interop-l2.sh`: o CHR 7.25 cria VLANs (comentada, desabilitada com MTU 1400,
  S-tag e C-tag sobre ela), exporta, e o terminal do CoreRouter importa o arquivo como veio.
  O laboratório achou que o RouterOS exporta em ordem de nome, não de dependência (`add
  interface=s42 name=c43` vem antes de `name=s42`): o `/import` agora põe no fim do lote o passo que
  falhou e roda o lote atômico de novo. Um passo já adiado só volta a ser adiado se mais passos
  rodaram antes da falha (uma cadeia se resolve, duas linhas ruins não trocam de lugar para sempre),
  o último nunca, e no máximo 64 vezes; a linha ruim continua falhando com o número dela no script.
  Testar: `cargo test -p corerouter-shell a_routeros_vlan_export_imports_as_written`,
  `cargo xtask vm-lab run -- scripts/routeros-interop-l2.sh rsc`.

- 2026-10-29 — G3.9hc: Interfaces › New VLAN Interface ganhou a caixa "Use Service Tag" (802.1ad S-tag, TPID 0x88a8),
  enviada como `use_service_tag` só quando marcada (um daemon de antes do 802.1ad ainda cria a VLAN
  comum), e ⓘ em Name, Interface, VLAN ID, Use Service Tag e MTU, com a explicação em português e
  inglês (S-tag × C-tag, quando ligar, o cuidado do TPID igual nos dois lados, IEEE 802.1ad,
  `use-service-tag` do RouterOS). Na lista, a coluna Info mostra o selo `S-VLAN 100` na mesma cor
  por hash do id que a `VLAN 100` e o texto "s-vlan 100 on ether1 (802.1ad)"; a janela
  "Interface <nome>" de uma VLAN mostra "Use Service Tag" com ⓘ (yes/no e o TPID), só leitura.
  Opção A do mockup (sem coluna nova). Testar: `cargo test -p corerouter-ui vlan_service_tag`;
  screenshots claro e escuro em `docs/changes/G3.9hc-screenshots/`.

- 2026-10-29 — G0.31c: Conntrack lido e filtrado fora do lock do `Session`, com o mecanismo da G0.31b
  (`Session::defer`). Sob o lock, `ip.firewall.connection.list`, `ip.firewall.connection.top` e
  `ip.firewall.cgnat.capacity.preview` pegam só o `Arc` do dump em cache e os pools do CGNAT. Se o
  dump passou de `CACHE_SECS`, pegam também um leitor do kernel com socket próprio
  (`Hal::conntrack_scanner`, o mesmo do `cgnat-scan` da G2.7b). Ler, filtrar, ordenar, somar e
  montar o JSON roda depois do lock, na thread da conexão. O dump lido ali vai para o cache
  (`ConnCache`: um mutex próprio, segurado só para copiar o `Arc`, e outro que serializa as
  leituras). Duas janelas que pedem ao mesmo tempo leem a tabela uma vez só. O backend virtual
  não tem leitor e continua lendo sob o lock (tabela pequena). `kill` continua sob o lock: ele
  precisa do HAL para apagar, e a G3.9hd o revê.

  Como testar: `cargo test -p corerouter-engine --lib firewall_connection` (duas leituras ao mesmo
  tempo leem a tabela uma vez e publicam o dump; `list` e `top` adiam e dão a mesma resposta) e
  `cargo test -p corerouter-engine --test it connections`. Bench em namespace sem root:
  `COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- cargo bench -p
  corerouter-daemon --bench netns_conntrack` (`cargo xtask bench` o roda no namespace).

- 2026-10-29 — G0.31d: As rotas estáticas (`ip.routes`) viraram `corerouter_model::routes::Routes`: o mesmo `CowList` em
  blocos, com um índice (tabela, destino, gateway) → ids, no molde do `AddressLists` da G0.21. O
  `ip.route.add`/`set` acha o mesmo próximo salto em O(1) em vez de comparar com todas as rotas; o
  `ip.route.set`/`remove` acha a rota pelo id em O(log n) (a lista está em ordem de id). O índice é
  montado na primeira consulta, compartilhado pelas cópias da config (`CowMap`, uma escrita copia
  uma folha) e mantido por `push`, `update` e `remove`; qualquer outra escrita pelo `DerefMut` o
  descarta e a próxima consulta o refaz. O arquivo salvo e o journal não mudam (serializa como a
  lista). A validação do commit (`route_checks`) continua igual, agora recebendo os ids do mesmo
  salto.

  Mudança no `crates/model/src/config.rs`: uma linha, o tipo do campo `routes` (aditiva para quem
  lê: `Routes` tem `Deref` para `CowList<RouteEntry>`).

  Como testar: `cargo test -p corerouter-model --lib routes::` (o índice segue cada escrita e as
  cópias mantêm o seu), `cargo test -p corerouter-engine --test it route::` (o teste
  `the_same_hop_twice_is_refused_after_set_and_remove`). Bench novo: `cargo bench -p
  corerouter-engine --bench route_scale`.

- 2026-10-29 — G1.6qa: `system.reboot` e `system.shutdown`, como o `/system reboot|shutdown` do RouterOS: pedem
  `confirm: true` (no terminal, `/system reboot confirm=yes`) e são recusados sem `force` em Safe
  Mode (o boot subiria a config da entrada e desfaria as mudanças) ou com mudanças de transação
  pendentes (seriam perdidas), e sempre dentro de um lote atômico (não dá para desfazer). Ficam no
  journal e no log como qualquer comando. O engine só registra o pedido (`crate::power`); o
  serviço `power` do daemon o pega fora do lock, espera 1 s para o cliente ler a resposta e manda
  SIGTERM (reboot) ou SIGUSR2 (desligar) ao PID 1. O `corerouter-init` devolve SIGTERM ao daemon,
  que grava o checkpoint da config (G0.27), para o FRR, faz `sync` e desmonta `/config`. Fora da
  imagem (PID 1 que não é o `corerouter-init`, ou daemon que não é filho dele) os comandos ficam
  desligados com o motivo ("PID 1 is systemd…"): um sinal a outro PID 1 pararia a máquina de
  desenvolvimento.

  Testes: `cmd::system_power` (sucesso, validação, Safe Mode, transação pendente, lote atômico),
  `service::power` (detecção do init) e, na imagem, no QEMU como usuário (sem root):
  `power-test.sh` (reboot pela rede, a config mudada antes sobrevive, depois shutdown e o QEMU
  sai).

  Na imagem (build desta branch, QEMU/KVM, 2 vCPUs, 1 GiB, 2026-10-29, **medido**): sem `confirm`
  recusado; `system.identity.set` e `system.reboot {confirm: true}` pela TLS → o init escreve
  "reboot: stopping services" e o daemon responde de novo em 3,0 s (de parede, do pedido ao
  `ready:`), com a identidade mantida; `system.shutdown {confirm: true}` → "power off: stopping
  services" e o QEMU sai em 2,0 s (1 s é a pausa para o cliente ler a resposta).

- 2026-10-29 — G3.9fg: BGP: `set bgp-path-prepend N` com a contagem do RouterOS v7. Para um vizinho eBGP a rota sai com o
  nosso AS N vezes no total (a cópia do eBGP conta; N = 1 não muda nada), **medido** no RouterOS
  7.25 CHR com o caso novo `prepend` de `scripts/routeros-interop-bgp.sh` (CHR: N = 1, 2, 3 → 1, 2,
  3 cópias; CoreRouter antes: 2, 3, 4; depois: 1, 2, 3). Na saída iBGP e na entrada o CHR não põe
  cópia nenhuma (N = 1, 2, 3 → 0, **medido**; o FRR punha N): o CoreRouter também não, e o
  `rule.check` avisa que ali o prepend não faz nada.

  - Render: o mapa de saída eBGP põe N − 1 (`set as-path prepend`), o de entrada e de saída iBGP
    nada; chain usada nos dois lugares ganha `CR-<chain>+ebgp-out`, só para as saídas eBGP e só
    quando difere. A prévia e o impacto (`Side.counted`) fazem a mesma conta; o proptest que compara
    o render com o avaliador roda as três contagens.
  - Migração: um filtro gravado antes (sem o campo `prepend`) é lido como `legacy` e manda os mesmos
    caminhos de antes. `routing.filter.status` (`prepend`, `prepend_warning`), o `rule.check`
    (`prepend-count`) e a janela Routing › Filters (selo **Prepend count**, botão **Use RouterOS
    count**, ⓘ) avisam. `routing.filter.prepend.set {count: routeros}` troca e, com `keep_paths`
    (padrão), reescreve N → N + 1 nas chains que só saem por eBGP; o que não dá para manter (chain
    na entrada ou no iBGP, onde o prepend deixa de valer; N = 16) volta em `left`. Escolhido em vez de converter na leitura: a
    mesma regra pode estar numa chain de entrada, de iBGP e de eBGP, e só o operador decide como
    separar.

  Como testar: `cargo test -p corerouter-proto-bgp prepend`, `cargo test -p corerouter-engine
  routing_filter`; contra o CHR, `cargo xtask vm-lab run -- scripts/routeros-interop-bgp.sh prepend`.

- 2026-10-29 — G3.9fh: BGP: o RouterOS 7.25 manda IPv6 numa sessão IPv4 com o next hop IPv4-mapeado `::ffff:10.39.1.1`
  (fora da RFC 2545 §3); o FRR aceita a rota, mas o kernel não a instala. Agora a chain de entrada
  reescreve o next hop: `set gw ENDEREÇO`, a propriedade `gw` do RouterOS v7. Vira `set ipv6
  next-hop global X` (ou `set ip next-hop X`) no FRR, numa entrada guardada por um teste de família,
  para não pôr um next hop IPv6 numa rota IPv4. O avaliador e a prévia mostram `gw X` na mudança; o
  proptest render × avaliador inclui `set gw` das duas famílias. O parser recusa mapeado,
  link-local, multicast, loopback e não especificado, com a coluna.

  `routing.bgp.connection.check` (`mpbgp-nexthop`): numa conexão IPv4 com `afi=ipv6`, vira
  `warning` com a regra pronta quando a chain de entrada não reescreve o next hop IPv6, e `info`
  com o endereço quando reescreve.

  Escolhido em vez de uma opção nova na conexão: o RouterOS já tem `gw` no filtro, e o next hop de
  cada vizinho é o endereço dele, que vai na chain dele. A rota IPv6 via gateway IPv4 (`via inet`,
  como na RFC 8950) não serve: o Linux não aceita gateway IPv4 numa rota IPv6.

  Contra o RouterOS 7.25 CHR (**medido**, VM `corerouter-lab`, 2026-10-29, caso `mpbgp`): sem `set
  gw` o `fd39:203::/48` do CHR fica no bgpd com next hop `::ffff:10.39.1.1` e fora do kernel; com a
  regra na entrada ele entra no kernel via `fd39:1::1` 169 ms depois do commit, sem reset da sessão,
  e as rotas IPv4 continuam via `10.39.1.1`.

  Como testar: `cargo test -p corerouter-proto-bgp set_gw`, `cargo test -p corerouter-engine --lib
  routing_bgp`; contra o CHR, `cargo xtask vm-lab run -- scripts/routeros-interop-bgp.sh mpbgp`.
