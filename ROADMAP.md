# CoreRouter — roadmap

Fonte de verdade das tarefas: `docs/gaps.md` (ids G*). Este arquivo resume fases e registra o log.

| Fase | Escopo | Gaps | Saída esperada |
|---|---|---|---|
| 0 | Motor arquitetural | — | Registro de comandos, camadas, MCP, GUI, xtask ci (**feito**, v0.1.0) |
| 1 | Core / Interfaces | G1.*, G0.2, G0.6 | Roteador L3 básico em kernel real com persistência e Safe Mode |
| 2 | Firewall / CGNAT | G2.* | nftables + CGNAT PBA; XDP para alta capacidade |
| 3 | OSPF / BGP / MPLS | G3.* | FRR orquestrado; simulador de protocolos no lab |
| 4 | Serviços e telemetria | G4.* | DNS, DHCP, PPPoE, métricas, gráficos |

Restante até uma beta de Fase 1: ~70 h de agente (**estimado**, soma de G0.2, G0.6, G1.1–G1.5).

## Log

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

## Histórico de revisão

- 2026-10-21 — log do G1.1.
- 2026-10-21 — log do G0.6.
- 2026-10-21 — log do G1.2.
- 2026-10-21 — log do G1.9.
- 2026-10-21 — log do G0.4.
- 2026-10-21 — log do G1.10 + G1.11.
- 2026-10-21 — log do G5.2 (Parte 1).
- 2026-10-21 — log do G1.12.
- 2026-10-21 — log do G1.5.
- 2026-10-21 — log do G1.13.
- 2026-10-22 — log do G1.14.
- 2026-10-22 — log do G1.4.
- 2026-10-22 — log do G5.1.
- 2026-10-22 — log do G1.15.
- 2026-10-22 — log do G5.2 (Parte 2).
