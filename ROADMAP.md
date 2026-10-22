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

## Histórico de revisão

- 2026-10-21 — log do G1.1.
- 2026-10-21 — log do G0.6.
- 2026-10-21 — log do G1.2.
- 2026-10-21 — log do G1.9.
- 2026-10-21 — log do G0.4.
- 2026-10-21 — log do G1.12.
