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

## Histórico de revisão

- 2026-10-21 — log do G1.1.
- 2026-10-21 — log do G1.9.
