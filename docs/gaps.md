# CoreRouter — gaps (lista ranqueada do que falta)

De onde um agente tira a próxima tarefa quando ninguém passa uma: o primeiro item **aberto** da
seção "Ordem de execução". Status: `aberto` · `em andamento (<branch>)` · `feito (<commit>)`.
Estimativas em horas de agente, todas **estimadas** (nada medido ainda).

## Ordem de execução

1. G0.2 · 2. G1.1 · 3. G0.6 · 4. G1.2 · 5. G1.5 · 6. G1.4 · 7. G0.4 · 8. G2.1 · 9. G3.1 ·
10. G0.3 · 11. G2.3 · 12. G3.2 · demais na ordem das fases.

## G0 — Transversais

| Id | Tarefa | Crates | Critério de aceite | Est. | Status |
|---|---|---|---|---|---|
| G0.1 | Escolher licença do projeto | raiz | Decisão do dono registrada; `license` no `[workspace.package]`. **Agentes: não decidam, perguntem** | — | feito: AGPL-3.0-or-later |
| G0.2 | CI no GitHub Actions | `.github/` | Workflow roda `cargo xtask ci` (Linux) + build macOS/Windows da GUI; cache de target | 3 h | feito (`stream/G0.2-github-actions`) |
| G0.3 | Autenticação e TLS no canal de controle | control, daemon | `rustls`, tokens por usuário, grupos read/write/full (como RouterOS); bind não-loopback só com TLS; testes de recusa | 12 h | aberto |
| G0.4 | GUI como cliente remoto + WebSocket para WASM | ui, control, gui, daemon | Trait de backend na UI (local/remoto); daemon serve WS; GUI web gerencia um roteador real | 14 h | aberto |
| G0.5 | Fuzzing | engine, control, mcp | `cargo-fuzz` para JSON de config, `read_line_bounded`, `handle_message`; rodada de 10 min sem crash | 6 h | aberto |
| G0.6 | Persistência da config | model, engine, daemon | running + histórico em `/config` (escrita atômica, fsync); carregados no boot; corrupção → última revisão boa. Feito: `model::persist` (JSON `format_version` 1), trait `engine::ConfigStorage`, crate `storage-fs` (L4), `corerouter-daemon --config-dir` | 6 h | feito (`stream/G0.6-persistence`) |
| G0.7 | MCP completo | mcp | resources (`corerouter://state`, `command/{id}`), prompts, completions, progresso/cancelamento, erro `-32003` (motor ocupado) | 10 h | aberto |
| G0.8 | CLI interativa estilo RouterOS | cli, engine | `/ip address add address=… interface=…` traduzido para comandos; autocompletar a partir do registro | 10 h | aberto |

## Fase 1 — Core / Interfaces

| Id | Tarefa | Crates | Critério de aceite | Est. | Status |
|---|---|---|---|---|---|
| G1.1 | VLAN, bridge, loopback | model, engine (`cmd/interface.rs`), ui | `interface.vlan.add`, `interface.bridge.add`, `interface.bridge.port.add`, `interface.remove`; validação de dependências; janela na UI. Bonding saiu para G1.8 | 8 h | feito (`stream/G1.1-vlan-bridge`) |
| G1.2 | `hal-linux` aplica via rtnetlink | hal-linux | links (up/down, MTU), VLAN, bridge, endereços; transação com rollback; testes em network namespace (sem root na CI via `unshare`) | 16 h | feito (`stream/G1.2-netlink`) |
| G1.3 | Reconciliação e drift | hal-linux, engine | Lê estado do kernel, `config.drift` lista divergências; boot semeia `disabled` do estado do kernel (hoje `Session::new` aplica `disabled=false` e sobe portas descobertas que estavam down) | 6 h | aberto |
| G1.4 | Safe Mode | engine, ui | `config.commit {confirm_timeout}`; sem `config.confirm` no prazo → rollback automático; botão Safe Mode na barra | 6 h | aberto |
| G1.5 | Rotas estáticas e VRF | model, engine, hal-linux, ui | `ip.route.add/remove/list`, distance, VRF; tabela de rotas ao vivo na janela Routes | 10 h | aberto |
| G1.6 | Imagem Buildroot | `os/` (novo) | Imagem x86_64 A/B + squashfs + dm-verity bootando o daemon em QEMU; script de build reprodutível | 20 h | aberto |
| G1.7 | Estatísticas via netlink | hal-linux | `poll` e `discover_links` via netlink (substituem sysfs, que mostra o netns de quem montou `/sys`, não o do processo) | 3 h | aberto |
| G1.8 | Bonding (802.3ad, active-backup) | model, engine (`cmd/interface.rs`), ui | `interface.bonding.add {name, slaves, mode}`; slave não pode ser porta de bridge nem ter endereço; mesmo padrão de dependências do G1.1 | 4 h | aberto |
| G1.9 | Tabelas estilo WinBox: seleção, menu de contexto, duplo clique | ui | Mecanismo reutilizável em `crates/ui` (`table.rs`): clique/Ctrl/Shift/espaço vazio/Ctrl+A/↑↓ selecionam; Delete, Ctrl+E/D/M, Enter (atalhos do WinBox v3/v4); barra +, −, ✓, ✗, comentário e Find, desabilitados com o motivo; menu do botão direito na linha (Enable/Disable, Remove, Comment…, Properties…, Add VLAN on <if>, Add to Bridge ▸) e no espaço vazio (Add ▸, Select All, Refresh); duplo clique abre "Interface <nome>" (OK/Cancel/Apply/Disable/Remove); diálogos New VLAN/Bridge/Loopback no lugar dos formulários fixos. Interfaces e Addresses usam; tudo via `CoreRouterUi::run`. Testes headless com eventos sintéticos | 6 h | feito (`stream/G1.9-winbox-tables`) |

## Fase 2 — Firewall / CGNAT

| Id | Tarefa | Crates | Critério de aceite | Est. | Status |
|---|---|---|---|---|---|
| G2.1 | Firewall (filter/nat/mangle, address-lists) | model, engine, hal-linux, ui | Modelo + comandos; render nftables; aplicação atômica via netlink batch; janela Firewall | 20 h | aberto |
| G2.2 | Conntrack | hal-linux, engine, ui | `ip.firewall.connection.list` ao vivo; timeouts configuráveis | 6 h | aberto |
| G2.3 | CGNAT em nftables | proto-cgnat, engine, hal-linux | Pools, PBA, NAT determinístico, log por bloco (RFC 6888/7422); testes de alocação | 16 h | aberto |
| G2.4 | Flowtable fast path | hal-linux | Offload de conexões estabelecidas; hw offload quando a NIC suporta | 5 h | aberto |
| G2.5 | `dataplane-ebpf` (XDP com aya) | dataplane-ebpf(-common), hal-linux | CGNAT/ACL em XDP; `unsafe` só neste crate, com `SAFETY:`; fallback para nftables | 40 h | aberto |
| G2.6 | Benchmarks de pps | `bench/` | pktgen/TRex, números **medidos** por cenário em `docs/perf.md` | 8 h | aberto |

## Fase 3 — OSPF / BGP / MPLS

| Id | Tarefa | Crates | Critério de aceite | Est. | Status |
|---|---|---|---|---|---|
| G3.1 | `hal-frr` | hal-frr (novo, plataforma) | Render dos proto-* para frr.conf; apply via frr-reload/mgmtd; rollback; testes com FRR em container | 16 h | aberto |
| G3.2 | BGP completo | model, proto-bgp, engine | peers/connections/templates, prefix-lists, route-maps, communities, AFI/SAFI | 24 h | aberto |
| G3.3 | Estado BGP | hal-frr, engine, ui | `routing.bgp.session.list` via `vtysh … json`; janela com sessões ao vivo | 6 h | aberto |
| G3.4 | OSPFv2/v3 | proto-ospf, engine, ui | Áreas, interfaces, custo, stub/NSSA, auth; estado de vizinhos | 16 h | aberto |
| G3.5 | MPLS + LDP | proto-mpls, hal-linux, hal-frr | Rotas MPLS no kernel, LDP via ldpd, labels na UI | 16 h | aberto |
| G3.6 | BFD | proto-bgp/ospf, hal-frr | BFD por peer/interface | 5 h | aberto |
| G3.7 | Simulador de protocolos no lab | hal (virt), proto-* | Topologia de N roteadores virtuais; BGP/OSPF convergem no `VirtualHal` (wasm incluso) | 24 h | aberto |
| G3.8 | Avaliar holo | hal-holo (spike) | Relatório comparando holo × FRR (features, interop, estabilidade) | 8 h | aberto |

## Fase 4 — Serviços DNS / DHCP e Telemetria

| Id | Tarefa | Crates | Critério de aceite | Est. | Status |
|---|---|---|---|---|---|
| G4.1 | DNS | proto-dns, daemon, ui | hickory: cache, forwarders, estáticos, DoT/DoH upstream | 12 h | aberto |
| G4.2 | DHCPv4/v6 + relay | proto-dhcp, daemon, ui | dhcproto; pools, leases persistidos, opções, PD; janela DHCP Server | 16 h | aberto |
| G4.3 | PPPoE / IPoE | proto-pppoe (novo), daemon | Orquestração do accel-ppp; sessões na UI | 16 h | aberto |
| G4.4 | Prometheus, IPFIX/sFlow | daemon | `/metrics`; exportador de fluxos | 8 h | aberto |
| G4.5 | Gráficos de tráfego na UI | ui | Séries por interface (como o Traffic do WinBox), sem travar o frame | 6 h | aberto |
| G4.6 | NTP e syslog remoto | daemon | ntpd-rs; syslog RFC 5424 | 5 h | aberto |

## Histórico de revisão

- 2026-10-21 — lista inicial.
- 2026-10-21 — G0.2 feito: `.github/workflows/ci.yml` (ainda não rodou no GitHub; sem push).
- 2026-10-21 — G1.1 feito (VLAN, bridge, loopback, `interface.remove`); bonding separado em G1.8.
- 2026-10-21 — G0.6 feito (persistência: `running.json` + `.prev`, escrita atômica, quarentena).
- 2026-10-21 — G1.2 feito (rtnetlink: plano puro + executor com rollback, testes em netns); notas novas em G1.3 e G1.7.
- 2026-10-21 — G1.9 (tabelas estilo WinBox) adicionado e feito.
