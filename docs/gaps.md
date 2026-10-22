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
| G0.4 | GUI como cliente remoto + WebSocket para WASM | ui, control, gui, daemon | Trait de backend na UI (local/remoto); daemon serve WS; GUI web gerencia um roteador real. Feito: `ui::Backend` (`submit`/`poll`/`link`) + `Local`; `corerouter-gui --connect HOST:PORT` (thread + reconexão; `--control` repassa ao daemon); `corerouter-daemon --ws <porta> [--ws-origin …] [--web-root dist]` com lista de `Origin`; GUI web por `?connect=ws://…`, `?lab` ou mesma origem | 14 h | feito (`stream/G0.4-gui-remote`) |
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
| G1.4 | Safe Mode | engine, control, ui | Semântica do RouterOS: `config.safe-mode.enter {timeout_secs?}` / `exit` (confirma) / `cancel` (desfaz); queda da conexão dona ou timeout → volta à config da entrada; nada salvo como boot até confirmar; botão Safe Mode na barra com contagem regressiva. Feito: `engine::safe_mode`, `Caller` por conexão (`control::new_caller`/`hang_up`), `control::spawn_clock` | 6 h | feito (`stream/G1.4-safe-mode`) |
| G1.5 | Rotas estáticas e VRF | model, engine, hal-linux, ui | `ip.route.add/remove/list`, distance, VRF; tabela de rotas ao vivo na janela Routes. Feito: `ip.route.add/set/remove/list` (IPv4/IPv6, gateway IP / interface / `ip%interface`, distance → métrica do kernel, conectadas derivadas com flags `ADC`), `ip.vrf.add/set/remove/list` (VRF = interface tipo `vrf` com tabela própria), `model::route::reach` compartilhado por engine e `hal-linux`, plano com rotas + VRF (links "reconstruídos" têm rotas removidas/recolocadas explicitamente), janela IP › Routes no padrão G1.9. Fora: ECMP, blackhole, pref-src; VRF pela GUI virou G1.13 | 10 h | feito (`stream/G1.5-static-routes`) |
| G1.6 | Imagem Buildroot | `os/` (novo) | Imagem x86_64 A/B + squashfs + dm-verity bootando o daemon em QEMU; script de build reprodutível; kernel com `CONFIG_NET_VRF=y` (sem ele `ip.vrf.add` fica desabilitado, G1.14) | 20 h | aberto |
| G1.7 | Estatísticas via netlink | hal-linux | `poll` e `discover_links` via netlink (substituem sysfs, que mostra o netns de quem montou `/sys`, não o do processo) | 3 h | aberto |
| G1.8 | Bonding (802.3ad, active-backup) | model, engine (`cmd/interface.rs`), ui | `interface.bonding.add {name, slaves, mode}`; slave não pode ser porta de bridge nem ter endereço; mesmo padrão de dependências do G1.1 | 4 h | aberto |
| G1.9 | Tabelas estilo WinBox: seleção, menu de contexto, duplo clique | ui | Mecanismo reutilizável em `crates/ui` (`table.rs`): clique/Ctrl/Shift/espaço vazio/Ctrl+A/↑↓ selecionam; Delete, Ctrl+E/D/M, Enter (atalhos do WinBox v3/v4); barra +, −, ✓, ✗, comentário e Find, desabilitados com o motivo; menu do botão direito na linha (Enable/Disable, Remove, Comment…, Properties…, Add VLAN on <if>, Add to Bridge ▸) e no espaço vazio (Add ▸, Select All, Refresh); duplo clique abre "Interface <nome>" (OK/Cancel/Apply/Disable/Remove); diálogos New VLAN/Bridge/Loopback no lugar dos formulários fixos. Interfaces e Addresses usam; tudo via `CoreRouterUi::run`. Testes headless com eventos sintéticos | 6 h | feito (`stream/G1.9-winbox-tables`) |
| G1.10 | Comentários inline nas tabelas | ui | Como o "Comment Type" do WinBox v4 (comentário como cabeçalho do item ou como coluna; manual.mikrotik.com, WinBox › GUI Settings) e a linha `;;;` do terminal: item marcável "Inline Comments" no menu de contexto da linha e do espaço vazio de toda tabela com coluna `table::comment()`; ligado, a coluna some e o comentário vira uma faixa acima do item (fundo sutil na cor de destaque, barra e ícone de balão à esquerda, itálico, largura da tabela, legível nos dois temas). A faixa pertence ao item: clique/Shift/Ctrl selecionam, duplo clique abre o diálogo Comment, menu de contexto age no item; Find casa o texto do comentário; refresh de 1 s e atalhos inalterados. Testes headless | 4 h | feito (`stream/G1.10-inline-comments-theme`) |
| G1.11 | Tema claro/escuro na barra superior | ui, gui | Seletor Sistema/Claro/Escuro (ícones desenhados) à direita da barra, troca na hora via `Context::set_theme`; a escolha e o "Inline Comments" de cada tabela são preferência da janela (não config do roteador, sem comando do engine), salvos pela persistência do eframe (arquivo em `~/.local/share/corerouter-gui`, `localStorage` na web) e restaurados ao abrir; cores próprias da UI (ícones da barra, faixa de comentário) boas nos dois temas. Testes headless (troca altera `ctx.theme()`, preferências hostis ignoradas) | 3 h | feito (`stream/G1.10-inline-comments-theme`) |
| G1.12 | Maximizar e restaurar as janelas internas | ui | Botão □ na barra de título de toda janela flutuante (Interfaces, Addresses, BGP, History, Log, "Interface <nome>", New VLAN/Bridge/Loopback), ao lado do ▼ e do ✕: maximiza na área central (sem cobrir barra superior, menu lateral e barra de status) e vira ❐, que devolve exatamente o retângulo anterior; duplo clique na barra e menu de contexto da barra (Maximize/Restore) alternam; maximizada acompanha o redimensionamento da janela do app; arrastar e recolher continuam. Wrapper único (`crates/ui/src/float.rs`); estado só da UI. Testes headless | 3 h | feito (`stream/G1.12-window-maximize`) |
| G1.13 | VRF pela GUI | ui | Janela IP › VRF no padrão G1.9 sobre `ip.vrf.add/set/remove/list` (G1.5): colunas flag X, Name, Table, Interfaces, Comment; seleção, +/−/✓/✗/Comment, Find, menu de contexto (Enable/Disable, Remove, Comment…, Properties…, Add VRF…; espaço vazio: Add VRF…, Select All, Refresh), atalhos Delete/Ctrl+E/D/M/Enter, comentários inline; "New VRF" (nome + caixas de seleção dos membros) com Apply que vira "VRF <nome>"; "VRF <nome>" mostra a tabela e edita membros, comentário e Disabled (OK/Cancel/Apply/Disable/Remove). A lista de membros só oferece interfaces que não são VRF, nem porta de bridge, nem membro de outra VRF (o engine confere de novo); recusas do engine ficam no diálogo. Num kernel sem VRF (G1.14), + e "Add VRF…" ficam cinza com o motivo no tooltip, lido de `engine.list` pelo backend (também na GUI remota). Tudo via `CoreRouterUi::run`. Testes headless | 3 h | feito (`stream/G1.13-vrf-gui`) |
| G1.14 | Kernel sem VRF: detectar e explicar | hal, hal-linux, engine, xtask, `.github/` | `Hal::features() -> Features { vrf }` (aditivo, padrão "tudo"); `LinuxHal` sonda uma vez, sob demanda, criando e apagando um link `vrf` descartável (nome livre, nunca toca links existentes) e guarda o resultado; `ip.vrf.add` desabilitado com "this kernel has no VRF support (CONFIG_NET_VRF / module vrf)"; criar link `vrf` com EOPNOTSUPP dá o mesmo texto. CI: `sudo modprobe vrf` no runner (com `linux-modules-extra` como plano B) e `COREROUTER_REQUIRE_VRF=1`, que faz o teste de VRF em netns e o passo netns do xtask falharem em vez de pular | 3 h | feito (`stream/G1.14-vrf-kernel-support`) |

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

## G5 — Descoberta de vizinhos e gerência em malha

Inspirado no que o MikroTik oferece com MNDP (vizinhos), WinBox (tela de conexão) e RoMON
(gerência sem IP, a vários saltos). MNDP e RoMON são **proprietários e sem especificação**: não os
clonamos. O CoreRouter usa um protocolo próprio documentado (CRDP), o padrão aberto LLDP e, só para
leitura, o formato público do MNDP para enxergar MikroTiks numa rede mista.

| Id | Tarefa | Crates | Critério de aceite | Est. | Status |
|---|---|---|---|---|---|
| G5.1 | Fase A — CRDP + vizinhos + tela de conexão | proto-discovery (novo), model, engine, daemon, ui, gui | Protocolo próprio documentado em `docs/discovery.md` (UDP, broadcast IPv4 + `ff02::1`, a cada 30 s, expira em ~120 s, TLVs: id do nó, identity, versão, placa, uptime, endereços, interface, portas de gerência), codec puro com proptest/fuzz; ligado só nas interfaces da lista de descoberta (nunca na WAN por padrão); `ip.neighbor.list` e `ip.neighbor.discovery.set`; janela IP › Neighbors; tela de conexão estilo WinBox (login à esquerda; abas Neighbors/Saved à direita; duplo clique preenche "Connect to"); GUI nativa escuta anúncios, web pega a lista do daemon | 20 h | aberto |
| G5.2 | Fase B — LLDP (IEEE 802.1AB) + escuta passiva de MNDP | proto-lldp (novo), proto-mndp (novo, só decodificação), hal-linux, daemon | Envia e recebe LLDP (socket de camada 2 no `hal-linux`, testes em namespace sem root); decodifica MNDP recebido (UDP 5678) a partir de documentação pública, sem nunca anunciar MNDP; vizinhos LLDP/MNDP entram na mesma tabela do G5.1 com a coluna de protocolo; codecs com proptest/fuzz | 16 h | Parte 1 feita (`stream/G5.2-lldp-mndp`: codecs, I/O no `hal-linux`, testes em netns; `docs/lldp-mndp.md`). Falta a Parte 2 (ligar à tabela do G5.1), depois do G5.1 |
| G5.3 | Fase C — gerência em malha (estilo RoMON) | discovery, control, daemon, ui | **Depende de G0.3.** Transporte por IPv6 link-local entre vizinhos (sem IP configurado); anúncios inundados com sequência e saltos, assinados com o segredo da malha; GUI conecta num agente e escolhe o destino; sessão cifrada de ponta a ponta até o roteador destino (nós intermediários não leem nem alteram); login final é o do destino | 40 h | aberto |

## Histórico de revisão

- 2026-10-21 — lista inicial.
- 2026-10-21 — G0.2 feito: `.github/workflows/ci.yml` (ainda não rodou no GitHub; sem push).
- 2026-10-21 — G1.1 feito (VLAN, bridge, loopback, `interface.remove`); bonding separado em G1.8.
- 2026-10-21 — G0.6 feito (persistência: `running.json` + `.prev`, escrita atômica, quarentena).
- 2026-10-21 — G1.2 feito (rtnetlink: plano puro + executor com rollback, testes em netns); notas novas em G1.3 e G1.7.
- 2026-10-21 — G1.9 (tabelas estilo WinBox) adicionado e feito.
- 2026-10-21 — G0.4 feito (GUI cliente do daemon, nativo e web; WebSocket com Origin; `--web-root`).
- 2026-10-21 — G5 adicionado: descoberta de vizinhos (CRDP), LLDP + MNDP passivo e gerência em malha.
- 2026-10-21 — G1.10 (comentários inline) e G1.11 (tema claro/escuro) adicionados e feitos.
- 2026-10-21 — G5.2 Parte 1 feita (proto-lldp, proto-mndp só decodificação, LLDP/MNDP no `hal-linux`); integração com a tabela do G5.1 pendente.
- 2026-10-21 — G1.12 (maximizar/restaurar janelas internas) adicionado e feito.
- 2026-10-21 — G1.5 feito (rotas estáticas IPv4/IPv6, VRF básico, janela Routes).
- 2026-10-21 — G1.13 (VRF pela GUI) adicionado e feito.
- 2026-10-22 — G1.14 (kernel sem VRF: `Hal::features`, `ip.vrf.add` desabilitado com o motivo, CI carrega o módulo `vrf`) adicionado e feito; nota de `CONFIG_NET_VRF=y` em G1.6.
- 2026-10-22 — G1.4 feito (Safe Mode: comandos `config.safe-mode.*`, dono por conexão, timeout, sem salvar até confirmar).
