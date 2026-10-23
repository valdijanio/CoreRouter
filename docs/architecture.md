# CoreRouter — arquitetura

Status: esqueleto v0.1.0 (motor arquitetural pronto; sem data plane real). Números marcados como
**estimado** não foram medidos neste repositório.

## 1. Sistema base e stack de rede

### 1.1 Sistema operacional do roteador

**Decisão: imagem imutável construída com Buildroot, operada só pela API (filosofia Talos).**

| Opção | Prós | Contras | Veredito |
|---|---|---|---|
| **Buildroot** | Imagem de 30–60 MB (estimado), só o que compilamos, kernel e config sob controle total, reprodutível, cross-compile trivial (x86_64, aarch64) | Sem gerenciador de pacotes (é o objetivo) | **Produção** |
| Alpine imutável | musl, apk, comunidade grande | Ainda é uma distro de uso geral; superfície maior; atualização por pacote não é atômica | Lab/dev |
| Talos-like (custom init) | Sem shell, API-only, atômico | Talos é específico para Kubernetes; copiamos a filosofia, não o produto | Filosofia adotada |

Layout da imagem:

- Kernel LTS com `nftables`, `nf_flow_table` (+ offload), XDP/eBPF (BTF), MPLS (`mpls_router`,
  `mpls_iptunnel`), VRF, bonding, 802.1Q, bridge VLAN filtering, WireGuard.
- rootfs **squashfs read-only + dm-verity**, partições **A/B** (atualização atômica, volta para
  a partição anterior se o boot falhar), `/config` (ext4) gravável só pelo daemon.
- PID 1 mínimo (BusyBox init ou init em Rust) sobe `corerouter-daemon`; FRR, accel-ppp e
  serviços são filhos supervisionados pelo daemon. Sem SSH/shell por padrão; console de
  emergência atrás de flag de boot.
- Perfil de desenvolvimento: VM QEMU/Alpine ou Debian com o daemon em `--backend linux` dentro
  de network namespaces (gap G1.6).

### 1.2 Data plane, firewall e CGNAT

| Critério | Kernel nativo (Netlink + nftables) | **eBPF/XDP com `aya`** | DPDK / VPP |
|---|---|---|---|
| Desempenho | 1–3 Mpps/core no slow path; flowtable (fast path) muito mais (estimado) | 10–25 Mpps/core em XDP nativo (estimado) | 20–40+ Mpps/core (estimado) |
| Integração | Total: rotas, conntrack, tc, ferramentas Linux | Convive com o kernel; slow path continua no kernel | Tira a NIC do kernel; tudo precisa ser reimplementado ou espelhado |
| Segurança / Rust | `rtnetlink`/`netlink-packet-*` em Rust puro, sem `unsafe` nosso | `aya` em Rust puro; programas `no_std` exigem `unsafe` isolado; verificador do kernel limita o estrago | FFI C, hugepages, muito `unsafe` |
| Operação | Simples | Média (mapas, versões de kernel) | Cores dedicados, NICs suportadas, debugging difícil |

**Decisão: híbrido atrás do trait `Hal` (L1).**

1. **Fase 1–2:** kernel nativo. `rtnetlink`/`netlink-packet-route` para links, VLAN, bridge,
   endereços, rotas e rotas MPLS; nftables via netlink batch (transação atômica do kernel) para
   firewall/NAT; **flowtables** para o fast path de conexões estabelecidas.
2. **Fase 2+:** `dataplane-ebpf` (XDP com `aya`) para o que o kernel não escala bem: **CGNAT
   determinístico com port-block allocation** (RFC 6888/7422 — log por bloco, não por sessão),
   ACL de borda e mitigação de DDoS. Programas no crate isolado `dataplane-ebpf` (único lugar
   com `unsafe`), tipos compartilhados em `dataplane-ebpf-common`, loader no `hal-linux`.
3. **DPDK/VPP:** não entra no caminho crítico. Se um cliente precisar de >100 Gbit/s de CGNAT
   por caixa, vira um terceiro backend do mesmo trait (VPP pela API binária).

### 1.3 Control plane (BGP, OSPF, MPLS/LDP, BFD)

**Decisão: orquestrar FRRouting sob a camada transacional do engine; avaliar holo como segundo
backend.**

- Reescrever BGP/OSPF/LDP/BFD com interoperabilidade de produção custa anos (estimado); FRR é
  maduro, usado por operadores e testado contra os grandes fabricantes.
- O engine continua dono da verdade: o candidate é validado pelos `proto-*` (L2), que
  **renderizam** a config FRR (`proto-bgp::render_frr` já existe). O driver L1 `hal-frr` (G3.1)
  aplica como transação (`frr-reload`/mgmtd), faz rollback se falhar e lê estado via
  `vtysh -c '… json'`.
- **holo** (suíte de roteamento em Rust, modelo YANG) é o candidato a backend Rust-nativo do
  mesmo trait (G3.8) — sem mudar UI, comandos ou MCP.
- FSMs próprias só para o **simulador** (sessões BGP/OSPF entre roteadores virtuais no lab, G3.7)
  e onde não houver implementação madura.

### 1.4 Serviços de borda

| Serviço | Escolha | Observação |
|---|---|---|
| DNS: resolvedor do roteador, encaminhador com cache, estáticos, servidor autoritativo | Hickory DNS, Rust puro (decisão do usuário, 2026-10-22): `hickory-proto` no resolvedor (G4.1a), `hickory-server` no servidor (G4.1c) | Num processo só, integrado aos comandos e às transações; veja "DNS (G4.1)" na seção 3 e `docs/dns.md` |
| DHCPv4/DHCPv6 (+PD) e relay | Rust puro (decisão do usuário, 2026-10-22). DHCPv4: codec `dhcproto` atrás de um saneador no cliente; o servidor (G4.2a) lê pedidos com leitor próprio e responde pelo `dhcproto`; DHCPv6: codec próprio (G4.7b: o `dhcproto` 0.15 v6 dá panic/dessincroniza com bytes hostis); servidor e diário de concessões próprios | Diário só de acréscimo em `/config` com `fdatasync` antes do ACK e compactação atômica; veja "Servidor DHCP (G4.2)" e `docs/dhcp.md` |
| PPPoE / IPoE (BNG) | orquestrar `accel-ppp` | Não há BNG Rust maduro; mesmo padrão do FRR |
| NTP | Cliente SNTP próprio (G4.6: `proto-ntp` L2 puro + thread no daemon); `ntpd-rs` fica como opção para o servidor NTP e a disciplina do relógio (G4.6b/G4.6c) | Medir o offset é um pacote de 48 bytes e quatro timestamps (RFC 5905 §8/§14): um processo externo a mais não paga isso, e o status vai direto para `system.ntp.client.get` sem parsear saída. Ajustar o relógio (slew/step, `CAP_SYS_TIME`) e servir hora são outra conversa: lá a maturidade do `ntpd-rs`/chrony pesa mais |
| Syslog remoto | Codec RFC 5424 próprio (`proto-syslog`, só encode) + UDP (RFC 5426) no daemon | Regras e ações estilo `/system logging` do RouterOS no engine; TCP/TLS (RFC 5425) depois |
| Gerência remota | `rustls` + provedor `ring` (TLS do canal de controle e do WebSocket), `rcgen` (certificado autoassinado), `argon2` (hash de senha), `keyring` ("Remember password" da GUI nativa); `russh` (CLI SSH) depois | G0.3 feito |
| Telemetria | `prometheus-client`, export IPFIX/sFlow | G4.4 |

## 2. Camadas do workspace

Regra central: dependência só para baixo; nada abaixo de L5 depende de egui/eframe/winit/wgpu.
Imposta por `cargo xtask layers` (`xtask/src/layers.rs`, com testes).

| Camada | Crate | Responsabilidade | Pode depender de |
|---|---|---|---|
| L0 | `crates/model` | Tipos (Asn, VlanId, IfName, MacAddr, ItemId, Gateway, RoutingTable, prefixos `ipnet`), árvore `Config`, `ConfigStore` (candidate/running, commit, rollback, diff, histórico), `route` (resolução de gateway e rotas conectadas), `users` (contas e grupos, salvos fora das revisões), `firewall` e `interface_list` (G2.1) | serde, ipnet, thiserror |
| L0 | `crates/buildinfo` | Versão e commit do build (`COREROUTER_COMMIT` pelo `build.rs`): `server.info` e o aviso de daemon de outro commit na GUI. Crate à parte para um commit novo não recompilar o workspace | nada do workspace |
| L1 | `crates/hal` | Trait `Hal` (discover, apply transacional, poll, relógio, features, `prober`, entradas dinâmicas de address-list, transporte do cliente DHCP `dhcp_port`/`DhcpPort`, G4.7; DHCPv6 `dhcp6_port`/`Dhcp6Port` e o que o kernel aprendeu por RA `ipv6_learned`/`Learned`, G4.7b; `sfp_module`/`cable_tester`, G1.20) + `VirtualHal` (lab, wasm, CI; guarda o ruleset que aplicaria; simula um SFP+ e o teste de cabo); `probe` (trait `Prober`/`ProbeSocket` das ferramentas), `sim` (rede simulada determinística, G6.2) e `sff` (EEPROM SFF-8472/8636 decodificado em código puro, G1.20) | L0, `firewall` (lateral permitido) |
| L1 | `crates/firewall` | Firewall puro (G2.1): validação, grafo de jumps e render nftables da tabela `inet corerouter`; sem I/O, compila para wasm. L1 (e não `proto-*`) porque o `hal-linux` também renderiza. Veja `docs/firewall.md` | L0 |
| L1 | `crates/hal-linux` | Backend Linux: `apply` via rtnetlink (links, VLAN, bridge, dummy, VRF, endereços, rotas estáticas; G1.2/G1.5), descoberta/contadores via rtnetlink (`RTM_GETLINK`, G1.18) com política de posse (`owner`); I/O de descoberta de vizinhos (`l2`: LLDP por `AF_PACKET`, escuta MNDP em UDP 5678; G5.2, só bytes); ICMP das ferramentas (`icmp`: ping socket ou raw, G6.2); firewall por `nft -f -` (módulo `nft`, G2.1); estado/hardware/contadores das portas por ethtool e devlink netlink (`genl`, `ethtool`, `nic`, `pci_ids`; G1.19, sem ioctl — veja `docs/interfaces.md`); cliente DHCP (`dhcp`: `AF_PACKET` com filtro BPF, UDP 68, sonda ARP; G4.7); cliente DHCPv6 (`dhcp6`: UDP 546 → `ff02::1:2`) e RA (`ra`: `accept_ra` por interface a cada apply, limpeza do aprendido; G4.7b); configuração Ethernet, EEPROM do módulo e teste de cabo por ethtool netlink (`ether`, G1.20). **Plataforma** | L0, `hal`, `firewall` (laterais permitidos) |
| L2 | `crates/proto-{bgp,ospf,mpls,cgnat,dns,dhcp}` | `validate(&Config) -> Vec<Issue>` + render para o backend (FRR, nftables…); `proto-dhcp` também tem o codec DHCPv4 (`dhcproto` atrás de um saneador), a máquina de estados pura do cliente e o servidor simulado do lab (G4.7, `docs/dhcp-client.md`); o mesmo para DHCPv6 com codec próprio (`v6`, `client6`, `lab6`; G4.7b) | L0, L1 |
| L2 | `crates/proto-discovery` | CRDP, protocolo de descoberta próprio: codec puro (`Announcement::encode`/`decode`) + `validate` das configurações de descoberta. Veja `docs/discovery.md` | L0 |
| L2 | `crates/proto-{lldp,mndp}` | Codecs puros de descoberta: LLDPDU (`decode`/`encode`) e anúncio MNDP (só `decode`; nunca anunciamos MNDP). Veja `docs/lldp-mndp.md` | nada do workspace |
| L3 | `crates/engine` | `Session::execute`, `CommandSpec`/`cmd!`, checagem de params, **permissão por grupo** (`auth`: `Principal` do `Caller`, Argon2id), guard de panic, commit/rollback, batch, journal (sem segredos), tabela de vizinhos (estado operacional), tarefas das ferramentas (`tasks`, `tools/`: ping, MTU, MTR; G6.1–G6.3), clientes DHCP em execução (`dhcp_client`: `Session::dhcp_service`, concessões como entradas dinâmicas vistas pelo HAL em `Session::effective`; G4.7; DHCPv6 em `dhcp6_client`, com os endereços `from_pool` resolvidos no mesmo `effective`, G4.7b) | L0–L2 (nunca plataforma) |
| L4 | `crates/control` | Canal JSON-por-linha (TCP em loopback ou TLS em qualquer endereço), WebSocket com lista de `Origin` (+ arquivos da GUI web), `dispatch`, `Host`, `Client`; G0.3: `auth::Gate` (login, tokens, limite de força bruta), `local_token`, `tls` (rustls, pinagem), `known_hosts` (TOFU), `dial`; `ThreadRunner` das tarefas (G6.1) | L0–L3 |
| L4 | `crates/discovery` | Runtime do CRDP (sockets UDP + threads std, `socket2`): `Agent` do daemon (anuncia, escuta, alimenta `Session::record_neighbor`) e `Listener` passivo da GUI nativa; não compila para wasm | L0–L3 |
| L4 | `crates/storage-fs` | `ConfigStorage` em diretório (`/config`): `running.json` + `.prev` e um `rev-<n>.json` por revisão, escrita atômica | L0–L3 |
| L4 | `crates/shell` | Terminal estilo RouterOS gerado do `engine.list`: parser, Tab, cores, `print`, `/export`/`/import`. Puro (sem I/O, wasm): pede chamadas do canal de controle ao front end (janela da GUI, `corerouter-cli shell`, SSH). Veja `docs/terminal.md` | `serde_json` (nada do workspace; testes usam o engine) |
| L4 | `crates/mcp` | Servidor MCP stdio; backends `Headless`/`Remote` | L0–L3, `control` (lateral permitido) |
| L5 | `crates/ui` | Painéis WinBox em egui puro (sem eframe); trait `Backend` assíncrono + `Local`; janelas novas são **painéis** (`panel.rs`: `pub(crate) const PANEL` num arquivo, descoberto pelo `build.rs` com os módulos e os testes de `src/tests/`) | L0–L4 + egui |
| L6 | `apps/corerouter-{daemon,gui,cli}` | Binários; únicos que escolhem backend de plataforma e janela | tudo |
| L7 | `xtask` | `cargo xtask ci`, `layers`, `wasm`, `agents-sync`, `bench` (criterion, G0.9; `docs/perf.md`), `docs` (arquivos de mudança por PR em `docs/changes/`; `docs fold` consolida na fila de entrada, `scripts/land.sh`) | nenhum crate do workspace |

```
CoreRouter/
├── Cargo.toml            # workspace, lints sem panic, [workspace.dependencies]
├── clippy.toml           # unwrap/expect/panic/indexing liberados só em testes
├── rust-toolchain.toml   # stable + rustfmt, clippy, wasm32-unknown-unknown
├── .cargo/config.toml    # alias: cargo xtask
├── AGENTS.md = CLAUDE.md
├── ROADMAP.md
├── docs/{architecture,gaps,mcp,control-protocol,lldp-mndp,tools,dhcp-client}.md
├── crates/
│   ├── model/            # L0
│   ├── hal/              # L1 (traits + virtual)
│   ├── hal-linux/        # L1 plataforma
│   ├── firewall/         # L1 puro: validação + render nftables (G2.1)
│   ├── proto-bgp/ proto-ospf/ proto-mpls/ proto-cgnat/ proto-dns/ proto-dhcp/   # L2
│   ├── proto-lldp/ proto-mndp/   # L2: codecs de descoberta (G5.2)
│   ├── proto-ntp/ proto-syslog/  # L2: cliente SNTP e mensagens syslog (G4.6)
│   ├── proto-discovery/  # L2: codec do CRDP (G5.1)
│   ├── engine/           # L3: src/cmd/{mod,args,interface,ip,routing,system,config}.rs
│   ├── control/          # L4
│   ├── mcp/              # L4
│   ├── storage-fs/       # L4: persistência da config em arquivo
│   ├── discovery/        # L4: runtime do CRDP (sockets, threads)
│   ├── shell/            # L4: terminal RouterOS gerado do registro (G0.8)
│   └── ui/               # L5
├── apps/
│   ├── corerouter-daemon/
│   ├── corerouter-gui/   # nativo + wasm (index.html para trunk)
│   └── corerouter-cli/
└── xtask/                # L7
```

Planejados (gaps): `crates/hal-frr` (L1 plataforma, G3.1), `crates/dataplane-ebpf` e
`crates/dataplane-ebpf-common` (L1 plataforma, G2.5).

## 3. Fluxo de um comando

```
UI (CoreRouterUi::run) ─┐
CLI / terminal (shell) ─┤
canal de controle ──────┼──► Session::execute(id, params)
MCP (Headless/Remote) ──┘        1. acha o CommandSpec (ou "did you mean")
                                 2. check_params contra o doc `params`
                                 3. enabled → Err(motivo legível)
                                 4. snapshot do candidate
                                 5. guard::run (catch_unwind) → run(&mut Session, params)
                                 6. modo immediate: validate_all (proto-*) → Hal::apply → commit
                                 7. erro em qualquer passo → restaura o snapshot
                                 8. journal
```

Modos: `immediate` (RouterOS: cada comando vira revisão) e `transactional` (VyOS/Junos:
`config.diff` → `config.commit`; `config.rollback {revision}` carrega histórico).

Cópias da config (G0.16): as seções grandes (`interfaces`, `ip` e, dentro dele, endereços,
rotas, firewall com cada tabela e as address lists, DNS estático, zonas, servidor DHCP) são
`model::cow::CowArc` — um `Arc` que copia só quando alguém escreve (`Arc::make_mut`). O
snapshot do passo 4, a running, as revisões do histórico e o store da entrada do Safe Mode
compartilham o que ninguém escreveu: clonar a `Config` custa alguns contadores de referência, e
um comando paga a cópia só das seções que escreve (com 10 000 rotas, um `interface.set` em modo
transacional caiu de 90 µs para 4 µs, **medido**). A igualdade compara o ponteiro primeiro, e o
`ConfigStore` só compara candidate × running depois de alguém pedir `candidate_mut`. Comparado
com estruturas persistentes (`im`/`imbl`, cópia O(log n) também dentro de uma lista): elas
trocariam o tipo de toda lista da config (centenas de usos como slice) e trariam uma
dependência nova; fica para quando uma lista sozinha for o gargalo (hoje, acrescentar a uma
address list de 60 000 entradas ainda copia a lista: ~0,6 ms, **medido**).

### Safe Mode (G1.4)

Como no RouterOS: `config.safe-mode.enter` guarda a config running da entrada (a própria
`Config`, não um número de revisão: o histórico é limitado a 64). Toda mudança feita depois —
de qualquer cliente, como no RouterOS — roda no data plane, vira revisão marcada `[safe mode]`
e **não é salva** no `ConfigStorage`. Fim:

| Evento | Efeito |
|---|---|
| `config.safe-mode.exit` | confirma: salva e mantém |
| `config.safe-mode.cancel`, conexão dona fecha, `timeout_secs` expira | a config da entrada é commitada como revisão nova ("safe mode undo: …"); journal registra o automático |
| daemon reinicia no meio | o disco ainda tem a config da entrada: sobe nela |

Quem é o dono: `Session::execute_as(&Caller, …)` (também `batch_as`, `inspect_as`); o canal de
controle dá um `Caller` por conexão TCP/WebSocket (`control::new_caller`) e, quando ela fecha,
chama `control::hang_up` → `Session::hang_up(id)`. `Session::execute` sem `_as` é o
`Caller::local()` (GUI em lab, testes). Só um dono por vez: outro `enter` recebe "held by
`<conexão>` since `<UTC>` (N s ago)"; `exit`/`cancel` de outro cliente pedem `force: true`
(o "release"/"unroll" do RouterOS).

Relógio: o engine não tem (wasm32). O tempo vem de `Hal::now_unix` ou de `Session::tick(unix)`,
que o daemon e a GUI em lab chamam a cada segundo (`control::spawn_clock`); expiração é
conferida em cada tick e antes de cada comando. Sem relógio (wasm `?lab`), Safe Mode funciona
sem timeout. Uma conexão TCP ociosa morta (rede caiu sem FIN) só é percebida pelo timeout: por
isso o botão oferece 1/5/10 min no clique direito.

### Persistência (G0.6)

Todo commit bem-sucedido grava running + histórico (`model::persist::encode`, JSON com
`format_version`) num `ConfigStorage` (trait do engine, sem I/O). No boot,
`Session::with_storage` tenta o slot `current` e depois o `previous`; o que não decodifica
(truncado, lixo, versão desconhecida, invariantes quebradas) vai para quarentena (`*.corrupt`) e
gera `storage.boot_errors` no `state.inspect`. Nada legível → config descoberta dos ports. O
candidate nunca é gravado (edição não commitada não sobrevive a reinício, como no Junos/VyOS).
O arquivo é JSON compacto e limitado a 32 MiB (`SAVE_BUDGET_BYTES`): quando não cabe, as
revisões mais antigas ficam de fora (`storage.revisions_not_saved`), nunca a running; um commit
cuja config sozinha passaria de ~15 MiB é recusado. A leitura aceita até 256 MiB, para arquivos
de versões anteriores. Em Safe Mode qualquer gravação escreve o store da entrada. Se a config
restaurada não chega ao plano de dados no boot, `storage.boot_apply_error` mostra o motivo, o
tick tenta de novo a cada segundo e o próximo commit aplica a config inteira.

Histórico em arquivos (G1.23): num backend com `revision_files()` (os dois de baixo) o slot guarda
só a running e a revisão mais nova (o mesmo formato, com histórico de uma entrada, que versões
anteriores leem), e cada revisão vira um arquivo próprio (`rev-<n>.json`,
`persist::encode_revision`), escrito uma vez pelo commit que a criou e apagado quando sai do
histórico. O commit serializa a config uma vez (o texto vai para o slot e para o arquivo da
revisão), então o custo é o tamanho da config, não do histórico: `commit/routes/10000` com 64
revisões em disco (fsync) caiu de 396 ms para 11,0 ms (**medido**, `storage_fs/commit/*`). Ordem:
arquivos de revisão que faltam → slot → apagar os que saíram. No boot, os arquivos mais antigos
que o slot completam o histórico; um ilegível custa só aquela revisão (`storage.boot_errors`); um
mais novo que o slot (gravação interrompida) é ignorado e reescrito. Arquivos de versões
anteriores (histórico inteiro no slot) carregam e migram no primeiro commit. O limite de 32 MiB
vale para a soma dos arquivos de revisão.

| Backend | Onde | Uso |
|---|---|---|
| `MemoryStorage` | engine | GUI, wasm, testes, daemon em lab sem `--config-dir` |
| `FileStorage` | `storage-fs` (L4) | daemon: temp + fsync → rename current→prev → rename temp→current → fsync do diretório; `rev-<n>.json` (temp + fsync + rename) antes do slot |

### GUI como cliente do daemon (G0.4)

A GUI não segura a `Session`: fala com um `Backend` (trait de `crates/ui`) por requisição e
resposta, com os métodos do canal de controle (`engine.execute`, `state.inspect`, …).
`submit(method, params) -> RequestId` enfileira e volta na hora; `poll()` entrega as respostas
que chegaram, em qualquer ordem; `link()` diz conectando/conectado/desconectado (barra
superior). Contrato: todo id recebe exatamente uma resposta (erro se a conexão cair).

```
CoreRouterUi::run(id, params) ─► Backend::submit("engine.execute") ─► pending[id] = Action{then}
frame N+k: Backend::poll() ─► log + refresh + efeito (fecha diálogo, abre a interface criada…)
refresh (1 s, um por vez): state.inspect + 5 listas ─► cache; resposta mais velha que a já
aplicada no mesmo campo é descartada
```

| Backend | Onde | Transporte |
|---|---|---|
| `Local` | `crates/ui` | `Session` no processo; responde na hora (testes headless, `corerouter-gui` sem `--connect`, `?lab` na web) |
| `Remote` | `apps/corerouter-gui` (nativo) | `control::Client` numa thread de trabalho com canais std; reconecta a cada 2 s; requisição sem conexão falha na hora (nunca fica para "depois") |
| `WsBackend` | `apps/corerouter-gui` (wasm) | `web_sys::WebSocket`; eventos do navegador só enchem uma fila lida em `poll` |

O daemon serve o WebSocket com `control::ws` (thread por conexão, `tungstenite` síncrono) e
pode servir os arquivos da GUI web na mesma porta (`--web-root`, modelo WebFig); a lista de
`Origin` impede que uma página qualquer comande o roteador local. Detalhes em
`docs/control-protocol.md`.

### Autenticação e TLS (G0.3)

Quem decide **o que** cada um pode é o engine; quem decide **quem é** cada um é o canal de
controle. Cada conexão tem um `Caller`; a cada requisição o `control::auth::Gate` troca o
`token` pelo `Principal` (`Local` = processo ou token local, `User(nome)`, `Anonymous`) e o põe
no `Caller` antes de `Session::execute_as`. O engine olha o grupo **atual** da conta no `Users`
da sessão e compara com `auth::required_group` (consulta `read`, ação `write`, `user.*` `full`),
recusando com `EngineError::Denied` e marcando `enabled: false` no `engine.list` daquele
chamador (botões cinza da GUI, G1.16). A senha é verificada pelo `Gate` **fora** do lock da
sessão (Argon2 é lento de propósito); a sessão só entrega o hash e registra o login
(`user.active.list`). Contas ficam no mesmo arquivo da config, fora das revisões: rollback nunca
restaura senha. O token local (arquivo 0600 do usuário do sistema que roda o roteador) dá a CLI
e o MCP locais sem senha; TCP puro só aceita loopback, qualquer outro endereço é TLS
(`--listen`, `--ws-listen`) com login, e os clientes nativos fixam o certificado no primeiro uso
(`known_hosts`). Primeiro acesso (G0.3b, RouterOS 7): `Session::bootstrap_admin` (só na partida
do daemon, não é comando) cria `admin` sem senha (`password_hash: None`); o `Gate` aceita senha
vazia só de loopback e recusa todo login da rede enquanto houver conta `full` sem senha; a UI e o
`corerouter-shell` sabem disso por `auth.whoami` (`no_password`) e pedem a senha pelo
`user.set` normal. Detalhes em `docs/control-protocol.md`.

### Preferências da janela (G1.11)

Tema (Sistema/Claro/Escuro) e "Inline Comments" de cada tabela são estado da janela, não do
roteador: não passam pelo engine nem pelo journal. `CoreRouterUi::prefs()` devolve um JSON
pequeno que o app grava pela persistência do eframe (`App::save`, a cada 2 s e ao sair):
arquivo `app.ron` em `~/.local/share/corerouter-gui` (o `app_id` separa da pasta de config do
daemon) ou `localStorage` na web; `apply_prefs` o lê na criação e ignora o que não entende. A
memória do egui (posição das janelas) não é persistida.

### Descoberta de vizinhos (G5.1)

Protocolo próprio, o CRDP (`docs/discovery.md`); LLDP e MNDP passivo (G5.2) entram na mesma
tabela. Os vizinhos são **estado operacional**, como os contadores de link: ficam na `Session`
(`neighbors.rs`), nunca no `Config`, nunca no `running.json`. Só as configurações (`enabled`,
`interfaces`, `interval_secs`) são config, em `ip.neighbor_discovery`.

```
daemon: corerouter_discovery::Agent (3 threads std)
  tx (1 s): lock → expire_neighbors(now) + cópia da running → solta → anuncia nas interfaces ativas
  rx4/rx6: datagrama → proto_discovery::decode → interface de chegada → lock → record_neighbor
daemon --backend linux: link_discovery (1 thread std, G5.2)
  1 s: lock → expire + cópia da running → solta → hal_linux::l2::LldpIo abre/fecha portas,
       proto_lldp::encode → send (TTL 0 na porta que sai)
  200 ms: LldpIo::recv / MndpListener::recv → proto_lldp/proto_mndp::decode → lock → record_neighbor
ip.neighbor.list ◄── Session::neighbors() filtrada pelas interfaces ativas da running
```

`record_neighbor` não é comando: é dado da rede, não ação do operador (não passa pelo journal
nem gera revisão), e a sessão descarta o que chega por interface sem descoberta ativa. O relógio
é o de quem grava (`last_seen` em segundos Unix), então a tabela não depende do `Hal::now_unix`
e roda igual em wasm/testes. Índice de interface (para `ff02::1%if` e para saber por onde um
link-local chegou) vem de `/proc/net/if_inet6`, que é do network namespace de quem lê; o
`LinkInfo` do `Hal` ainda não tem índice.

A GUI nativa abre na tela de conexão (`ui::ConnectScreen`) quando não recebe `--connect`; a tela
só coleta a escolha, e o app (`apps/corerouter-gui`, trait `Platform`) fornece os vizinhos
(`Listener` no nativo, `ip.neighbor.list` do daemon na web), guarda a lista Saved e conecta. O
canal `--control` da GUI segue o alvo escolhido (`Target::Choosing` responde `server.info` e
`ui.screenshot`).

### `hal-linux`: aplicação no kernel (G1.2)

`LinuxHal::apply(from, to)` tem duas metades:

1. **Plano puro** (`crates/hal-linux/src/plan.rs`, compila em qualquer plataforma): o diff
   `from` → `to` vira uma lista ordenada de `Op` — remover endereços → soltar portas de bridge →
   apagar links (filhos VLAN antes do pai) → criar links (pai antes) → MTU (reduções dos filhos
   para o pai, aumentos do pai para os filhos) → prender portas → adicionar endereços → up/down.
   Mudou o tipo ou o VLAN id de um link virtual: apaga e recria, junto com as VLANs empilhadas
   nele (o kernel as apagaria de qualquer jeito). Porta física nunca é criada nem apagada.
2. **Executor** (`netlink.rs`, só Linux): roda cada `Op` com `rtnetlink` num runtime tokio
   *current-thread* criado dentro do `apply` (o trait `Hal` continua síncrono). Antes de cada
   mudança lê o link no kernel e guarda o desfazer; se o passo N falha, desfaz N-1..0 na ordem
   inversa e devolve `HalError::Rejected` dizendo o passo, o motivo e se o rollback foi completo.
   Mudança já em vigor (MTU igual, endereço presente) é no-op sem desfazer.

**Recursos do kernel (G1.14).** `Hal::features()` diz o que a plataforma suporta (hoje só
`vrf`), para um comando recusar de antemão com o motivo (`enabled`) em vez de falhar no
`apply`. O `LinuxHal` sonda uma vez, na primeira consulta, com um link descartável por recurso
(nome livre, apagado em seguida; links existentes nunca são tocados) e guarda o resultado num
`OnceLock`. Um kernel de terceiros sem `CONFIG_NET_VRF` deixa `ip.vrf.add` desabilitado; as
imagens do G1.6 vêm com `CONFIG_NET_VRF=y`.

### `hal-linux`: descoberta e posse dos links (G1.18)

**Uma fonte só.** `discover_links`, `poll` e o `apply` falam com o kernel do mesmo network
namespace: um dump `RTM_GETLINK` (`netlink::links`) dá nome, índice, `IFLA_INFO_KIND`, tipo
`ARPHRD_*`, master, `IFLA_LINK_NETNSID` (par em outro namespace), MTU, MAC, `IFF_UP`, operstate e
`stats64`. O sysfs saiu: `/sys/class/net` mostra o namespace de quem montou `/sys` (num
`unshare --net` sem remontar, o do host), e a descoberta via sysfs semeava as interfaces do host
num daemon que aplicava no namespace — `ip.address.add` falhava e o boot tentava mudar o MTU de
`br-…` do Docker.

**Posse** (`crates/hal-linux/src/owner.rs`, puro, testado em qualquer plataforma). Cada link é
`Managed`, `External(motivo)` ou `Conflict(motivo)`; primeira regra que casa:

1. nome que o modelo não aceita (`IfName`) → externo;
2. o loopback do kernel (`ARPHRD_LOOPBACK`, `lo`) → externo (é do SO);
3. nome em `--unmanaged` (nome ou `prefixo*`) → externo, até porta física;
4. porta de um master externo (a veth de container dentro do `docker0`) → externo;
5. nome que a config declara: gerenciado se o tipo do kernel serve (`vlan`/`bridge`/`dummy`/`vrf`
   para o que o CoreRouter cria; física, `veth` ou `dummy` para uma porta `ether`). Porta `ether`
   sobre outra coisa (config antiga que semeou o `docker0`) → externo; link virtual de outro tipo
   → conflito (listado como não gerenciado; o executor recusa com a mensagem dele e faz rollback);
6. porta física (sem `IFLA_INFO_KIND`, `ARPHRD_ETHER`) → gerenciada;
7. `veth` com o par no mesmo namespace (um cabo dentro deste roteador) → gerenciada; com o par em
   outro namespace (de container) → externa, salvo `--manage`;
8. `veth`/`dummy` em `--manage` → gerenciada;
9. o resto (`bridge`, `vlan`, `ppp`, `tun`, `wireguard`, … criados por outro programa) → externo.

Porta com MTU fora de 68..=9216 também é externa (o modelo não a representa sem mudar o kernel).

**Efeitos.** `discover_links` devolve só portas gerenciadas, com `up` (admin): o seed do engine
copia MTU, MAC e `disabled = !up`, então o primeiro `apply` (padrão → seed) não muda nada no
kernel (porta que estava down continua down; parte do G1.3). `poll` devolve todos os links com
`kind`, `mtu`, `mac` e `unmanaged: Option<motivo>`; `interface.list` mostra as interfaces da
config (com `kind` do kernel, `managed`, `unmanaged_reason`) e depois os links fora da config,
sempre `managed: false`. `Hal::unmanaged()` (padrão vazio; o lab virtual não tem) alimenta
`refuse_unmanaged` nos comandos que mudam interfaces (`interface.set`, `*.add` com o nome,
`vlan.add` no pai, `bridge.port.*`, `ip.address.add`, `ip.vrf.add/set`): "'docker0' is not managed
by CoreRouter: a bridge created outside CoreRouter". `interface.remove` aceita apagar uma porta
`ether` da config cujo link é externo (limpeza de seed antigo). No `apply`, ops sobre links
externos são descartadas com aviso no log, antes do executor: nem MTU, nem up/down, nem
endereço chegam a eles. A GUI deixa as ações cinza com o mesmo motivo e a linha esmaecida.

`corerouter-daemon --manage <nomes>` / `--unmanaged <nomes>` ajustam a regra (labs com veth entre
namespaces usam `--manage ether*`, como `tests/netns_l2.rs`). Na imagem de produção (G1.6) as
portas físicas são gerenciadas pela regra 6, sem flag.

### Firewall (G2.1)

`ip.firewall` (filter, nat, mangle, address-lists) e `interface_lists` são config; entradas de
address-list com timeout são estado operacional na `Session` (`firewall_dyn.rs`), como os
vizinhos. O commit valida com `corerouter_firewall::validate`; o `LinuxHal::apply` troca a
tabela `inet corerouter` inteira por `nft -f -` (atômico no kernel) **antes** do plano netlink, e
recarrega o ruleset anterior se o plano falhar; sem mudança no firewall o `nft` não roda. Detalhes,
mapeamento RouterOS → nftables e o porquê do `nft` em `docs/firewall.md`.

G2.1b: o `Caller` carrega o `Link` da conexão TCP (cliente e endereço local, preenchido pelo
`control::server::accept_loop`). `Session::commit_candidate` chama `engine::lockout`, que passa os
pacotes dessa conexão pelo firewall atual e pelo candidato com `corerouter_firewall::eval` e
recusa (`EngineError::Lockout`, texto `lockout: …`) o que os cortaria, salvo `force: true` no
comando (`Session::lockout_ack`, vale até o fim do comando ou do batch) ou Safe Mode; o desfazer do
Safe Mode usa `commit_restoring`, sem a checagem. O crate `firewall` ganhou `eval` (destino de um
pacote), `shadow` (regras sombreadas) e `describe` (frase em português), todos puros. Defaults,
modelos e zonas são comandos do engine (`cmd/firewall_assist.rs`, `cmd/firewall_zone.rs`) que
escrevem regras comuns pelo mesmo `add` dos comandos de regra; a GUI só junta parâmetros
(`ui::firewall_assist`) e segura a recusa de lockout para o operador decidir (`ui::lockout`).

### Rotas estáticas e VRF (G1.5)

- **Modelo:** `ip.routes` (`RouteEntry`: `dst_address`, `gateway`, `distance`, `routing_table`,
  `disabled`, `comment`; ids `*N` próprios, `ip.next_route_id`). Rotas conectadas não são
  guardadas: derivam de `ip.addresses`. Um VRF é uma interface `InterfaceKind::Vrf { table }`
  (o device `vrf` do Linux; nome = nome da tabela) e cada membro guarda `Interface.vrf`, que é
  o `IFLA_MASTER` dele — por isso porta de bridge e membro de VRF se excluem.
- **Uma regra só para "a rota vale agora":** `model::route::reach(cfg, rota)` resolve o gateway
  dentro da tabela da rota e devolve `Active { link, gateway }`, `Inactive(motivo)` (rota,
  interface, VRF ou endereço desabilitado) ou `Invalid { campo, motivo }` (gateway fora de toda
  rede conectada, famílias trocadas, tabela/interface inexistente, endereço do próprio
  roteador, link-local sem interface). O engine usa para validar (`validate::route_issues`,
  também chamado pelos comandos) e para as flags de `ip.route.list` (X A D C S, ordem do
  RouterOS v6; ativa = usável e de menor distância no par tabela+destino); o `hal-linux` usa
  para decidir o que fica no kernel. Assim nunca divergem.
- **Kernel:** distance vira a métrica (o kernel também prefere a menor), protocolo `static`;
  rota sem gateway em IPv4 tem escopo `link`. O plano ganhou o passo 0 (remover rotas) e o 9
  (adicionar rotas). O kernel apaga sozinho rotas de link que desce, é recriado, entra/sai de
  VRF ou perde o último IPv4, e apaga os IPv6 de link que desce ou entra em VRF
  (`keep_addr_on_down=0`): o plano remove essas rotas/endereços explicitamente antes e os
  recoloca depois, para que o desfazer de uma falha devolva tudo. Rota existente no kernel só é
  adotada se for idêntica (static, mesma tabela/métrica/next hop); outra rota no mesmo destino e
  métrica faz o apply falhar e desfazer.

Proteções do host: só interfaces do config entram no plano; o `lo` do kernel não é descoberto;
link existente só é adotado se tiver o mesmo tipo (e VLAN id/pai) do config, e nunca se apaga
um link cujo tipo no kernel difere do config. Testes de integração (`tests/netns.rs`) rodam
num network namespace descartável sem root: `cargo xtask netns` (passo do `cargo xtask ci`,
que vira `skip` onde `unshare` sem root não é permitido).

### Tarefas das ferramentas (G6.1–G6.3)

Ping, MTU e (G6.3) MTR levam segundos ou não terminam: o comando valida, inicia um **job** e
devolve o id; o resultado chega por `tool.task.poll`. Estado operacional, como os vizinhos:
fora do `Config`, do journal e do disco.

```
tool.ping.start ─► Session::start_task(kind, título, job)        (sob o lock, rápido)
                     Hal::prober() ─► Arc<dyn Prober>            (L1: hal-linux::icmp | hal::sim)
                     Runner::spawn(job)                          (thread std do app; engine não tem)
job (fora do lock): Prober::open ─► ProbeSocket::send/recv ─► TaskCtx::emit / summary ─► TaskCell
tool.task.poll ─► TaskCell (mutex próprio): eventos > after_seq, resumo, estado
Session::tick (1 s): tarefa sem poll há 60 s ─► stop; terminada há 300 s ─► some
```

O engine não tem relógio nem threads (wasm32): o `Runner` dá a thread e o `Clock` (tempo
monotônico e `sleep`) do job; o RTT é medido pelo socket. Os jobs (`engine/src/tools/`) são
lógica pura sobre `ProbeSocket` + `TaskCtx` e são testados com a rede simulada e um relógio
falso (sem esperar de verdade). Detalhes, limites e a rede simulada: `docs/tools.md`.

### DNS (G4.1)

**Decisão do usuário (2026-10-22):** o DNS inteiro é **Hickory DNS, em Rust puro**, embutido no
daemon. São três partes sobre a mesma config (`/ip dns`) e o mesmo cache:

- **G4.1a**, resolvedor do próprio roteador: mensagens com `hickory-proto`, sem runtime async.
- **G4.1b**, encaminhador com cache para a LAN (`allow_remote_requests`, `/ip dns static`),
  em partes: base (cadeia de etapas, ACL, limite, estáticos, serve-stale), depois Statistics
  (G4.1e), Adlist/Forwarders/DoT-DoH (G4.1d) e Zones (G4.1c), cada uma como etapas novas.
- **G4.1c**, servidor completo estilo BIND (zonas autoritativas, DNSSEC) com `hickory-server`.

Por que não orquestrar Unbound, Knot ou PowerDNS, como o FRR no roteamento: um processo só
elimina um ponto de falha e uma config paralela. Estáticos, servidores do DHCP e o cache viram
comandos, entram em transações e no Safe Mode e aparecem no MCP. Os erros chegam estruturados,
sem parsear saída. **Risco aceito:** o Hickory é menos testado em escala de ISP que
Unbound/Knot/PowerDNS. Ele será medido com benchmarks (consultas/s, latência com cache quente e
frio, memória por entrada) na G4.1c, e a decisão pode ser revista com esses números.

```
ping/MTR/MTU ─► Session::tool_prober ─► RouterResolver::resolve ─┐
cliente NTP ─► service::dns::resolve ────────────────────────────┤ (sem lock do Session)
                                                                 ▼
               proto-dns::Resolver: cache (lock curto) ─► fetch: servidores um a um
                                                                 │ Transport
               service/dns.rs: UDP (+TCP no TC) ◄────────────────┘
thread "dns" (1 s): Session::dns_settings (running ip.dns + DHCP use_peer_dns) ─► configure
```

O `proto-dns` não abre socket: compila em wasm e é testado com um transporte falso e um relógio
falso. Sem daemon registrado, as ferramentas usam o resolvedor do prober (o simulado, no lab).

**Encaminhador da LAN (G4.1b): Hickory para o protocolo, nossa camada de regras na frente.** O
`hickory-server` 0.26 tem forwarder com cache, DNSSEC, DoT/DoH/DoQ e ACL, mas exige tokio, não
tem limite por cliente, não lista nem limpa o cache e não fala as estatísticas no formato do
RouterOS (e o README ainda diz "not recommended in production"). Por isso o encaminhador usa só o
`hickory-proto` (mensagens) e passa cada consulta por uma **cadeia de etapas**
(`proto-dns/src/server/stage/*.rs`, achadas pelo `build.rs`, ordenadas pelo `order` de cada uma):
`acl → limit → special → adlist → static → zones → cache → upstream`. Sem runtime async: no
daemon (`service/dns_server.rs`) uma thread por socket responde o que a cadeia resolve sem rede
(cache, estáticos) na hora, e cada falta de cache ganha uma thread, no máximo
`max_concurrent_queries`. Medido: 0,8 µs por consulta respondida do cache (bytes a bytes), ~1,2 M
consultas/s por núcleo sem contar o socket.

**Zonas autoritativas (G4.1c-1): a busca é nossa, numa etapa da cadeia.** O plano era servir as
zonas pelo `hickory-server`. A versão 0.26.3 não tem IXFR, NOTIFY (enviado ou recebido), zona
secundária nem ACL de IP para AXFR, e a busca dela é async (tokio), fora da cadeia síncrona que
compila em wasm. Então a etapa `zones` (`proto-dns/src/zone/`) faz a busca da RFC 1034 §4.3.2 sobre
registros do `hickory-proto`. Transferências e NOTIFY são atendidos antes da cadeia, e o serviço
`dns zones` do daemon faz o NOTIFY enviado e as secundárias. Medido: 1,04 µs por resposta de zona
(como um acerto de cache), nada para quem não tem zonas. Na assinatura DNSSEC (G4.1c-2) o
`hickory-server` também ficou de fora: o `InMemoryZoneHandler::secure_zone_mut` dele assina o NS
de delegação e a glue (a RFC 4035 §2.2 proíbe), marca RRSIG no bitmap de delegações sem DS e não
tem rotação de chaves. A criptografia é a do `hickory-proto` (ring, feature `dnssec` do proto-dns,
ligada só pelo daemon: engine, GUI e wasm não ligam o ring); a cadeia NSEC3, as provas e as
rotações são nossas. As chaves ficam fora da config versionada (estado operacional
`dnssec-keys`), para um rollback nunca tirar uma chave cujo DS está no pai. Medido: 24 ms para
assinar 1000 registros, 1,56 µs por resposta assinada. Detalhes em `docs/dns.md`, "G4.1c —
Zonas".

```
UDP/TCP 53 ─► Forwarder::start (thread do socket) ─► acl, limit, special, adlist, static, zones, cache
                                                          │ falta de cache: Step::Wait
                                                          ▼
                     thread por consulta (≤ max_concurrent_queries) ─► upstream: Resolver::resolve
                                                          │ (o mesmo cache do roteador)
efeitos (address-list) ─► thread "dns-effects" ─► Session::dns_address_list
```

**Adlist e HTTPS do daemon (G4.1d).** As listas de bloqueio ficam fora da config e fora do lock
do `Session`: o serviço `service/dns_adlist.rs` baixa, lê e ordena cada lista numa thread própria
e troca o conjunto da etapa `adlist` de uma vez (`proto-dns::adlist::Adlists`). O conjunto é uma
arena de texto ordenada com deslocamentos (busca binária por rótulo), não um `HashSet<String>`:
**medido** 31,8 MB para 1 M nomes (~32 B/nome, contra ~70 B estimados no `HashSet`), 230 ms para
ler e montar, 80–110 ns por consulta. O download usa um cliente HTTP/1.1 nosso
(`service/https.rs`, rustls + raízes Mozilla do `webpki-roots`) e não o `ureq`/`reqwest`: o
roteador não tem resolvedor do sistema nem loja de CAs, então o nome do servidor passa pelo
resolvedor do roteador, e todos os limites (cabeçalho, corpo, redirecionamentos) são nossos. O
mesmo cliente serve o DoH da G4.1d-2.

**DoT/DoH upstream (G4.1d-2): rustls e o nosso HTTP/1.1, sem tokio.** O `hickory-proto` tem
clientes DoT/DoH, mas só sobre tokio; o daemon é por threads. O `proto-dns` monta a consulta (id 0,
padding de 128 bytes) e o resolvedor escolhe o servidor; o daemon (`service/dns_secure.rs`) fala
TLS (RFC 7858) ou `POST application/dns-message` (RFC 8484) e guarda até 4 conexões ociosas por
servidor por 20 s. HTTP/1.1 em vez de HTTP/2 (que a RFC 8484 §5.2 recomenda): com a conexão
reaproveitada a diferença some. **Medido** (2026-10-22, release, cache vazio, 15 nomes populares
pelo 1.1.1.1 a ~48 ms de RTT): UDP 48–51 ms, DoT 47–49 ms, DoH 49–53 ms por consulta. Revisar se um
servidor exigir HTTP/2 ou se o pipelining (várias consultas na mesma conexão) fizer falta.

Detalhes, regras de RFC e pesquisa: `docs/dns.md`.

### Supervisor de serviços do daemon (G0.10)

Os serviços do daemon (`apps/corerouter-daemon/src/service/<nome>.rs`: `dns-resolver`,
`dns-server`, `ntp-client`, `remote-logging`, `metrics`) rodam sob um supervisor
(`service/supervisor.rs`), para que uma thread que morre ou um bind que falha não vire queda
silenciosa.

- **Interface.** `Service { name, flags, topic, enable, depends, start }`. O `start(&Ctx)` roda
  uma vez no boot, lê as flags (erro = o daemon não sobe, como antes) e devolve o corpo
  `Run = Fn(&Health) -> Result<(), String>`, que o supervisor roda numa thread própria e de novo
  a cada falha. O laço do corpo usa `while health.sleep(TICK) { health.beat(); … }` e informa
  `listen`, `event`/`error` e `disabled(motivo)`; `health.spawn` conta as threads auxiliares e
  contém o panic delas. O guia completo está no topo de `service/mod.rs`.
- **Política.** Reinicia sempre (systemd `Restart=always`, Erlang `permanent`): o corpo que
  termina sem ser pedido, devolve `Err` ou dá panic (`catch_unwind`; o perfil de release é
  `panic = "unwind"`) volta depois de 1 s, 2 s, 4 s… até 60 s (systemd 254 `RestartSteps` /
  `RestartMaxDelaySec`); uma execução de 60 s zera a espera. Com 5 falhas em 60 s desiste e fica
  `failed` (`StartLimitBurst`/`StartLimitIntervalSec`, intensidade/período do OTP), com linha
  `critical` no log do roteador (o syslog remoto a encaminha). `start` e `reset-failures`
  tentam de novo.
- **Estados.** `disabled` (roda ocioso porque a config o desliga, com o motivo), `starting`
  (sem heartbeat ainda, ou esperando uma dependência), `running`, `restarting` (com os segundos
  que faltam), `stopped` (pelo admin, até o próximo boot; a config não muda) e `failed`.
- **Engine.** O engine não tem threads e não depende do daemon: o supervisor publica as linhas
  em `ServiceTable` (`s.ext_mut`, `corerouter_model::service`) a cada 200 ms e retira os pedidos
  que `system.service.start|stop|restart|reset-failures` enfileiram (no máximo 64). Um lock
  curto por volta e nenhum outro lock enquanto isso. Sem daemon (lab, WASM) a tabela fica vazia
  e as ações explicam por quê.
- **`control`.** A linha do canal de controle é `protected`: `stop` e `restart` são recusados
  com o motivo (cortariam a própria sessão de gestão).
- **Uma thread não se mata.** `stop` pede (`Health::stopping`) e o corpo devolve; um heartbeat
  com mais de 30 s aparece como motivo ("no heartbeat for N s"), sem reinício forçado.
- **Métricas.** `system.metrics` traz `services`, e o exportador gera `corerouter_service_up` e
  `corerouter_service_restarts_total` por `name`.

### Servidor DHCP (G4.2)

**Decisão do usuário (2026-10-22):** servidor DHCP em **Rust puro** sobre o `dhcproto`, dentro do
daemon, em vez de orquestrar o Kea ou o dnsmasq.

| | Rust puro (G4.2a) | Kea (OPNsense/VyOS) | dnsmasq (OpenWrt) |
|---|---|---|---|
| Processo | nenhum a mais | `kea-dhcp4` + `kea-lfc` + `kea-dhcp-ddns` | um |
| Config | comandos, transações, Safe Mode, MCP | JSON próprio, recarga por API de controle | arquivo, recarga por sinal |
| Concessões no motor | direto (`ip.dhcp-server.lease.print`, make-static, release) | API de controle ou leitura do CSV | arquivo de leases |
| DHCP → DNS e firewall | chamada direta (`dns_dynamic_lease`, address-list dinâmica) | D2 + RFC 2136 com TSIG | hosts locais, sem PTR remoto |
| Vazão do núcleo | **medido**: 171–214 k leases/s (§9 de `docs/dhcp.md`) | milhares de leases/s com memfile (**estimado**; o ISC publica números com `perfdhcp`) | **estimado**: alguns k/s |
| Maturidade, interoperabilidade | nova; testada contra o nosso cliente, o lab e a RFC | muito alta | alta |

Por que Rust puro ganhou: um processo e um ponto de falha a menos; concessões dentro das
transações, do Safe Mode e do MCP; integração direta com o DNS e o firewall sem protocolo no meio;
números de vazão acima do que um roteador de borda precisa. O gargalo do servidor no daemon é o
disco: uma `fdatasync` por rodada, com todas as concessões da rodada (group commit).
**Risco aceito:** clientes estranhos (CPEs, ONUs, IoT) que o Kea já viu e nós não. Mitigação:
leitor de pedidos tolerante e testado com proptest, comportamento do RouterOS como referência, e
a decisão pode ser revista com números de campo.

Camadas: o servidor é L2 puro (`proto-dhcp/src/server/`, compila em wasm: o lab do navegador
também o roda), o engine guarda o estado e aplica os efeitos, o daemon só o dirige
(`service/dhcp_server.rs`) e o `hal-linux` só carrega bytes (`dhcp_server.rs`).

### Tuning do sistema (G1.26)

**Decisão: Rust puro, sem `tuned`, `irqbalance`, `ethtool` nem `sysctl.conf`.**

**Comparado:**

- **Números.** Aplicar um perfil grava ~40 arquivos de `/proc/sys`: < 1 ms em Rust (**estimado**),
  contra ~200 ms para subir o `tuned-adm`, um processo Python (**estimado**). Não é o gargalo de
  ninguém. O que pesa é o resto.
- **O que pesa:**
  - Os perfis do `tuned` são para servidor: buffers TCP, busy_poll, THP. Os de roteador precisam
    de outros valores.
  - O `irqbalance` move as IRQs a cada 10 s e sobrescreve a afinidade manual (`scaling.rst`), o
    contrário do que um roteador quer.
  - Nenhum dos dois tem transação nem rollback, nem diz por que escolheu um valor.
  - Os dois são processos externos e superfície a mais na imagem.

**Como fica:**

- Os valores vivem na config (`system.tuning`) e passam pelo mesmo caminho de tudo: comando, diff,
  Safe Mode, journal, rollback.
- O `hal-linux` (`tuning.rs`) grava tudo ou nada, com o valor original guardado na primeira mudança
  (tirar da config o restaura).
- O engine (`tuning.rs`) calcula perfis, faixas e diagnóstico, puro e testado sem kernel.
- Medida de pps em netns: `docs/tuning.md`.

## Histórico de revisão

- 2026-10-21 — versão inicial (esqueleto v0.1.0).
- 2026-10-21 — G0.6: crate `storage-fs` (L4) e seção de persistência.
- 2026-10-21 — `hal-linux` aplica via rtnetlink (G1.2): plano puro + executor com rollback.
- 2026-10-21 — G0.4: trait `Backend` da UI, GUI remota (nativo e WebSocket), `control::ws`.
- 2026-10-21 — G1.11: preferências da janela (tema, comentários inline) fora do engine.
- 2026-10-21 — G5.2: crates `proto-lldp`/`proto-mndp` (L2) e módulo `l2` do `hal-linux`.
- 2026-10-21 — G1.5: rotas estáticas e VRF (`model::route`, passos 0 e 9 do plano).
- 2026-10-22 — G1.14: `Hal::features` e a sonda de recursos do `hal-linux`.
- 2026-10-22 — G1.4: seção Safe Mode (`Caller` por conexão, `hang_up`, relógio por `tick`).
- 2026-10-22 — G5.1: crates `proto-discovery` (L2) e `discovery` (L4), tabela de vizinhos no engine, tela de conexão.
- 2026-10-22 — G5.2 Parte 2: LLDP/MNDP no daemon (`link_discovery.rs`), cola L1+L2 na app.
- 2026-10-22 — G1.18: descoberta/contadores do `hal-linux` via rtnetlink e política de posse dos links.
- 2026-10-22 — G0.8: crate `shell` (L4) e o terminal no fluxo de um comando.
- 2026-10-22 — G0.3: `model::users`, `engine::auth`, `control::{auth,tls,local_token,known_hosts,dial}`, seção de autenticação.
- 2026-10-22 — G6.1/G6.2: tarefas das ferramentas (`tasks`, `tools/`, `Hal::prober`, `hal::sim`, `hal-linux::icmp`, `ThreadRunner`).
- 2026-10-22 — G2.1a: crate `firewall` (L1 puro), seção Firewall, `Hal::address_list_dynamic`.
- 2026-10-22 — G6.3: MTR nas tarefas das ferramentas.
- 2026-10-22 — G0.3b: primeiro acesso sem senha (bootstrap no engine, regra de rede no `Gate`, `ui::first_login`).
- 2026-10-22 — G1.19: `hal::nic` e os métodos `ethernet_monitor`/`hardware`/`counters` do `Hal`, genetlink do `hal-linux`, `engine::link_watch`.
- 2026-10-22 — G4.7a: cliente DHCPv4 (`proto-dhcp` codec/cliente/lab, `Hal::dhcp_port`, `hal-linux::dhcp`, `engine::dhcp_client`, relógio de serviço no `control`).
- 2026-10-22 — G1.20: `hal::sff`, `Hal::sfp_module`/`cable_tester`, `hal-linux::ether`, `engine::dom_watch`, `Interface::ethernet` no model.
- 2026-10-22 — G2.1b: `Caller::link`, `engine::lockout`, `firewall::{eval,shadow,describe}`, `ui::{firewall_assist,lockout}`.
