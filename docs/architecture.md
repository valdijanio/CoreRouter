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
| DNS cache/forwarder, registros estáticos | `hickory-server` + `hickory-resolver` | Embutido no daemon; DoT/DoH upstream via `rustls` |
| DHCPv4/DHCPv6 (+PD) e relay | codec `dhcproto` + servidor e banco de leases próprios | Leases em `/config`, escrita atômica |
| PPPoE / IPoE (BNG) | orquestrar `accel-ppp` | Não há BNG Rust maduro; mesmo padrão do FRR |
| NTP | `ntpd-rs` | Rust, memória segura |
| Gerência remota | `rustls` (TLS do canal de controle), `russh` (CLI SSH) | G0.3 |
| Telemetria | `prometheus-client`, export IPFIX/sFlow | G4.4 |

## 2. Camadas do workspace

Regra central: dependência só para baixo; nada abaixo de L5 depende de egui/eframe/winit/wgpu.
Imposta por `cargo xtask layers` (`xtask/src/layers.rs`, com testes).

| Camada | Crate | Responsabilidade | Pode depender de |
|---|---|---|---|
| L0 | `crates/model` | Tipos (Asn, VlanId, IfName, MacAddr, ItemId, prefixos `ipnet`), árvore `Config`, `ConfigStore` (candidate/running, commit, rollback, diff, histórico) | serde, ipnet, thiserror |
| L1 | `crates/hal` | Trait `Hal` (discover, apply transacional, poll, relógio) + `VirtualHal` (lab, wasm, CI) | L0 |
| L1 | `crates/hal-linux` | Backend Linux: `apply` via rtnetlink (links, VLAN, bridge, dummy, endereços; G1.2), descoberta/contadores via sysfs; nftables em G2.1. **Plataforma** | L0, `hal` (lateral permitido) |
| L2 | `crates/proto-{bgp,ospf,mpls,cgnat,dns,dhcp}` | `validate(&Config) -> Vec<Issue>` + render para o backend (FRR, nftables…) | L0, L1 |
| L3 | `crates/engine` | `Session::execute`, `CommandSpec`/`cmd!`, checagem de params, guard de panic, commit/rollback, batch, journal | L0–L2 (nunca plataforma) |
| L4 | `crates/control` | Canal JSON-por-linha em loopback, WebSocket com lista de `Origin` (+ arquivos da GUI web), `dispatch`, `Host`, `Client` | L0–L3 |
| L4 | `crates/storage-fs` | `ConfigStorage` em diretório (`/config`): `running.json` + `.prev`, escrita atômica | L0–L3 |
| L4 | `crates/mcp` | Servidor MCP stdio; backends `Headless`/`Remote` | L0–L3, `control` (lateral permitido) |
| L5 | `crates/ui` | Painéis WinBox em egui puro (sem eframe); trait `Backend` assíncrono + `Local` | L0–L4 + egui |
| L6 | `apps/corerouter-{daemon,gui,cli}` | Binários; únicos que escolhem backend de plataforma e janela | tudo |
| L7 | `xtask` | `cargo xtask ci`, `layers`, `wasm`, `agents-sync` | nenhum crate do workspace |

```
CoreRouter/
├── Cargo.toml            # workspace, lints sem panic, [workspace.dependencies]
├── clippy.toml           # unwrap/expect/panic/indexing liberados só em testes
├── rust-toolchain.toml   # stable + rustfmt, clippy, wasm32-unknown-unknown
├── .cargo/config.toml    # alias: cargo xtask
├── AGENTS.md = CLAUDE.md
├── ROADMAP.md
├── docs/{architecture,gaps,mcp,control-protocol}.md
├── crates/
│   ├── model/            # L0
│   ├── hal/              # L1 (traits + virtual)
│   ├── hal-linux/        # L1 plataforma
│   ├── proto-bgp/ proto-ospf/ proto-mpls/ proto-cgnat/ proto-dns/ proto-dhcp/   # L2
│   ├── engine/           # L3: src/cmd/{mod,args,interface,ip,routing,system,config}.rs
│   ├── control/          # L4
│   ├── mcp/              # L4
│   ├── storage-fs/       # L4: persistência da config em arquivo
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
CLI ────────────────────┤
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

| Backend | Onde | Uso |
|---|---|---|
| `MemoryStorage` | engine | GUI, wasm, testes, daemon em lab sem `--config-dir` |
| `FileStorage` | `storage-fs` (L4) | daemon: temp + fsync → rename current→prev → rename temp→current → fsync do diretório |

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
`docs/control-protocol.md`. Autenticação/TLS continuam no G0.3: tudo só em loopback.

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

Proteções do host: só interfaces do config entram no plano; o `lo` do kernel não é descoberto;
link existente só é adotado se tiver o mesmo tipo (e VLAN id/pai) do config, e nunca se apaga
um link cujo tipo no kernel difere do config. Testes de integração (`tests/netns.rs`) rodam
num network namespace descartável sem root: `cargo xtask netns` (passo do `cargo xtask ci`,
que vira `skip` onde `unshare` sem root não é permitido).

## Histórico de revisão

- 2026-10-21 — versão inicial (esqueleto v0.1.0).
- 2026-10-21 — G0.6: crate `storage-fs` (L4) e seção de persistência.
- 2026-10-21 — `hal-linux` aplica via rtnetlink (G1.2): plano puro + executor com rollback.
- 2026-10-21 — G0.4: trait `Backend` da UI, GUI remota (nativo e WebSocket), `control::ws`.
- 2026-10-22 — G1.4: seção Safe Mode (`Caller` por conexão, `hang_up`, relógio por `tick`).
