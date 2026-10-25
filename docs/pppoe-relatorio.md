# Relatório do PPPoE do CoreRouter (BNG em Rust puro, G4.3)

Para quem opera provedor: o que o BNG do CoreRouter já faz, como foi testado em cada camada, os
números **medidos** e onde ele está comparado ao MikroTik RouterOS v7, ao accel-ppp/VyOS e aos
BNGs de operadora (Juniper MX, Cisco ASR 9000, Nokia 7750 SR).

Máquina de todos os números, salvo quando dito: AMD Ryzen AI Max+ 395, 32 CPUs, Linux 7.0.0-38,
build release, outubro de 2026. O laboratório usa veth em namespaces: mede o plano de controle e
a correção, não a vazão de uma placa (a medição em placa real é a G4.3cb).

## 1. Resumo

- **Plano de controle:**
  - em memória: 303 mil sessões novas por segundo com 8 workers (58 mil/s com 1);
  - contra o BNG Blaster pela rede, antes das correções da G4.3g e numa thread: 9,2–9,8 mil/s
    até 10 mil sessões e 3,2–3,7 mil/s com 100 mil;
  - a rodada com as correções e os workers está pendente (§3.7).
- **Escala testada:**
  - 100 mil sessões PPPoE contra o BNG Blaster, com keepalive e tráfego de verificação, queda
    total e reconexão em massa;
  - 100 mil sessões nos mapas do XDP a ~125 ns por pacote na descida e ~138 ns na subida.
- **Policer por assinante no XDP:** erro de 0 a 1% em 100 assinantes a 2× a taxa contratada.
- **RADIUS completo:** autenticação, accounting, CoA e Disconnect (RFC 5176) testados sob
  carga. `new_session_rate=auto` segura a onda de reconexão pela saúde do RADIUS.
- **Interoperabilidade:**
  - o cliente Linux `pppd` 2.4.9 com o plugin `pppoe.so` (rp-pppoe) e o cliente do BNG Blaster
    sobem, fazem keepalive, tráfego e encerramento dos dois lados;
  - as conversas reais viraram testes dourados.
- **Falta para "BNG de operadora":**
  - alta disponibilidade entre dois BNGs (G4.3h);
  - L2TP LAC/LNS (G4.3i);
  - shaping com fila (EDT) e entrega do kernel ao assinante com XDP (G4.3ca);
  - medição em placa real (G4.3cb).

## 2. O que o BNG faz hoje

| Área | O que tem | Onde |
|---|---|---|
| PPPoE (RFC 2516) | PADI/PADO/PADR/PADS/PADT com todas as tags, AC-Cookie HMAC-SHA-256 (sem estado por PADI), Host-Uniq, Relay-Session-Id, PPP-Max-Payload (RFC 4638), Agent-Circuit-Id/Remote-Id (TR-101, RFC 4679), VLAN e QinQ na descoberta | `crates/proto-pppoe` |
| PPP | Autômato da RFC 1661 §4 célula por célula, LCP com todas as opções, keepalive, PAP, CHAP-MD5, MS-CHAPv1/v2 com chaves MPPE, IPCP com DNS (RFC 1877), IPv6CP com identificador estável e opaco (RFC 8064) | `proto-pppoe` |
| IPv6 por assinante (G4.3e) | RA por sessão com /64 do pool, DHCPv6-PD (/56 delegado), RDNSS; contabilização com Framed-IPv6-Prefix e Delegated-IPv6-Prefix | `pppoe_bng6.rs` (PR #219) |
| AAA | `/ppp secret` local (caller-id, service, only-one, limit-bytes) ou RADIUS (Framed-IP, Framed-Pool, Mikrotik-Rate-Limit, Mikrotik-Group, Session-Timeout, Acct-Interim-Interval, Reply-Message); Accounting Start/Interim/Stop com Acct-Terminate-Cause | `pppoe_bng.rs`, `proto-radius`, `radius_aaa.rs` |
| CoA/Disconnect (RFC 5176) | Rate-limit ao vivo, address-list (aviso de inadimplência), Disconnect, Framed-IP = reconectar; NAK 401/407 | `pppoe_bng.rs` |
| Plano de dados | XDP sem netdev por sessão: decapsula e encapsula no XDP, anti-spoofing, policer com o burst do RouterOS, contadores; sem XDP, um caminho lento em userspace | G4.3c, `dataplane-ebpf` |
| Proteções | `padi_limit`, `mac_padi_limit`, `new_session_rate` (fixo ou `auto`), `pado_delay` e `pado_delay_by_load`, `max_sessions`, one-session-per-host | `interface.pppoe-server` |
| Escala | Vários núcleos (`workers=auto|N`), SESSION_ID por faixa de worker sem lock, índices O(1) para secret, endereço, login e id de sessão | G4.3g |
| Operação | Janela PPP no estilo do WinBox (servidores, secrets, perfis, ativos, histórico), **Why?** (onde cada login para e por quê), histórico de quedas com motivo, "Quem era?" do CGNAT pelo login, gráfico por assinante, derrubar N sessões, coluna New Sessions com o motivo do limite | `crates/ui/src/ppp.rs` |
| Tudo é comando | `ppp.*` e `interface.pppoe-server.*` pela CLI, pela GUI e pelo MCP, com transação, rollback e Safe Mode | engine |
| Diagnóstico | `system.health.check` › Socket buffers (o buffer de recepção que o `rmem_max` cortou), monitor com `dataplane`, `workers`, `admission_rate` e o motivo | G4.3g |

## 3. Testes, camada por camada

### 3.1 Unidade e as regras das RFCs

- **`proto-pppoe`:** cada regra das RFCs 2516, 1661, 1332, 1334, 1994, 2433, 2759, 5072, 4638
  e 4679 tem o teste que a cumpre (a tabela fica em `docs/pppoe.md` §4).
- **`proto-radius`:** os exemplos das RFCs são testes dourados (RFC 2865 §7 com as erratas
  1469 e 6486, RFC 5997 §6, RFC 2759 §9, RFC 3079 §3.5).
- **Tamanho:** ≈ 125 testes no `proto-pppoe`, 71 no `proto-radius`, 41 no
  `dataplane-ebpf-common` e ≈ 30 do BNG no daemon (contagem de `#[test]`, **medido**).

### 3.2 Entrada hostil: proptest e fuzz

- **Oráculos de fuzz do `proto-pppoe`:** cinco alvos (descoberta, sessão, servidor, cliente e
  conversa viva, em que cliente e servidor conversam com quadros editados em voo). Rodam
  curtos no CI com proptest e longos com libFuzzer.
- **Proptest:** no codec RADIUS e no plano de dados XDP (ida e volta com 0, 1 e 2 tags,
  spoofing, quadro cortado). O policer nunca passa do balde mais a taxa.

### 3.3 Simulação em memória (100 mil assinantes)

`crates/proto-pppoe/tests/sim.rs` roda o servidor contra 100 000 clientes numa rede hostil (0,5%
de perda, 0,2% de duplicação, 1% de reordenação) e chega às 100 000 sessões em Opened. Outras
simulações:

- inundação de 200 mil PADIs;
- 100 mil PADRs com cookie forjado;
- reboot em massa de CPEs;
- 10% de senha errada;
- queda de 60 s.

A simulação achou oito defeitos de interoperabilidade (Configure-Ack duplicado, Success de
CHAP perdido, PADR atrasado derrubando a sessão, entre outros), todos corrigidos antes da
primeira sessão real (`docs/pppoe.md` §5).

### 3.4 Benchmarks (release)

| O quê | Resultado (**medido**) |
|---|---|
| `proto-pppoe`: PADI → PADO com AC-Cookie | 175 ns (5,7 M/s num núcleo) |
| `proto-pppoe`: sessão completa, PADI → IPCP Opened, servidor + cliente | 6,3 µs (159 mil/s) |
| BNG do daemon (`benches/pppoe_bng.rs`), 1 worker | 58 mil sessões/s |
| BNG do daemon, 8 workers (vários núcleos, G4.3g) | 303 mil sessões/s |
| Custo por sessão com 0 → 50 mil já no ar | 12–16 µs, plano (era 19 → 181 µs antes do índice de secrets) |
| Memória por sessão no BNG | ≈ 5,0 KB (com IPv6) |
| RADIUS: login completo pelo serviço | 13,9 µs (72 mil/s um a um; 194 mil/s em lote de 1000) |
| `ppp.secret.add` em lote | 3,9 ms por 1000 (era 9,8); 100 mil em ≈ 1,5 s de commits |

### 3.5 Ponta a ponta em namespace, sem root

`apps/corerouter-daemon/tests/netns_pppoe.rs` e `netns_pppoe6.rs` sobem o daemon real numa veth,
com CPEs `proto-pppoe` do outro lado (build debug):

- 1, 100 e 10 000 sessões, com ping pelo caminho lento;
- `ppp.active.remove` e usuário RADIUS no servidor de teste;
- reconexão em massa de 10 mil com `new_session_rate=1000`;
- dual-stack: 10 000 sessões com /64 e /56 em 19,8 s.

### 3.6 XDP com root

`cargo xtask xdp-root` (o programa real carregado no kernel, num namespace):

- **Diferencial:** 6000 quadros pelo programa e pelo modelo do host dão a mesma ação e os
  mesmos bytes.
- **100 000 sessões nos mapas:** descida encapsulando em 124–127 ns e subida decapsulando em
  137–139 ns, plano de 1 a 100 mil sessões.
- **Policer:** erro de −0,00% (1 assinante a 1 Gbit/s), −0,02% (100 a 20 Mbit/s) e −1,53%
  (10 000 a 0,2 Mbit/s, onde um pacote vale 1,4%).
- **Encaminhamento em veth generic:** 913 kpps com decapsulação + FIB.

### 3.7 Laboratório em massa com o BNG Blaster

`cargo xtask bng-lab` (G4.3g) sobe o daemon release num namespace e o BNG Blaster 1.0.1
(rtbrick) noutro, com uma porta de acesso a cada 50 mil sessões. Sem root usa o caminho lento;
com `--root` liga o XDP e o `pppd`.

**Primeira rodada** (antes das correções da G4.3g, root com XDP, 1 thread):

| | 1 mil | 10 mil | 100 mil |
|---|---:|---:|---:|
| Setup (proteções desligadas) | 9210/s | 9838/s | 3243/s |
| CPU do daemon por sessão | 50 µs | 39 µs | 267 µs |
| Reconexão com new-session-rate 2000 | 0,10 s | 6,8 s | 57 s |
| Encerramento (PADT de todas) | 0,30 s | 1,30 s | 10,3 s |

O laboratório achou o que nenhum teste anterior pegava. Cada achado foi corrigido na própria
série G4.3g:

- **Login O(n):** o secret era procurado percorrendo a lista; o usuário N custava N
  comparações.
- **Varreduras de todas as sessões:** no PADI (`new_session_rate`), no only-one, por pacote
  na descida do caminho lento e por id em `ppp.active.remove`.
- **Uma thread só:** o plano de controle rodava num núcleo (98%, os outros parados).
- **"Why?" esquecia tudo:** a tabela se apagava inteira a cada 50 mil logins.
- **`ppp.active.list` caro:** copiava e ordenava as 100 mil sessões a cada atualização da GUI,
  com o lock do engine.
- **Monitor errado:** o `dataplane` dizia "caminho lento" com o XDP ligado.

A rodada sem root (caminho lento, sem policer) deu o mesmo perfil:

- setup de 9536/s com 1 mil, 8952/s com 10 mil e 3731/s com 100 mil;
- 100 mil reconectando em 51,5 s com as proteções padrão;
- RADIUS a 940 sessões/s;
- CoA e Disconnect com as 10 respostas certas;
- sem policer fora do XDP, o tráfego oferecido (2×) passa inteiro, como esperado.

**O que mudou depois da primeira rodada** (todos medidos em memória; §3.4):

- Login: o custo por sessão com 50 mil no ar caiu de 181 µs para 15 µs.
- Vários núcleos: 303 mil sessões/s com 8 workers.
- "Why?" sem apagar tudo; `ppp.active.list` e `ppp.active.remove` sem varrer nem copiar a
  tabela.
- `new_session_rate=auto`.

**Rodada final: pendente.** A rodada com as correções, a etapa `workers` (100 mil com 1 worker
e com `auto`, CPU por thread) e a etapa `wave` (100 mil contra um RADIUS que responde 3000/s,
com o limite desligado, fixo em 2000 e `auto`) espera uma máquina com root: a do usuário, ou a
VM `corerouter-lab` da G0.26 quando a sessão puder rodar nela. Os comandos estão prontos:

```sh
cargo xtask bng-lab --blaster <bngblaster> --scales 1000,10000,100000 --radius 100 --wave 100000 --radius-cap 3000
cargo xtask bng-lab --root --blaster <bngblaster> --scales 1000,10000,100000 --radius 100 --wave 100000 --radius-cap 3000
```

Este relatório é atualizado com os números quando a rodada rodar.

### 3.8 Interoperabilidade

- **`pppd` 2.4.9 + `pppoe.so` (rp-pppoe):** é o cliente do Linux e do OpenWrt, que muitos CPEs
  usam.
  - A sessão sobe em 3,1 s, com CHAP e MTU 1480.
  - Ping pelo túnel e pelo BNG.
  - LCP echo a cada 1 s mantido.
  - Derrubada pelo BNG vista pelo `pppd` em 0,11 s; o encerramento pelo cliente (PADT) é
    visto pelo BNG.
- **Cliente do BNG Blaster:** CHAP, IPCP, keepalive, tráfego verificado em todas as sessões e
  reconexão automática.
- **Goldens:** as duas conversas, gravadas pelo laboratório, ficam em
  `crates/proto-pppoe/tests/fixtures` (27 e 73 quadros). Todo quadro dos dois lados decodifica
  e volta aos mesmos bytes.
- **Testes de interop que faltam:** RouterOS como cliente, CPEs reais (TP-Link, Huawei,
  Intelbras) e FreeRADIUS como servidor (G4.3bb).

## 4. Comparação

Os números dos fabricantes vêm das fontes públicas; os de escala de Juniper, Cisco e Nokia
ficam em guias que pedem login, então a tabela usa o que está aberto. MikroTik e accel-ppp não
publicam escala; os números deles são de relatos de operadores e marcados assim.

| | CoreRouter (hoje) | MikroTik RouterOS v7 | accel-ppp / VyOS | Juniper MX | Cisco ASR 9000 | Nokia 7750 SR |
|---|---|---|---|---|---|---|
| Sessões por caixa | 100 mil testadas no laboratório; o mapa XDP tem 131 072 vagas | sem limite oficial ("não recomendado" muitas num aparelho); relatos de 2,4–3 mil num CCR1036 e de 2,4 mil num CCR2116 a 100% de CPU | relatos de ~4 mil por servidor | sem número aberto; o JVD testou 4k PPPoE + 4k IPoE por BNG | 64 mil por placa e 128–256 mil por chassi (Typhoon/Tomahawk) | sem número aberto; clientes com mais de 1 milhão de assinantes em vários chassis |
| Sessões novas por segundo | 9,8 mil/s pela rede numa thread, antes das correções (a rodada com os workers está pendente); 303 mil/s no BNG em memória | não publicado | não publicado | não publicado | 80 CPS na tabela do XR 5.2/5.3; "até 200" num ASR 9001 (fórum) | não publicado |
| Plano de dados | XDP sem netdev por sessão, ~125–138 ns por pacote em 1–100 mil sessões | kernel, uma interface ppp por sessão | kernel, uma netdev ppp por sessão | NPU Trio | NPU | FP5 |
| Rate-limit por assinante | policer no XDP com o burst do RouterOS, erro ≤ 1,5% | simple queue na CPU (shaper) | TBF/HTB e policer no tc | HQoS no hardware | QoS no NP (8 mil por porta com QoS) | HQoS no hardware |
| Reação a onda de reconexão | `new_session_rate=auto` (AIMD pela latência e pelos timeouts do RADIUS), padi-limit, limite por MAC, pado-delay por carga | sem limite de taxa de sessões | `max-starting`, `padi-limit`, `pado-delay` | call admission control | `pppoe throttle`, call admission | controle de taxa de sessões |
| CoA/Disconnect | sim, testado sob carga | sim (`/radius incoming`) | sim (`dae-allowed`) | sim | sim | sim |
| IPv6 (DHCPv6-PD, RA) | sim (G4.3e) | sim | sim | sim | sim | sim |
| IPoE | em PR (G4.3f) | não como sessão | sim | sim | sim | sim |
| L2TP LAC/LNS | não (G4.3i) | sim | sim | sim | sim | LNS no ESA |
| Alta disponibilidade de assinantes | não (G4.3h) | não | não | M:N subscriber redundancy | SRG (licença à parte) | SRRP + MCS |
| Diagnóstico de login | "Why?" por usuário e MAC, histórico de quedas com motivo, monitor com a razão do limite | log | log | `show subscribers`, traceoptions | `show subscriber`, debug | `show service` |
| Automação | tudo é comando: CLI, GUI e MCP, com transação e rollback | API e scripts | config em arquivo; o VyOS reinicia o daemon e derruba as sessões num commit | NETCONF | NETCONF | NETCONF / gNMI |

### Onde estamos à frente

- **Escala e taxa num servidor comum:** 100 mil sessões e o plano de controle em vários núcleos
  ficam bem acima do que se relata do MikroTik e do accel-ppp no mesmo tipo de hardware. A taxa
  de sessões novas medida também passa as poucas publicadas pelos BNGs de operadora.
- **Plano de dados sem uma interface por sessão:** o XDP mantém o custo por pacote igual de 1 a
  100 mil sessões; no MikroTik e no accel-ppp cada sessão é uma netdev do kernel.
- **Reconexão em massa guiada pelo RADIUS** (`auto`), com o motivo na tela: nenhum dos outros
  mostra por que está segurando.
- **Diagnóstico ("Why?") e "tudo é comando":** transação, rollback e MCP sobre o BNG; mudar a
  config não derruba sessões (no VyOS um commit reinicia o accel-ppp).

### Onde empatamos

- **PPPoE, PPP e autenticação:** os quatro métodos, RADIUS com os atributos do RouterOS, CoA,
  Disconnect e accounting.
- **IPv6 por assinante e as proteções clássicas:** padi-limit, pado-delay, max-sessions.

### O que falta

- **Alta disponibilidade entre BNGs (G4.3h):** é o que Juniper, Cisco e Nokia vendem e o que um
  operador grande exige.
- **L2TP LAC/LNS (G4.3i)** e **IPoE como sessão (G4.3f, em PR).**
- **HQoS e shaping com fila (G4.3ca):** hoje é policer; o hardware dos fabricantes faz filas
  hierárquicas por assinante.
- **Medição em placa real (G4.3cb):** os números de pacote daqui são de veth.
- **A taxa pela rede:** a leitura das portas ainda é uma thread só, que entrega os quadros aos
  workers. O próximo passo é o `PACKET_FANOUT` com cBPF escolhendo o socket pelo MAC, no
  kernel, quando a rodada final mostrar o leitor como gargalo.
- **Interop com CPEs comerciais e com o RouterOS como cliente.**

## 5. Como reproduzir

```sh
cargo test -p corerouter-proto-pppoe                       # unidade, RFCs, fuzz curto, simulação, goldens
cargo bench -p corerouter-daemon --bench pppoe_bng         # sessões/s por número de workers
COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
    cargo test -p corerouter-daemon --test netns_pppoe -- --test-threads 1
cargo xtask bng-lab --blaster <bngblaster>                  # laboratório sem root
cargo xtask bng-lab --root --blaster <bngblaster>           # com XDP e pppd (pede sudo)
COREROUTER_REQUIRE_XDP=1 cargo xtask xdp-root               # o XDP no kernel (pede sudo)
```

O BNG Blaster é o `.deb` do release oficial (github.com/rtbrick/bngblaster), desempacotado com
`dpkg-deb -x`, sem instalar.

## 6. Fontes da comparação

- MikroTik:
  - https://help.mikrotik.com/docs/spaces/ROS/pages/2031625/PPPoE
  - https://help.mikrotik.com/docs/spaces/ROS/pages/132350049/PPP+AAA
  - relatos: https://forum.mikrotik.com/t/maximum-pppoe-ccr-2116/161715 e
    https://forum.mikrotik.com/t/max-pppoe-concurrent-sessions-in-a-ccr/64599
- accel-ppp:
  - https://github.com/accel-ppp/accel-ppp
- VyOS:
  - https://docs.vyos.io/en/latest/configuration/service/pppoe-server.html
- Juniper:
  - https://www.juniper.net/documentation/us/en/software/jvd/jvd-metro-fabric-and-broadband-edge/results_summary_and_analysis.html
  - https://juniper.net/documentation/us/en/software/junos/subscriber-mgmt-sessions/topics/topic-map/m-to-n-subscriber-redundancy.html
- Cisco:
  - https://community.cisco.com/t5/service-providers-knowledge-base/bng-deployment-scale-guidelines-on-asr9000/ta-p/3156300
  - https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/710x/bng/configuration/guide/b-bng-cg-asr9000-710x/bng-geo-redundancy.html
- Nokia:
  - https://documentation.nokia.com/acg/24-7-2/books/tpsda-classic/c045-esm-ipv4-redirection.html
  - https://www.lightreading.com/cable-technology/evaluating-nokia-s-vnfs-part-2
- BNG Blaster:
  - https://rtbrick.github.io/bngblaster/
