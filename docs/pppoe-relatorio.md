# Relatório do PPPoE do CoreRouter (BNG em Rust puro, G4.3)

Para quem opera provedor: o que o BNG do CoreRouter já faz, como foi testado em cada camada, os
números **medidos** e onde ele está comparado ao MikroTik RouterOS v7, ao accel-ppp/VyOS e aos
BNGs de operadora (Juniper MX, Cisco ASR 9000, Nokia 7750 SR).

**Onde cada número foi medido:**

- **Laboratório com o BNG Blaster (§3.7):** VM corerouter-lab, 8 vCPUs (AMD EPYC-Genoa), 16 GiB,
  kernel 7.0, build release, 25 de outubro de 2026, salvo onde dito. A rodada no hardware
  do usuário fica como verificação extra.
- **Testes, benchmarks e simulações:** AMD Ryzen AI Max+ 395, 32 CPUs, Linux 7.0.0-38, release.
- **O que o laboratório mede:** usa veth em namespaces, então mede o plano de controle e a
  correção, não a vazão de uma placa (a medição em placa real é a G4.3cb).

## 1. Resumo

- **Plano de controle:**
  - pela rede, contra o BNG Blaster: 100 mil sessões PPPoE em 1,7 s, 57,7–57,9 mil sessões/s
    com 6 workers (14,5–15,2 mil/s com 1);
  - em memória: 303 mil sessões/s com 8 workers.
- **Reconexão em massa contra um RADIUS lento:** com `new_session_rate=auto`, 100 mil CPEs
  contra um servidor que responde 3000 pedidos/s voltam em 33,6 s, a 2978/s (99% da capacidade
  do servidor), sem nenhum timeout e sem nenhuma retransmissão. Com o limite desligado são
  36,1 s e 90 mil retransmissões; com o fixo em 2000, 39,8 s.
- **Escala testada:**
  - 100 mil sessões com keepalive e tráfego verificado numa amostra de 10 mil, sem nenhuma queda
    em regime;
  - queda total e reconexão;
  - 100 mil sessões nos mapas do XDP a ~125 ns por pacote na descida e ~138 ns na subida.
- **Policer por assinante no XDP:** 1,003–1,004× o contratado com 2× oferecido, em 100
  assinantes.
- **RADIUS completo:** autenticação, accounting, CoA e Disconnect (RFC 5176) testados sob
  carga, com 10 de 10 respostas certas.
- **Interoperabilidade:**
  - o cliente Linux `pppd` 2.4.9 com o plugin `pppoe.so` (rp-pppoe) e o cliente do BNG Blaster
    sobem, fazem keepalive, tráfego e encerramento dos dois lados;
  - as conversas reais viraram testes dourados.
- **O laboratório achou e corrigiu** cinco defeitos que nenhum teste anterior pegava. O pior
  ficava no cliente RADIUS: quase todo login saía duas vezes (§3.7).
- **Falta para "BNG de operadora":**
  - alta disponibilidade entre dois BNGs (G4.3h);
  - L2TP LAC/LNS (G4.3i);
  - shaping com fila (EDT) e entrega do kernel ao assinante com XDP (G4.3ca);
  - medição em placa real (G4.3cb);
  - IPoE no laboratório (G4.3f).

## 2. O que o BNG faz hoje

| Área | O que tem | Onde |
|---|---|---|
| PPPoE (RFC 2516) | PADI/PADO/PADR/PADS/PADT com todas as tags, AC-Cookie HMAC-SHA-256 (sem estado por PADI), Host-Uniq, Relay-Session-Id, PPP-Max-Payload (RFC 4638), Agent-Circuit-Id/Remote-Id (TR-101, RFC 4679), VLAN e QinQ na descoberta | `crates/proto-pppoe` |
| PPP | Autômato da RFC 1661 §4 célula por célula, LCP com todas as opções, keepalive, PAP, CHAP-MD5, MS-CHAPv1/v2 com chaves MPPE, IPCP com DNS (RFC 1877), IPv6CP com identificador estável e opaco (RFC 8064) | `proto-pppoe` |
| IPv6 por assinante (G4.3e) | RA por sessão com /64 do pool, DHCPv6-PD (/56 delegado), RDNSS; contabilização com Framed-IPv6-Prefix e Delegated-IPv6-Prefix | `pppoe_bng6.rs` |
| AAA | `/ppp secret` local (caller-id, service, only-one, limit-bytes) ou RADIUS (Framed-IP, Framed-Pool, Mikrotik-Rate-Limit, Mikrotik-Group, Session-Timeout, Acct-Interim-Interval, Reply-Message); Accounting Start/Interim/Stop com Acct-Terminate-Cause | `pppoe_bng.rs`, `proto-radius`, `radius_aaa.rs` |
| Cliente RADIUS | Timeout adaptativo (SRTT + 4·RTTVAR, RFC 6298, amostras de Karn), backoff da RFC 5080, failover e Status-Server; numa onda, a autenticação passa à frente do accounting, e o Acct-Delay-Time conta a espera (RFC 2866 §5.2); o login de quem desistiu sai da fila | `proto-radius`, `radius_aaa.rs` |
| CoA/Disconnect (RFC 5176) | Rate-limit ao vivo, address-list (aviso de inadimplência), Disconnect, Framed-IP = reconectar; NAK 401/407 | `pppoe_bng.rs` |
| Plano de dados | XDP sem netdev por sessão: decapsula e encapsula no XDP, anti-spoofing, policer com o burst do RouterOS, contadores; sem XDP, um caminho lento em userspace | G4.3c, `dataplane-ebpf` |
| Proteções | `padi_limit`, `mac_padi_limit`, `new_session_rate` (fixo ou `auto`), `pado_delay` e `pado_delay_by_load`, `max_sessions`, one-session-per-host | `interface.pppoe-server` |
| Escala | Vários núcleos (`workers=auto|N`), SESSION_ID por faixa de worker sem lock, índices O(1) para secret, endereço, login e id de sessão | G4.3g |
| Operação | Janela PPP no estilo do WinBox (servidores, secrets, perfis, ativos, histórico), **Why?** (onde cada login para e por quê), histórico de quedas com motivo, "Quem era?" do CGNAT pelo login, gráfico por assinante, derrubar N sessões, coluna New Sessions com o motivo do limite | `crates/ui/src/ppp.rs` |
| Tudo é comando | `ppp.*` e `interface.pppoe-server.*` pela CLI, pela GUI e pelo MCP, com transação, rollback e Safe Mode | engine |
| Diagnóstico | `system.health.check` › Socket buffers (o buffer de recepção que o `rmem_max` cortou); monitor com `dataplane`, `workers`, `admission_rate` e o motivo, e `rx_dropped` (quadros perdidos antes do BNG ler) | G4.3g |

## 3. Testes, camada por camada

### 3.1 Unidade e as regras das RFCs

- **`proto-pppoe`:** cada regra das RFCs 2516, 1661, 1332, 1334, 1994, 2433, 2759, 5072, 4638
  e 4679 tem o teste que a cumpre (a tabela fica em `docs/pppoe.md` §4).
- **`proto-radius`:** os exemplos das RFCs são testes dourados (RFC 2865 §7 com as erratas
  1469 e 6486, RFC 5997 §6, RFC 2759 §9, RFC 3079 §3.5).
- **Tamanho:** 146 testes no `proto-pppoe`, 72 no `proto-radius`, 41 no
  `dataplane-ebpf-common` e 31 do BNG no daemon, mais 12 do serviço RADIUS (contagem de
  `#[test]`, **medido**).

### 3.2 Entrada hostil: proptest e fuzz

- **Oráculos de fuzz do `proto-pppoe`:** cinco alvos (descoberta, sessão, servidor, cliente e
  conversa viva, em que cliente e servidor conversam com quadros editados em voo). Rodam
  curtos no CI com proptest e longos com libFuzzer.
- **Proptest:** no codec RADIUS e no plano de dados XDP (ida e volta com 0, 1 e 2 tags,
  spoofing, quadro cortado). O policer nunca passa do balde mais a taxa.

### 3.3 Simulações em memória

- **`crates/proto-pppoe/tests/sim.rs`:** o servidor contra 100 000 clientes numa rede hostil
  (0,5% de perda, 0,2% de duplicação, 1% de reordenação) chega às 100 000 sessões em Opened.
  Também roda:
  - inundação de 200 mil PADIs;
  - 100 mil PADRs com cookie forjado;
  - reboot em massa de CPEs;
  - 10% de senha errada;
  - queda de 60 s.

  Ela achou oito defeitos de interoperabilidade (Configure-Ack duplicado, Success de CHAP
  perdido, PADR atrasado derrubando a sessão, entre outros), todos corrigidos antes da primeira
  sessão real (`docs/pppoe.md` §5).
- **`proto-radius/tests/load_sim.rs`:** 100 mil Access-Requests e as interims de 20 mil
  sessões, com 3% de perda nos dois sentidos e o servidor primário fora do ar por 60 s.
  - Terminam com 14 timeouts de login, nenhum accounting perdido e a última interim de cada
    sessão no servidor.
  - O primário volta.
- **Onda de reconexão com o BNG inteiro** (`pppoe_bng_tests.rs`, no relógio do laboratório):
  60 mil CPEs contra um RADIUS de 3000/s, com o cliente RADIUS de verdade na frente
  (retransmissão, timeout adaptativo, MRD). Foi essa simulação que reproduziu e isolou o
  defeito dos timers (§3.7).

  | `new_session_rate` | Todas no ar | Timeouts | Retransmissões |
  |---|---:|---:|---:|
  | auto | 20,6 s | 0 | 0 |
  | desligado | 20,1 s | 0 | 55 550 |
  | fixo 2000 | 44,1 s | 0 | 19 008 |

  No CI, um teste com 6000 CPEs contra 300/s exige do `auto` nenhum timeout e no máximo 1%
  de cópias.

### 3.4 Benchmarks (release)

| O quê | Resultado (**medido**) |
|---|---|
| `proto-pppoe`: PADI → PADO com AC-Cookie | 175 ns (5,7 M/s num núcleo) |
| `proto-pppoe`: sessão completa, PADI → IPCP Opened, servidor + cliente | 6,3 µs (159 mil/s) |
| BNG do daemon (`benches/pppoe_bng.rs`), 1 / 2 / 4 / 8 workers | 58 / 115 / 202 / 303 mil sessões/s |
| Custo por sessão com 0 → 50 mil já no ar | 12–16 µs, plano (era 19 → 181 µs antes do índice de secrets) |
| Memória por sessão no BNG | ≈ 5,0 KB (com IPv6) em memória; ≈ 4,1 KB de RSS no laboratório |
| RADIUS: login completo pelo serviço | 13,9 µs (72 mil/s um a um; 194 mil/s em lote de 1000) |
| `ppp.secret.add` em lote | 100 mil em 2,9–3,0 s pelo `engine.batch` (33–35 mil/s, VM) |

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
com `--root` liga o XDP e o `pppd`. As etapas:

- `scale`: 1 mil, 10 mil e 100 mil sessões, com setup, keepalive, tráfego, reconexão e
  encerramento;
- `radius`: 100 sessões pelo RADIUS, policer, CoA e Disconnect;
- `workers`: 100 mil com 1 worker e com `auto`, com a CPU de cada thread;
- `wave`: 100 mil contra um RADIUS que responde 3000/s, com o limite desligado, fixo em 2000 e
  `auto`;
- `pppd`: interop com o cliente do Linux.

O RADIUS da onda se comporta como um FreeRADIUS saturado. Ele guarda no máximo 2 s de trabalho
na fila e descarta a cópia de um pedido que já tem (RFC 5080 §2.2.2).

#### Escala e RADIUS (VM, com XDP)

| | 1 mil | 10 mil | 100 mil |
|---|---:|---:|---:|
| Setup, proteções desligadas | 4,9 mil/s | 9,8 mil/s | 9,97 mil/s (10,0 s) |
| CPU do daemon por sessão no setup | 50 µs | 65 µs | 67 µs |
| Memória por sessão (RSS) | — | 3,3 KB | 4,1 KB |
| Keepalive em regime (LCP a cada 10 s + 1 pps de tráfego) | 1,6% de um núcleo | 3,0% | 18,9% |
| Tráfego verificado | 2000 de 2000 fluxos | 20 000 de 20 000 | 20 000 de 20 000 (amostra de 10 mil sessões) |
| Reconexão com as proteções padrão (`new_session_rate` 2000) | 0,1 s | 6,8 s | 26,2 s |
| Reconexão sem proteções | 0,1 s | 1,0 s | 10,0 s |
| Encerramento (PADT de todas) | 0,3 s | 1,2 s | 10,2 s |

O setup de 100 mil é limitado pelo `start-rate` de 10 mil/s do BNG Blaster nesta etapa. A etapa
`workers` o leva ao máximo de 65 535 do esquema. As 100 mil ficaram 30 s em regime sem uma
queda.

- **RADIUS:** 100 sessões pelo RADIUS, todas com Access-Accept, accounting e o
  Mikrotik-Rate-Limit "1M/2M" aplicado.
- **Policer no XDP:** 1,003–1,004× o limite (mín. 0,999, máx. 1,012) com 2× oferecido, nos dois
  sentidos.
- **CoA:** 10 de 10 CoA-ACK, ida e volta média de 0,05–0,06 ms.
  - As sessões com CoA passam a 1,000–1,001× o novo limite ("2M/4M"), e as outras seguem no
    antigo.
  - O `ppp.active` mostra o novo rate.
- **Disconnect:** 10 de 10 Disconnect-ACK. As derrubadas voltam em 1,1 s (o BNG Blaster
  reconecta), e as outras 90 seguem no limite.

#### Vários núcleos (etapa `workers`, 100 mil sessões, BNG Blaster a 65 535/s)

| | 1 worker | 6 workers (`auto` em 8 vCPUs) |
|---|---:|---:|
| Sessões/s | 14,5 mil (6,9 s) | **57,7 mil (1,7 s)** |
| CPU dos workers, somada | 43% | 216% |
| Leitor das portas (`svc-pppoe`) | 11% | 49% |
| BNG Blaster | 24% de um núcleo | 67% |
| Quadros perdidos antes do BNG (`rx_dropped`) | 30 967 | 0 |

Rodada 6. A rodada 3, com o mesmo leitor, deu 15,2 mil e 57,9 mil: a diferença é ruído. O filtro
das cópias de saída e o contador de perdas não custam nada que se meça.

**Por que 1 worker perde quadros.** O BNG Blaster manda os 100 mil PADIs em 1,5 s (65 535/s).
Um worker só atende ~14,5 mil sessões/s. A rajada enche primeiro o canal do worker (65 536
quadros) e depois o buffer do socket.

- O que sobra se perde, e o `rx_dropped` conta: foram 30 967.
- Ninguém fica de fora: o CPE repete o PADI (RFC 2516 §5) e todas as sessões sobem.
- Com 6 workers a mesma rajada é atendida a tempo, sem perda.

**O que o operador deve configurar:**

- **`workers=auto`**, o padrão: CPUs − 2, no máximo 8.
- **`workers=1` só para depurar.**
- **`rx_dropped` crescendo fora de uma volta de energia:** o BNG está abaixo da carga.
  - Aumente os workers.
  - Ou limite a entrada com `new_session_rate=auto`, que segura os logins pela capacidade do
    RADIUS.
- **`system.health.check` › Socket buffers** avisa quando o kernel cortou o buffer de
  recepção (`rmem_max`).

A recepção é um leitor que entrega cada quadro ao worker do MAC do cliente por um canal. Uma
alternativa sem leitor foi medida e descartada: cada worker com o próprio socket, filtrado no
kernel por BPF pelo hash do MAC.

- No namespace ela baixou a parte serial de 550–1050 ns para 150–350 ns por quadro.
- Contra o BNG Blaster, ficou em 22,4 mil/s sem fila (rodada 4) e em 24,0 mil/s com uma fila
  no worker (rodada 5), com o BNG Blaster a 91% de um núcleo.

A decisão e os números estão em `docs/architecture.md`, "Plano de controle PPPoE em vários
núcleos".

#### Onda de reconexão: 100 mil contra um RADIUS de 3000/s

| `new_session_rate` | Todas no ar | Sessões/s | Timeouts do RADIUS | Retransmissões |
|---|---:|---:|---:|---:|
| **auto** | **33,6 s** | **2978** | **0** | **0** |
| desligado | 36,1 s | 2774 | 2 | 90 161 |
| fixo 2000 | 39,8 s | 2510 | 5 | 64 574 |

Rodada 5. O ideal é 100 000 / 3000 = 33,3 s: o `auto` usa 99% da capacidade do servidor. O
limite chegou a 2990/s e não passou dela, e não houve uma cópia de pedido sequer.

#### Histórico das rodadas e o que cada correção mudou

O laboratório rodou seis vezes na VM; cada rodada achou o que a anterior escondia. Antes da
primeira, a máquina do usuário já tinha mostrado o O(n) do login.

| Rodada | Workers (1 → 6) | Onda: desligado / fixo 2000 / auto | O que veio a seguir |
|---|---|---|---|
| Antes da VM (máquina do usuário, sem root, 1 thread) | 3,7 mil/s com 100 mil | — | O laboratório achou o login O(n), as varreduras de todas as sessões, o plano de controle numa thread a 98%, o "Why?" que se apagava inteiro, `ppp.active.list` copiando 100 mil sessões e o monitor dizendo "caminho lento" com XDP. Tudo corrigido. |
| 1 | medida errada (o número de workers não era aplicado) | nenhum modo terminou: 5837 / 0 / 0 no ar em 620 s | O laboratório passou a esperar o `settings.get running` e a medir a CPU por thread. O RADIUS de teste era uma fila sem limite que respondia, minutos depois, a pedidos que ninguém esperava mais; passou a ter fila de 2 s e descarte de cópias, como o FreeRADIUS. |
| 2 | 14,5 → 54,2 mil/s | 6039 no ar / 11 686 no ar / **517 s** | O `auto` era um AIMD pela latência e se cortava pela metade até rastejar. Virou à moda do BBR: mede a capacidade em logins respondidos, segura os logins numa fila no BNG (não os PADIs, porque um CPE recusado recua) e limita os pedidos em voo. Entrou o timeout adaptativo do cliente RADIUS. |
| 3 | 15,2 → **57,9 mil/s** | 69,4 s / 94,6 s / 106,7 s | O accounting dividia o servidor com os logins, e o `auto` media a capacidade antes dele chegar. A autenticação passou à frente do accounting, e os pedidos em voo passaram a seguir o BDP (capacidade × tempo sem fila). |
| 4 | 10,5 → 22,4 mil/s (socket por worker) | 42,1 s / 36,5 s / 62,4 s | Dois achados. A rajada de PADIs transbordava os sockets por worker. E um **defeito no cliente RADIUS**: o timer de um pedido respondido disparava no pedido seguinte do mesmo slot, e quase todo login saía duas vezes, 0–250 ms depois. Isso explica as 59–236 mil retransmissões das rodadas 2 a 4. O identificador passou a ser único no cliente; entrou também a janela inicial de 64 pedidos. |
| 5 | 14,3 → 24,0 mil/s (socket por worker + fila) | 36,1 s / 39,8 s / **33,6 s** | A onda ficou resolvida. O socket por worker continuou abaixo do leitor e foi descartado. |
| 6 | 14,5 → **57,7 mil/s** (leitor) | — | O leitor da rodada 3, agora com o filtro das cópias de saída e o contador `rx_dropped`, empata com ele; as perdas com 1 worker ficam visíveis (30 967). |

**Hipótese do socket por worker, não confirmada:** com fila e sem perda, o BNG Blaster gastou
~3× mais CPU por sessão, o que sugere retransmissão do lado do CPE por latência. O worker
esvazia a rajada inteira antes de responder, e as respostas de LCP e IPCP esperam atrás dela.
Confirmar exige os contadores de retransmissão por sessão do BNG Blaster.

#### Comandos

```sh
cargo xtask bng-lab --blaster <bngblaster>                                   # sem root, caminho lento
cargo xtask bng-lab --root --blaster <bngblaster>                            # com XDP e pppd (pede sudo)
cargo xtask bng-lab --root --scales 100000 --only wave,workers --wave 100000 --radius-cap 3000
cargo xtask vm-lab run -- cargo xtask bng-lab --root ...                     # na VM corerouter-lab
```

O resultado sai em `target/bng-lab/summary.md` (tabela) e `summary.json` (para máquina), com
os logs, os pcap e os relatórios do BNG Blaster.

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
| Sessões por caixa | 100 mil testadas no laboratório, sem queda em regime; o mapa XDP tem 131 072 vagas | sem limite oficial ("não recomendado" muitas num aparelho); relatos de 2,4–3 mil num CCR1036 e de 2,4 mil num CCR2116 a 100% de CPU | relatos de ~4 mil por servidor | sem número aberto; o JVD testou 4k PPPoE + 4k IPoE por BNG | 64 mil por placa e 128–256 mil por chassi (Typhoon/Tomahawk) | sem número aberto; clientes com mais de 1 milhão de assinantes em vários chassis |
| Sessões novas por segundo | 57,7–57,9 mil/s pela rede com 6 workers numa VM de 8 vCPUs; 303 mil/s no BNG em memória | não publicado | não publicado | não publicado | 80 CPS na tabela do XR 5.2/5.3; "até 200" num ASR 9001 (fórum) | não publicado |
| Plano de dados | XDP sem netdev por sessão, ~125–138 ns por pacote em 1–100 mil sessões | kernel, uma interface ppp por sessão | kernel, uma netdev ppp por sessão | NPU Trio | NPU | FP5 |
| Rate-limit por assinante | policer no XDP com o burst do RouterOS, 1,003–1,004× no laboratório | simple queue na CPU (shaper) | TBF/HTB e policer no tc | HQoS no hardware | QoS no NP (8 mil por porta com QoS) | HQoS no hardware |
| Reação a onda de reconexão | `new_session_rate=auto` pela capacidade medida do RADIUS (100 mil em 33,6 s contra 3000/s, sem retransmissão), padi-limit, limite por MAC, pado-delay por carga | sem limite de taxa de sessões | `max-starting`, `padi-limit`, `pado-delay` | call admission control | `pppoe throttle`, call admission | controle de taxa de sessões |
| CoA/Disconnect | sim, testado sob carga | sim (`/radius incoming`) | sim (`dae-allowed`) | sim | sim | sim |
| IPv6 (DHCPv6-PD, RA) | sim (G4.3e) | sim | sim | sim | sim | sim |
| IPoE | em PR (G4.3f) | não como sessão | sim | sim | sim | sim |
| L2TP LAC/LNS | não (G4.3i) | sim | sim | sim | sim | LNS no ESA |
| Alta disponibilidade de assinantes | não (G4.3h) | não | não | M:N subscriber redundancy | SRG (licença à parte) | SRRP + MCS |
| Diagnóstico de login | "Why?" por usuário e MAC, histórico de quedas com motivo, monitor com a razão do limite e as perdas de quadros | log | log | `show subscribers`, traceoptions | `show subscriber`, debug | `show service` |
| Automação | tudo é comando: CLI, GUI e MCP, com transação e rollback | API e scripts | config em arquivo; o VyOS reinicia o daemon e derruba as sessões num commit | NETCONF | NETCONF | NETCONF / gNMI |

### Onde estamos à frente

- **Escala e taxa num servidor comum:** 100 mil sessões sobem em 1,7 s numa VM de 8 vCPUs. Isso
  fica bem acima do que se relata do MikroTik e do accel-ppp no mesmo tipo de hardware, e a taxa
  passa as poucas publicadas pelos BNGs de operadora.
- **Reconexão em massa guiada pelo RADIUS:** o `auto` mede a capacidade do servidor e a usa
  quase inteira (99%), sem cópias, com o motivo na tela. Nos outros, o limite é um número fixo
  que o operador acerta à mão, e nenhum mostra por que está segurando.
- **Plano de dados sem uma interface por sessão:** o XDP mantém o custo por pacote igual de 1 a
  100 mil sessões; no MikroTik e no accel-ppp cada sessão é uma netdev do kernel.
- **Diagnóstico ("Why?") e "tudo é comando":** transação, rollback e MCP sobre o BNG; mudar a
  config não derruba sessões (no VyOS um commit reinicia o accel-ppp).

### Onde empatamos

- **PPPoE, PPP e autenticação:** os quatro métodos, RADIUS com os atributos do RouterOS, CoA,
  Disconnect e accounting.
- **IPv6 por assinante e as proteções clássicas:** padi-limit, pado-delay, max-sessions.

### O que falta

- **Alta disponibilidade entre BNGs (G4.3h):** é o que Juniper, Cisco e Nokia vendem e o que um
  operador grande exige.
- **L2TP LAC/LNS (G4.3i)** e **IPoE como sessão (G4.3f, em PR),** com o IPoE no laboratório.
- **HQoS e shaping com fila (G4.3ca):** hoje é policer; o hardware dos fabricantes faz filas
  hierárquicas por assinante.
- **Medição em placa real (G4.3cb):** os números de pacote daqui são de veth.
- **Leitura das portas sem o leitor único (G4.3ga):** o leitor ficou a 51% de um núcleo a 57,9
  mil sessões/s. Ele ainda não é o gargalo, mas será perto de 110 mil/s. O socket filtrado por
  worker já foi medido e descartado; ficam o `PACKET_FANOUT` por cBPF (precisa de uma API
  segura) e o AF_XDP.
- **Interop com CPEs comerciais, com o RouterOS como cliente e com o FreeRADIUS (G4.3bb).**

## 5. Como reproduzir

```sh
cargo test -p corerouter-proto-pppoe                       # unidade, RFCs, fuzz curto, simulação, goldens
cargo test -p corerouter-proto-radius                      # cliente RADIUS, RFCs, load_sim
cargo bench -p corerouter-daemon --bench pppoe_bng         # sessões/s por número de workers
cargo test --release -p corerouter-daemon --bin corerouter-daemon wave_with_the_real_client -- --ignored --nocapture
COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
    cargo test -p corerouter-daemon --test netns_pppoe -- --test-threads 1
cargo xtask bng-lab --blaster <bngblaster>                  # laboratório sem root
cargo xtask bng-lab --root --blaster <bngblaster>           # com XDP e pppd (pede sudo)
COREROUTER_REQUIRE_XDP=1 cargo xtask xdp-root               # o XDP no kernel (pede sudo)
```

O BNG Blaster é o `.deb` do release oficial (github.com/rtbrick/bngblaster), desempacotado com
`dpkg-deb -x`, sem instalar. O workflow `bng-lab` (Actions, só à mão) roda o laboratório no
runner do GitHub, com os números marcados como "runner do CI, 4 vCPUs".

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
- RFCs do cliente RADIUS e da onda: RFC 2865, RFC 2866 §5.2 (Acct-Delay-Time), RFC 5080 §2.2
  (retransmissão e duplicatas), RFC 5176 (CoA/DM), RFC 6298 (timeout adaptativo), RFC 2516 §5
  (recuo do PADI).
