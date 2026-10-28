# BFD — Bidirectional Forwarding Detection (G3.6)

O CoreRouter tem um BFD próprio, em Rust puro (`crates/proto-bfd` + o serviço `bfd` do daemon),
e não usa o `bfdd` do FRR. O FRR continua como motor de BGP, OSPF e LDP; a ligação entre o nosso
BFD e esses protocolos é a parte (b) do G3.6.

| Parte | O quê | Estado |
|---|---|---|
| G3.6a | Codec, máquina de estados, autenticação SHA1, dampening, motor multithread, perfis, peers, sessões, histórico | este documento |
| G3.6b | Ligação com o FRR (BGP/OSPF caem com o BFD) como data plane do `bfdd`, BFD nas conexões e templates BGP, `routing.bfd.attach` | ver "Ligação com o FRR" |
| G3.6c | Janela Routing › BFD (Sessions, Profiles, History), perfil BFD no modal BGP | ver "Janela" |

## Como usar

```sh
corerouter-cli run routing.bfd.peer.add '{"address":"192.0.2.2","profile":"fast"}'
corerouter-cli run routing.bfd.peer.add '{"name":"rr1","address":"198.51.100.9","multihop":true}'
corerouter-cli run routing.bfd.session.list      # estado, timers, jitter p99, quedas em 24 h, threads
corerouter-cli run routing.bfd.history.list      # quedas e subidas, com o diagnóstico (RFC 5880 §4.1)
corerouter-cli run routing.bfd.profile.add '{"name":"wan","min_tx":300,"min_rx":300,"multiplier":5,"auth":"meticulous-keyed-sha1","auth_secret":"segredo"}'
corerouter-cli run routing.bfd.profile.list
```

- **Perfis** (`routing.bfd.profile.*`): intervalos, multiplicador, modo passivo, dampening,
  autenticação e TTL mínimo do multihop. Dois vêm de fábrica e não podem ser apagados (o
  `remove` volta aos valores de fábrica):
  - `default`: 300 ms × 3, detecção em 900 ms (o padrão do FRR e do Junos).
  - `fast`: 50 ms × 3, detecção em 150 ms (intervalo comum da RFC 7419). Abaixo de 100 ms o
    `add`/`set` devolve um aviso de CPU.
- **Peers** (`routing.bfd.peer.*`): uma sessão explícita (endereço, endereço local, interface,
  multihop, perfil). BGP, OSPF e rotas estáticas vão pedir sessões do mesmo jeito (G3.6b); a
  sessão mostra quem a usa (`users`). Dois pedidos para o mesmo par (endereço, multihop, endereço
  local) são a mesma sessão e precisam do mesmo perfil.
- **Dampening ligado por padrão**: cada queda Up → Down soma 1000 de penalidade, que cai à metade
  a cada 15 s; acima de 2500 (a terceira queda seguida) a sessão fica "dampened" — o BFD continua
  rodando, mas os clientes a veem caída até a penalidade voltar abaixo de 800 (uns 30 s quieta) ou
  passar o máximo de 120 s. Uma queda pedida pelo operador do outro lado (AdminDown) não conta
  (RFC 5882 §3.2).
- **Diagnóstico por sessão**: `tx_jitter_p99_us` (quanto o nosso pacote periódico saiu atrasado:
  a carga do motor), `rx_gap_p99_us` (o intervalo entre pacotes recebidos, a folga até o tempo de
  detecção), `detect_time_us`, `flaps_24h`, `dropped` (pacotes recusados: TTL, autenticação,
  endereço) e a thread.

## Como funciona

### Protocolo (`crates/proto-bfd`, sans-IO, compila para WASM)

- `packet`: o pacote de controle (RFC 5880 §4.1) e as checagens de §6.8.6 que só dependem dos
  bytes (versão, tamanho, multiplicador, M, My Discriminator).
- `session`: as variáveis de §6.8.1, a recepção (§6.8.6), a transmissão (§6.8.7), os timers
  (§6.8.2–§6.8.4) e o Poll/Final (§6.5).
  - Fora de Up o Desired Min TX anunciado é ≥ 1 s (§6.8.3). Ao subir, os intervalos rápidos entram
    por uma sequência Poll; um TX maior ou um RX menor só valem depois do Final (§6.8.3).
  - Jitter de transmissão: 0–25 % a menos, ou 10–25 % com multiplicador 1 (§6.8.7).
  - A detecção é o multiplicador recebido × max(nosso Required Min RX, o Desired Min TX recebido)
    (§6.8.4); vencida, a sessão cai com Diag 1 e o discriminador remoto volta a 0 (§6.8.1).
  - Um par em Demand mode é respeitado (sem periódicos com os dois em Up); o nosso Demand mode
    local e a função Echo não são oferecidos (opcionais na RFC; viram gaps).
  - Um pacote de estado novo sai na hora (o handshake de três vias não espera o timer de 1 s).
- `auth`: Keyed SHA1 e Meticulous Keyed SHA1 (§6.7.4), com a ordem da errata 7083: o hash é
  conferido antes de mexer na janela de sequência. MD5 e senha simples não são oferecidos (fracos;
  a própria RFC avisa).
- `dampen`: penalidade exponencial com teto (como o RFC 2439 do BGP).
- `wheel`: timer wheel com fatias de 1 ms e 4096 posições, preguiçoso (a sessão guarda o próprio
  prazo; entrada velha custa uma consulta).
- `hist`: histograma logarítmico (64 faixas de 25 %) para os p99 por sessão.

### Motor (`apps/corerouter-daemon/src/service/bfd*`)

- **N threads nomeadas (`bfd-0`…)**, cada uma dona de uma parte das sessões: a sessão mora na
  thread `discriminador mod N` (o discriminador é aleatório e único, RFC 5880 §6.8.1, escolhido
  com esse resto).
- **Cada thread tem os próprios sockets e o próprio timer wheel.** As portas 3784 (salto único,
  RFC 5881) e 4784 (multihop, RFC 5883) têm um socket por thread no mesmo grupo `SO_REUSEPORT`,
  e um programa BPF clássico no grupo (`SO_ATTACH_REUSEPORT_CBPF`: `ld [8]; mod #N; ret a`)
  entrega cada pacote ao socket `Your Discriminator mod N`, a thread dona. Pacotes com Your
  Discriminator 0 (sessão subindo) vão ao socket 0, que acha a dona pelo endereço e passa o
  pacote por uma fila limitada. Sem o programa (kernel antigo), o hash do kernel espalha e a
  thread errada repassa (contado em `forwarded`).
- **Sem lock no caminho do pacote**: a thread só toca nas próprias sessões. Comandos (nova
  sessão, timers novos) chegam por fila limitada (8192) e um socketpair acorda a thread; eventos
  (mudança de estado) saem por fila limitada (8192); a cada 250 ms a thread troca a sua cópia do
  estado sob um mutex só dela. O controlador (a thread do serviço) lê a config a cada segundo,
  copia o estado para o `Session` a cada 500 ms e grava o histórico: o lock do `Session` nunca é
  segurado em E/S.
- **TTL 255** em tudo que sai; no salto único só entra pacote com TTL 255 (RFC 5881 §5; com
  autenticação a RFC diz MAY, aplicamos sempre: é o GTSM da RFC 5082); no multihop, TTL ≥
  `min_ttl` do perfil (254 por padrão, como o FRR).
- **Porta de origem**: uma por thread e família, de 49152–65535 (RFC 5881 §4). A RFC diz SHOULD
  ser única por sessão; com 1000 sessões seriam 1000 descritores (o limite padrão de um processo
  é 1024), e os receptores separam por discriminador e endereço, não pela porta.
- **Espera em µs (`ppoll`)**: com o `poll` em milissegundos cada pacote saía até 1 ms atrasado.
- O motor só abre as portas com a primeira sessão e fecha com a última.

## Janela Routing › BFD (G3.6c)

- **Sessions:** uma linha por sessão: Peer (selo `multihop`), Used by (selos coloridos por nome:
  `BGP upstream-a`, `OSPF ether1`, `peer core1`), State (`up`, `down`, `init`, `dampened`,
  `inactive`), Tx/Rx, Detect Time, Jitter p99, Flaps 24h. Barra: + e − de peers (uma sessão do
  BGP ou do OSPF não se remove aqui: diz onde desligar), **Use BFD Everywhere**
  (`routing.bfd.attach`). Rodapé: contagens e o motor (threads, CPU de cada uma, `reuseport-cbpf`).
- **Profiles:** a lista com selo `built-in`, Options (`dampening`, `passive`, `sha1`) e quem usa;
  o modal tem a prévia do engine (`routing.bfd.profile.preview`: tempo de detecção, pacotes por
  segundo, aviso de CPU abaixo de 100 ms, multiplicador baixo, dampening, autenticação).
- **History:** as mudanças, a mais nova primeiro, com o diagnóstico e o tempo de detecção;
  `down » dampened` quando a sessão volta mas fica segura, `dampened » up` quando é liberada.
- O modal de conexão e de template BGP ganhou o campo **BFD Profile**.
- ⓘ em toda coluna, aba, campo e no título, em português (padrão) e inglês.

## Ligação com o FRR (G3.6b)

**Decisão: o nosso motor é o *distributed data plane* do `bfdd`** (opção (a) do plano), não
derrubar vizinhos pelo vty (opção (b)).

- **Como funciona.** O init sobe o `bfdd` com `--dplaneaddr unix:/var/run/frr/bfdd_dplane.sock`;
  o serviço `bfd` do daemon (com `--frr`) conecta como cliente (de novo a cada segundo enquanto não
  consegue). O `bfdd` então não abre socket BFD nenhum (`bfd_vrf_start_sockets` sai cedo no FRR
  10.7.1) e entrega cada sessão que cria — `neighbor … bfd profile` do BGP, `ip ospf bfd profile`
  do OSPF, os `peer` do bloco `bfd` — por `DP_ADD_SESSION`, com o discriminador escolhido por ele
  (o motor a põe na thread `discriminador mod N`, a mesma regra). O motor manda e recebe os pacotes
  e devolve `BFD_STATE_CHANGE`; o `bfdd` avisa `bgpd`/`ospfd`, que derrubam a sessão. Também
  respondemos `DP_REQUEST_SESSION_COUNTERS` (pacotes; bytes estimados em 24 ou 52 por pacote) e
  `ECHO_REQUEST`.
- **O que o render manda ao FRR** (`proto_bfd::frr::render`, contexto `bfd` do `bfdd`, só quando
  alguém usa BFD): todos os perfis em vigor (`detect-multiplier`, `receive-interval`,
  `transmit-interval`, `passive-mode`, `minimum-ttl`) e os peers de `routing.bfd.peer`. O BGP ganha
  `bfd` (perfil) nos parâmetros de conexão e de template (`neighbor X bfd profile P`); o OSPF já
  tinha o `bfd` do interface-template (G3.4). Um perfil citado que não existe é recusado no commit.
- **O que o `bfddp` não leva e o motor põe:** autenticação (no FRR 10.7.1 ela é um TODO no
  protocolo), dampening e TTL mínimo vêm do nosso perfil, achado pela sessão: o peer, a conexão BGP
  com aquele endereço, o template OSPF daquela interface; sem ninguém (sessão digitada à mão no
  FRR), o perfil de mesmos timers.
- **Dampening para os clientes:** enquanto a sessão está "dampened" o `bfdd` ouve Down, mesmo com
  o BFD em Up.
- **Por que não (b):** `clear bgp neighbor` não segura o vizinho caído (o TCP volta se o caminho
  só perdeu um sentido); segurar exigiria `neighbor shutdown` na config pelo vty a cada queda e o
  inverso a cada subida, uma escrita de config por evento, sem cobrir OSPF. A latência de (a) é uma
  mensagem num socket Unix mais o aviso do `bfdd` ao `bgpd` por zapi, abaixo de 1 ms (**estimado**;
  o teste com o `bfdd` real na VM mede). O teste `data_plane_for_a_fake_bfdd` (um `bfdd` falso num
  socket Unix e um segundo motor como vizinho) mede o nosso lado: Up entregue, contadores, e Down
  com Diag 1 em ≤ 250 ms do fim do vizinho, com detecção de 150 ms (**medido**).
- **Sem FRR** (laboratório virtual, `--bfd-dplane off`): o motor roda sozinho os peers de
  `routing.bfd.peer`, como na G3.6a.
- **BFD com um clique:** `routing.bfd.attach {protocols?: [bgp, ospf], profile?}` põe o perfil em
  toda conexão BGP e interface-template OSPF sem perfil (próprio ou herdado).

Ficou para depois (gaps): `check_gateway=bfd` nas rotas estáticas (G3.6g, depende da G1.27f, que
cria a retirada de rota estática do kernel) e BFD no link de sync do par BNG (G3.6h).

## Desempenho e paralelismo

Medido em 2026-10-27, AMD Ryzen AI MAX+ 395 (32 threads), build release, dois motores nossos no
loopback de um namespace descartável, 50 ms × 3, 15 s em regime (teste `bfd::tests::load`,
comando no topo de `service/bfd/tests.rs`). CPU é a de cada thread de um dos motores (o outro é
simétrico), lida de `/proc/thread-self/stat` (resolução de 10 ms: o máximo por segundo é
quantizado em 4–8 %). "Jitter" é quanto o periódico saiu depois do prazo (p99 de cada sessão; o
pior e a mediana entre as sessões; o valor é o teto da faixa de 25 % do histograma).

Com `ppoll` (o código deste PR), **medido**:

| sessions | threads | CPU %/thread avg | CPU %/thread max | tx jitter p99 worst (µs) | tx jitter p99 median (µs) | rx gap p99 worst (µs) | false downs | handed over |
|---|---|---|---|---|---|---|---|---|
| 100 | 1 | 1.6 | 8.0 | 87 | 69 | 50708 | 0 | 0 |
| 100 | 2 | 0.9 | 4.0 | 3081 | 1578 | 56052 | 0 | 26 |
| 100 | 4 | 0.4 | 4.0 | 87 | 69 | 51384 | 0 | 48 |
| 100 | 8 | 0.5 | 4.0 | 136 | 69 | 50073 | 0 | 76 |
| 500 | 1 | 5.9 | 8.0 | 265 | 69 | 50712 | 0 | 0 |
| 500 | 2 | 4.5 | 12.0 | 1578 | 108 | 54477 | 0 | 199 |
| 500 | 4 | 3.5 | 8.0 | 4815 | 1972 | 56052 | 0 | 318 |
| 500 | 8 | 1.7 | 8.0 | 108 | 69 | 51647 | 0 | 351 |
| 1000 | 1 | 10.1 | 16.0 | 517 | 69 | 53205 | 0 | 0 |
| 1000 | 2 | 6.9 | 12.0 | 1262 | 108 | 54480 | 0 | 506 |
| 1000 | 4 | 4.4 | 8.0 | 136 | 69 | 52314 | 0 | 619 |
| 1000 | 8 | 2.9 | 8.0 | 6019 | 1972 | 56052 | 0 | 729 |

Antes, com `poll` em milissegundos (mesma bancada, **medido**): o jitter p99 mediano era de
1 050 µs em todos os casos (o timeout arredondado para cima em ms), contra 69 µs agora; a CPU de
1000 sessões numa thread era 5,6 % (a thread dormia mais e juntava timers), agora 10,1 %.
Ficamos com o `ppoll`: 15 vezes menos atraso por alguns % de um núcleo.

| sessions | threads | CPU %/thread avg | CPU %/thread max | tx jitter p99 worst (µs) | tx jitter p99 median (µs) | rx gap p99 worst (µs) | false downs | handed over |
|---|---|---|---|---|---|---|---|---|
| 100 | 1 | 0.8 | 4.0 | 1262 | 1052 | 51058 | 0 | 0 |
| 100 | 2 | 0.5 | 4.0 | 1262 | 1052 | 51204 | 0 | 30 |
| 100 | 4 | 0.7 | 4.0 | 4815 | 1972 | 56052 | 0 | 60 |
| 100 | 8 | 0.3 | 4.0 | 1262 | 1053 | 52681 | 0 | 76 |
| 500 | 1 | 4.3 | 8.0 | 1262 | 1055 | 51709 | 0 | 0 |
| 500 | 2 | 2.8 | 8.0 | 1262 | 1053 | 53152 | 0 | 187 |
| 500 | 4 | 1.2 | 8.0 | 1262 | 1052 | 52044 | 0 | 314 |
| 500 | 8 | 0.8 | 4.0 | 1262 | 1050 | 52513 | 0 | 386 |
| 1000 | 1 | 5.6 | 8.0 | 1262 | 1053 | 51447 | 0 | 0 |
| 1000 | 2 | 2.5 | 8.0 | 1262 | 1052 | 51927 | 0 | 454 |
| 1000 | 4 | 2.6 | 8.0 | 1262 | 1056 | 53338 | 0 | 575 |
| 1000 | 8 | 1.7 | 8.0 | 1262 | 1052 | 52328 | 0 | 749 |

Os picos de alguns ms no pior p99 de algumas linhas (2 threads com 100, 4 com 500, 8 com 1000)
são, provavelmente, preempção (não isolado): a máquina rodava ao mesmo tempo a compilação de outra sessão; nesses três casos a mediana também subiu (1,6–2 ms, a máquina inteira atrasou); nos outros nove ficou em 69–108 µs, e o intervalo recebido p99 em ≤ 56 ms em todos os casos (folga de quase 100 ms
até a detecção de 150 ms). Nenhuma queda falsa em 180 s de 100 a 1000 sessões.

`proto-bfd` (criterion, por operação, **medido**): decode 6,7 ns, encode 2,6 ns, SHA1 assinar
43 ns e conferir 39 ns, receber na sessão 5,5 ns, montar 3,2 ns; um segundo de 1000 sessões a
50 ms no timer wheel (20 000 disparos, recepção e montagem) 0,30 ms.

**Leitura:**

- **Uma thread carrega 1000 sessões a 50 ms × 3** (20 000 pacotes/s de cada lado) com ~10 %
  de um núcleo (~7 % por thread com duas) e nenhuma queda falsa. O trabalho por pacote é constante: decodificar 6,7 ns,
  receber na sessão 5,5 ns, montar 3,2 ns, SHA1 assinar 43 ns e conferir 39 ns; um segundo de
  1000 sessões no timer wheel custa 0,30 ms de CPU (bench `proto-bfd`, **medido**). O resto é
  syscall (`recvmsg`/`sendmsg`).
- **Mais threads não melhoram a latência** — o gargalo de uma sessão é o relógio, não a CPU —,
  mas dividem a CPU e isolam: uma thread ocupada atrasa só as sessões dela.
- **Padrão (`--bfd-threads auto`)**: uma thread por 500 sessões, até 4 e até o número de núcleos.
  Com poucas sessões, uma thread; a divisão entra quando um núcleo começaria a pesar.
- **Comparação com o `bfdd` do FRR**: medida na VM do laboratório (G3.6i, seção abaixo). Numa
  thread, o nosso motor gasta o mesmo que o `bfdd` (36,5 % × 32,7 % de um núcleo a 1000 sessões),
  sem queda falsa em nenhum dos dois; a diferença é que o nosso divide o trabalho em threads.
- **XDP**: não precisa. A 1000 sessões o custo é de cerca de 10 % de uma thread; BFD em XDP só faria
  sentido para dezenas de milhares de sessões ou intervalos de 3,3 ms (gap G3.6f).

## Contra o `bfdd` real (G3.6i, VM do laboratório)

Medido em 2026-10-27 na VM `corerouter-lab` (8 vCPUs EPYC-Genoa `host-model`, kernel 7.0,
virtio), FRR 10.7.1, build release. Roteiros: `scripts/frr-bfd-live.sh` (testes `#[ignore]` de
`service/bfd/live_bfdd.rs`: o motor num namespace, `zebra` + `bfdd` noutro, um veth) e
`scripts/frr-bfd-dplane-live.sh` (o nosso daemon como data plane do `bfdd` da VM, com `bgpd`).

**Interoperabilidade** (`bfdd_interop`), **medido**:

- Up nos dois lados em ~1 s; enquanto o `bfdd` pede 300 ms, mandamos a 300 ms (RFC 5880 §6.8.7);
- Poll iniciado pelo `bfdd` (timers para 50 ms): passamos a mandar a 50 ms em 242 ms; Poll
  iniciado por nós (200 ms): o `bfdd` mostra `remote-transmit-interval 200` em 8 ms; nenhuma
  mudança de estado nos dois Polls;
- SHA1 só do nosso lado: a sessão cai e não volta (o `bfdd` 10.7.1 não tem autenticação e descarta
  pacotes com o bit A, como manda o RFC 5880 §6.8.6); sem SHA1 volta em < 1 s. Autenticação BFD
  com o FRR, portanto, não existe: só entre CoreRouters (ou com quem implementa);
- o `bfdd` detecta o nosso silêncio com `control detection time expired` (114–155 ms com 50 ms ×
  3); nós detectamos o `bfdd` morto (`kill -9`) em 146 ms, Diag 1.

**Modo data plane com `bgpd`** (`frr-bfd-dplane-live.sh`): o `bfdd` da VM sobe com
`--dplaneaddr`, o daemon conecta, o eBGP com `bfd profile` sobe e a sessão BFD aparece no nosso
motor com usuário "BGP peer". Cortando só os pacotes BFD do vizinho (o TCP do BGP segue), o `bfdd`
recebe o nosso `BFD_STATE_CHANGE` 108–147 ms depois do corte (detecção de 150 ms) e o `bgpd`
derruba a sessão.

**Carga** (`bfdd_load`, 50 ms × 3, 15 s em regime), **medido**. "bfdd tx gap" é o intervalo
entre os pacotes do `bfdd` medido aqui (p99 por sessão; o histograma tem faixas de 25 %, então
56 052 µs é o teto da faixa de 50–56 ms). A CPU do `bfdd` é a do processo (`/proc/<pid>/stat`).

| sessions | our threads | our CPU %/thread | bfdd CPU % | our tx jitter p99 median (µs) | worst | bfdd tx gap p99 median (µs) | worst | our false downs | bfdd false downs |
|---|---|---|---|---|---|---|---|---|---|
| 100 | 1 | 7.5 | 5.6 | 97 | 108 | 50940 | 53587 | 0 | 0 |
| 100 | 2 | 3.7 | 5.9 | 108 | 136 | 50945 | 53498 | 0 | 0 |
| 100 | 4 | 1.9 | 6.1 | 108 | 136 | 50942 | 54603 | 0 | 0 |
| 500 | 1 | 24.8 | 20.3 | 87 | 265 | 56052 | 56052 | 0 | 0 |
| 500 | 2 | 14.7 | 23.4 | 87 | 169 | 56052 | 56052 | 0 | 0 |
| 500 | 4 | 8.1 | 24.5 | 87 | 136 | 56052 | 56052 | 0 | 0 |
| 1000 | 1 | 36.5 | 32.7 | 69 | 331 | 56052 | 56052 | 0 | 0 |
| 1000 | 2 | 25.2 | 39.7 | 87 | 212 | 56052 | 56052 | 0 | 0 |
| 1000 | 4 | 15.4 | 44.7 | 87 | 212 | 56052 | 56052 | 0 | 0 |

Nós contra nós na mesma VM (o `bfd::tests::load`, 10 s), para separar a VM do motor: 1000 sessões
numa thread custam 32,4 % (no host, 10,1 %); a syscall na VM sai ~3× mais cara, e é ela o custo
(o trabalho do protocolo é de nanossegundos, `proto-bfd` criterion).

**Leitura:**

- **CPU:** numa thread empatamos com o `bfdd` (±15 %; os dois são `recvmsg`/`sendmsg` por pacote).
  O `bfdd` é uma thread só e fica nisso; o nosso divide: com 4 threads, 15 % por thread a 1000
  sessões. A soma das threads cresce um pouco (61 % com 4 contra 36,5 % com 1: cada thread acorda
  por conta própria e junta menos pacotes por acordar). A CPU do `bfdd` também sobe quando
  dividimos (32,7 → 44,7 %): os nossos pacotes chegam mais espalhados no tempo e ele junta menos
  por acordar.
- **Regularidade:** o nosso p99 de atraso de envio fica em 69–108 µs (mediana); o do `bfdd`, visto
  daqui, cabe na faixa de 50–56 ms do histograma. Nenhuma queda falsa em 135 s de 100 a 1000
  sessões, nos dois lados.
- **O ganho que sobra é de syscalls:** `sendmmsg`/`recvmmsg` em lote nos disparos do mesmo tick
  cortariam o custo por pacote, que na VM é o que pesa. Fica na G3.6j, com esta bancada como
  medida de antes.
- **Achado do `bfdd`:** uma sessão de salto único é identificada pelo endereço do vizinho (e a
  interface), não pelo endereço local: dez blocos `peer 10.76.0.1 local-address …` viram uma
  sessão só. O nosso motor separa por (vizinho, local).

## Pesquisa

Fontes (lidas em 2026-10-27):

- RFC 5880 (BFD) e as erratas (errata.rfc-editor.org/rfc5880): 2530 (número de sequência), 7082 e
  7083 (conferir o hash antes de mudar a sequência — seguida), 6926 (nome de variável), 5205
  (detecção derruba mesmo vindo de AdminDown — retida para revisão, seguimos o texto original),
  4410 (Demand), 7240 (LocalDiag). Atualizada pelas RFCs 7419, 7880 e 8562.
- RFC 5881 (salto único: portas, TTL 255, porta de origem), RFC 5882 (aplicação genérica:
  dampening, AdminDown não é falha), RFC 5883 (multihop: porta 4784, TTL configurável), RFC 7419
  (intervalos comuns: 3,3, 10, 20, 50, 100 ms e 1 s), RFC 7130 (micro-BFD em LAG), RFC 7880
  (S-BFD).
- MikroTik RouterOS v7 (help.mikrotik.com, "BFD"): `/routing bfd configuration` (permitir ou
  proibir por interface, endereço, lista e VRF, em ordem), `/routing bfd session` (estado,
  `state-changes`, intervalos, multiplicador, pacotes), `use-bfd` na conexão BGP e no
  interface-template OSPF. Não tem: autenticação, echo, BFD em gateway de rota.
- FRR `bfdd` (docs.frrouting.org, "BFD"): perfis (`receive-interval`/`transmit-interval` 300 ms,
  `detect-multiplier` 3, `minimum-ttl` 254, `passive-mode`, `echo-mode`), autenticação
  cleartext e SHA1 (meticulous), BFD em BGP (`neighbor … bfd`, `bfd strict`), OSPF (`ip ospf
  bfd`), rotas estáticas (`ip route … bfd`), e o *distributed data plane* (`--dplaneaddr`,
  protocolo `bfddp`, porta 50700, modo cliente; o data plane externo manda e recebe e o `bfdd`
  segue avisando `bgpd`/`ospfd`).
- Junos `bfd-liveness-detection`: `minimum-interval`, `multiplier`, `holddown-interval` (adiar a
  subida para os clientes), `detection-time threshold` (alarme), autenticação SHA1 meticulosa,
  adaptação automática dos intervalos sob carga e BFD distribuído nas placas.
- Cisco IOS-XE `bfd-template single-hop|multi-hop`: `interval min-tx min-rx multiplier`,
  `authentication sha-1 keychain`, `dampening half-life reuse suppress max-suppress`.

O que adotamos e por quê:

- Nomes e sessão do MikroTik (`session`, `state-changes`, `multiplier`); perfis do FRR/Cisco
  (um lugar para os timers de BGP, OSPF e rotas), com dois de fábrica.
- Dampening do Cisco, ligado por padrão (o MikroTik e o FRR não têm; o Junos tem o
  `holddown-interval`).
- Autenticação SHA1 (o MikroTik não tem); TTL 255 sempre no salto único.
- Medidas que nenhum dos outros mostra: jitter p99 e intervalo recebido p99 por sessão, quedas em
  24 h, thread e CPU por thread.

Ficou de fora (gaps): micro-BFD em LAG (RFC 7130, G3.6d), S-BFD (RFC 7880, G3.6e), BFD em XDP e
a função Echo (G3.6f), Demand mode local.
