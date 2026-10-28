# Simulador de rede (G3.7)

Tools › Network Simulator: N roteadores virtuais rodando OSPF, BGP e BFD **simplificados** sobre
uma topologia de enlaces ponto a ponto, num relógio virtual. O operador corta um enlace, derruba
um roteador, muda um custo e vê a rede convergir — na GUI nativa, no navegador (wasm) e no CI.

**Simulação — não é a rede real.** O simulador nunca substitui o FRR em produção e nunca toca no
roteador real: o estado vive só na memória do `Session` (`s.ext`), some ao reiniciar, e toda
resposta de `tool.netsim.get` traz o selo `badge`.

## Desenho

```
tool.netsim.* (engine/src/cmd/netsim.rs)
        │
        ▼
engine::netsim::Lab ── um Session por roteador virtual (VirtualHal, mesmos comandos e validações)
        │                 └─ node_config(): lê a running de cada um → NodeConfig
        ▼
corerouter-netsim::Simulation (L2, puro, wasm)
        ├─ Node: fila de eventos, portas, OSPF, BGP, FIB
        ├─ janelas + barreira (paralelo no nativo, pool de threads)
        └─ linha do tempo, falhas, convergência
```

- **Cada roteador virtual é um CoreRouter de verdade.** O laboratório cria um `Session` sobre o
  `VirtualHal` por nó e configura-o **por comandos** (`system.identity.set`, `interface.loopback.add`,
  `ip.address.add`, `routing.filter.rule.add`, `routing.bgp.instance.set`,
  `routing.bgp.connection.add`), numa transação por roteador. `tool.netsim.node.run` executa
  qualquer comando dentro de um roteador virtual (com as validações dele); depois o simulador lê a
  running de novo (`engine::netsim::node_config`): endereços IPv4, a instância BGP `default`, as
  conexões com os templates aplicados (`BgpConnection::effective`) e o `/routing filter`,
  compilado pelo avaliador do `proto-bgp` (o mesmo da prévia da G3.2b).
- **Camadas.** O motor (`crates/netsim`, `corerouter-netsim`) é L2, ao lado dos `proto-*`: puro,
  sem E/S, compila para `wasm32-unknown-unknown`. Depende do `model` e, lateralmente (permitido em
  `xtask/src/layers.rs`), do `proto-bgp`, para rodar os filtros reais e para conferir o processo de
  decisão contra `proto_bgp::decision`. O engine (L3) guarda o laboratório e os comandos; a UI (L5)
  só chama os comandos.
- **Não usa `proto-ospf` nem `proto-bfd`.** As máquinas simplificadas ficam no `netsim` (as do
  FRR continuam sendo as de produção). O modelo de configuração OSPF da G3.4 entrou na `main`
  depois deste desenho; ler área, custo e interfaces passivas dele nos nós é a G3.7d.

## Eventos discretos, relógio virtual e determinismo

- O tempo é `u64` em microssegundos e só anda quando `Simulation::advance(até, orçamento)` manda.
  A GUI chama `tool.netsim.tick {wall_ms}` a cada quadro: com o relógio em "play", ele avança
  `wall_ms × speed` (×1 a ×3600). `tool.netsim.clock {action: step}` processa uma janela.
- Cada roteador tem a sua fila (`queue.rs`): mais cedo primeiro, empates pela ordem de inserção.
- **Determinístico.** Toda escolha "aleatória" (fase do primeiro hello, fase do BFD, perda) vem
  de SplitMix64 sobre a semente e o roteador; nenhum mapa é percorrido em ordem de hash; a barreira
  entrega na ordem dos roteadores. A mesma semente e os mesmos comandos dão a mesma linha do tempo
  em qualquer máquina e qualquer número de threads (teste `same_seed_same_run_on_any_number_of_threads`,
  que compara a impressão digital de todas as FIBs e da linha do tempo com 1, 4 e 8 threads).
- **Orçamento.** Um comando processa no máximo 400 mil eventos (`EVENT_BUDGET`) com o lock do
  `Session`; volta `done: false` e o cliente pede de novo. Parar e retomar dá a mesma execução
  (`a_budget_stops_and_resumes_the_same_run`).

## Paralelismo: janelas conservadoras

Nenhuma mensagem chega a outro roteador antes da menor latência de enlace (o *lookahead*). A
simulação repete: acha o evento mais cedo `t0`, aplica as falhas de `t0`, deixa cada roteador
processar os seus eventos em `[t0, t0 + lookahead)` — independentes dentro da janela — e, na
barreira, entrega o que eles enviaram, na ordem dos roteadores (PDES conservadora, como o
"YAWNS"/janelas síncronas da literatura de simulação paralela).

- **Pool persistente** (`pool.rs`, só no nativo): N threads nomeadas `netsim-<k>` vivem com a
  simulação. Numa janela com 16 ou mais roteadores com trabalho, os roteadores ativos vão para os
  trabalhadores por `mem::take` (cópia da struct, sem alocação), em rodízio, e voltam na barreira.
  Nada é compartilhado e nenhum lock é segurado enquanto eles rodam. A primeira versão criava
  threads com `thread::scope` a cada janela e ficava **mais lenta** que uma thread (500 roteadores:
  11,3 s × 4,9 s, **medido**).
- **No navegador**, uma thread só (o pool nem compila para wasm).
- **O que fica serial**: a barreira (entrega por roteador e mensagem, roteamento salto a salto das
  mensagens BGP pelas FIBs). Medida à parte (`Stats::barrier_ns`): ~2 % do tempo com 500
  roteadores, então não compensa dividi-la ainda.

## O que cada protocolo guarda

**OSPFv2** (RFC 2328, uma área, só ponto a ponto, `ospf.rs`):
- hellos a cada 10 s, dead 40 s (§9.5, §10.5, padrões do FRR), checagem de 2-Way;
- um router-LSA por roteador com os enlaces p2p e as redes stub (§12.4.1.1–12.4.1.2; loopback como
  /32 de custo 0, como o FRR);
- inundação com número de sequência (§13), e o roteador que recebe uma cópia mais nova do próprio
  LSA pula para depois dela (§13.4);
- MinLSInterval de 5 s (§12.4, FRR `timers throttle lsa all 5000`);
- LSAs inundados no mesmo instante saem num único LS Update por interface;
- SPF com a checagem de 2-Way do §16.1 (2)(b) e ECMP até 16;
- o throttle do FRR (`timers throttle spf 0 50 5000`, `ospf_spf_calculate_schedule`: espera 0, hold
  de 50 ms que cresce ×1, ×2, ×3… até 5 s sob churn).

Fora: DR/BDR, troca DD/LSR/LSAck (o banco inteiro é inundado no Full), MinLSArrival, envelhecimento,
áreas, LSAs externos, autenticação.

**BGP-4** (RFC 4271, IPv4 unicast, `bgp.rs`):
- OPEN/KEEPALIVE com checagem do AS do par (§6.2), hold e keepalive (§4.4, §10; vence o menor hold
  dos dois OPEN), UPDATE com anúncios e retiradas, detecção de laço de AS (§9.1.2), prepend e
  next-hop-self no eBGP, `nexthop-choice=force-self` no iBGP, split horizon do iBGP (sem refletor),
  next hop resolvido pelo IGP (inválido sem rota);
- processo de decisão na ordem do FRR (`bgp_path_info_cmp`), conferido contra
  `proto_bgp::decision::compare` por proptest (`decision_matches_proto_bgp`), inclusive o passo
  "older path" do eBGP;
- as chains de `/routing filter` de cada conexão, rodadas pelo avaliador do `proto-bgp`;
  RFC 8212 (eBGP sem chain não aceita nem envia; chain inexistente recusa tudo, como um route-map
  ausente no FRR);
- *fast external failover* na perda de portadora e BFD nos vizinhos de um salto;
- cada tentativa de conexão tem um número (como uma conexão TCP nova): um OPEN repetido da mesma
  tentativa só reenvia o KEEPALIVE. Sem isso a primeira resposta perdida (a rota de volta ainda não
  existia) travava o par em OpenSent/OpenConfirm — o teste `every_seed_converges` roda 20 sementes.

Fora: TCP de verdade (o OPEN que chega é a conexão), colisão do §6.8, MRAI (o do FRR é 0), route
refresh, graceful restart, multipath, IPv6, refletor de rotas.

**BFD** (RFC 5880, analítico): numa falha silenciosa, cada ponta com BFD percebe
`intervalo × multiplicador` (300 ms × 3, padrão do `bfdd`) depois do último pacote recebido, que
chegou em algum momento do último intervalo; a sessão volta ~2 intervalos depois do reparo
(§6.2). Não simulamos cada pacote: com 500 roteadores seriam ~6 600 eventos por segundo virtual,
e o resultado (quando a queda é vista) é o mesmo.

## Falhas e linha do tempo

`tool.netsim.fault {kind}`:
- `link-cut`: falha silenciosa, as portas continuam up. Só hello, BFD ou hold timer percebem.
- `link-down`: perda de portadora; as duas pontas reagem na hora.
- `link-restore`: reparo do enlace.
- `node-down`: roteador travado; os vizinhos percebem por BFD, hello ou hold.
- `node-up`: o roteador volta.
- `latency` e `loss`: atraso e perda; a perda é por hash, determinística.

A linha do tempo (`tool.netsim.timeline`, paginada por `after`) registra, com o instante virtual e
o roteador:
- a falha;
- `bfd-down`/`bfd-up`;
- `adj-up`/`adj-down` com o motivo (dead timer, BFD, interface, 1-way);
- `igp-changed` (o SPF mudou rotas);
- `bgp-up`/`bgp-down` com o motivo, e `bgp-error` (AS errado, recusado pelo par), uma vez só;
- `bgp-best` (o processo de decisão mudou melhores caminhos: total, +, −, trocados).

O resumo `convergence` do `tool.netsim.get` dá, desde a última falha: quando ela foi percebida,
a última mudança do OSPF, a última do BGP, a soma de prefixos BGP melhores antes e agora, e há
quanto tempo nada muda. Exemplo do quadrado (corte silencioso R1–R2 com BFD): percebido em
+0,79 s, OSPF reconvergiu em +0,80 s, BGP sem perda (as sessões iBGP são entre loopbacks).

## "E se?" com a config real

`tool.netsim.import {name?}` cria um roteador virtual com a configuração **deste** roteador, digitada
como comandos:
- endereços IPv4, criando interfaces tipo loopback para nomes que o roteador virtual não tem;
- prefix-lists, community-lists e regras de `/routing filter`;
- a instância BGP, os templates (pais primeiro) e as conexões.

A chave MD5 continua selada no roteador real e não é copiada; o RPKI fica de fora (não há
validador no laboratório). Comando recusado pelo roteador virtual volta na lista `refused`, sem
abortar. Depois ligam-se roteadores virtuais às interfaces dele (`tool.netsim.link.add`) e
simula-se corte ou custo **antes** de mexer em produção.

## Cenário exportado como teste

`tool.netsim.export {expect: true}` devolve o cenário: os roteadores com os comandos digitados em
cada um, os enlaces, as falhas com o instante e, com `expect`, o que cada roteador tem no fim
(rotas BGP instaladas e sessões estabelecidas). `tool.netsim.load` reconstrói tudo. O teste
`crates/engine/tests/netsim_scenarios.rs` roda cada `crates/engine/tests/netsim/*.json` até o
`run_ms` e exige o mesmo `expect`. Basta salvar um export lá para virar teste de CI. O exemplo
incluído é o quadrado com o enlace R4–R1 cortado aos 60 s.

## Topologias prontas

`tool.netsim.new {preset, nodes, bgp, seed}`:
- `square`, a da janela: R1–R3 são um provedor (AS 65000, OSPF num triângulo com BFD, iBGP em
  malha entre loopbacks, R2 origina 100.64.0.0/16) e R4 é o upstream (AS 65100, eBGP com R1 e R3,
  origina 198.51.100.0/24 e 203.0.113.0/24);
- `ring`, `mesh`, `star` e `grid`, de 2 a 500 roteadores, com `bgp: none | ebgp` (cada roteador
  no seu AS, eBGP em todo enlace) `| ibgp` (malha completa, até 30).

Endereços: /30 por enlace em 10.0.0.0/9, loopback 10.255.x.y/32, um /24 por roteador em
172.16.0.0/12. O editor acrescenta roteadores (`tool.netsim.node.add`) e enlaces
(`tool.netsim.link.add`, que digita os /30 nos dois roteadores e cria o eBGP quando os AS diferem)
e muda custo, BFD, latência e perda (`tool.netsim.link.set`).

## Desempenho e paralelismo

Ver a seção `## perf` de `docs/changes/G3.7-netsim-core.md`, consolidada em `docs/perf.md`.
Ferramentas: `cargo run --release -p corerouter-netsim --example measure -- 10 100 500` e
`cargo xtask bench` (`crates/netsim/benches/netsim.rs`).

## Pesquisa

- **Cisco Modeling Labs (CML)**, https://developer.cisco.com/modeling-labs/. Roda as imagens
  reais (IOSv, IOS XRv, NX-OSv) em VMs, com editor de topologia, injeção de falhas por enlace
  (latência, perda, jitter) e API. Fidelidade total, mas cada nó custa GBs de RAM e não há relógio
  virtual nem determinismo.
  - *Adotamos*: o editor na própria janela, a falha por enlace, o "o que muda se eu cortar isto".
- **Juniper vLabs / vMX / cRPD**, https://jlabs.juniper.net/vlabs/. Laboratórios prontos com Junos
  real (vMX pesado; cRPD em contêiner, só o plano de controle).
  - *Adotamos*: cenários prontos (`preset`) e a ideia do plano de controle isolado, sem o de dados.
- **GNS3 / EVE-NG**, https://www.gns3.com/, https://www.eve-ng.net/. Emuladores com imagens
  reais (o RouterOS CHR inclusive), topologia desenhada, captura de pacotes. Mesmo custo e a mesma
  falta de reprodutibilidade dos anteriores.
  - *Adotamos*: o desenho da topologia com o estado do enlace (cores, tracejado no corte), na
    janela da parte seguinte (G3.7b).
- **Batfish**, https://www.batfish.org/ (https://github.com/batfish/batfish). **Não emula**: lê
  as configurações e calcula as tabelas de controle, com perguntas como "este tráfego passa?",
  "o que acontece se este enlace cair?" (análise de falhas) e comparação entre duas versões da
  config. Rápido e determinístico, mas sem tempo: não diz *quando* a rede converge.
  - *Adotamos*: o "e se?" sobre a config real **antes** de aplicar, a configuração lida dos próprios
    roteadores (aqui, os `Session` virtuais) e o resultado determinístico que vira teste.
  - *Acrescentamos* o que o Batfish não tem: o tempo (BFD × dead timer × hold timer na linha do
    tempo).
- **containerlab** (https://containerlab.dev) e os topotests do FRR (munet): topologias de
  contêineres com o FRR real, o caminho do teste de fidelidade (G3.7c, na VM do laboratório).
- **MikroTik**: não tem simulador. O operador usa CHR no GNS3/EVE-NG; a referência de nomes e
  comportamento continua sendo o RouterOS v7, que os roteadores virtuais executam pelos mesmos
  comandos.
- **Simulação paralela por eventos discretos**: janelas conservadoras com lookahead (Chandy–Misra,
  janelas síncronas do YAWNS; o ns-3 também tem simulador distribuído conservador),
  https://www.nsnam.org/docs/models/html/distributed.html.
- **RFCs**:
  - RFC 2328: OSPF (§9.5, §10.5, §12.4, §13, §13.4, §16.1); errata vista, nenhuma muda o que
    modelamos.
  - RFC 4271: BGP (§4.4, §6.2, §9.1.2, §9.2, §10), atualizada pelas RFC 6286, 6608, 6793, 7606,
    7607, 8212, 8654 e 9072. Da cadeia, entra no simulador só a RFC 8212.
  - RFC 5880: BFD (§6.2, §6.8.1).
  - RFC 8212: política padrão do eBGP.

**Fica para depois (gaps):**
- G3.7b: a janela Tools › Network Simulator;
- G3.7c: o teste de fidelidade com o FRR real na VM (bloqueado pelo disco da VM);
- G3.7d: ler a config OSPF da G3.4 e o `use_bfd` da G3.2d/G3.6 nos nós; IPv6 e refletor de rotas.
