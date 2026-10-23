# CGNAT (G2.3)

NAT44 de operadora: cada assinante recebe um endereço público e uma faixa de portas própria, sem
log por conexão. Determinístico por padrão (RFC 7422); por blocos sob demanda (PBA) como opção
(G2.3c). O "Quem era?" responde IP público + porta + data/hora → assinante, que é o que o Marco
Civil (Lei 12.965/2014, art. 13) cobra do provedor de conexão.

Estado: **G2.3a**, **G2.3b** e **G2.3c** (este documento descreve o que entrou e o plano das partes seguintes).

## 1. Como funciona

### 1.1 A fórmula (uma só, para todos)

`corerouter_model::cgnat::Layout` é a função de mapeamento. Fica no L0 (`crates/model`), é pura
(sem I/O, sem relógio, compila em wasm) e é usada por todos:

- o engine: comandos, "Quem era?", tabela de correspondência, planner;
- o backend do kernel (`hal-linux`), que carrega os elementos dos mapas;
- o caminho XDP (`dataplane-ebpf`, G2.5), que vai calcular o mesmo mapeamento.

API estável:

| Função | O que faz |
|---|---|
| `Layout::new(inside, outside, port_range, ports)` | monta a geometria, ou diz por que não fecha (`LayoutError::Capacity` traz quantos IPs públicos faltam) |
| `forward(assinante) → Slot {public, first_port, last_port}` | ida (RFC 7422 §2, f1) |
| `reverse(público, porta) → assinante` | volta (f2), sem estado |
| `slot(i)`, `subscriber(i)`, `subscriber_index(ip)` | por índice |
| `locate(público, porta) → (endereço, bloco)` | o bloco de uma porta (PBA usa os mesmos blocos) |
| `entries()` | todos os pares, em ordem (o que vira elementos do mapa) |
| `per_address()`, `capacity()`, `public_used()` | os números do planner |
| `cgnat::plan(...)` | só a aritmética, para o planner sem listas de endereços |

A geometria:

1. Os assinantes são numerados na **ordem em que as faixas foram escritas** (`inside`): 0, 1, 2…
2. Os IPs públicos (`outside`) são numerados do mesmo jeito.
3. A faixa de portas (`port_range`, padrão 1024–65535: RFC 4787 REQ-3 tira as portas bem
   conhecidas) é cortada em blocos de `ports_per_subscriber` portas. Cada IP tem
   `blocos = ⌊faixa / portas⌋` blocos; a sobra do fim (por exemplo 1535 portas com 1000 por
   assinante) não é usada.
4. O assinante `i` fica com o IP `⌊i / blocos⌋` e o bloco `i mod blocos` dele.

Exemplo: 100.64.0.0/22 (1024 assinantes) em 203.0.113.0/28 (16 IPs), 1000 portas cada → 64
assinantes por IP, os 16 IPs usados. 100.64.0.65 → 203.0.113.1, portas 2024–3023.

TCP, UDP e o identificador do ICMP (RFC 5508 §3.1) usam a mesma faixa. O kernel aplica a faixa
de portas do `snat` aos ids do ICMP (`nf_nat_l4proto_unique_tuple`), o que foi **medido** no teste
em netns. Outros protocolos (GRE, ESP) saem com o mesmo IP público, sem porta. Assim a regra do IP
pareado (RFC 6888 REQ-2) vale para todos.

Por que essa ordem? A RFC 7422 §2 lista vários algoritmos e deixa a escolha ao operador:
sequencial, escalonado, round-robin, intercalado e aleatório com chave.

- Escolhemos o sequencial **por assinante**: vizinhos de numeração ficam no mesmo IP público.
  Assim um IP público responde por uma sequência contígua de assinantes, que é o que o setor de
  abuso lê.
- A RFC (§5) observa que a alocação sequencial facilita adivinhar o vizinho. Dentro da faixa, o
  kernel escolhe a porta ao acaso, o que atende a RFC 6056 e a RFC 7857 §9.
- O algoritmo vai junto em cada época do histórico, como a §3 pede. Um segundo algoritmo, se
  vier, é um campo novo do pool, sem mudar os antigos.

### 1.2 Exceções 1:1

`ip.firewall.cgnat.exception.add {subscriber, public}` dá ao assinante um IP público só dele,
fora de qualquer pool. Ele sai com as portas originais e recebe todo o tráfego de entrada desse
IP (o "IP fixo" de cliente empresarial).

O slot dele no pool **continua reservado e sem uso**. Assim, criar ou apagar uma exceção não
muda o mapeamento de mais ninguém.

### 1.3 EIM, EIF e hairpin (RFC 4787)

São por pool:

- **`endpoint_independent_mapping`** (padrão ligado), REQ-1: a mesma porta pública para todos os
  destinos de uma porta UDP do assinante. Jogos, VoIP e WebRTC dependem disso.
  - O Linux sozinho já reaproveita o mapeamento enquanto a conexão anterior vive
    (`find_appropriate_src`).
  - Nós o mantemos por 5 min mesmo depois que ela some: REQ-5 pede um timer de no mínimo 2 min
    e recomenda 5.
- **`endpoint_independent_filtering`** (padrão desligado), REQ-8: qualquer host da Internet
  alcança um mapeamento vivo ("full cone").
  - Desligado, só responde quem o assinante procurou.
  - EIF exige EIM: a validação recusa EIF sem EIM.
- **`hairpin`** (padrão ligado), REQ-9: um assinante alcança outro pelo IP:porta público, e quem
  recebe vê o IP:porta público de quem mandou.

Como é feito (RFC 4787 §4, sem módulo fora da árvore do kernel):

1. Uma chain `filter` em `postrouting`, prioridade `srcnat + 10`, grava a conexão UDP nova em dois
   mapas dinâmicos com timeout:
   - `eim_<id>`: público.porta → assinante.porta;
   - `eimr_<id>`: o inverso.
2. Precisa ser `filter`: uma segunda chain `nat` não roda depois que a primeira fez a tradução. A
   pesquisa verificou isso.
3. No `postrouting`, `snat … map @eimr_<id>` vem antes da fórmula.
4. No `prerouting`, `dnat … map @eim_<id>` atende o EIF e o hairpin. Sem EIF, essa regra só vale
   para origem dentro do pool, ou seja, só o hairpin.

### 1.4 O que o kernel recebe

Tudo fica na tabela `ip corerouter_cgnat`, separada da `inet corerouter` do firewall, para uma
nunca substituir a outra. Por pool, **um mapa e poucas regras**, nunca uma regra por assinante (o
script RouterOS clássico tem duas por assinante: 76 mil linhas para um /21).

| Objeto | O que guarda | Para quê |
|---|---|---|
| `d_<id>` | assinante → `público . porta_inicial-porta_final`, um elemento por assinante | **uma** regra `snat` para todos os protocolos |
| `pub_<id>` | as faixas públicas (conjunto de intervalos) | o `forward` descarta pacote para o bloco público que nenhuma conexão reclama; sem isso, o bloco roteado ao CGN voltaria pela rota padrão |
| `eim_<id>` / `eimr_<id>` | os mapeamentos UDP vivos (seção 1.3) | EIM, EIF e hairpin |
| `x_1to1` / `x_1to1_in` | as exceções | antes de qualquer pool |

A regra `snat` de cada pool vale para todos os protocolos:

- TCP e UDP recebem a faixa nas portas, e o ICMP no id de consulta;
- GRE, ESP e os demais saem só com o endereço, porque o kernel ignora a faixa de portas de quem
  não tem porta.

Assim o IP pareado (RFC 6888 REQ-2) vale para todos.

Como chega ao kernel (G2.3b):

- `hal-linux` fala **nfnetlink direto**, num lote atômico, sem o programa `nft`. A decisão e os
  números estão em `docs/architecture.md` §1.2.1.
- Quando só elementos mudam (portas por assinante, mais assinantes na faixa, o endereço de uma
  exceção), o lote leva só os elementos que saíram e os que entraram. Os mapeamentos UDP vivos
  sobrevivem.
- Qualquer outra mudança troca a tabela inteira no mesmo lote.
- Se o kernel recusar o lote incremental (alguém esvaziou a tabela), a tabela inteira vai em
  seguida.

`ip.firewall.cgnat.rules` mostra exatamente o que o kernel tem ("Ver regras geradas"): o texto e
as mensagens saem da mesma descrição (`corerouter_firewall::program::Table`), e o `nft list table
ip corerouter_cgnat` lê o mesmo.

O `nft` recusaria a regra única: ele exige `meta l4proto {…}` para mapear portas; o kernel não.

### 1.5 "Quem era?" ao longo do tempo

A RFC 7422 §3 pede que o CGN **registre toda mudança** de faixas internas e externas, portas por
assinante, algoritmo e portas reservadas, com data e hora. Também é a armadilha que Juniper e F5
documentam: mudou o pool, o mapeamento antigo some, e a pergunta de ontem passa a ter outra
resposta.

O registro:

- Cada commit que muda os pools ou as exceções em produção grava uma **época** no journal
  próprio `journal-cgnat-history.log`. A época é a seção inteira, poucas centenas de bytes.
- Rollback e desfazer do Safe Mode passam pelo mesmo commit e também entram no journal.
- O journal fica guardado por `history_days` (padrão 365).
- Ele fica fora das revisões da config, que guardam só 64.

`ip.firewall.cgnat.who-was {public, port, time?}` procura a época em vigor em `time` e aplica a
fórmula dela. A resposta traz:

- o assinante e o pool (ou `exception`);
- o slot inteiro;
- desde e até quando aquele mapeamento valeu;
- quando existe, quem tinha o IP do assinante por DHCP naquela hora: MAC, host-name e Option 82
  circuit-id/remote-id, do histórico de concessões G4.2b.

O login PPPoE entra quando houver BNG (G7.x).

O tempo aceita Unix ou RFC 3339 com fuso (`2026-05-03T14:02:00-03:00`); sem fuso é UTC, e a
resposta é sempre em UTC. Ofício judicial costuma vir em horário de Brasília: escreva o
`-03:00`.

### 1.6 Validação (antes do commit)

`proto-cgnat::checks`, com selos na GUI.

**Erro** (recusa o commit):
- assinantes em dois pools;
- dois pools com o mesmo IP público (dariam as mesmas portas);
- público dentro de assinantes;
- capacidade que não fecha: a mensagem diz quantos IPs faltam;
- EIF sem EIM;
- `out_interface` inexistente;
- exceção num IP de pool, duplicada ou em laço;
- limites de tamanho.

**Aviso:**
- portas abaixo de 1024 (RFC 4787 REQ-3);
- assinantes fora de 100.64.0.0/10 (RFC 6598) e do espaço privado;
- "público" em espaço privado;
- menos de 300 portas por assinante;
- IP do próprio roteador no pool (as conexões dele usam portas do pool).

No modo blocos, mais assinantes que blocos é aviso ("oversubscribed"), não erro.

**OK:** o selo de capacidade (assinantes, por IP, IPs usados e sobrando).

`pool.set` responde `remapped`: quantos assinantes mudam de IP ou portas. Mudar
`ports_per_subscriber` remapeia todo mundo.

Depois de aplicar, o `hal-linux` faz duas coisas:

- **derruba as conexões dos remapeados** pelo ctnetlink, como o VyOS faz com `conntrack -D`. Elas
  ainda levam a tradução antiga; derrubadas, o "Quem era?" da época nova fica exato;
- **esquece os mapeamentos UDP vivos** do pool, porque eles apontariam para portas que agora podem
  ser de outro assinante. Cada um é reaprendido no próximo pacote.

Aumentar a faixa de assinantes no fim não remapeia ninguém e não derruba nada.

### 1.7 Modo blocos (PBA, G2.3c)

`mode: blocks` dá a cada assinante, **sob demanda**, um bloco de `ports_per_subscriber` portas, com a
mesma geometria da fórmula (`Layout::block`). A RFC 6888 §5 (REQ-13/14) e a RFC 7422 §1 tratam disso.

**Primeiro pacote:**

- Um assinante sem bloco tem o primeiro pacote segurado numa fila do netfilter, a número **7422**,
  por uma regra `filter` em `postrouting` com prioridade `srcnat - 10`.
- O serviço `cgnat` do daemon atende a fila: pede o bloco ao engine (`Session::cgnat_block_for`), que
  o põe no mapa `d_<id>` do kernel, e solta o pacote.
- O pacote segue para o NAT e já acha o elemento. Medido em netns.
- Sem ninguém atendendo a fila, o pacote **cai**. Ele nunca sai com o IP privado: a regra não tem
  `bypass`.
- Sem bloco livre, ou com o assinante no máximo de blocos, o pacote cai também (RFC 6888 REQ-11). O
  ICMP code 1 da REQ-11b é a G2.7.

**Pareado (REQ-2):** todos os blocos de um assinante ficam no mesmo IP público. O primeiro vai para o
IP com menos blocos.

**Cresce:** quando o bloco atual passa de 80 % de uso (o protocolo mais cheio), o assinante ganha
outro, até `max_blocks`. As conexões novas vão para o novo; as velhas continuam no antigo.

**Solta e segura:**

- Um bloco sem conexão por `block_timeout` é liberado.
- O bloco liberado não vai para ninguém por **120 s** (RFC 6888 REQ-8), para uma conexão atrasada não
  cair noutro assinante.
- Quando a geometria do pool muda (outras portas, outros IPs), os blocos velhos são liberados na hora,
  sem quarentena, e as conexões deles são derrubadas, como num remapeamento determinístico.

**Log por bloco:**

- Cada alocação e liberação vira uma linha no log do roteador, tópico `cgnat`:
  - `ALLOC 100.64.0.9 -> 203.0.113.1:1024-2023 pool pba (first packet)`;
  - `RELEASE … (idle)`.
- Para mandar ao syslog remoto (RFC 5424):
  - `system.logging.action.add {name: "isp", remote: <ip>}`;
  - `system.logging.add {topics: ["cgnat"], action: "isp"}`.
- O mesmo vai no journal `journal-cgnat-blocks.log`, que o "Quem era?" lê e que reconstrói os blocos
  no boot. No boot, os blocos são reinstalados no kernel antes de qualquer alocação nova.
- O formato segue a RFC 6888 §4: assinante, IP externo, faixa de portas e data; sem destino
  (REQ-12).

**Quem era? em blocos:** o bloco que cobria aquela porta daquele IP naquela hora, pelo histórico de
blocos (`ip.firewall.cgnat.block.history`).

### 1.8 Alerta de portas esgotadas

Vale para os dois modos (RFC 7422 §2.2).

**O que conta:** a cada 10 s, o engine lê o conntrack e conta, por assinante, as portas públicas
distintas em uso, por protocolo; vale o protocolo mais cheio.

**Quando dispara:**

- no modo determinístico, quando o assinante passa de `alert_percent` (padrão 90 %) do seu slot;
- no modo blocos, quando ele já está no máximo de blocos.

**O que fica registrado:**

- Cada **travessia** do limite vira uma linha `warning` no log, tópico `cgnat`.
- A travessia também entra em `ip.firewall.cgnat.alert.list`, com:
  - portas usadas, % e pico;
  - quantas vezes cruzou;
  - primeira e última vez.

O kernel não avisa quando uma conexão nova não acha porta livre: só conta em `insert_failed`. O alerta
mostra o crescimento desse contador desde o início.

## 2. Comandos

| Comando | O que faz |
|---|---|
| `ip.firewall.cgnat.pool.add/set/remove/list` | pools; `list` traz os números e os selos |
| `ip.firewall.cgnat.exception.add/set/remove/list` | 1:1 |
| `ip.firewall.cgnat.set/get` | `history_days`; `get` resume pools e histórico |
| `ip.firewall.cgnat.lookup {subscriber}` | ida: o slot do assinante agora |
| `ip.firewall.cgnat.who-was {public, port, time?}` | volta, no tempo |
| `ip.firewall.cgnat.mapping.list {pool, offset?, count?, subscriber?, public?}` | tabela de correspondência por página (≤ 5000 linhas) |
| `ip.firewall.cgnat.history.list` | as épocas (RFC 7422 §3) |
| `ip.firewall.cgnat.rules {pool?}` | o nftables gerado |
| `ip.firewall.cgnat.block.list {pool?, subscriber?}` | blocos ativos (modo blocos), o atual de cada assinante e há quanto tempo está ocioso |
| `ip.firewall.cgnat.block.history {subscriber?, public?, port?, from?, to?}` | o log de blocos (alocação e liberação) |
| `ip.firewall.cgnat.alert.list` / `alert.clear` | assinantes no limite de portas e o `insert_failed` do kernel |
| `tool.ip-calc.cgnat.plan {inside, outside, ports_per_subscriber?, port_range?, mode?, preview?}` | o planner (Tools › IP Calculator): números, checagens, sugestões, prévia e os parâmetros do `pool.add`; aceita quantidades (`"4096"`) |
| `tool.ip-calc.cgnat.export {…, format: csv \| text \| routeros \| nft}` | a tabela do plano em CSV, texto imprimível, script RouterOS ou o nftables |

Exemplo:

```sh
cargo run -p corerouter-cli -- --connect 127.0.0.1:7979 run ip.firewall.cgnat.pool.add \
  '{"name":"cgnat1","inside":"100.64.0.0/22","outside":"203.0.113.0/28","ports_per_subscriber":1000}'
cargo run -p corerouter-cli -- --connect 127.0.0.1:7979 run ip.firewall.cgnat.who-was \
  '{"public":"203.0.113.1","port":2500,"time":"2026-10-23T14:02:00-03:00"}'
```

## 3. Testes

- **Mapeamento (model, proptest):**
  - ida e volta em toda porta de borda;
  - nenhum bloco repetido;
  - nada fora da faixa e da sobra;
  - a ordem escrita é a ordem do mapa;
  - texto hostil nas faixas.
- **Validação (`proto-cgnat`):** cada erro e aviso da seção 1.6.
- **Comandos (`crates/engine/tests/cgnat.rs`):**
  - sucesso, validação de cada parâmetro e rollback;
  - "Quem era?" antes e depois de mudar o pool;
  - modo transacional;
  - o histórico atravessando um reinício.
- **Parâmetros lixo:** o `command_sweep` cobre.
- **Blocos (`crates/engine/tests/cgnat_blocks.rs`, no lab):**
  - os assinantes "online" do lab recebem blocos pareados, espalhados pelos IPs;
  - os pesados ganham um segundo bloco no mesmo IP;
  - o ocioso solta o bloco, com log, e não recebe o mesmo de volta antes de 120 s;
  - os blocos sobrevivem a um reinício;
  - pool esgotado recusa; pool mudado solta;
  - alertas: uma linha por travessia.
- **Kernel (`crates/hal-linux/tests/netns_cgnat.rs`, netns sem root):**
  - assinantes num namespace saem pelo NAT deste até um servidor num terceiro;
  - UDP, TCP e ICMP saem no IP e na faixa da fórmula, e a volta da fórmula sobre o que o servidor
    viu dá o assinante;
  - a exceção 1:1 mantém a porta;
  - EIM: a mesma porta pública para dois destinos;
  - EIF: um estranho alcança o mapeamento;
  - hairpin: quem recebe vê o IP público de quem mandou;
  - tirar os pools apaga a tabela;
  - modo blocos: sem ouvinte da fila, o primeiro pacote cai; com ouvinte, sai no bloco alocado; o
    bloco sobrevive à troca da tabela;
  - esgotamento (G2.3e, RFC 6888 REQ-3/11): com 64 portas, 80 fluxos dão exatamente 64, todos no slot
    do assinante (nunca uma porta do vizinho), e o kernel conta as recusas;
  - remapear mata as conexões antigas mesmo com um ping no meio (o bug do #178).
- **Bateria de propriedades (`crates/engine/tests/cgnat_battery.rs`, G2.3e):**
  - para formas aleatórias de pool, o que o planner diz que cabe é o que o pool criado com os
    parâmetros dele faz;
  - a prévia é a tabela do pool;
  - todo assinante volta pelo "Quem era?" a partir do próprio slot (primeira, última e porta do
    meio);
  - entrada hostil no planner, na exportação e no "Quem era?" vira erro de parâmetro, nunca panic.
- **Fast path (G2.4):** veja `docs/fastpath.md` §3.
- **Desempenho:** seção 6 (benches `netns_cgnat`, `netns_cgnat_pps`, `cgnat_who_was`).

## 4. Plano das próximas partes

| Parte | O que entra |
|---|---|
| G2.3b (feito) | nftables por nfnetlink, sem o binário `nft`; diferença de elementos; uma regra para todos os protocolos; remapeados derrubados e mapeamentos UDP esquecidos; números em `docs/architecture.md` §1.2.1 |
| G2.2a (feito) | IP › Firewall › Connections (ctnetlink: lista, filtros, assinantes com mais conexões, kill, timeouts, uso da tabela, coluna Via) |
| G2.3c (feito) | Modo blocos (fila 7422 + alocador pareado, cresce, solta com quarentena de 120 s), log por bloco (log do roteador e syslog), "Quem era?" pelo histórico de blocos, alerta de portas |
| G2.3d (feito) | Janela IP › Firewall › CGNAT: pools, exceções, Quem era?, mapeamento, histórico, alertas; ⓘ em cada campo |
| G6.9a (feito) | Tools › IP Calculator: Subnet, IPv6/PD, CGNAT planner (criar pool, exportar, ver regras, script RouterOS); comandos `tool.ip-calc.*` |
| G2.4a (feito) | Fast path (flowtable em software, offload em hardware mlx5) e a janela Fast path |
| G2.3e (feito) | Bateria final de bugs e desempenho e o relatório (seção 6) |

## 5. Pesquisa

### MikroTik RouterOS v7

Fonte: [NAT](https://help.mikrotik.com/docs/spaces/ROS/pages/3211299/NAT) (seção CGNAT).

- A receita oficial cita a RFC 7422 e é um **script que gera um `src-nat` por assinante**, com
  `to-addresses` e `to-ports`, organizado em chains de jump. Não usa `netmap`.
- A comunidade faz o mesmo com `netmap` por /29, com geradores como o
  [made4it](https://www.made4it.com.br/cgnat/). São ~6 mil regras por /21, todas geradas por
  script.
- Não há PBA nem log por bloco; os pedidos no fórum são antigos
  ([bulk port allocation](https://forum.mikrotik.com/t/feature-request-bulk-port-allocation-for-cgnat/155965),
  [sticky NAT](https://forum.mikrotik.com/t/cgnat-src-port-reuse-to-different-destinations-sticky-nat/151471)).
- `endpoint-independent-nat` existe só para UDP e precisa de um par de regras srcnat/dstnat.
- "Quem era?" no MikroTik: abrir o script e fazer a conta à mão.

### Outros

- **VyOS** ([CGNAT](https://docs.vyos.io/en/latest/configuration/nat/cgnat.html)):
  - comandos `nat cgnat pool external … per-user-limit port` (padrão 2000) e
    `show nat cgnat allocation`;
  - por baixo, mapas de intervalo do nftables, uma regra por protocolo, verificação de capacidade
    e `conntrack -D` ao mudar. É o desenho mais próximo do nosso.
- **Juniper** (`deterministic-port-block-allocation`, PBA):
  - `block-size`, `max-blocks-per-address`, `active-block-timeout`, `interim-logging-interval`;
  - logs `JSERVICES_NAT_PORT_BLOCK_ALLOC/RELEASE/ACTIVE`;
  - comandos de ida e volta `show services nat deterministic-nat internal-host / nat-port-block`;
  - a documentação manda arquivar o mapeamento antigo, porque mudar a config remapeia.
- **Cisco IOS-XE**:
  - `ip nat settings pap`, `bpa set-size … step-size …`;
  - log só por NetFlow v9 (IEs 361/363/364 para o bloco).
- **A10** (`fixed-nat`): `ports-per-user`, `usable-nat-ports` e um `dynamic-pool-size` para quando
  o bloco fixo acaba.
- **F5** (LSN):
  - modos `napt`, `deterministic` e `pba`;
  - `dnatutil` faz a volta com a hora;
  - bugs públicos ensinam: volta errada com faixas maiores que /16 e estado intercalado entre
    núcleos (por isso a nossa fórmula é uma só, testada por proptest).
- **Jool** (`pool4`): limite de iterações na busca de porta livre, para um pool cheio não queimar
  CPU.

### RFCs

Toda a cadeia, com errata:

- [RFC 7422](https://www.rfc-editor.org/rfc/rfc7422):
  - §2: f1 e f2, e a MAY de usar a faixa para os ids de ICMP;
  - §2.2: alarmes de utilização;
  - §3: registrar mudanças;
  - errata 4211, editorial;
- [RFC 6888](https://www.rfc-editor.org/rfc/rfc6888), BCP 127, atualiza a 4787:
  - REQ-2: IP pareado;
  - REQ-3: pools não contíguos;
  - REQ-4: limite de portas por assinante;
  - REQ-7: EIF recomendado;
  - REQ-8: porta liberada segura por 120 s;
  - REQ-11: sem mapeamento, descarta e SHOULD mandar ICMP *code 1*;
  - REQ-12: não registrar destinos;
  - §5: blocos;
- [RFC 7857](https://www.rfc-editor.org/rfc/rfc7857):
  - EIM/EIF por protocolo;
  - porta aleatória (§9);
  - RST (§2.2);
- [RFC 4787](https://www.rfc-editor.org/rfc/rfc4787):
  - REQ-1: EIM;
  - REQ-3: portas abaixo de 1024;
  - REQ-5: timer UDP ≥ 2 min, 5 min recomendado;
  - REQ-8: EIF/ADF;
  - REQ-9: hairpin com o endereço externo;
- [RFC 5382](https://www.rfc-editor.org/rfc/rfc5382) (TCP: ocioso ≥ 2 h 4 min, transitório ≥ 4
  min);
- [RFC 5508](https://www.rfc-editor.org/rfc/rfc5508) (ICMP: id traduzido, timer ≥ 60 s);
- [RFC 6598](https://www.rfc-editor.org/rfc/rfc6598) (100.64.0.0/10, §4);
- [RFC 8512](https://www.rfc-editor.org/rfc/rfc8512) (nomes do YANG de NAT; não tem tipo
  "determinístico").

Kernel:

- `nf_nat_core.c`:
  - `get_unique_tuple` tenta a porta original, depois reaproveita o mapeamento da mesma origem e
    só então sorteia na faixa;
  - sem tupla livre, a conexão cai em silêncio e conta em `insert_failed`. Por isso o alerta de
    portas esgotadas (G2.3c) não pode depender de o kernel avisar;
- `nf_nat_proto.c`: faixa aplicada ao id do ICMP;
- [`nf_flowtable`](https://docs.kernel.org/networking/nf_flowtable.html) (G2.4).

### O que adotamos e o que melhoramos

- **Adotado:**
  - um objeto de primeira classe compilado em mapas: o do VyOS, mas com uma regra para os três
    protocolos em G2.3b;
  - verificação de capacidade no commit, dizendo quantos IPs faltam;
  - ida e volta como comandos;
  - as defaults da RFC.
- **Melhor que os outros:**
  - "Quem era?" **no tempo**, com o histórico de definições que a RFC 7422 §3 pede;
  - o MAC e o Option 82 do DHCP na mesma resposta;
  - `remapped` antes de aplicar;
  - exceções que não remapeiam ninguém;
  - prévia do nftables;
  - tudo transacional, com Safe Mode e rollback.
- **Fica para depois (vira gap):**
  - ICMP code 1 quando as portas acabam (RFC 6888 REQ-11b): o kernel descarta sem avisar, e
    responder exige um caminho no plano de dados (nfqueue ou XDP, G2.5);
  - porta liberada segura por 120 s (REQ-8) no modo blocos;
  - PCP (REQ-9);
  - login PPPoE no "Quem era?" (com o BNG);
  - testes em hardware real (seção 6).

## 6. Desempenho

Tudo **medido** em 2026-10-23, build release, num namespace sem root, Ryzen AI MAX+ 395 (32 threads),
kernel 7.0. A máquina estava com carga 8–16 (CIs de outras sessões): os números comparam
configurações entre si, num núcleo. Não são o teto de um servidor.

### 6.1 Carga da tabela (G2.3b)

| Operação | netlink | `nft -f` |
|---|---|---|
| 64 Ki assinantes | 66 ms | 303 ms |
| um assinante a mais | 0,155 ms | 2,40 ms |

Tabela completa em `docs/architecture.md` §1.2.1 (bench `netns_cgnat`).

### 6.2 Pacotes por segundo pelo NAT (bench `netns_cgnat_pps`)

Um gerador `AF_PACKET` em Rust escreve quadros UDP de 64 bytes de 255 assinantes (um fluxo
cada) numa veth. Eles atravessam o CGNAT e saem por outra veth, e os `tx_packets` dela contam.
Antes de medir, cada fluxo recebe uma resposta (escrita do outro lado a partir da tupla do
conntrack): UDP só fica `established` depois de uma resposta, e só aí entra no flowtable.

| Caminho | pps (mediana) |
|---|---|
| só roteamento (sem conntrack) | ~830 mil |
| CGNAT (conntrack + mapa da fórmula) | ~650 mil |
| CGNAT + fast path em software (G2.4) | ~1,04 milhão (254 de 255 fluxos no flowtable) |

O fast path devolve o custo do NAT e do conntrack: com ele o CGNAT fica no nível do
roteamento puro (o limite passa a ser a veth num núcleo).

### 6.3 Conexões novas por segundo

Cada quadro é uma conexão nunca vista (outra porta de origem de um dos 255 assinantes). Entre as
rodadas, fora do tempo, as conexões novas são apagadas: cada rodada começa com ~20 conexões por
assinante, como num roteador.

| Caminho | conexões novas/s |
|---|---|
| só conntrack, sem NAT | ~551 mil |
| CGNAT, EIM desligado | ~274 mil |
| CGNAT (EIM ligado, o padrão) | ~255 mil |

- O NAT custa cerca de metade da criação da conexão: a escolha de uma porta livre no slot do
  assinante (`nf_nat`).
- O EIM (o `update` no mapa dinâmico) custa pouco, ~7 %.
- **Slot quase cheio:** sem apagar entre as rodadas, as conexões se acumulam até perto das 1000
  portas de cada assinante, e a taxa cai para **~13 mil/s**, ~20× mais lenta. Com quase todas as
  portas ocupadas, o kernel tenta várias antes de achar uma livre (ou desistir).
- **Consequência operacional:** o alerta de portas (padrão 90 %) avisa antes desse ponto.
  Assinantes que vivem perto do limite pedem mais portas por assinante (o planner mostra quantas
  cabem).

### 6.4 "Quem era?" (bench `cgnat_who_was`, engine)

| Pool | Histórico | Latência |
|---|---|---|
| 64 Ki assinantes | 1 época | 1,4 µs |
| 64 Ki assinantes | 365 épocas (uma mudança por dia, um ano) | 3,0 µs |

É a busca da época em vigor mais o `Layout::reverse`: não depende do tráfego nem de log, porque não
há log por conexão (RFC 7422 §2).

### 6.5 Memória por conexão (**estimado**)

O `struct nf_conn` com as extensões de NAT, contabilidade e timestamp ocupa ~320–400 bytes no slab
`nf_conntrack` (fonte do kernel 6.x/7.x). O tamanho medido exige ler `/proc/slabinfo` como root, e
fica no G2.3f: `sudo grep nf_conntrack /proc/slabinfo` (coluna `objsize`).

Para 1 milhão de conexões, ~400 MB. Os mapas do CGNAT são ~200 B por assinante (**estimado**): 13 MB
para 64 Ki assinantes.

### 6.6 O que veth mede e o que só hardware mostra

- **A veth mede** o custo relativo no kernel: NAT × roteamento × fast path, criação de conexão,
  efeito do slot cheio e o tempo de aplicar a tabela.
- **A veth não mede:**
  - vazão por porta com RSS em vários núcleos;
  - custo de interrupção e DMA;
  - limite da tabela de CT de uma placa;
  - offload em hardware (veth recusa `flags offload`);
  - comportamento com milhões de conexões vivas e a memória real.

Isso é o G2.3f (CGNAT em servidor real) e o G2.4b (ConnectX em switchdev).
