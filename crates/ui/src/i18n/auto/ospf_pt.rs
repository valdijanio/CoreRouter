//! Portuguese labels and explanations of the Routing › OSPF window (G3.4),
//! each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"ASBR Summary"##, r##"ASBR summary"##),
    (r##"Address"##, r##"Endereço"##),
    (r##"Age"##, r##"Idade"##),
    (r##"All"##, r##"Todos"##),
    (r##"Area"##, r##"Área"##),
    (r##"Area ID"##, r##"ID da área"##),
    (r##"Areas"##, r##"Áreas"##),
    (r##"Auth"##, r##"Autenticação"##),
    (r##"Auth ID"##, r##"ID da chave"##),
    (r##"Auth Key"##, r##"Chave"##),
    (r##"Authentication"##, r##"Autenticação"##),
    (r##"BFD"##, r##"BFD"##),
    (r##"BFD Profile"##, r##"Perfil BFD"##),
    (r##"Back to the whole map"##, r##"Volta ao mapa inteiro"##),
    (r##"Body"##, r##"Conteúdo"##),
    (r##"Comment"##, r##"Comentário"##),
    (r##"Cost"##, r##"Custo"##),
    (r##"Dead Interval"##, r##"Dead interval"##),
    (r##"Default Cost"##, r##"Custo padrão"##),
    (r##"Diagnose"##, r##"Diagnosticar"##),
    (r##"Diagnosing…"##, r##"Diagnosticando…"##),
    (r##"Disabled"##, r##"Desativado"##),
    (r##"External"##, r##"Externo"##),
    (r##"Fit"##, r##"Ajustar"##),
    (r##"Hello Interval"##, r##"Hello interval"##),
    (r##"ID"##, r##"ID"##),
    (r##"Instance"##, r##"Instância"##),
    (r##"Instances"##, r##"Instâncias"##),
    (r##"Interface"##, r##"Interface"##),
    (r##"Interface Template"##, r##"Interface template"##),
    (r##"Interface Templates"##, r##"Interface templates"##),
    (r##"Interfaces"##, r##"Interfaces"##),
    (r##"Interfaces Now"##, r##"Interfaces agora"##),
    (r##"Key Chain"##, r##"Key chain"##),
    (r##"Key Chains"##, r##"Key chains"##),
    (r##"Keys"##, r##"Chaves"##),
    (r##"Kind"##, r##"Tipo"##),
    (r##"LSDB"##, r##"LSDB"##),
    (r##"MTU Ignore"##, r##"Ignorar MTU"##),
    (r##"Match"##, r##"Casa com"##),
    (r##"NSSA"##, r##"NSSA"##),
    (r##"NSSA Translate"##, r##"Tradução NSSA"##),
    (r##"Name"##, r##"Nome"##),
    (r##"Neighbors"##, r##"Vizinhos"##),
    (r##"Network"##, r##"Network"##),
    (r##"Network Type"##, r##"Tipo de rede"##),
    (r##"Networks"##, r##"Redes"##),
    (r##"New Interface Template"##, r##"Novo interface template"##),
    (r##"New Key Chain"##, r##"Nova key chain"##),
    (r##"New OSPF Area"##, r##"Nova área OSPF"##),
    (r##"New OSPF Instance"##, r##"Nova instância OSPF"##),
    (r##"New…"##, r##"Novo…"##),
    (r##"Next Hop"##, r##"Próximo salto"##),
    (r##"No LSDB to draw yet"##, r##"Ainda não há LSDB para desenhar"##),
    (r##"No Summaries"##, r##"Sem sumários"##),
    (r##"No neighbor: add an instance, an area and an interface template."##, r##"Nenhum vizinho: crie uma instância, uma área e um interface template."##),
    (r##"OSPF Area"##, r##"Área OSPF"##),
    (r##"OSPF Instance"##, r##"Instância OSPF"##),
    (r##"Originate Default"##, r##"Originar padrão"##),
    (r##"Originator"##, r##"Originador"##),
    (r##"Out Filter Chain"##, r##"Chain de saída"##),
    (r##"Passive"##, r##"Passiva"##),
    (r##"Prefix"##, r##"Prefixo"##),
    (r##"Priority"##, r##"Prioridade"##),
    (r##"Ranges"##, r##"Ranges"##),
    (r##"Reading the database from the routing daemon…"##, r##"Lendo a base do daemon de roteamento…"##),
    (r##"Redistribute"##, r##"Redistribuir"##),
    (r##"Rotation"##, r##"Rotação"##),
    (r##"Router"##, r##"Router"##),
    (r##"Router ID"##, r##"Router ID"##),
    (r##"Routes"##, r##"Rotas"##),
    (r##"Sending Now"##, r##"Enviando agora"##),
    (r##"Sequence"##, r##"Sequência"##),
    (r##"Show"##, r##"Mostrar"##),
    (r##"State"##, r##"Estado"##),
    (r##"Subscriber Pools"##, r##"Pools de assinantes"##),
    (r##"Summary"##, r##"Summary"##),
    (r##"Topology"##, r##"Topologia"##),
    (r##"Type"##, r##"Tipo"##),
    (r##"Uptime"##, r##"Tempo de pé"##),
    (r##"Used By"##, r##"Usada por"##),
    (r##"VRF"##, r##"VRF"##),
    (r##"Version"##, r##"Versão"##),
    (r##"Warnings"##, r##"Avisos"##),
    (r##"Why this neighbor is not Full, with the RFC section that says so"##, r##"Por que este vizinho não chega a Full, com a seção da RFC que diz isso"##),
    (r##"Why this path?"##, r##"Por que esse caminho?"##),
    (r##"agrees"##, r##"confere"##),
    (r##"cost"##, r##"custo"##),
    (r##"daemon's route"##, r##"rota do daemon"##),
    (r##"dead in"##, r##"dead em"##),
    (r##"differs"##, r##"difere"##),
    (r##"layout"##, r##"layout"##),
    (r##"priority"##, r##"prioridade"##),
    (r##"retransmit"##, r##"retransmissão"##),
    (r##"virtual lab sample"##, r##"amostra do laboratório virtual"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"ospf.area"##, r##"## O que é
Uma área OSPF (`/routing ospf area`). A prévia mostra as interfaces dela e o que a mudança derruba."##),
    (r##"ospf.area.area_id"##, r##"## O que é
O id de 32 bits da área, escrito pontuado (0.0.0.1) ou como número. A **0.0.0.0 é o backbone**: toda outra área se liga a ela."##),
    (r##"ospf.area.default_cost"##, r##"## O que é
Em stub/NSSA: o custo da rota padrão que o ABR anuncia."##),
    (r##"ospf.area.instance"##, r##"## O que é
A instância a que a área pertence."##),
    (r##"ospf.area.name"##, r##"## O que é
O nome da área (os templates a citam por ele)."##),
    (r##"ospf.area.no_summaries"##, r##"## O que é
Em stub/NSSA: nem rotas entre áreas, só a padrão ("totally stubby"). Menos LSAs nos roteadores pequenos."##),
    (r##"ospf.area.nssa_translate"##, r##"## O que é
Em NSSA: se este ABR traduz LSAs tipo 7 em tipo 5 para o resto da rede. `candidate` (padrão): eleito entre os ABRs (RFC 3101 §3.1)."##),
    (r##"ospf.area.ranges"##, r##"## O que é
Ranges da área: as redes dela sumarizadas pelo ABR para as outras áreas (RFC 2328 §12.4.3)."##),
    (r##"ospf.area.type"##, r##"## O que é
`default`; `stub`: sem rotas externas, só uma padrão do ABR (RFC 2328 §3.6); `nssa`: stub que aceita externas próprias como LSA tipo 7 (RFC 3101).

## Cuidado
Todos os roteadores da área precisam do mesmo tipo (os bits E/N do Hello): trocar derruba as adjacências da área. O backbone não pode ser stub nem NSSA."##),
    (r##"ospf.diagnose"##, r##"## O que é
Por que um vizinho não chega a Full, a partir da config, do estado do daemon e dos pacotes vistos, com a seção da RFC:
- MTU diferente (parado em ExStart, §10.6);
- hello/dead, área, máscara, bits E/N do tipo de área (§10.5, RFC 3101 §2.3);
- autenticação e key id (§D.3);
- router id duplicado (§C.1);
- tipo de rede diferente (um elege DR, o outro é ptp)."##),
    (r##"ospf.disabled"##, r##"## O que é
Fica na config e não roda."##),
    (r##"ospf.instance"##, r##"## O que é
Uma instância OSPF (`/routing ospf instance`). A prévia mostra em quais interfaces ela roda e o que a mudança faz (inclusive adjacências que caem)."##),
    (r##"ospf.instance.name"##, r##"## O que é
O nome da instância (as áreas a citam por ele)."##),
    (r##"ospf.instance.originate_default"##, r##"## O que é
Anunciar a rota padrão: `never`, `if-installed` (só enquanto este roteador tem uma) ou `always`."##),
    (r##"ospf.instance.out_filter_chain"##, r##"## O que é
A chain do `/routing filter` por onde passam as rotas redistribuídas. No OSPF valem os testes de prefixo (`dst`, listas) e `set bgp-med` (a métrica externa); testes de AS path ou communities são recusados no commit."##),
    (r##"ospf.instance.redistribute"##, r##"## O que é
Rotas anunciadas no OSPF como externas (LSA tipo 5): `connected`, `static`, `bgp`, `kernel`.

## Cuidado
Redistribuir o BGP inteiro no OSPF é quase sempre um erro: use uma `out_filter_chain`."##),
    (r##"ospf.instance.router_id"##, r##"## O que é
O identificador de 32 bits do roteador no OSPF, único no AS (RFC 2328 §C.1).

## Recomendado
Fixe um (o endereço de uma loopback). Vazio, o daemon escolhe, e trocar o router id derruba **todas** as adjacências."##),
    (r##"ospf.instance.subscriber_pools"##, r##"## O que é
Anuncia os pools de endereços PPPoE e IPoE, cada um sumarizado em uma rota externa só (o núcleo vê uma rota por pool, não uma por assinante). A rota sai sozinha quando o último assinante do pool cai."##),
    (r##"ospf.instance.version"##, r##"## O que é
2: OSPFv2, para IPv4 (RFC 2328). 3: OSPFv3, para IPv6 (RFC 5340). Uma instância de cada por VRF."##),
    (r##"ospf.instance.vrf"##, r##"## O que é
A VRF em que a instância roteia (`main` por padrão)."##),
    (r##"ospf.keychain"##, r##"## O que é
Uma key chain: várias chaves com janelas de envio e aceite. As chaves se acrescentam com `routing.ospf.keychain.key.add`."##),
    (r##"ospf.keychain.keys"##, r##"## O que é
As chaves: id e algoritmo (o texto da chave nunca aparece)."##),
    (r##"ospf.keychain.name"##, r##"## O que é
O nome da key chain (os templates a citam por ele)."##),
    (r##"ospf.keychain.rotation"##, r##"## O que é
Se a rotação derrubaria vizinho: um momento sem chave de envio, chave enviada antes de ser aceita, ou a chave antiga deixando de ser aceita quando a nova começa a ser enviada (o vizinho com relógio atrasado cai)."##),
    (r##"ospf.keychain.sending"##, r##"## O que é
A chave enviada agora, pelo relógio do roteador (UTC). Nenhuma: as adjacências que usam a chain caem."##),
    (r##"ospf.keychain.used_by"##, r##"## O que é
Os templates que usam a key chain."##),
    (r##"ospf.lsa.age"##, r##"## O que é
Segundos desde a origem (renovado a cada 30 min; some aos 60, RFC 2328 §14)."##),
    (r##"ospf.lsa.body"##, r##"## O que é
O que o LSA diz: enlaces, roteadores da LAN, prefixo e métrica."##),
    (r##"ospf.lsa.id"##, r##"## O que é
O Link State ID: um router id, o endereço do DR ou uma rede, conforme o tipo."##),
    (r##"ospf.lsa.originator"##, r##"## O que é
O roteador que originou o LSA."##),
    (r##"ospf.lsa.sequence"##, r##"## O que é
O número de sequência: o maior é o mais novo."##),
    (r##"ospf.lsa.type"##, r##"## O que é
`router` (1: os enlaces de um roteador), `network` (2: os roteadores de uma LAN), `summary` (3: rede de outra área), `asbr-summary` (4), `external` (5), `nssa-external` (7). `self`: originado por nós."##),
    (r##"ospf.neighbor.address"##, r##"## O que é
O endereço do vizinho no enlace (no OSPFv3, o link-local)."##),
    (r##"ospf.neighbor.interface"##, r##"## O que é
A interface por onde o vizinho é visto."##),
    (r##"ospf.neighbor.router_id"##, r##"## O que é
O router id do vizinho: o identificador de 32 bits dele no OSPF, único no AS (RFC 2328 §C.1)."##),
    (r##"ospf.neighbor.state"##, r##"## O que é
O estado da adjacência (RFC 2328 §10.1): Down, Init, 2-Way, ExStart, Exchange, Loading, Full; e o papel do vizinho no enlace (DR, BDR, DROther, ptp).

## Normal
Full com o DR e o BDR; 2-Way com os demais numa LAN (RFC 2328 §10.4).

## Cuidado
Parado em ExStart/Exchange é quase sempre MTU diferente (§10.6); em Init, o vizinho não aceita os nossos Hellos."##),
    (r##"ospf.neighbor.uptime"##, r##"## O que é
Tempo no estado atual (em Full: há quanto tempo a adjacência está de pé)."##),
    (r##"ospf.path"##, r##"## O que é
O caminho mais curto até um endereço ou router id sobre a LSDB, com o custo somado salto a salto (Dijkstra, RFC 2328 §16.1), conferido com a rota que o daemon calculou (`agrees`)."##),
    (r##"ospf.route.cost"##, r##"## O que é
O custo total (E2: a métrica externa, e entre parênteses o custo até o ASBR)."##),
    (r##"ospf.route.kind"##, r##"## O que é
`intra-area` (da própria área), `inter-area` (de outra área, via ABR), `ext-1`/`ext-2` (redistribuídas; na E2 só a métrica externa conta)."##),
    (r##"ospf.route.nexthop"##, r##"## O que é
O próximo salto e a interface."##),
    (r##"ospf.route.prefix"##, r##"## O que é
O destino."##),
    (r##"ospf.tab.areas"##, r##"## O que é
As áreas de cada instância. A 0.0.0.0 é o backbone; as outras se ligam a ele por um ABR (roteador de borda de área)."##),
    (r##"ospf.tab.instances"##, r##"## O que é
Um processo OSPF por versão (2: IPv4, RFC 2328; 3: IPv6, RFC 5340) e por VRF: router id, redistribuição e rota padrão."##),
    (r##"ospf.tab.keychains"##, r##"## O que é
Key chains: várias chaves, cada uma com uma janela de envio e outra de aceite, para trocar a chave sem derrubar vizinho (RFC 8177).

## Como trocar sem queda
- acrescente a chave nova aceita desde já e enviada a partir de uma data;
- deixe a antiga aceita por um tempo depois dessa data;
- a coluna **Rotation** avisa se algum momento fica sem chave ou se a antiga deixa de ser aceita cedo demais."##),
    (r##"ospf.tab.lsdb"##, r##"## O que é
O banco de estado de enlace (`/routing ospf lsa` do RouterOS): todo LSA que o roteador tem, por tipo e área. É dele que cada roteador calcula as rotas (SPF, RFC 2328 §16)."##),
    (r##"ospf.tab.neighbors"##, r##"## O que é
As adjacências que o OSPF formou (`/routing ospf neighbor` do RouterOS), ao vivo. Selecione uma e use **Diagnose** para ver por que ela não chega a Full."##),
    (r##"ospf.tab.routes"##, r##"## O que é
As rotas que o OSPF calculou. Selecione uma (ou digite um endereço) para ver **por que esse caminho**: o custo somado salto a salto."##),
    (r##"ospf.tab.templates"##, r##"## O que é
Quais interfaces rodam OSPF e como: casadas por nome, interface list ou rede. **O primeiro template que casa ganha**, então a ordem importa."##),
    (r##"ospf.tab.topology"##, r##"## O que é
A rede como a LSDB a descreve: roteadores, redes de trânsito e o custo de cada enlace. Clique num roteador para ver o caminho até ele."##),
    (r##"ospf.template"##, r##"## O que é
Um interface template (`/routing ospf interface-template`). A prévia mostra **quais interfaces ele pega agora**, o tipo de rede sugerido para cada uma, a autenticação ausente ou fraca, `passive` sugerido em interface de cliente e as adjacências que caem (com Safe Mode)."##),
    (r##"ospf.template.area"##, r##"## O que é
A área em que as interfaces casadas entram."##),
    (r##"ospf.template.auth"##, r##"## O que é
`simple` (a chave em claro), `md5` (RFC 2328 §D), `sha1`…`sha512` (HMAC-SHA, RFC 5709; no v3, o trailer da RFC 7166).

## Recomendado
`sha256` (padrão quando só a chave é dada).

## Cuidado
`simple` e `md5` são inseguros. Sem autenticação, qualquer um no enlace forma adjacência e injeta rotas."##),
    (r##"ospf.template.auth_id"##, r##"## O que é
O id da chave no pacote (0..255 no v2). Precisa ser igual nos vizinhos. Vazio: 1 (o RouterOS usa 0 quando vazio)."##),
    (r##"ospf.template.auth_key"##, r##"## O que é
Uma chave só, selada na hora: nunca volta para a tela, o log ou o journal. Vazio mantém a atual. Para trocar sem queda, use uma key chain."##),
    (r##"ospf.template.bfd"##, r##"## O que é
O perfil BFD que vigia as adjacências: detecta a falha em menos de um segundo em vez de esperar o dead interval (RFC 5882)."##),
    (r##"ospf.template.cost"##, r##"## O que é
O custo da interface (1..65535): o SPF soma os custos e fica com o menor caminho. Vazio: calculado pela banda."##),
    (r##"ospf.template.dead_interval"##, r##"## O que é
Segundos sem Hello até o vizinho ser dado como caído (padrão 40, 4× o hello). **Precisa ser igual nos vizinhos.**"##),
    (r##"ospf.template.hello_interval"##, r##"## O que é
Segundos entre Hellos (padrão 10). **Precisa ser igual nos vizinhos** (RFC 2328 §10.5)."##),
    (r##"ospf.template.interfaces"##, r##"## O que é
Nomes de interface ou interface lists que este template pega (separados por vírgula)."##),
    (r##"ospf.template.keychain"##, r##"## O que é
Uma key chain no lugar de uma chave: troca de chave sem derrubar vizinho."##),
    (r##"ospf.template.matched"##, r##"## O que é
As interfaces que este template pega agora (um template mais abaixo não as recebe)."##),
    (r##"ospf.template.mtu_ignore"##, r##"## O que é
Aceita MTU diferente na troca de DD (RFC 2328 §10.6).

## Cuidado
O certo é igualar o MTU; ignorar pode fazer pacotes grandes sumirem."##),
    (r##"ospf.template.networks"##, r##"## O que é
Uma interface com endereço dentro de uma destas redes casa (IPv4 no v2, IPv6 no v3)."##),
    (r##"ospf.template.passive"##, r##"## O que é
Anuncia as redes da interface mas não manda Hello: ninguém forma adjacência por ela.

## Recomendado
Em interfaces de cliente (PPPoE, DHCP) e loopbacks: um cliente não consegue injetar rota."##),
    (r##"ospf.template.priority"##, r##"## O que é
Prioridade na eleição de DR (0: nunca é DR). Não vale em ptp."##),
    (r##"ospf.template.type"##, r##"## O que é
`broadcast` (LAN, elege DR), `ptp` (dois roteadores: /30, /31, PPP), `nbma` (sem multicast, vizinhos estáticos), `ptmp`, `virtual-link` (RFC 2328 §15).

## Recomendado
`ptp` em enlace de dois roteadores: sem eleição de DR, a adjacência sobe até 40 s mais cedo e não há LSA de rede.

## Cuidado
As duas pontas precisam do mesmo tipo."##),
    (r##"ospf.template.warnings"##, r##"## O que é
O que merece um olhar: autenticação ausente ou fraca, um tipo de rede melhor, `passive` em interface de cliente, template escondido por outro anterior."##),
    (r##"ospf.topology.legend"##, r##"## O que é
Círculos são roteadores (o nosso em destaque, vizinhos em verde, ABR/ASBR com anel), quadrados são redes de trânsito; os números são os custos dos enlaces (a/b quando as pontas diferem). Arraste para mover, role para aproximar, clique num roteador para ver o caminho."##),
];
