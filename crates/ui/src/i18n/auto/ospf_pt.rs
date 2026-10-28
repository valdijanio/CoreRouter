//! Portuguese labels and explanations of the Routing › OSPF window (G3.4),
//! each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"ASBR Summary"##, r##"ASBR summary"##),
    (r##"Address"##, r##"Endereço"##),
    (r##"Adjacency SIDs"##, r##"Adjacency SIDs"##),
    (r##"After Convergence"##, r##"Depois da convergência"##),
    (r##"Age"##, r##"Idade"##),
    (r##"All"##, r##"Todos"##),
    (r##"Announced"##, r##"Anunciado"##),
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
    (r##"Backup"##, r##"Reserva"##),
    (r##"Before"##, r##"Antes"##),
    (r##"Behavior"##, r##"Comportamento"##),
    (r##"Body"##, r##"Conteúdo"##),
    (r##"Comment"##, r##"Comentário"##),
    (r##"Cost"##, r##"Custo"##),
    (r##"Coverage"##, r##"Cobertura"##),
    (r##"Cut the link to"##, r##"Cortar o link para"##),
    (r##"Dead Interval"##, r##"Dead interval"##),
    (r##"Default Cost"##, r##"Custo padrão"##),
    (r##"Diagnose"##, r##"Diagnosticar"##),
    (r##"Diagnosing…"##, r##"Diagnosticando…"##),
    (r##"Disabled"##, r##"Desativado"##),
    (r##"External"##, r##"Externo"##),
    (r##"Fast Reroute"##, r##"Fast Reroute"##),
    (r##"Fit"##, r##"Ajustar"##),
    (r##"Force"##, r##"Forçar"##),
    (r##"Hello Interval"##, r##"Hello interval"##),
    (r##"ID"##, r##"ID"##),
    (r##"In"##, r##"Entra"##),
    (r##"Index"##, r##"Índice"##),
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
    (r##"LDP"##, r##"LDP"##),
    (r##"LSDB"##, r##"LSDB"##),
    (r##"Label"##, r##"Rótulo"##),
    (r##"Label Stack"##, r##"Pilha de rótulos"##),
    (r##"Loopback SIDs"##, r##"SIDs das loopbacks"##),
    (r##"MSD"##, r##"MSD"##),
    (r##"MTU Ignore"##, r##"Ignorar MTU"##),
    (r##"Match"##, r##"Casa com"##),
    (r##"NSSA"##, r##"NSSA"##),
    (r##"NSSA Translate"##, r##"Tradução NSSA"##),
    (r##"Name"##, r##"Nome"##),
    (r##"Neighbors"##, r##"Vizinhos"##),
    (r##"Network"##, r##"Network"##),
    (r##"Network SIDs"##, r##"SIDs da rede"##),
    (r##"Network Type"##, r##"Tipo de rede"##),
    (r##"Networks"##, r##"Redes"##),
    (r##"New Interface Template"##, r##"Novo interface template"##),
    (r##"New Key Chain"##, r##"Nova key chain"##),
    (r##"New OSPF Area"##, r##"Nova área OSPF"##),
    (r##"New OSPF Instance"##, r##"Nova instância OSPF"##),
    (r##"New Prefix SID"##, r##"Novo prefix SID"##),
    (r##"New…"##, r##"Novo…"##),
    (r##"Next Hop"##, r##"Próximo salto"##),
    (r##"No LSDB to draw yet"##, r##"Ainda não há LSDB para desenhar"##),
    (r##"No Summaries"##, r##"Sem sumários"##),
    (r##"No neighbor: add an instance, an area and an interface template."##, r##"Nenhum vizinho: crie uma instância, uma área e um interface template."##),
    (r##"Node MSD"##, r##"MSD do nó"##),
    (r##"OSPF Area"##, r##"Área OSPF"##),
    (r##"OSPF Instance"##, r##"Instância OSPF"##),
    (r##"Originate Default"##, r##"Originar padrão"##),
    (r##"Originator"##, r##"Originador"##),
    (r##"Out"##, r##"Sai"##),
    (r##"Out Filter Chain"##, r##"Chain de saída"##),
    (r##"Passive"##, r##"Passiva"##),
    (r##"Pick a neighbor: the routes that leave by it are shown with the backup they take and the path after OSPF converges."##, r##"Escolha um vizinho: as rotas que saem por ele aparecem com o reserva que usam e o caminho depois que o OSPF converge."##),
    (r##"Prefix"##, r##"Prefixo"##),
    (r##"Prefix SID"##, r##"Prefix SID"##),
    (r##"Prefix SIDs"##, r##"Prefix SIDs"##),
    (r##"Primary"##, r##"Principal"##),
    (r##"Priority"##, r##"Prioridade"##),
    (r##"Protected"##, r##"Protegido"##),
    (r##"Ranges"##, r##"Ranges"##),
    (r##"Reading the database from the routing daemon…"##, r##"Lendo a base do daemon de roteamento…"##),
    (r##"Reason"##, r##"Motivo"##),
    (r##"Redistribute"##, r##"Redistribuir"##),
    (r##"Rotation"##, r##"Rotação"##),
    (r##"Router"##, r##"Router"##),
    (r##"Router ID"##, r##"Router ID"##),
    (r##"Routes"##, r##"Rotas"##),
    (r##"SR Routers"##, r##"Roteadores SR"##),
    (r##"SR disabled"##, r##"SR desativado"##),
    (r##"SR off"##, r##"SR desligado"##),
    (r##"SR on"##, r##"SR ligado"##),
    (r##"SRGB"##, r##"SRGB"##),
    (r##"SRLB"##, r##"SRLB"##),
    (r##"Segment Routing"##, r##"Segment Routing"##),
    (r##"Segment Routing is off. Turn it on for the OSPFv2 instance: the preview shows what moves to labels before anything changes."##, r##"O Segment Routing está desligado. Ligue-o na instância OSPFv2: a prévia mostra o que passa a ir por rótulo antes de qualquer mudança."##),
    (r##"Segments"##, r##"Segmentos"##),
    (r##"Sending Now"##, r##"Enviando agora"##),
    (r##"Sequence"##, r##"Sequência"##),
    (r##"Settings…"##, r##"Configurar…"##),
    (r##"Show"##, r##"Mostrar"##),
    (r##"Simulate"##, r##"Simular"##),
    (r##"Simulate Link Cut"##, r##"Simular corte de link"##),
    (r##"State"##, r##"Estado"##),
    (r##"Subscriber Pools"##, r##"Pools de assinantes"##),
    (r##"Summary"##, r##"Summary"##),
    (r##"TI-LFA"##, r##"TI-LFA"##),
    (r##"TI-LFA off"##, r##"TI-LFA desligado"##),
    (r##"TI-LFA · link"##, r##"TI-LFA · enlace"##),
    (r##"TI-LFA · node"##, r##"TI-LFA · nó"##),
    (r##"TI-LFA…"##, r##"TI-LFA…"##),
    (r##"The router fails"##, r##"O roteador cai"##),
    (r##"This Router"##, r##"Este roteador"##),
    (r##"Topology"##, r##"Topologia"##),
    (r##"Turn Off…"##, r##"Desligar…"##),
    (r##"Turn On…"##, r##"Ligar…"##),
    (r##"Type"##, r##"Tipo"##),
    (r##"Unprotected"##, r##"Sem proteção"##),
    (r##"Uptime"##, r##"Tempo de pé"##),
    (r##"Used By"##, r##"Usada por"##),
    (r##"VRF"##, r##"VRF"##),
    (r##"Version"##, r##"Versão"##),
    (r##"Warnings"##, r##"Avisos"##),
    (r##"Why this neighbor is not Full, with the RFC section that says so"##, r##"Por que este vizinho não chega a Full, com a seção da RFC que diz isso"##),
    (r##"Why this path?"##, r##"Por que esse caminho?"##),
    (r##"agrees"##, r##"confere"##),
    (r##"conflict"##, r##"conflito"##),
    (r##"cost"##, r##"custo"##),
    (r##"daemon's route"##, r##"rota do daemon"##),
    (r##"dead in"##, r##"dead em"##),
    (r##"differs"##, r##"difere"##),
    (r##"error"##, r##"erro"##),
    (r##"layout"##, r##"layout"##),
    (r##"priority"##, r##"prioridade"##),
    (r##"protected"##, r##"protegidos"##),
    (r##"retransmit"##, r##"retransmissão"##),
    (r##"simulation: nothing changes"##, r##"simulação: nada muda"##),
    (r##"unavailable"##, r##"indisponível"##),
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
    (r##"ospf.frr.after"##, r##"## O que é
O caminho e o custo depois que o OSPF reconverge sem o enlace cortado."##),
    (r##"ospf.frr.backup"##, r##"## O que é
O próximo salto de reserva que o zebra deixou instalado (TI-LFA). No laboratório virtual é o calculado (selo `lab`)."##),
    (r##"ospf.frr.coverage"##, r##"## O que é
A porcentagem das rotas OSPF que têm reserva instalada, como o `show ... fast-reroute prefix-summary` da Cisco. Verde ≥ 95%, âmbar ≥ 70%, vermelho abaixo. A aba **Sem proteção** diz o motivo de cada uma."##),
    (r##"ospf.frr.labels"##, r##"## O que é
A pilha de rótulos do reserva, de cima para baixo: os segmentos do reparo (nó P, adjacência P→Q) e o SID do destino."##),
    (r##"ospf.frr.primary"##, r##"## O que é
O próximo salto principal: endereço · interface."##),
    (r##"ospf.frr.protected"##, r##"## O que é
Se a rota tem reserva pronto."##),
    (r##"ospf.frr.reason"##, r##"## O que é
Por que a rota está sem reserva: único caminho (o enlace é ponte), conectada, anunciada fora da área, nó protegido igual ao destino, ou um roteador do caminho sem SID."##),
    (r##"ospf.frr.segments"##, r##"## O que é
Os segmentos do reparo calculados como o `ospfd` faz (nó PQ, ou nó P e adjacência P→Q)."##),
    (r##"ospf.frr.views"##, r##"## O que é
**Rotas**: cada rota com o próximo salto principal e o de reserva e a pilha de rótulos (como o next-hop de reserva do Junos). **Sem proteção**: as rotas sem reserva e por quê (único caminho, conectada, externa, roteador sem SID). **Simular corte de link**: escolha um vizinho e veja o reserva de cada rota afetada e o caminho depois da convergência, sem tocar a rede."##),
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
    (r##"ospf.sid"##, r##"## O que é
Um prefix SID deste roteador: o índice de um /32 de loopback no SRGB (RFC 8665 §5).

## Antes do commit
A prévia confere o índice com os SIDs que a rede já anuncia: um índice que outro roteador usa para outro prefixo é recusado (o tráfego de um iria para o outro). **Forçar** aceita, para anycast."##),
    (r##"ospf.sid.announced"##, r##"## O que é
Se o OSPF anuncia esta loopback (ela está num interface template da instância). Sem isso o SID não vai para a rede."##),
    (r##"ospf.sid.behavior"##, r##"## O que é
O que o penúltimo salto faz com o rótulo (RFC 8665 §5, flags NP e E):
- `php`: tira o rótulo um salto antes (padrão, como o LDP);
- `no-php`: o rótulo chega até aqui;
- `explicit-null`: troca por explicit null (o campo de classe de tráfego chega até aqui)."##),
    (r##"ospf.sid.force"##, r##"## O que é
Aceita um índice que outro roteador já anuncia para outro prefixo. Só para anycast consciente."##),
    (r##"ospf.sid.index"##, r##"## O que é
O índice no SRGB: único na rede (RFC 8402 §3.2). Vazio ou `auto`: escolhido sozinho."##),
    (r##"ospf.sid.interface"##, r##"## O que é
A interface (loopback) do prefixo, ou por onde o rótulo sai."##),
    (r##"ospf.sid.label"##, r##"## O que é
O rótulo do SID num roteador com o mesmo SRGB: início do SRGB + índice."##),
    (r##"ospf.sid.prefix"##, r##"## O que é
O /32 que o SID identifica. O FRR só aceita endereço de interface loopback."##),
    (r##"ospf.sr"##, r##"## O que é
O Segment Routing da instância OSPFv2 em VRF main (o FRR só roda SR lá, um por processo, em todas as áreas da instância).

## Prévia
Mostra os prefixos que passam a ir por rótulo, o SID automático das loopbacks, o MTU que falta, as interfaces sem MPLS e os SIDs em conflito com a rede. Use o Safe Mode: se a mudança cortar o acesso, ela volta sozinha."##),
    (r##"ospf.sr.adjacencies"##, r##"## O que é
Quantos adjacency SIDs o roteador anunciou (um por vizinho, no SRLB dele)."##),
    (r##"ospf.sr.auto_sid"##, r##"## O que é
Dá um prefix SID a cada /32 de loopback da instância que ainda não tem: o índice é o último octeto do endereço quando está livre aqui e na rede, senão o menor livre."##),
    (r##"ospf.sr.conflicts"##, r##"## O que é
SIDs em conflito na rede: um índice para dois prefixos (o tráfego de um vai para o outro) ou um prefixo com dois índices. A RFC 8660 §2.5 deixa a solução ao operador: corrija o índice num dos roteadores."##),
    (r##"ospf.sr.in_label"##, r##"## O que é
O rótulo que este roteador recebe para o SID (instalado no kernel)."##),
    (r##"ospf.sr.instance"##, r##"## O que é
A instância OSPFv2 (VRF main) que roda o SR."##),
    (r##"ospf.sr.ldp_block"##, r##"## O que é
Os rótulos que o LDP usa enquanto o SR roda. O zebra do FRR recusa um SRGB dentro do bloco dinâmico, e com o bloco inteiro o LDP poderia pegar um rótulo do SRGB antes; por isso o LDP vai para fora dos blocos do SR (como no IOS-XR, a partir de 24000)."##),
    (r##"ospf.sr.nexthop"##, r##"## O que é
O vizinho para onde o pacote rotulado vai."##),
    (r##"ospf.sr.node_msd"##, r##"## O que é
Maximum SID Depth (RFC 8476): quantos rótulos este roteador consegue empilhar, anunciado aos outros. Vazio: não anuncia."##),
    (r##"ospf.sr.out_label"##, r##"## O que é
O rótulo com que o pacote sai. `implicit-null (pop)`: o próximo salto é o dono do SID (PHP)."##),
    (r##"ospf.sr.router"##, r##"## O que é
O router ID OSPF de quem anuncia."##),
    (r##"ospf.sr.srgb"##, r##"## O que é
Segment Routing Global Block (RFC 8402 §2): os rótulos reservados para os prefix SIDs. O rótulo de um SID é o início do bloco + o índice. Padrão 16000–23999 (o do FRR e da Cisco).

## Cuidado
O bloco fica **fora da faixa do LDP**: com a faixa padrão do `/mpls settings`, o LDP passa a usar os rótulos acima do SR (24000–1048575); com uma faixa sua, o commit recusa sobreposição. Use o mesmo SRGB em toda a rede: o rótulo fica igual em todo salto."##),
    (r##"ospf.sr.srlb"##, r##"## O que é
Segment Routing Local Block: rótulos locais do roteador, usados pelos adjacency SIDs. Padrão 15000–15999. Não pode sobrepor o SRGB."##),
    (r##"ospf.sr.ti_lfa"##, r##"## O que é
TI-LFA (RFC 9855) na instância inteira (o FRR liga por processo):
- `link`: protege o enlace até o próximo salto;
- `node`: protege o roteador do próximo salto (a rota até ele mesmo fica sem reserva);
- `off`: sem reserva pré-calculada."##),
    (r##"ospf.sr.views"##, r##"## O que é
**Este roteador**: os prefix SIDs da config, com + − para editar. **SIDs da rede**: tudo o que o `ospfd` aprendeu, com o rótulo de entrada e de saída. **Roteadores SR**: o SRGB e o SRLB de cada um (em âmbar quando o SRGB difere do nosso)."##),
    (r##"ospf.tab.areas"##, r##"## O que é
As áreas de cada instância. A 0.0.0.0 é o backbone; as outras se ligam a ele por um ABR (roteador de borda de área)."##),
    (r##"ospf.tab.frr"##, r##"## O que é
Fast Reroute por **TI-LFA** (RFC 9855): para cada rota, o `ospfd` do FRR calcula um caminho de reserva sem laço, com uma pilha de rótulos SR, e o zebra o deixa pronto. Quando o vizinho principal cai, o tráfego vai pelo reserva **antes** de o OSPF reconvergir.

## Requisitos
Precisa do Segment Routing ligado (aba Segment Routing) e de SID em todos os roteadores do caminho. Para ver a queda rápido, use BFD nos interface templates."##),
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
    (r##"ospf.tab.sr"##, r##"## O que é
Segment Routing MPLS sobre OSPFv2 (RFC 8665): cada roteador anuncia um **índice** para a sua loopback e todos encaminham até ela com o rótulo **início do SRGB + índice**, sem LDP. O `ospfd` do FRR calcula; aqui ficam o liga/desliga com prévia, os SIDs deste roteador, os da rede e os conflitos.

## Seguro por padrão
Ligar o SR muda o encaminhamento interno de IP para rótulo: a prévia lista os prefixos que mudam, o MTU curto (+4 bytes por rótulo) e as interfaces sem entrada MPLS, e sugere o Safe Mode."##),
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
