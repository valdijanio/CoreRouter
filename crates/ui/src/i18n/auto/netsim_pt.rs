//! Portuguese labels and explanations of Tools › Network Simulator
//! (G3.7b), each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"Add link"##, r##"Adicionar enlace"##),
    (r##"Add router"##, r##"Adicionar roteador"##),
    (r##"Apply"##, r##"Aplicar"##),
    (r##"BGP sessions"##, r##"Sessões BGP"##),
    (r##"Carrier down"##, r##"Sem portadora"##),
    (r##"Click a router or a link."##, r##"Clique num roteador ou num enlace."##),
    (r##"Clock"##, r##"Relógio"##),
    (r##"Cost"##, r##"Custo"##),
    (r##"Cut"##, r##"Cortar"##),
    (r##"Editor"##, r##"Editor"##),
    (r##"Latency"##, r##"Latência"##),
    (r##"Link"##, r##"Enlace"##),
    (r##"Loss"##, r##"Perda"##),
    (r##"Network Simulator"##, r##"Simulador de rede"##),
    (r##"New"##, r##"Nova"##),
    (r##"No simulation. Pick a preset and press New."##, r##"Nenhuma simulação. Escolha uma topologia e clique em Nova."##),
    (r##"OSPF neighbors"##, r##"Vizinhos OSPF"##),
    (r##"Pause"##, r##"Pausar"##),
    (r##"Play"##, r##"Rodar"##),
    (r##"Presets"##, r##"Topologias prontas"##),
    (r##"Restart the preset at t = 0"##, r##"Recomeça a topologia em t = 0"##),
    (r##"Restore"##, r##"Restaurar"##),
    (r##"Router"##, r##"Roteador"##),
    (r##"Router down"##, r##"Derrubar roteador"##),
    (r##"Router up"##, r##"Ligar roteador"##),
    (r##"Routers"##, r##"Roteadores"##),
    (r##"Routes"##, r##"Rotas"##),
    (r##"Simulation"##, r##"Simulação"##),
    (r##"Step: the next instant something happens"##, r##"Passo: o próximo instante em que algo acontece"##),
    (r##"Timeline"##, r##"Linha do tempo"##),
    (r##"Topology"##, r##"Topologia"##),
    (r##"Virtual routers in memory; nothing here touches this router."##, r##"Roteadores virtuais na memória; nada aqui toca este roteador."##),
    (r##"What if"##, r##"E se?"##),
    (r##"What if: add this router"##, r##"E se? Adicionar este roteador"##),
    (r##"simulation — not the real network"##, r##"simulação — não é a rede real"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"netsim.badge"##, r##"## O que é
Uma simulação: roteadores virtuais na memória deste roteador, rodando OSPF, BGP e BFD simplificados num relógio virtual. Nada aqui é aplicado neste roteador nem na rede, e tudo some quando o daemon reinicia.

## Para que serve
Ver o que uma falha ou uma mudança faz **antes** de fazê-la: quais rotas mudam, quanto tempo leva, quantos prefixos se perdem. Nunca substitui o FRR em produção."##),
    (r##"netsim.clock"##, r##"## O que é
O relógio virtual. ⏯ roda e pausa, ⏭ avança até o próximo instante em que algo acontece, ⏮ recomeça a topologia em t = 0, ×N é quantos segundos virtuais passam por segundo.

## Bom saber
Mesma semente, mesmos comandos: a mesma execução, sempre (pode virar teste)."##),
    (r##"netsim.editor"##, r##"## O que é
Acrescenta um roteador (com AS próprio, loopback e instância BGP) ou um enlace entre dois roteadores. O enlace ganha um /30 digitado nos dois roteadores, roda OSPF e, quando os AS são diferentes, vem junto o eBGP."##),
    (r##"netsim.link"##, r##"## O que é
Um enlace ponto a ponto. **Cortar** descarta tudo em silêncio (as duas portas continuam up: só BFD, hellos ou o hold timer do BGP percebem). **Sem portadora** derruba as duas portas na hora. **Restaurar** conserta. Custo é o custo OSPF das duas pontas; o BFD (300 ms × 3) faz um corte ser visto em menos de um segundo."##),
    (r##"netsim.node"##, r##"## O que é
Um roteador virtual: um CoreRouter próprio, com os mesmos comandos e validações. Mostra as rotas, os vizinhos OSPF e as sessões BGP como a simulação os tem agora. **Derrubar roteador** o trava (os vizinhos percebem por BFD, hellos ou hold timer); **Ligar roteador** o liga de novo."##),
    (r##"netsim.presets"##, r##"## O que é
Topologias prontas: **square** (um provedor de três roteadores com OSPF e iBGP, mais um upstream com eBGP), **ring** (anel), **mesh** (malha), **star** (estrela) e **grid** (grade). Nas quatro últimas cada roteador tem o seu AS, há eBGP em todo enlace e OSPF para as loopbacks; até 500 roteadores."##),
    (r##"netsim.timeline"##, r##"## O que é
O que os protocolos fizeram e quando, em tempo virtual: a falha, o BFD, as adjacências e o SPF do OSPF, as sessões e as mudanças de melhor caminho do BGP. A linha de cima resume a última falha: quando foi percebida, quando o OSPF e o BGP terminaram e quantos prefixos se perderam."##),
    (r##"netsim.topology"##, r##"## O que é
Os roteadores em selos (cor pelo AS) e os enlaces coloridos pelo estado:
- verde: OSPF Full;
- âmbar: OSPF ainda não subiu;
- azul: só eBGP;
- vermelho tracejado: cortado;
- cinza tracejado: sem portadora.

O número no enlace é o custo OSPF. Clique num roteador ou num enlace para vê-lo e agir nele."##),
    (r##"netsim.whatif"##, r##"## O que é
Acrescenta um roteador virtual com a configuração **deste** roteador, digitada como comandos (a chave TCP MD5 não é copiada):
- os endereços;
- a instância BGP, os templates e as conexões;
- os filtros de roteamento.

Ligue roteadores virtuais às interfaces dele e teste um corte ou uma mudança de custo antes de fazer em produção."##),
];
