//! Portuguese labels and explanations of Tools › LSP Ping (G3.5b), each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"Address"##, r##"Endereço"##),
    (r##"Code"##, r##"Código"##),
    (r##"Count"##, r##"Quantidade"##),
    (r##"EXP"##, r##"EXP"##),
    (r##"FEC"##, r##"FEC"##),
    (r##"FEC Type"##, r##"Tipo de FEC"##),
    (r##"From"##, r##"De"##),
    (r##"Hop"##, r##"Salto"##),
    (r##"Interval (ms)"##, r##"Intervalo (ms)"##),
    (r##"LSP Ping"##, r##"LSP Ping"##),
    (r##"Labels"##, r##"Rótulos"##),
    (r##"MTU"##, r##"MTU"##),
    (r##"Max Hops"##, r##"Máx. de saltos"##),
    (r##"Mode"##, r##"Modo"##),
    (r##"Path"##, r##"Caminho"##),
    (r##"Ping"##, r##"Ping"##),
    (r##"Return Code"##, r##"Código de retorno"##),
    (r##"Sends MPLS echo requests along the LSP of the FEC (RFC 8029). The router at the far end answers if it runs an LSP ping responder (CoreRouter, Cisco, Junos, Nokia)."##, r##"Envia MPLS echo requests pelo LSP da FEC (RFC 8029). O roteador na outra ponta responde se tiver um respondedor de LSP ping (CoreRouter, Cisco, Junos, Nokia)."##),
    (r##"Seq"##, r##"Seq"##),
    (r##"Size"##, r##"Tamanho"##),
    (r##"Start"##, r##"Iniciar"##),
    (r##"Stop"##, r##"Parar"##),
    (r##"TTL"##, r##"TTL"##),
    (r##"The FEC has several paths: the requests follow the first"##, r##"A FEC tem vários caminhos: os pedidos seguem o primeiro"##),
    (r##"The next hop is the egress: the request leaves unlabeled"##, r##"O próximo salto é o egress: o pedido sai sem rótulo"##),
    (r##"Time (ms)"##, r##"Tempo (ms)"##),
    (r##"Timeout (ms)"##, r##"Timeout (ms)"##),
    (r##"Traceroute"##, r##"Traceroute"##),
    (r##"Type the FEC (the egress's loopback)"##, r##"Digite a FEC (o loopback do egress)"##),
    (r##"Validate FEC"##, r##"Validar FEC"##),
    (r##"egress"##, r##"egress"##),
    (r##"from"##, r##"de"##),
    (r##"loss"##, r##"perda"##),
    (r##"on"##, r##"por"##),
    (r##"received"##, r##"recebidos"##),
    (r##"sent"##, r##"enviados"##),
    (r##"stopped"##, r##"parou"##),
    (r##"via"##, r##"via"##),
];

/// Explanations: (key, text).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"lsp_ping.col.code"##, r##"## O que é
O código de retorno numa letra, como o Cisco imprime:

- `!` egress (3): o LSP chega ao roteador da FEC;
- `L` label switched (8): um LSR de trânsito;
- `.` sem resposta a tempo; `Q` não enviado (sem entrada ARP, enlace caído);
- `N` sem entrada para o rótulo (11): o LSR não conhece o rótulo;
- `F` sem mapeamento para a FEC (4); `f` o rótulo é de outra FEC (10);
- `D` mapeamento divergente (5): interface ou rótulo diferentes do que o salto anterior disse;
- `I` interface de entrada desconhecida (6); `B` comutado sem MPLS (9); `M` malformado (1); `m` TLV não entendido (2); `X` outro código."##),
    (r##"lsp_ping.col.from"##, r##"## O que é
O roteador que respondeu (o endereço de origem do echo reply dele)."##),
    (r##"lsp_ping.col.hop"##, r##"## O que é
O TTL do rótulo do pedido: o salto 0 é este roteador (o que ele empilha, para onde manda)."##),
    (r##"lsp_ping.col.labels"##, r##"## O que é
Os rótulos que este salto passa ao próximo (selos azuis), ou `implicit-null` quando ele os retira (o próximo é o egress: penultimate hop popping)."##),
    (r##"lsp_ping.col.mtu"##, r##"## O que é
O MTU do enlace até o próximo LSR, como o salto informa (Downstream Detailed Mapping, RFC 8029 §3.4)."##),
    (r##"lsp_ping.col.return_code"##, r##"## O que é
O código de retorno por extenso (RFC 8029 §3.1) e, numa divergência, a interface e os rótulos com que o pedido chegou de fato."##),
    (r##"lsp_ping.col.seq"##, r##"## O que é
O número de sequência do pedido."##),
    (r##"lsp_ping.col.time"##, r##"## O que é
Ida e volta: do envio do pedido à chegada da resposta, medido por este roteador. A resposta volta por IP, não pelo LSP."##),
    (r##"lsp_ping.count"##, r##"## O que é
Quantos pedidos enviar (padrão 5, como no Cisco e no Junos); 0 envia até Parar."##),
    (r##"lsp_ping.exp"##, r##"## O que é
Classe de tráfego dos rótulos (os antigos bits EXP, 0–7, RFC 5462), e também o DSCP do pacote: para testar o LSP com a classe de um serviço (voz em EXP 5, por exemplo)."##),
    (r##"lsp_ping.fec"##, r##"## O que é
A Forwarding Equivalence Class a testar: no LDP, o loopback do roteador de saída (`10.255.0.3/32`). Endereço sem comprimento vira /32 (/128).

O pedido segue a rota da FEC com os rótulos dela (MPLS › Forwarding Table mostra); sem rota não há por onde mandar."##),
    (r##"lsp_ping.fec_type"##, r##"## O que é
Como a FEC é descrita aos LSRs (RFC 8029 §3.2): `ldp` (prefixo LDP IPv4/IPv6) para LSPs que o LDP montou; `generic` (prefixo genérico IPv4/IPv6) para um LSP estático, cujos rótulos nenhum protocolo anunciou."##),
    (r##"lsp_ping.interval"##, r##"## O que é
Intervalo entre dois pedidos (100–60000 ms, padrão 1000). Um pedido não espera a resposta do anterior."##),
    (r##"lsp_ping.max_hops"##, r##"## O que é
Maior TTL que o traceroute tenta (1–64, padrão 30). Termina antes no egress ou no primeiro erro."##),
    (r##"lsp_ping.mode"##, r##"## Ping ou Traceroute
**Ping** envia pedidos com o TTL do rótulo em 255: o egress responde cada um (código 3, `!`). **Traceroute** envia TTL 1, 2, 3…: cada LSR onde o TTL expira responde com os rótulos que passa adiante, que vão no próximo pedido, e assim cada salto confere o que o anterior anunciou."##),
    (r##"lsp_ping.path"##, r##"## O que é
Como o pedido sai deste roteador: os rótulos que a rota da FEC empilha (selos azuis; `implicit-null` quando o próximo salto é o egress), o próximo salto e a interface, e o endereço de origem para onde as respostas voltam. O quadro vai para 127.0.0.1 com TTL IP 1 (RFC 8029 §4.3), então nenhum roteador o encaminha como IP: ou segue os rótulos, ou chega a um plano de controle."##),
    (r##"lsp_ping.size"##, r##"## O que é
Tamanho do conteúdo UDP de cada pedido (64–9000 bytes): um Pad TLV preenche (RFC 8029 §3.5). Com os rótulos e cabeçalhos, serve para achar o MTU MPLS do caminho: pedido grande demais para um enlace se perde. A resposta não traz o enchimento."##),
    (r##"lsp_ping.timeout"##, r##"## O que é
Quanto esperar cada resposta (100–10000 ms, padrão 2000). A resposta volta pela rota IP, que pode ser mais longa que o LSP."##),
    (r##"lsp_ping.ttl"##, r##"## O que é
TTL do rótulo do topo (1–255, padrão 255, RFC 8029 §4.3). Menor, o pedido para naquele salto (que responde "label switched")."##),
    (r##"lsp_ping.validate"##, r##"## O que é
A flag V (RFC 8029 §3): pede a cada LSR que confira se o rótulo que recebeu é o que ele associou a esta FEC. Rótulo de outra FEC responde código 10 (`f`).

## Padrão
Ligado: é o que acha um rótulo que vaza para o LSP errado."##),
    (r##"menu.lsp-ping"##, r##"## O que faz
LSP ping e traceroute (RFC 8029): MPLS echo requests enviados pelo caminho rotulado de uma FEC, como iriam os dados dessa FEC, para testar o próprio LSP e não só a rota IP. É o `ping mpls ipv4` e o `traceroute mpls ipv4` do Cisco e o `ping mpls ldp` do Junos. O RouterOS não tem: o traceroute dele só mostra os rótulos que os roteadores põem nos erros ICMP.

## Quando usar
Um LSP do LDP ou estático que deveria funcionar e um tráfego que não passa: o ping diz se a outra ponta recebe; o traceroute diz em que salto o LSP quebra e por quê."##),
];
