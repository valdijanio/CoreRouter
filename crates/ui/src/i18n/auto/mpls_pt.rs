//! Portuguese labels and explanations of MPLS › LDP and Forwarding Table
//! (G3.5), each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"+ Static LSP"##, r##"+ LSP estático"##),
    (r##"10.255.0.1 (the loopback)"##, r##"10.255.0.1 (o loopback)"##),
    (r##"100 replies/s"##, r##"100 respostas/s"##),
    (r##"AFI"##, r##"AFI"##),
    (r##"Adjacencies"##, r##"Adjacências"##),
    (r##"Apply"##, r##"Aplicar"##),
    (r##"Comment"##, r##"Comentário"##),
    (r##"Disabled"##, r##"Desativado"##),
    (r##"Dynamic Label Range"##, r##"Faixa de rótulos dinâmicos"##),
    (r##"Edit Static LSP…"##, r##"Editar LSP estático…"##),
    (r##"FEC"##, r##"FEC"##),
    (r##"FEC, label, next hop…"##, r##"FEC, rótulo, próximo salto…"##),
    (r##"FECs"##, r##"FECs"##),
    (r##"Flags"##, r##"Flags"##),
    (r##"Forwarding Table"##, r##"Tabela de encaminhamento"##),
    (r##"GTSM"##, r##"GTSM"##),
    (r##"Hello"##, r##"Hello"##),
    (r##"Hello Interval"##, r##"Intervalo de Hello"##),
    (r##"Hold"##, r##"Espera"##),
    (r##"Hold Time"##, r##"Tempo de espera"##),
    (r##"IGP Sync"##, r##"IGP sync"##),
    (r##"IGP Sync Holddown"##, r##"Espera do IGP sync"##),
    (r##"In Label"##, r##"Rótulo de entrada"##),
    (r##"In Use"##, r##"Em uso"##),
    (r##"Interface"##, r##"Interface"##),
    (r##"Interfaces"##, r##"Interfaces"##),
    (r##"Keepalive Hold"##, r##"Espera do keepalive"##),
    (r##"LDP"##, r##"LDP"##),
    (r##"LDP Interface"##, r##"Interface LDP"##),
    (r##"LDP Neighbor"##, r##"Vizinho LDP"##),
    (r##"LDP off"##, r##"LDP desligado"##),
    (r##"LDP runs in FRR's ldpd: start the daemon with --frr to see sessions."##, r##"O LDP roda no ldpd do FRR: inicie o daemon com --frr para ver as sessões."##),
    (r##"LDP runs on no interface yet: + adds the links towards the other LSRs."##, r##"O LDP ainda não roda em nenhuma interface: + adiciona os enlaces para os outros LSRs."##),
    (r##"LDP: no daemon"##, r##"LDP: sem daemon"##),
    (r##"LSP Ping Rate"##, r##"Taxa do LSP ping"##),
    (r##"LSP Ping Responder"##, r##"Responder LSP ping"##),
    (r##"LSP Ping…"##, r##"LSP ping…"##),
    (r##"LSP Traceroute…"##, r##"LSP traceroute…"##),
    (r##"LSR ID"##, r##"LSR ID"##),
    (r##"Labels"##, r##"Rótulos"##),
    (r##"MTU"##, r##"MTU"##),
    (r##"MTU too small"##, r##"MTU pequeno"##),
    (r##"Neighbors"##, r##"Vizinhos"##),
    (r##"New Interface…"##, r##"Nova interface…"##),
    (r##"New LDP Interface"##, r##"Nova interface LDP"##),
    (r##"New LDP Neighbor"##, r##"Novo vizinho LDP"##),
    (r##"New Neighbor…"##, r##"Novo vizinho…"##),
    (r##"New Static LSP"##, r##"Novo LSP estático"##),
    (r##"Next Hop"##, r##"Próximo salto"##),
    (r##"No LDP instance: set the LSR ID in the Settings tab."##, r##"Sem instância LDP: defina o LSR ID na aba Configurações."##),
    (r##"No label yet: LDP labels the IGP's routes once a neighbor is up; + Static LSP adds one by hand."##, r##"Nenhum rótulo ainda: o LDP rotula as rotas do IGP quando um vizinho sobe; + LSP estático adiciona um à mão."##),
    (r##"No neighbor yet: LDP finds them by Hello on its interfaces; + adds one for a password or targeted Hellos."##, r##"Nenhum vizinho ainda: o LDP os acha por Hello nas suas interfaces; + adiciona um para senha ou Hellos dirigidos."##),
    (r##"Origin"##, r##"Origem"##),
    (r##"Out Label"##, r##"Rótulo de saída"##),
    (r##"Out Labels"##, r##"Rótulos de saída"##),
    (r##"Password"##, r##"Senha"##),
    (r##"Payload MTU"##, r##"MTU do pacote IP"##),
    (r##"Preferred AFI"##, r##"AFI preferida"##),
    (r##"Propagate TTL"##, r##"Propagar TTL"##),
    (r##"Reason"##, r##"Motivo"##),
    (r##"Remove"##, r##"Remover"##),
    (r##"Remove LDP"##, r##"Remover LDP"##),
    (r##"Settings"##, r##"Configurações"##),
    (r##"State"##, r##"Estado"##),
    (r##"Static LSP"##, r##"LSP estático"##),
    (r##"Sync IGP"##, r##"Sync IGP"##),
    (r##"TCP MD5 key (optional)"##, r##"chave TCP MD5 (opcional)"##),
    (r##"Targeted"##, r##"Dirigido"##),
    (r##"The FECs come from FRR's ldpd (--frr); the kernel's labels are below."##, r##"As FECs vêm do ldpd do FRR (--frr); os rótulos do kernel estão abaixo."##),
    (r##"Transport"##, r##"Transporte"##),
    (r##"Transport Addresses"##, r##"Endereços de transporte"##),
    (r##"Uptime"##, r##"Tempo ativo"##),
    (r##"Use Explicit Null"##, r##"Usar NULL explícito"##),
    (r##"Without label"##, r##"Sem rótulo"##),
    (r##"above the dynamic range"##, r##"acima da faixa dinâmica"##),
    (r##"achieved"##, r##"sincronizado"##),
    (r##"active"##, r##"ativas"##),
    (r##"address for targeted Hellos (optional)"##, r##"endereço para Hellos dirigidos (opcional)"##),
    (r##"disabled"##, r##"desativado"##),
    (r##"down"##, r##"fora"##),
    (r##"empty: pop (implicit-null)"##, r##"vazio: retira (implicit-null)"##),
    (r##"error"##, r##"erro"##),
    (r##"interfaces"##, r##"interfaces"##),
    (r##"ip | ipv6 | ip,ipv6"##, r##"ip | ipv6 | ip,ipv6"##),
    (r##"ipv6 (RFC 7552)"##, r##"ipv6 (RFC 7552)"##),
    (r##"kernel labels"##, r##"rótulos no kernel"##),
    (r##"neighbors"##, r##"vizinhos"##),
    (r##"no MPLS in the kernel"##, r##"sem MPLS no kernel"##),
    (r##"no daemon"##, r##"sem daemon"##),
    (r##"off"##, r##"desligado"##),
    (r##"operational"##, r##"operacionais"##),
    (r##"running"##, r##"rodando"##),
    (r##"showing"##, r##"mostrando"##),
    (r##"static"##, r##"estáticos"##),
    (r##"the LSR ID; IPv6 needs one"##, r##"o LSR ID; IPv6 precisa de um"##),
    (r##"type in the search to narrow"##, r##"digite na busca para filtrar"##),
    (r##"wait for LDP (s; empty: no limit)"##, r##"esperar o LDP (s; vazio: sem limite)"##),
    (r##"waiting for LDP"##, r##"esperando o LDP"##),
    (r##"with label"##, r##"com rótulo"##),
    (r##"without label"##, r##"sem rótulo"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"menu.mpls-forwarding"##, r##"## O que faz
A tabela de encaminhamento por rótulo: para cada FEC (um prefixo), o rótulo que este roteador deu, o rótulo que o próximo salto pediu e para onde vai. Uma FEC sem rótulo de saída diz por quê.

Os LSPs estáticos (rótulos postos à mão, como o `mpls static binding` da Cisco) são adicionados aqui."##),
    (r##"menu.mpls-ldp"##, r##"## O que faz
O LDP (RFC 5036) distribui rótulos MPLS para as rotas do IGP e aprende os rótulos dos vizinhos, para o tráfego entre os loopbacks dos roteadores atravessar o núcleo comutado por rótulo. Quem roda é o ldpd do FRR.

## Cuidado
O LDP segue o IGP (OSPF): configure o OSPF antes. O IGP sync (RFC 5443) vem ligado, então um enlace só leva tráfego depois que o LDP sobe nele."##),
    (r##"mpls.afi"##, r##"## O que é
Famílias de endereço: `ip` (IPv4), `ipv6` (RFC 7552) ou as duas. Vazio numa interface: as da instância."##),
    (r##"mpls.disabled"##, r##"## O que é
Fica na configuração, sem rodar."##),
    (r##"mpls.explicit_null"##, r##"## O que é
Anuncia NULL explícito (rótulo 0) em vez de NULL implícito para os prefixos deste roteador: o último salto mantém o rótulo e os bits TC (QoS) chegam aqui (RFC 3032 §2.1)."##),
    (r##"mpls.fwd.fec"##, r##"## O que é
A Forwarding Equivalence Class: o prefixo cujos pacotes compartilham este rótulo (RFC 3031 §2.1). Vazio numa entrada sem FEC (um LSP estático)."##),
    (r##"mpls.fwd.in_label"##, r##"## O que é
O rótulo que este roteador anunciou para a FEC: pacotes que chegam com ele são comutados por esta linha. `implicit-null`: a FEC é deste roteador (o salto anterior retira o rótulo)."##),
    (r##"mpls.fwd.interface"##, r##"## O que é
A interface por onde o pacote rotulado sai."##),
    (r##"mpls.fwd.nexthop"##, r##"## O que é
O próximo roteador, pela rota do IGP até a FEC."##),
    (r##"mpls.fwd.origin"##, r##"## O que é
Quem instalou: `ldp`, `static` (/mpls static), `bgp` (labeled unicast) ou `other` (outro programa)."##),
    (r##"mpls.fwd.out_label"##, r##"## O que é
O rótulo que o próximo salto pediu. `implicit-null (pop)`: o próximo salto é o fim do LSP, o pacote sai como IP puro (penultimate hop popping, RFC 3031 §3.16). `-`: sem rótulo (veja Reason)."##),
    (r##"mpls.fwd.reason"##, r##"## O que é
Por que uma FEC não tem rótulo de saída (nenhum vizinho LDP de pé, o próximo salto não mandou, a rota sai por um enlace sem LDP…), ou um aviso sobre a linha (MTU)."##),
    (r##"mpls.fwd.unlabeled"##, r##"## O que é
Mostra só as FECs sem rótulo de saída: onde o LSP quebra."##),
    (r##"mpls.gtsm"##, r##"## O que é
GTSM (RFC 6720): os pacotes LDP de um vizinho diretamente conectado precisam chegar com TTL 255, então um atacante remoto não alcança a sessão. Negociado no Hello; ligado por padrão. No IPv6 é sempre ligado (RFC 7552 §9)."##),
    (r##"mpls.if"##, r##"## O que é
LDP numa interface: Hellos de enlace para 224.0.0.2 (IPv6 ff02::2) a cada intervalo, e as adjacências que eles formam (RFC 5036 §2.4.1)."##),
    (r##"mpls.if.adjacencies"##, r##"## O que é
Vizinhos cujos Hellos chegam por essa interface."##),
    (r##"mpls.if.hello_interval"##, r##"## O que é
Segundos entre Hellos de enlace (padrão 5)."##),
    (r##"mpls.if.hold_time"##, r##"## O que é
Segundos que o Hello de um vizinho vale antes de a adjacência cair (padrão 15, RFC 5036 §3.5.2). Vale o menor dos dois lados; precisam caber pelo menos três Hellos."##),
    (r##"mpls.if.interface"##, r##"## O que é
O enlace para outro LSR. O MTU dele precisa caber um pacote IP inteiro mais 4 bytes por rótulo."##),
    (r##"mpls.if.state"##, r##"## O que é
`active`: o LDP manda Hellos ali. `down`: o enlace caiu ou não tem endereço. `no daemon`: sem daemon de roteamento."##),
    (r##"mpls.lsp_ping_rate"##, r##"## O que é
Quantas respostas a MPLS echo request este roteador manda por segundo, no máximo (padrão 100). O excedente é descartado e contado.

## Por quê
A RFC 8029 §5 pede um limitador de taxa na porta UDP 3503: sem ele, uma enxurrada de pedidos ocupa o plano de controle. A resposta nunca é maior que o pedido mais os mapeamentos e vai só para quem pediu, então não serve de amplificador."##),
    (r##"mpls.lsp_ping_responder"##, r##"## O que é
Responde LSP ping e LSP traceroute (MPLS echo request, RFC 8029) que chegam a este roteador, como egress do LSP ou como LSR de trânsito onde o TTL do rótulo expirou.

## Padrão
Ligado, como no Cisco e no Junos: desligado, um ping que chega aqui parece um LSP quebrado. Só funciona nas interfaces que aceitam MPLS (MPLS › Interface ou LDP).

## Diagnóstico
`mpls.settings.get` mostra os contadores (`lsp_ping_counters`): pedidos ouvidos, respondidos, descartados pela taxa e por código de retorno."##),
    (r##"mpls.lsr_id"##, r##"## O que é
O LSR ID deste roteador (RFC 5036 §2.2.2), normalmente o endereço do loopback. Obrigatório para ligar o LDP."##),
    (r##"mpls.mtu"##, r##"## O que é
O MTU do enlace. Cada rótulo soma 4 bytes (RFC 3032 §3): `MTU 1500 < 1504` quer dizer que um pacote IP de 1500 bytes com um rótulo não cabe, e os pacotes cheios são descartados. Aumente o MTU das duas pontas."##),
    (r##"mpls.nbr"##, r##"## O que é
Um vizinho LDP configurado, identificado pelo LSR ID: senha TCP MD5 da sessão (RFC 5036 §2.9), Hellos dirigidos a um roteador que não é adjacente (§2.4.2) ou o tempo de keepalive."##),
    (r##"mpls.nbr.flags"##, r##"## O que é
`dynamic`: achado por Hello, não configurado. `targeted`: Hellos dirigidos. `MD5`: a sessão é assinada."##),
    (r##"mpls.nbr.in_use"##, r##"## O que é
Desses rótulos, os que estão em uso: esse vizinho é o próximo salto do IGP para a FEC."##),
    (r##"mpls.nbr.keepalive_hold"##, r##"## O que é
Segundos sem nenhuma mensagem LDP até fechar a sessão (RFC 5036 §2.5.5). Vale o menor dos dois lados. Padrão 180 s (FRR e Cisco)."##),
    (r##"mpls.nbr.labels"##, r##"## O que é
FECs para as quais esse vizinho mandou rótulo (retenção liberal: todos ficam guardados)."##),
    (r##"mpls.nbr.lsr_id"##, r##"## O que é
O LSR ID do vizinho: os quatro primeiros bytes do identificador LDP dele (RFC 5036 §2.2.2), normalmente o loopback."##),
    (r##"mpls.nbr.password"##, r##"## O que é
Assinatura TCP MD5 da sessão (RFC 5036 §2.9, RFC 2385). Fica selada na configuração, nunca em claro. Os dois lados precisam da mesma chave.

## Cuidado
Mudar a senha derruba a sessão."##),
    (r##"mpls.nbr.state"##, r##"## O que é
O estado da sessão (RFC 5036 §2.5.4): `operational` troca rótulos; `opensent`/`openrec`/`initialized` estão subindo; `present` tem só Hellos. `no daemon`: o daemon de roteamento não está rodando (laboratório virtual)."##),
    (r##"mpls.nbr.targeted"##, r##"## O que é
Manda Hellos dirigidos (unicast, UDP 646) a esse endereço: uma sessão com um roteador que não está num enlace comum (RFC 5036 §2.4.2). Os dois lados precisam aceitar; o tempo de espera é 45 s."##),
    (r##"mpls.nbr.transport"##, r##"## O que é
O endereço da sessão TCP (porta 646). Quem tem o maior endereço de transporte abre a conexão (RFC 5036 §2.5.2)."##),
    (r##"mpls.nbr.uptime"##, r##"## O que é
Há quanto tempo a sessão está de pé."##),
    (r##"mpls.payload_mtu"##, r##"## O que é
O tamanho de pacote IP que a checagem de MTU assume (padrão 1500): a checagem soma 4 bytes por rótulo a ele."##),
    (r##"mpls.preferred_afi"##, r##"## O que é
Com as duas famílias, qual delas leva a sessão única com cada vizinho (RFC 7552 §6.1.1). Padrão IPv6."##),
    (r##"mpls.propagate_ttl"##, r##"## O que é
Copia o TTL do IP para o rótulo e de volta (RFC 3032 §2.4.3, modelo uniforme). Desligado: o núcleo não aparece no traceroute do cliente (modelo pipe, RFC 3443)."##),
    (r##"mpls.range"##, r##"## O que é
Os rótulos que o LDP distribui (`dynamic-label-range` do RouterOS, padrão 16-1048575; 0-15 são reservados, RFC 3032 §2.1). LSPs estáticos usam rótulos acima da faixa, então reduza-a para usá-los. O Linux dimensiona a tabela de rótulos pelo fim (`platform_labels`)."##),
    (r##"mpls.static"##, r##"## O que é
Uma entrada de comutação por rótulo posta à mão: pacotes que chegam com o rótulo de entrada saem para o próximo salto com os rótulos de saída (ou sem rótulo). É o `mpls static binding` da Cisco e o LSP estático do Junos; o RouterOS não tem. O rótulo de entrada precisa estar acima da faixa dinâmica, para o LDP nunca distribuí-lo."##),
    (r##"mpls.static.interface"##, r##"## O que é
A interface de saída; vazio: achada pelo próximo salto."##),
    (r##"mpls.static.label"##, r##"## O que é
O rótulo de entrada, acima da faixa dinâmica (Settings)."##),
    (r##"mpls.static.nexthop"##, r##"## O que é
O endereço do próximo roteador num enlace conectado."##),
    (r##"mpls.static.out_labels"##, r##"## O que é
Os rótulos que substituem o de entrada, o de cima primeiro (`100 200`, até 30). Vazio: retira o rótulo (NULL implícito) e manda IP puro. 0 e 2 são NULL explícito."##),
    (r##"mpls.sync"##, r##"## O que é
Sincronização LDP-IGP (RFC 5443): enquanto o LDP não sobe num enlace, o OSPF o anuncia com o maior custo, para o tráfego nunca passar por um enlace sem rótulos (seria descartado ou sairia do LSP). `achieved`: o LDP está de pé e vale o custo real. `waiting for LDP`: custo máximo.

Ligado por padrão (o RouterOS não tem)."##),
    (r##"mpls.sync_holddown"##, r##"## O que é
Segundos que o IGP espera o LDP antes de usar o enlace mesmo assim. Vazio: espera o tempo que for (padrão do FRR, Cisco e Junos; a RFC 5443 não define)."##),
    (r##"mpls.tab.interfaces"##, r##"## O que é
Onde o LDP manda Hellos e forma adjacências: os enlaces para os outros roteadores de comutação por rótulo."##),
    (r##"mpls.tab.neighbors"##, r##"## O que é
As sessões LDP: os roteadores achados por Hello nas interfaces LDP (dinâmicos) e os configurados aqui (para senha ou Hellos dirigidos)."##),
    (r##"mpls.tab.settings"##, r##"## O que é
A instância LDP (LSR ID, famílias, endereço de transporte, IGP sync, GTSM) e o `/mpls settings` (faixa de rótulos, TTL). Um Apply manda os dois numa transação só."##),
    (r##"mpls.transport"##, r##"## O que é
O endereço de onde as sessões partem, um por família (RFC 5036 §2.5.2). IPv4: o LSR ID por padrão. IPv6 precisa de um endereço global (RFC 7552 §6.1). Precisa ser alcançável pelo IGP."##),
];
