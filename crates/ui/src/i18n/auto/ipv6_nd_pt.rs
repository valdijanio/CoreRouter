//! Portuguese labels and explanations of IPv6 › ND (G3.9ha), each sorted
//! by key (registered by `build.rs`).

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"Advertise DNS"##, r##"Anunciar DNS"##),
    (r##"Advertise MAC Address"##, r##"Anunciar o endereço MAC"##),
    (r##"Autonomous"##, r##"Autônomo (A)"##),
    (r##"Comment"##, r##"Comentário"##),
    (r##"DNS"##, r##"DNS"##),
    (r##"DNS Search"##, r##"Domínios de busca"##),
    (r##"DNS Servers"##, r##"Servidores DNS"##),
    (r##"Detail"##, r##"Detalhe"##),
    (r##"Disabled"##, r##"Desativado"##),
    (r##"Flags"##, r##"Flags"##),
    (r##"Hop Limit"##, r##"Limite de saltos"##),
    (r##"Interface"##, r##"Interface"##),
    (r##"Interfaces"##, r##"Interfaces"##),
    (r##"Interfaces reached"##, r##"Interfaces alcançadas"##),
    (r##"M / O"##, r##"M / O"##),
    (r##"MTU"##, r##"MTU"##),
    (r##"Managed Address Configuration"##, r##"Endereço por DHCPv6 (M)"##),
    (r##"ND Interface"##, r##"Interface ND"##),
    (r##"ND Prefix"##, r##"Prefixo ND"##),
    (r##"New ND Interface"##, r##"Nova interface ND"##),
    (r##"New ND Interface…"##, r##"Nova interface ND…"##),
    (r##"New ND Prefix"##, r##"Novo prefixo ND"##),
    (r##"New ND Prefix…"##, r##"Novo prefixo ND…"##),
    (r##"No Router Advertisements yet: + adds an interface (or all, which leaves the WAN, PPPoE server ports and prefix-less interfaces out)."##, r##"Nenhum anúncio de roteador ainda: + adiciona uma interface (ou all, que deixa de fora a WAN, as portas de servidor PPPoE e as interfaces sem prefixo)."##),
    (r##"On Link"##, r##"No enlace (L)"##),
    (r##"Origin"##, r##"Origem"##),
    (r##"Other Configuration"##, r##"Outras configurações por DHCPv6 (O)"##),
    (r##"Preference"##, r##"Preferência"##),
    (r##"Preferred"##, r##"Preferido"##),
    (r##"Preferred Lifetime"##, r##"Tempo de vida preferido"##),
    (r##"Prefix"##, r##"Prefixo"##),
    (r##"Prefixes"##, r##"Prefixos"##),
    (r##"RA Delay"##, r##"Atraso entre RAs"##),
    (r##"RA Interval"##, r##"Intervalo do RA"##),
    (r##"RA Lifetime"##, r##"Tempo de vida do RA"##),
    (r##"RA Preference"##, r##"Preferência do RA"##),
    (r##"RAs Sent"##, r##"RAs enviados"##),
    (r##"RSs Received"##, r##"RSs recebidas"##),
    (r##"Reachable Time"##, r##"Tempo de alcance"##),
    (r##"Retransmit Interval"##, r##"Intervalo de retransmissão"##),
    (r##"Sender"##, r##"Emissor"##),
    (r##"State"##, r##"Estado"##),
    (r##"Valid"##, r##"Válido"##),
    (r##"Valid Lifetime"##, r##"Tempo de vida válido"##),
    (r##"sender running"##, r##"emissor rodando"##),
    (r##"sender stopped (virtual lab)"##, r##"emissor parado (laboratório virtual)"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"ipv6_nd"##, r##"## O que é
Uma entrada de `/ipv6 nd` (RouterOS v7): o roteador envia Router Advertisements (RFC 4861 §6.2) nessa interface. É o que faz um host, um celular ou outro roteador (um RouterOS atrás deste) montar o endereço sozinho (SLAAC, RFC 4862) e pegar este roteador como gateway IPv6. O kernel do Linux nunca envia RA: sem esta entrada, a rede atrás do CoreRouter não autoconfigura.

## Cuidado
Com `all`, o CoreRouter deixa de fora a WAN (cliente DHCPv6, RA aceito, rota padrão), as portas de servidor PPPoE (o BNG anuncia a cada sessão), portas de bridge e de bond e as interfaces sem prefixo. Diferente do RouterOS, a config nova não vem com `all`."##),
    (r##"ipv6_nd.advertise_dns"##, r##"## O que é
Leva os servidores DNS no RA (opção RDNSS, RFC 8106 §5.1) e os domínios de busca (DNSSL, §5.2). Sem isso, um host que só faz SLAAC (Android não tem DHCPv6) fica sem DNS IPv6.

## De onde vêm
Na ordem: a lista **DNS Servers** desta entrada; senão, este roteador (um endereço global da interface) quando ele responde consultas (`ip.dns allow_remote_requests`); senão, os servidores IPv6 do `/ip dns` e os que o cliente DHCPv6 aprendeu. O tempo de vida é 3 × o intervalo máximo (RFC 8106 §5.1); o RA final manda 0."##),
    (r##"ipv6_nd.advertise_mac_address"##, r##"## O que é
Leva o MAC da porta no RA (opção Source Link-Layer Address, RFC 4861 §4.6.1): o host já sabe o MAC do gateway sem Neighbor Solicitation. Padrão ligado (a RFC diz SHOULD)."##),
    (r##"ipv6_nd.autonomous"##, r##"## O que é
Flag A: o host monta sozinho um endereço no prefixo (SLAAC, RFC 4862 §5.5.3). Desligue para obrigar o DHCPv6 (com M)."##),
    (r##"ipv6_nd.detail"##, r##"## O que é
Por que a interface ficou de fora, o erro do último envio, ou a divergência com outro roteador no enlace."##),
    (r##"ipv6_nd.disabled"##, r##"## O que é
Fica na config sem enviar RA. Ao desativar, a interface manda o RA final com Router Lifetime 0 (RFC 4861 §6.2.5): os hosts tiram a rota padrão na hora e os prefixos ficam depreciados."##),
    (r##"ipv6_nd.dns"##, r##"## O que é
Os servidores DNS que o RA anuncia (até 8), separados por vírgula. Vazio = automático (veja Advertise DNS)."##),
    (r##"ipv6_nd.dnssl"##, r##"## O que é
Domínios de busca (DNSSL, RFC 8106 §5.2), até 8: o host completa `servidor` para `servidor.isp.example`."##),
    (r##"ipv6_nd.flags"##, r##"## O que é
As flags M (endereço por DHCPv6) e O (outras configurações por DHCPv6) do RA (RFC 4861 §4.2)."##),
    (r##"ipv6_nd.hop_limit"##, r##"## O que é
Cur Hop Limit que os hosts passam a usar nos pacotes que enviam (RFC 4861 §4.2). Padrão 64; 0 = não especificado (o host fica com o dele)."##),
    (r##"ipv6_nd.interface"##, r##"## O que é
Onde o RA sai: uma interface ou `all` (todas as que parecem LAN e têm prefixo). Uma entrada por interface; a entrada própria de uma interface vale mais que a `all`.

## Cuidado
Nunca anuncie na WAN: os hosts do provedor passariam a usar este roteador como gateway. Uma entrada explícita numa interface com cara de WAN é aceita (pode ser de propósito), com aviso."##),
    (r##"ipv6_nd.managed"##, r##"## O que é
Flag M (Managed): os hosts pedem o endereço ao DHCPv6 (IA_NA) além ou no lugar do SLAAC. Ligue quando houver servidor DHCPv6 com endereços para a LAN."##),
    (r##"ipv6_nd.mtu"##, r##"## O que é
A opção MTU (RFC 4861 §4.6.4): os hosts usam esse MTU no enlace. Útil quando o enlace tem MTU menor que 1500 (PPPoE, túnel). Vazio ou `unspecified` = sem a opção. Mínimo 1280 (RFC 8200 §5)."##),
    (r##"ipv6_nd.on_link"##, r##"## O que é
Flag L: o prefixo está no enlace; o host fala direto com os vizinhos dele, sem passar pelo roteador."##),
    (r##"ipv6_nd.origin"##, r##"## O que é
`address`: vem de um endereço /64 da interface. `dhcp-pd`: de um endereço tirado do prefixo delegado por DHCPv6-PD; os tempos de vida seguem a delegação, com teto de 5400 s/2700 s (RFC 9096 §3.4). `static`: cadastrado aqui. `deprecated`: saiu do RA e ainda vai com tempos de vida 0 (RFC 9096 §3.5)."##),
    (r##"ipv6_nd.other"##, r##"## O que é
Flag O (Other): os hosts pedem ao DHCPv6 o resto da configuração (DNS, domínio) sem endereço (DHCPv6 sem estado, RFC 8415 §6.1)."##),
    (r##"ipv6_nd.port"##, r##"## O que é
Uma interface que alguma entrada alcança: as que enviam RA e as que ficaram de fora, com o motivo."##),
    (r##"ipv6_nd.port_state"##, r##"## O que é
`sending`: o RA saiu. `waiting`: ainda não saiu (endereço link-local em DAD, emissor parado). `failed`: o envio falhou (veja Detalhe). `skipped`: fora por segurança (WAN, porta PPPoE, sem prefixo). `conflict`: outro roteador no enlace anuncia valores diferentes (RFC 4861 §6.2.7)."##),
    (r##"ipv6_nd.ports"##, r##"## O que é
Cada interface que as entradas alcançam, com o estado do envio, os prefixos, os contadores e o motivo de quem ficou de fora."##),
    (r##"ipv6_nd.preferred_lifetime"##, r##"## O que é
Preferred Lifetime: até quando o endereço serve de origem para conexões novas. Padrão 1w; nunca maior que o válido. 0 = depreciado."##),
    (r##"ipv6_nd.prefix"##, r##"## O que é
O prefixo anunciado. Para SLAAC tem de ser um /64 (RFC 4862 §5.5.3, RFC 2464 §4); outro tamanho só serve para dizer que está no enlace (flag L)."##),
    (r##"ipv6_nd.prefix_disabled"##, r##"## O que é
Fica na config e sai do RA. Um prefixo estático desativado esconde o prefixo dinâmico igual (o do endereço): é como parar de anunciar um /64 sem mexer no endereço."##),
    (r##"ipv6_nd.prefix_flags"##, r##"## O que é
L (on-link) e A (autônomo, SLAAC) do Prefix Information (RFC 4861 §4.6.2)."##),
    (r##"ipv6_nd.prefix_interface"##, r##"## O que é
A interface em cujo RA o prefixo vai. Ela precisa de uma entrada em `/ipv6 nd` (ou da `all`)."##),
    (r##"ipv6_nd.prefixes"##, r##"## O que é
Os prefixos que vão no RA (Prefix Information, RFC 4861 §4.6.2). Os **dinâmicos** vêm de cada endereço global /64 da interface (o `advertise=yes` do RouterOS); os **estáticos** você cadastra aqui. Um estático com o mesmo prefixo e interface substitui o dinâmico; desativado, o esconde.

## Depreciado
Um prefixo que sai do RA ainda vai três vezes com tempos de vida 0 (RFC 9096 §3.5), para os hosts pararem de usá-lo como origem."##),
    (r##"ipv6_nd.ra_delay"##, r##"## O que é
O menor tempo entre dois RAs multicast (MIN_DELAY_BETWEEN_RAS, RFC 4861 §10; padrão 3 s). Limita as respostas a uma tempestade de Router Solicitations."##),
    (r##"ipv6_nd.ra_interval"##, r##"## O que é
`MinRtrAdvInterval-MaxRtrAdvInterval` (RFC 4861 §6.2.1): cada RA não pedido sai num momento aleatório dentro da faixa. Padrão 3m20s-10m.

## Regras
Máximo de 4 s a 18h12m15s (RFC 8319); mínimo de pelo menos 3 s e no máximo 0,75 × o máximo. Ao ligar a interface ou mudar o RA saem até 3 RAs com no máximo 16 s entre eles (§6.2.4)."##),
    (r##"ipv6_nd.ra_lifetime"##, r##"## O que é
Router Lifetime (RFC 4861 §4.2): por quanto tempo os hosts usam este roteador como gateway padrão. Padrão 30m.

## Quando mudar
0 = não sou gateway padrão (os hosts pegam endereço e prefixo, mas não a rota padrão): para uma rede só de serviço. Fora o 0, vale entre o intervalo máximo e 18h12m15s (RFC 8319)."##),
    (r##"ipv6_nd.ra_preference"##, r##"## O que é
Default Router Preference (RFC 4191 §2.2): com dois roteadores no mesmo enlace, os hosts preferem o `high`. Padrão `medium`."##),
    (r##"ipv6_nd.ra_sent"##, r##"## O que é
RAs enviados nesta interface desde que o daemon começou."##),
    (r##"ipv6_nd.rdnss"##, r##"## O que é
Os servidores DNS que vão no RA desta interface agora (RDNSS), já resolvidos: os da entrada, o próprio roteador ou os do `/ip dns` e do DHCPv6."##),
    (r##"ipv6_nd.reachable_time"##, r##"## O que é
Reachable Time em ms (RFC 4861 §6.3.2): quanto tempo um vizinho fica alcançável depois de uma confirmação. 0 = não especificado (o padrão do host, 30 s). Máximo 1 h."##),
    (r##"ipv6_nd.retransmit_interval"##, r##"## O que é
Retrans Timer em ms (RFC 4861 §6.3.2): o intervalo entre Neighbor Solicitations do host. 0 = não especificado (1 s)."##),
    (r##"ipv6_nd.rs_received"##, r##"## O que é
Router Solicitations válidas recebidas (RFC 4861 §6.1.1: hop limit 255). Cada uma é respondida em até 0,5 s com um RA multicast, nunca antes do `ra-delay` depois do último (§6.2.6)."##),
    (r##"ipv6_nd.sender"##, r##"## O que é
O emissor de RA do daemon: uma thread e um socket ICMPv6 raw para todas as interfaces. Só roda com `--backend linux`; no laboratório virtual fica parado."##),
    (r##"ipv6_nd.state"##, r##"## O que é
Em quantas interfaces a entrada anuncia (`advertising`; se o RA já saiu, veja Interfaces alcançadas), quantas ficaram de fora (`skipped`, o motivo está em Interfaces alcançadas) e se há aviso."##),
    (r##"ipv6_nd.tab_interfaces"##, r##"## O que é
As entradas de `/ipv6 nd`: onde o RA sai e com que valores."##),
    (r##"ipv6_nd.tab_prefixes"##, r##"## O que é
`/ipv6 nd prefix`: os prefixos que vão no RA de cada interface."##),
    (r##"ipv6_nd.valid_lifetime"##, r##"## O que é
Valid Lifetime (RFC 4861 §4.6.2): até quando o host mantém o endereço. Padrão 4w2d; `infinity` = sem fim.

## Cuidado
O host nunca encurta um prefixo conhecido para menos de 2 h por um RA (RFC 4862 §5.5.3 e), contra RAs falsos."##),
    (r##"menu.ipv6-nd"##, r##"## O que faz
Router Advertisements (`/ipv6 nd`): o roteador anuncia os prefixos das LANs para os hosts e roteadores atrás dele fazerem SLAAC e o usarem como gateway IPv6. O kernel do Linux não envia RA: sem isto, nada atrás do CoreRouter autoconfigura."##),
];
