//! Portuguese labels and explanations of the Routing › BGP window (G3.2a),
//! each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"AS"##, r##"AS"##),
    (r##"Address Families"##, r##"Famílias de endereço"##),
    (r##"Apply"##, r##"Aplicar"##),
    (r##"Ask the neighbor to send its routes again (RFC 2918): new inbound policy, no reset"##, r##"Pede ao vizinho que mande as rotas de novo (RFC 2918): aplica a nova política de entrada sem derrubar a sessão"##),
    (r##"BFD"##, r##"BFD"##),
    (r##"BGP Instance"##, r##"Instância BGP"##),
    (r##"Clear"##, r##"Reiniciar"##),
    (r##"Close the session and open it again (its routes are withdrawn meanwhile)"##, r##"Fecha a sessão e abre de novo (as rotas dela saem enquanto isso)"##),
    (r##"Connections"##, r##"Conexões"##),
    (r##"Defer Time"##, r##"Tempo de espera"##),
    (r##"Disabled"##, r##"Desativada"##),
    (r##"Enable"##, r##"Ativar"##),
    (r##"Families"##, r##"Famílias"##),
    (r##"Flaps"##, r##"Quedas"##),
    (r##"GR"##, r##"GR"##),
    (r##"GR Notification"##, r##"Notificação no GR"##),
    (r##"General"##, r##"Geral"##),
    (r##"Graceful Restart"##, r##"Graceful restart"##),
    (r##"Hard Admin Reset"##, r##"Hard Reset no clear"##),
    (r##"History"##, r##"Histórico"##),
    (r##"Hold"##, r##"Hold"##),
    (r##"Hold / Keepalive"##, r##"Hold / Keepalive"##),
    (r##"Instances"##, r##"Instâncias"##),
    (r##"Key"##, r##"Chave"##),
    (r##"Kind"##, r##"Tipo"##),
    (r##"LLGR"##, r##"LLGR"##),
    (r##"LLGR Stale Time"##, r##"Tempo do LLGR"##),
    (r##"Last Error"##, r##"Último erro"##),
    (r##"Limits"##, r##"Limites"##),
    (r##"Local Role"##, r##"Papel local"##),
    (r##"Messages"##, r##"Mensagens"##),
    (r##"Name"##, r##"Nome"##),
    (r##"New BGP Instance"##, r##"Nova instância BGP"##),
    (r##"New Connection…"##, r##"Nova conexão…"##),
    (r##"New Instance…"##, r##"Nova instância…"##),
    (r##"New Template…"##, r##"Novo template…"##),
    (r##"No BGP connection yet: add one in the Connections tab."##, r##"Nenhuma conexão BGP ainda: adicione uma na aba Conexões."##),
    (r##"Not a CoreRouter connection (typed into FRR by hand)."##, r##"Não é uma conexão do CoreRouter (digitada no FRR à mão)."##),
    (r##"Notification"##, r##"Notificação"##),
    (r##"Output Network"##, r##"Redes anunciadas"##),
    (r##"Policy In"##, r##"Política de entrada"##),
    (r##"Policy Out"##, r##"Política de saída"##),
    (r##"Prefixes In"##, r##"Prefixos recebidos"##),
    (r##"Prefixes Out"##, r##"Prefixos enviados"##),
    (r##"RPKI In"##, r##"RPKI entrada"##),
    (r##"Redistribute"##, r##"Redistribuir"##),
    (r##"Refresh"##, r##"Pedir rotas"##),
    (r##"Remote AS"##, r##"AS remoto"##),
    (r##"Remote Address"##, r##"Endereço remoto"##),
    (r##"Remote ID"##, r##"ID remoto"##),
    (r##"Rendered for FRR bgpd:"##, r##"Como vai para o bgpd do FRR:"##),
    (r##"Resend"##, r##"Reenviar rotas"##),
    (r##"Restart Time"##, r##"Restart Time"##),
    (r##"Router ID"##, r##"Router ID"##),
    (r##"Routes"##, r##"Rotas"##),
    (r##"Send our routes again: new outbound policy, no reset"##, r##"Manda as nossas rotas de novo: aplica a nova política de saída sem derrubar a sessão"##),
    (r##"Session"##, r##"Sessão"##),
    (r##"Sessions"##, r##"Sessões"##),
    (r##"Shutdown"##, r##"Desligar"##),
    (r##"Shutdown closes the session (Cease, administrative shutdown) and keeps the connection"##, r##"Desligar fecha a sessão (Cease, administrative shutdown) e mantém a conexão na config"##),
    (r##"Stale Time"##, r##"Tempo de stale"##),
    (r##"State"##, r##"Estado"##),
    (r##"Templates"##, r##"Templates"##),
    (r##"The routes this neighbor sent and we sent it, with the RPKI state of each (Routing › BGP Routes)"##, r##"As rotas que este vizinho mandou e que mandamos a ele, com o estado RPKI de cada uma (Routing › BGP Routes)"##),
    (r##"Uptime"##, r##"Tempo ativo"##),
    (r##"Used By"##, r##"Usado por"##),
    (r##"When this session went down and came back, and why"##, r##"Quando esta sessão caiu e voltou, e por quê"##),
    (r##"configured"##, r##"configurado"##),
    (r##"none"##, r##"nenhuma"##),
    (r##"none (RFC 8212: nothing accepted or sent)"##, r##"nenhuma (RFC 8212: nada é aceito nem enviado)"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"bgp.connection"##, r##"## O que é
Um vizinho BGP (`/routing bgp connection` do RouterOS). Campo vazio herda dos templates e depois do padrão. A prévia mostra os valores em vigor e o que a mudança faz.

## Cuidado
Mudar endereço, AS, papel, chave MD5 ou endereço local reinicia esta sessão (as rotas dela saem e voltam); as outras não caem."##),
    (r##"bgp.connection.disabled"##, r##"## O que é
Desligar: a sessão é fechada com um NOTIFICATION Cease (administrative shutdown, RFC 4486/RFC 8203) e fica fechada; a conexão continua na config.

## Quando usar
Manutenção no vizinho, ou para tirar um trânsito do ar sem perder a configuração."##),
    (r##"bgp.connection.instance"##, r##"## O que é
A instância BGP (AS local e router-id) deste vizinho. `default` é a tabela de rotas principal."##),
    (r##"bgp.connection.name"##, r##"## O que é
O nome da conexão; vai para o FRR como a descrição do vizinho, e é assim que uma sessão ao vivo acha a sua conexão. Letras, dígitos, `-`, `_` e `.`."##),
    (r##"bgp.connection.remote_address"##, r##"## O que é
O endereço do vizinho (`remote.address` do RouterOS), IPv4 ou IPv6. Uma conexão por endereço em cada instância."##),
    (r##"bgp.instance.asn"##, r##"## O que é
O nosso AS, em asplain ou asdot, de 4 bytes (RFC 6793). Valores reservados são recusados."##),
    (r##"bgp.instance.disabled"##, r##"## O que é
Uma instância desativada para: o `bgpd` fecha todas as sessões das conexões dela (Cease, administrative shutdown) e as rotas delas saem. A instância e as conexões continuam na config.

## Cuidado
A prévia diz quantas sessões param."##),
    (r##"bgp.instance.graceful_defer_time"##, r##"## O que é
Depois que o nosso `bgpd` sobe, quanto tempo a escolha do melhor caminho espera o End-of-RIB dos vizinhos que anunciam graceful restart antes de instalar e anunciar rotas (RFC 4724 §4.1; `select-defer-time` do FRR). 0..3600 s; vazio: 10 s (os 360 s do FRR deixaram as rotas de um vizinho RouterOS 120 s fora do kernel, **medido**).

## Cuidado
Um vizinho que nunca manda End-of-RIB (RouterOS 7.25; a checagem de saúde `bgp.end-of-rib` o aponta) segura as rotas dele pelo tempo inteiro depois de cada início do `bgpd`. 0 não espera: as rotas podem mudar enquanto os vizinhos reenviam as tabelas."##),
    (r##"bgp.instance.graceful_notification"##, r##"## O que é
O bit N da capacidade de graceful restart (RFC 8538 §2). Com ele dos dois lados, uma NOTIFICATION ou o hold timer expirado viram reinício: as rotas do vizinho ficam (stale) pelo Restart Time dele; só um Hard Reset (Cease 9 e, no FRR, também Maximum Prefixes, Shutdown, De-configured e BFD Down) as tira na hora. Ligado por padrão (FRR desde a 8.3).

## Cuidado
Uma queda silenciosa (energia, link cortado) de um vizinho que reinicia com GR deixa as rotas dele o hold time mais o Restart Time. Use BFD nessas conexões (a queda do BFD é Hard Reset); a prévia e a checagem de saúde `bgp.gr-bfd` avisam. Desligado: hold expirado ou NOTIFICATION tiram as rotas como antes da RFC 8538. O RouterOS 7.25 não documenta a RFC 8538."##),
    (r##"bgp.instance.graceful_restart_time"##, r##"## O que é
O Restart Time que anunciamos na capacidade de graceful restart (RFC 4724 §3): quanto tempo o vizinho guarda as nossas rotas (stale) depois que o nosso `bgpd` morre, esperando ele voltar. Só as conexões com Graceful Restart = yes o anunciam. 1..4095 s (12 bits); vazio: 120 s.

## Recomendado
Abaixo do hold time dessas conexões (RFC 4724 §3; a prévia avisa). Mais longo esconde uma falha de verdade: o vizinho continua mandando tráfego para um roteador que não vai voltar.

## Outros roteadores
FRR `bgp graceful-restart restart-time` (120), Junos `restart-time` (120), Cisco `bgp graceful-restart restart-time` (120). O RouterOS 7.25 não tem o parâmetro."##),
    (r##"bgp.instance.graceful_stale_time"##, r##"## O que é
Como helper: quanto tempo guardamos as rotas de um vizinho que reiniciou, marcadas stale, depois que ele volta e antes do End-of-RIB dele (RFC 4724 §4.2). As rotas stale que ele não mandou de novo saem quando chega o End-of-RIB ou quando este tempo acaba. 1..4095 s; vazio: 360 s.

## Cuidado
Um vizinho que nunca manda End-of-RIB (RouterOS 7.25) deixa as rotas velhas pelo tempo inteiro. FRR `bgp graceful-restart stalepath-time`, Junos `stale-routes-time` (300)."##),
    (r##"bgp.instance.hard_admin_reset"##, r##"## O que é
Se um reset administrativo (Cease 4: `routing.bgp.session.clear`) vai como Hard Reset (RFC 8538 §3) e tira as rotas do vizinho. Ligado por padrão. Desligado: o clear de um vizinho com bit N é gracioso, as rotas ficam stale até ele mandar de novo (bom para aplicar uma política sem buraco no tráfego). Shutdown sempre as tira."##),
    (r##"bgp.instance.llgr_stale_time"##, r##"## O que é
Long-Lived Graceful Restart (RFC 9494): quando acaba o Restart Time de um graceful restart, o vizinho guarda as nossas rotas por mais este tempo, marcadas com a comunidade `llgr-stale` e com a menor preferência, então qualquer rota viva ganha delas. 1..16777215 s (24 bits); vazio: desligado (§5: nunca ligado por padrão). O FRR tem um valor só para todas as famílias de endereço (a RFC pede por AFI/SAFI). Também é o máximo que guardamos das rotas do vizinho: o FRR fica com o menor entre o tempo dele e o nosso, então configure nos dois lados.

## Quando usar
Para rotas que têm alternativa, ou que é melhor ter velhas que não ter (VPN, rota padrão de duas operadoras). Rotas marcadas com `no-llgr` (Routing › Filters, `append bgp-communities no-llgr`) nunca ficam.

## Cuidado
Salto a salto, uma rota stale mais específica ainda ganha de uma rota viva menos específica (§5): o tráfego pode ir para um próximo salto morto o tempo todo. A prévia mostra o pior caso (hold + Restart Time + LLGR). O RouterOS 7.25 não suporta LLGR: o FRR não manda rotas stale para ele (§4.3)."##),
    (r##"bgp.instance.name"##, r##"## O que é
O nome da instância; `default` roda na tabela principal, outro nome é uma view separada do FRR."##),
    (r##"bgp.instance.router_id"##, r##"## O que é
O nosso identificador BGP, um endereço IPv4 único no AS (RFC 6286); normalmente o loopback."##),
    (r##"bgp.param.afi"##, r##"## O que é
O `afi` do RouterOS: as famílias de endereço que a sessão carrega (BGP multiprotocolo, RFC 4760): `ip` (IPv4 unicast), `ipv6`, ou as duas. Padrão `ip`.

## Cuidado
Uma conexão sem família nenhuma é recusada: não carregaria nada."##),
    (r##"bgp.param.bfd"##, r##"## O que é
O perfil BFD (Routing › BFD) que vigia esta sessão: quando o BFD vê o vizinho ou o caminho morrer, o BGP cai na hora em vez de esperar o hold time (`neighbor … bfd profile` do FRR). Vazio: herda dos templates; sem perfil, sem BFD.

## Recomendado
`default` (300 ms × 3) no eBGP com a operadora; o outro lado também precisa de BFD."##),
    (r##"bgp.param.graceful_restart"##, r##"## O que é
Graceful restart (RFC 4724) como quem reinicia: quando o `bgpd` deste roteador cai e volta, o vizinho guarda as nossas rotas (marcadas stale) até o Restart Time da instância (120 s por padrão), e o nosso kernel guarda as dele (o `zebra` não as tira). O tráfego segue enquanto o `bgpd` volta. Sem isso o vizinho retira as rotas assim que a sessão TCP cai (106 ms, **medido** contra o RouterOS 7.25).

## Valores
`yes`: anuncia a capacidade de reinício com o bit F (encaminhamento preservado). Vazio: só ajuda (guarda as rotas do vizinho quando ele reinicia), o padrão do FRR. `no`: nem isso.

## Cuidado
O vizinho precisa ser helper (o RouterOS anuncia `gr`). O Restart Time deve ser menor que o hold time (RFC 4724 §3; a prévia avisa). Os tempos ficam na instância (aba Instâncias, ou `routing.bgp.instance.set` com `graceful_restart_time` e `graceful_stale_time` (1..4095 s) e `graceful_defer_time` (0..3600 s, padrão 10: quanto o melhor caminho espera os End-of-RIB depois que o `bgpd` sobe; o FRR usaria 360 s)).

## Com MikroTik
O RouterOS 7.25 anuncia graceful restart mas não guarda as nossas rotas quando o `bgpd` cai, nem manda End-of-RIB (**medido**): do lado dele não há ganho. Do nosso lado o kernel continua guardando as rotas dele."##),
    (r##"bgp.param.hold_time"##, r##"## O que é
Segundos sem mensagem do vizinho até a sessão ser fechada (RFC 4271 §4.2). Vale o menor dos dois lados.

## Valores
0 (infinito) ou 3..65535. Padrão 180 s.

## Cuidado
Menos de 9 s derruba a sessão numa perda curta; para detectar falha rápido, use BFD."##),
    (r##"bgp.param.keepalive_time"##, r##"## O que é
Segundos entre KEEPALIVEs. Vazio: um terço do hold time (RFC 4271 §10). Tem que ser menor que o hold time."##),
    (r##"bgp.param.local_role"##, r##"## O que é
O `local.role` do RouterOS: `ibgp` (mesmo AS), `ibgp-rr` (iBGP em que este roteador é o refletor de rotas e o vizinho é cliente, RFC 4456) ou `ebgp`; os papéis `ebgp-provider`, `-customer`, `-peer`, `-rs` e `-rs-client` são anunciados no OPEN (RFC 9234) e deixam os dois lados pegarem um vazamento de rotas (route leak).

## Padrão
Vazio: pelo AS remoto (o nosso → ibgp, outro → ebgp).

## Recomendado
Trânsito: `ebgp-provider` do nosso lado é errado — o papel é o **nosso**: com um trânsito somos `ebgp-customer`."##),
    (r##"bgp.param.max_prefix"##, r##"## O que é
O máximo de prefixos aceitos do vizinho, por família (`input.limit-process-routes` do RouterOS). Protege o roteador de uma tabela completa mandada por engano. Vazio ou 0: sem limite.

## Recomendado
Cliente: um pouco acima do que ele anuncia; trânsito: ~1,2 milhão IPv4 e ~250 mil IPv6 (2026)."##),
    (r##"bgp.param.max_prefix_action"##, r##"## O que é
O que acontece acima do limite: `shutdown` (fecha a sessão até alguém reiniciá-la; padrão), `warning` (só registra) ou `restart` (fecha e tenta de novo depois do tempo de restart)."##),
    (r##"bgp.param.max_prefix_restart"##, r##"## O que é
Minutos até a sessão fechada pelo limite de prefixos abrir de novo (ação `restart`). Padrão 5."##),
    (r##"bgp.param.multihop"##, r##"## O que é
O vizinho eBGP está a mais de um salto (um loopback): `ebgp-multihop` no FRR (TTL 255). iBGP é sempre multihop.

## Cuidado
Com multihop, um ataque de longe consegue chegar à porta 179: prefira chave MD5 ou TTL security."##),
    (r##"bgp.param.nexthop_choice"##, r##"## O que é
O `nexthop-choice` do RouterOS: `default` (a regra do protocolo), `force-self` (sempre o nosso endereço, também para iBGP: `next-hop-self` no FRR) ou `propagate` (mantém o next hop recebido, também para eBGP).

## Quando usar
`force-self` no iBGP de um roteador de borda, para os outros não precisarem da rota até o trânsito."##),
    (r##"bgp.param.output_network"##, r##"## O que é
`output.network` do RouterOS: o nome de uma address-list do firewall (`/ip firewall address-list`) cujas redes este roteador anuncia ao vizinho. Cada rede só sai enquanto houver rota para ela (conectada, estática ou do OSPF), como no RouterOS; faixas `a-b` ficam de fora.

## Cuidado
O FRR anuncia por instância: a lista vale para as outras conexões da mesma família. Quem não deve receber filtra no Output Filter (eBGP sem ele não recebe nada, RFC 8212)."##),
    (r##"bgp.param.output_redistribute"##, r##"## O que é
`output.redistribute` do RouterOS: as rotas do próprio roteador que vão ao vizinho, separadas por vírgula: `connected`, `static` (as de `/ip route`) e `ospf`.

## Cuidado
Como a Output Network, vale para a instância inteira; o Output Filter escolhe o que cada vizinho recebe."##),
    (r##"bgp.param.remote_as"##, r##"## O que é
O AS do vizinho (`remote.as` do RouterOS), em asplain (`65100`) ou asdot (`1.10`), de 4 bytes (RFC 6793). Vazio: qualquer AS — `remote-as external` (eBGP) ou `internal` (iBGP) no FRR, conforme o papel.

## Recusados
0 (RFC 7607), 23456 (AS_TRANS, RFC 6793), 65535 e 4294967295 (RFC 7300)."##),
    (r##"bgp.param.tcp_md5_key"##, r##"## O que é
A chave de assinatura TCP MD5 (RFC 2385), a mesma dos dois lados; o `tcp-md5-key` do RouterOS. Fica selada: nunca aparece na config, no histórico, no journal, nos logs nem no MCP.

## Editar
Vazio mantém a chave; pela CLI, `tcp_md5_key=""` apaga.

## Cuidado
Trocar a chave reinicia a sessão; combine a troca com o outro lado."##),
    (r##"bgp.param.templates"##, r##"## O que é
Templates de onde herdar, separados por vírgula; o primeiro ganha. Um valor definido aqui sempre ganha dos templates."##),
    (r##"bgp.param.update_source"##, r##"## O que é
O `local.address` do RouterOS: o endereço (ou interface) de onde sai a sessão TCP — um loopback no iBGP entre roteadores."##),
    (r##"bgp.session.bfd"##, r##"## O que é
O estado do BFD para o vizinho (RFC 5880/5882), quando o BFD o vigia: detecta um enlace morto em fração de segundo, bem antes do hold time."##),
    (r##"bgp.session.flaps"##, r##"## O que é
Quantas vezes a sessão caiu depois de estabelecida. Um número que cresce aponta para enlace ou vizinho instável."##),
    (r##"bgp.session.gr"##, r##"## O que é
O papel deste roteador no graceful restart com o vizinho (RFC 4724): `restart` (reinicia sem o vizinho retirar as rotas), `helper` (só guarda as rotas do vizinho quando ele reinicia), `disable`. `EoR`: o vizinho mandou o End-of-RIB (§2), a tabela dele está completa. `no EoR` (âmbar): estamos como `restart` e o vizinho nunca mandou End-of-RIB; o RouterOS 7.25 é assim (**medido**): anuncia a capacidade e não manda o marcador, e também não guarda as nossas rotas quando o nosso `bgpd` cai. Depois de um início do `bgpd`, as rotas dele esperam o Defer Time da instância (10 s)."##),
    (r##"bgp.session.last_error"##, r##"## O que é
O último NOTIFICATION enviado ou recebido (RFC 4271 §4.5), ou o motivo da última queda ("Reached received prefix count": o limite de prefixos)."##),
    (r##"bgp.session.messages"##, r##"## O que é
Mensagens BGP recebidas e enviadas (OPEN, UPDATE, KEEPALIVE, NOTIFICATION, ROUTE-REFRESH)."##),
    (r##"bgp.session.policy"##, r##"## O que é
O route-map aplicado em cada direção. Sem nenhum, uma sessão eBGP não aceita nem envia nada (RFC 8212, ligado por padrão); as políticas chegam no G3.2b."##),
    (r##"bgp.session.prefixes_in"##, r##"## O que é
Prefixos aceitos do vizinho, todas as famílias. No eBGP sem política fica em 0 (RFC 8212)."##),
    (r##"bgp.session.prefixes_out"##, r##"## O que é
Prefixos enviados ao vizinho, todas as famílias."##),
    (r##"bgp.session.remote_id"##, r##"## O que é
O identificador BGP do vizinho (o router-id dele), do OPEN."##),
    (r##"bgp.session.state"##, r##"## O que é
O estado da sessão (RFC 4271 §8.2.2): `established` está no ar; `idle`, `connect`, `active`, `opensent` e `openconfirm` estão a caminho (ou falhando); `disabled` foi desligada; `no daemon` quer dizer que não há daemon de roteamento (laboratório virtual).

## Diagnóstico
Preso em `active`: o TCP não fecha (endereço, rota, firewall na 179, chave MD5 diferente). Cai depois do OPEN: AS ou papel errado — veja o último erro."##),
    (r##"bgp.session.timers"##, r##"## O que é
O hold time e o keepalive negociados (o menor hold dos dois lados, RFC 4271 §4.2); antes de a sessão subir, os configurados."##),
    (r##"bgp.session.uptime"##, r##"## O que é
Há quanto tempo a sessão está estabelecida."##),
    (r##"bgp.tab.connections"##, r##"## O que é
Os vizinhos, como o `/routing bgp connection` do RouterOS: endereço, AS, papel e os templates de onde cada um herda. Uma mudança vai para o FRR só com as linhas que mudaram: as outras sessões não caem.

## Dica
Parâmetros comuns (timers, famílias, limite de prefixos, chave MD5) ficam melhor num template: muda-se num lugar só."##),
    (r##"bgp.tab.instances"##, r##"## O que é
O nosso lado: o AS local (4 bytes, RFC 6793), o router-id e os tempos de graceful restart (RFC 4724). As conexões pertencem a uma instância (`default`). Duplo clique edita; a prévia diz o que a mudança faz com as sessões (AS ou router-id novos as reiniciam)."##),
    (r##"bgp.tab.sessions"##, r##"## O que mostra
As sessões BGP que o FRR está rodando agora, uma por conexão, como o `/routing bgp session` do RouterOS (só leitura, ao vivo a cada 2 s): estado, tempo ativo, prefixos recebidos e enviados, BFD. Selecione uma para ver o último erro, os timers, as políticas, as quedas e as ações Pedir rotas, Reenviar, Reiniciar e Desligar.

## Cuidado
No laboratório virtual não há FRR: o estado aparece como `no daemon`."##),
    (r##"bgp.tab.templates"##, r##"## O que é
Parâmetros compartilhados, como o `/routing bgp template` do RouterOS. Uma conexão lista templates; cada parâmetro que ela deixa vazio vem do primeiro template que o define, e um template pode ter pais (herança em laço é recusada).

## Outros roteadores
É o `group` do Junos e o `peer-session`/`peer-policy` do Cisco, mas com herança múltipla e qualquer valor sobrescrito na conexão."##),
    (r##"bgp.template"##, r##"## O que é
Parâmetros compartilhados por várias conexões (`/routing bgp template` do RouterOS). Uma mudança chega a toda conexão que herda o valor; a prévia lista quem usa e recusa a mudança que deixaria alguma inválida."##),
    (r##"bgp.template.name"##, r##"## O que é
O nome do template, como as conexões e outros templates o listam. Renomear atualiza todos que o listam."##),
    (r##"bgp.template.used_by"##, r##"## O que é
As conexões e templates que listam este template: quem muda quando ele muda. Um template em uso não pode ser removido."##),
];

pub(super) const TEMPLATES: &[(&str, &str)] = &[];
