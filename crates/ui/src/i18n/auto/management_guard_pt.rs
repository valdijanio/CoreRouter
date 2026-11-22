//! Portuguese labels and explanations of Routing › Management Guard
//! (G3.4z), each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"A learned route more specific than the connected network takes the replies to these management sessions. Click: Routing › Management Guard."##, r##"Uma rota aprendida mais específica que a rede conectada leva as respostas destas sessões de gerência. Clique: Routing › Management Guard."##),
    (r##"Comment"##, r##"Comentário"##),
    (r##"Disabled"##, r##"Desativado"##),
    (r##"Guarded Network"##, r##"Rede protegida"##),
    (r##"Interface"##, r##"Interface"##),
    (r##"Management Guard"##, r##"Guarda da gerência"##),
    (r##"Management networks not guarded"##, r##"Redes de gerência sem guarda"##),
    (r##"Management route"##, r##"Rota sobre a gerência"##),
    (r##"Network"##, r##"Rede"##),
    (r##"New Guarded Network"##, r##"Nova rede protegida"##),
    (r##"New Network…"##, r##"Nova rede…"##),
    (r##"No network guarded: a learned route more specific than the management network can still take the replies to your session. + adds one, or Protect above."##, r##"Nenhuma rede protegida: uma rota aprendida mais específica que a rede de gerência ainda pode levar as respostas da sua sessão. + acrescenta uma, ou Protect acima."##),
    (r##"Nobody looks at the routes of the sessions here (the virtual lab): the guard is kept in the config only."##, r##"Ninguém confere as rotas das sessões aqui (o laboratório virtual): a guarda fica só na configuração."##),
    (r##"Protect"##, r##"Proteger"##),
    (r##"Refused"##, r##"Recusadas"##),
    (r##"Sessions"##, r##"Sessões"##),
    (r##"State"##, r##"Estado"##),
    (r##"VRF"##, r##"VRF"##),
    (r##"covered"##, r##"coberta"##),
    (r##"mgmt route"##, r##"rota na gerência"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"management_guard"##, r##"## O que é
Uma rede de onde o roteador é gerenciado. Nenhum protocolo de roteamento pode instalar uma rota dentro dela mais longa que ela: um /32 de OSPF ou BGP dentro do /24 de gerência vence a rota conectada (prefixo mais longo, RFC 1812 §5.2.4.3) e manda as respostas ao operador por outra porta.

## Como funciona
O daemon de roteamento recusa essas rotas de todos os protocolos (FRR zebra `ip protocol any route-map`). Elas ficam na tabela do próprio protocolo como inativas, e o banco de estado de enlace não muda (RFC 2328 §2). Rotas conectadas e estáticas nunca são recusadas.

## Cuidado
Um host que esteja de verdade atrás de outro roteador dentro desta rede também é recusado: proteja só as redes de onde você gerencia."##),
    (r##"management_guard.disabled"##, r##"## O que é
Fica na configuração, sem aplicar: as rotas aprendidas dentro da rede voltam ao kernel. Desativar a guarda da rede da sua própria sessão enquanto uma rota aprendida cobre você é recusado como lockout (use o Safe Mode ou force)."##),
    (r##"management_guard.interface"##, r##"## O que é
A porta da rede conectada com este endereço. Vazio: a rede não é conectada aqui (ela recusa do mesmo jeito as rotas aprendidas dentro dela, para gerência que chega por rota estática)."##),
    (r##"management_guard.network"##, r##"## O que é
A rede de gerência, como está na porta: `192.168.0.0/24`. Os bits de host são zerados. Prefixos aprendidos dentro dela e mais longos (/25 a /32) são recusados; a própria rede e os mais curtos não, porque a rota conectada vence deles de qualquer jeito.

## Recomendado
As redes em Redes de gerência sem guarda: as de onde vêm as suas sessões."##),
    (r##"management_guard.refused"##, r##"## O que é
Rotas aprendidas dentro da rede que o daemon de roteamento tem e mantém fora do kernel, por protocolo, lidas da tabela dele (a cada 10 s com a janela aberta). `no kernel`: algumas ainda estão instaladas (a guarda ainda não foi aplicada)."##),
    (r##"management_guard.route_warning"##, r##"## O que é
Uma rota aprendida por OSPF, BGP ou outro protocolo é mais específica que a rede conectada de onde um operador gerencia: as respostas a essa sessão saem por outra porta, e a sessão pode já ter caído.

## O que fazer
Proteja a rede (Routing › Management Guard, ou o comando da dica) ou filtre o prefixo no vizinho que o anuncia. Se a sessão caiu, entre por outra rede ou pelo console."##),
    (r##"management_guard.sessions"##, r##"## O que é
Sessões de gerência abertas (GUI, terminal, MCP, CLI pela rede) cujo par está dentro desta rede. Sessões pelo loopback não contam: nenhuma rota as tira."##),
    (r##"management_guard.state"##, r##"## O que é
- `active`: o daemon de roteamento a aplica.
- `not-applied`: no candidato, sem commit ainda.
- `disabled`: só na configuração.
- `covered`: uma rota aprendida leva agora as respostas a uma sessão dentro dela.
- `in kernel`: rotas aprendidas dentro dela estão instaladas."##),
    (r##"management_guard.suggest"##, r##"## O que é
As redes conectadas de onde vêm as suas sessões de gerência abertas, ainda sem guarda. Protect acrescenta a rede num passo (`routing.management-guard.add`)."##),
    (r##"management_guard.vrf"##, r##"## O que é
A tabela de roteamento em que a rede está: `main`, ou a VRF da porta de gerência. O filtro de uma rede de VRF vai dentro do contexto `vrf <nome>` do zebra e só recusa rotas aprendidas dessa VRF (OSPF ou BGP dela); o mesmo prefixo em outra VRF é outra rede e fica como está.

## Padrão
Vazio, o roteador escolhe a tabela onde a rede é conectada (main quando ela também está na main). Uma guarda na tabela errada não protege nada: a prévia avisa quando a rede é conectada em outra."##),
    (r##"menu.management-guard"##, r##"## O que faz
Impede que rotas aprendidas (OSPF, BGP) tomem a rede de gerência: o roteador recusa um prefixo dentro dela mais longo que ela e avisa quando uma rota aprendida cobre uma sessão aberta."##),
];
