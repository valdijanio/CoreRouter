//! Portuguese labels and explanations of IP › Routes' check-gateway
//! (G1.27f), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("checking", "verificando"),
    ("down", "caiu"),
    ("held down for flapping, back in", "retida por oscilar, volta em"),
    ("not-checked", "sem verificação"),
    ("profile", "perfil"),
    ("reachable", "alcançável"),
    ("unreachable", "inalcançável"),
    ("up", "voltou"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "routes.bfd_profile",
        "## Perfil BFD

O perfil BFD da sessão até o gateway (Routing › BFD › Profiles): os intervalos e o multiplicador dão o tempo de detecção (`default`: 300 ms × 3 = 900 ms; `fast`: 50 ms × 3 = 150 ms). Vazio é `default`.

O gateway precisa falar BFD também (RFC 5880, salto único RFC 5881). Uma sessão que não subiu 5 s depois de a rota pedir conta como caída.",
    ),
    (
        "routes.check_gateway",
        "## Check Gateway

Se o gateway da rota está vivo, como o `check-gateway` do RouterOS:

- `none`: sem verificação; a rota fica enquanto a interface estiver de pé.
- `ping`: um eco ICMP a cada 10 s; 2 sem resposta seguidos e o gateway caiu.
- `arp`: uma consulta ARP a cada 10 s (gateway IPv4 no enlace): enxerga um gateway que descarta ping.
- `bfd`: uma sessão BFD até o gateway; cai no tempo de detecção do perfil (menos de um segundo).

Enquanto o gateway está caído a rota sai do kernel e a rota com a distância seguinte assume; na primeira resposta ela volta. Um gateway que cai de novo em 15 minutos fica retido: 10 s, depois 20 s, 40 s… até 5 min respondendo antes de as rotas voltarem, para um enlace oscilando não levar o tráfego de um lado para o outro.

Rotas pelo mesmo gateway dividem uma verificação: mil rotas, uma sonda.

**Estado**: `checking` (sem resposta ainda), `reachable`, `unreachable`, `not-checked` (nenhum daemon roda as verificações).",
    ),
    (
        "routes.reason",
        "## Motivo

Por que uma rota está **em espera** (uma rota de distância menor ganha; ela assume quando aquela cair) ou **inativa** (desativada, sem link, gateway inalcançável…).

Na linha de um grupo **ECMP** (caminhos na mesma distância que dividem o tráfego por conexão) é o aviso do grupo:

- `ECMP` azul (info): caminhos de uma origem só para uma rede que não é a rota padrão, como dois gateways estáticos. Em geral intencional.
- `ECMP` `aviso` âmbar: origens diferentes (estática + DHCP, dois uplinks DHCP) ou a rota padrão. Cada conexão sai por um dos uplinks, com um endereço público diferente: um site vê o mesmo usuário vindo de dois endereços, e um uplink que cai leva junto a parte dele das conexões. O texto termina com o comando que deixa um deles de reserva (distância 254 no cliente DHCP, ou a rota estática um passo atrás).

O aviso também conta em System › Health (`routes.ecmp`) e nas notas do cliente DHCP.",
    ),
];
