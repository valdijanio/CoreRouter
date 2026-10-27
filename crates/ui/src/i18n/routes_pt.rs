//! Portuguese labels and reason templates of IP › Routes (G1.27), each
//! sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("All", "Todas"),
    ("Changes (24 h)", "Trocas (24 h)"),
    ("Check gateway", "Check gateway"),
    ("Chosen", "Escolha"),
    ("IPv4", "IPv4"),
    ("IPv6", "IPv6"),
    ("Kernel", "Kernel"),
    ("Loading the route's detail…", "Carregando o detalhe da rota…"),
    ("Lookup", "Consultar"),
    ("Prefix", "Prefixo"),
    ("Route Lookup", "Consulta de rota"),
    ("Source", "Origem"),
    ("active", "ativas"),
    ("aggregate /16", "agregar /16"),
    ("ago", "atrás"),
    ("changed", "mudou"),
    ("contained", "contido"),
    ("contains", "contém"),
    ("created", "criada"),
    ("differs from the config", "diferente da config"),
    ("down for", "fora há"),
    ("exact", "exato"),
    ("inactive", "inativas"),
    ("incomplete", "incompleto"),
    ("kernel agrees", "kernel confere"),
    ("kernel differs", "kernel difere"),
    ("kernel not checked", "kernel não consultado"),
    ("local", "local"),
    ("matches the config", "igual à config"),
    ("misses", "falhas"),
    ("missing", "falta"),
    ("more", "mais"),
    ("next-hops", "próximos saltos"),
    ("no change seen", "nenhuma troca vista"),
    ("none", "nenhum"),
    ("not ours", "não é nossa"),
    ("of", "de"),
    ("open", "abrir"),
    ("routes", "rotas"),
    ("standby", "em espera"),
    ("unreachable", "inalcançável"),
];

/// Why a route is standby or inactive (`route.<reason_id>`), with the
/// engine's arguments.
pub(super) const TEMPLATES: &[(&str, &str)] = &[
    (
        "choice.ecmp",
        "divide o tráfego com mais {others} caminho(s) na distância {distance}",
    ),
    (
        "choice.lowest",
        "menor distância ({distance}) entre as rotas usáveis; a seguinte ({next}) assume se ela cair",
    ),
    (
        "choice.only",
        "a única rota para este prefixo",
    ),
    (
        "choice.only-usable",
        "a única rota usável ({others} outra(s) inativa(s))",
    ),
    (
        "route.address-disabled",
        "o endereço de '{interface}' que alcança {gateway} está desativado",
    ),
    (
        "route.bond-slave",
        "'{interface}' é escravo do bond '{master}'; roteie por '{master}'",
    ),
    (
        "route.bridge-port",
        "'{interface}' é porta da bridge '{master}'; roteie por '{master}'",
    ),
    (
        "route.check-gateway",
        "check-gateway={method} falhou há {secs} s: {gateway} não responde",
    ),
    (
        "route.check-gateway-down",
        "check-gateway={method}: {gateway} não responde",
    ),
    (
        "route.connected-disabled",
        "a interface '{interface}' ou o endereço dela está desativado",
    ),
    (
        "route.connected-wins",
        "perde para a rede conectada em {interface}",
    ),
    (
        "route.disabled",
        "rota desativada",
    ),
    (
        "route.empty",
        "gateway vazio",
    ),
    (
        "route.family-mismatch",
        "o gateway {gateway} e o destino {dst} são de famílias diferentes",
    ),
    (
        "route.interface-disabled",
        "a interface '{interface}' (ou a VRF dela) está desativada",
    ),
    (
        "route.interface-down",
        "interface '{interface}' sem link",
    ),
    (
        "route.loses-distance",
        "perde para a distância {distance} (rota {route} via {via})",
    ),
    (
        "route.needs-interface",
        "o gateway link-local {gateway} precisa da interface: {gateway}%<interface>",
    ),
    (
        "route.network-disabled",
        "a rede de {gateway} está num endereço ou interface desativado",
    ),
    (
        "route.no-interface",
        "a interface '{interface}' não existe",
    ),
    (
        "route.no-table",
        "a tabela '{table}' não existe (crie com ip.vrf.add)",
    ),
    (
        "route.not-on-interface",
        "{gateway} não está numa rede de '{interface}'",
    ),
    (
        "route.other-table",
        "'{interface}' está na tabela '{table}', não em '{route_table}'",
    ),
    (
        "route.own-address",
        "{gateway} é um endereço deste roteador (em '{interface}')",
    ),
    (
        "route.tie",
        "a rota {route} via {via} tem a mesma distância e ganha",
    ),
    (
        "route.unreachable",
        "gateway {gateway} fora de qualquer rede conectada da tabela '{table}'",
    ),
];
