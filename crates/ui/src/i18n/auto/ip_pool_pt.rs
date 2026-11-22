//! Portuguese labels and explanations of IP › Pool (G4.2i), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("All", "Todos"),
    ("Owner", "Dono"),
    ("Pools", "Pools"),
    ("The first addresses, in address order: narrow with Owner or Find", "Os primeiros endereços, em ordem: filtre por Dono ou Find"),
    ("Used Addresses", "Endereços em uso"),
    ("addresses", "endereços"),
    ("of", "de"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "ip_pool.used",
        "## Used

Endereços do pool em uso agora: as concessões do servidor DHCP (bound ou em oferta) mais as sessões PPP (PPPoE) que tiraram o endereço deste pool. Conflitos e endereços recusados ficam reservados à parte e também não estão disponíveis.

O selo de porcentagem fica âmbar a partir de 80 %.",
    ),
    (
        "ip_pool.used.address",
        "## Address

O endereço entregue. Com Settings › Subscriber identity ligado, o nome do assinante aparece ao lado.

Um endereço em duas linhas é um **conflito**: uma concessão DHCP e uma sessão PPP estão com ele.",
    ),
    (
        "ip_pool.used.info",
        "## Info

Quem está com o endereço: no DHCP, o MAC e o host name do cliente; no IPoE, também o login; no PPP, o usuário e o MAC (e a VLAN por onde entrou). Num conflito, diz quem mais está com ele.",
    ),
    (
        "ip_pool.used.owner",
        "## Owner (dono)

O serviço que pegou o endereço, como o `owner` do `/ip pool used` do RouterOS: o servidor DHCP (selo **DHCP**, ou **IPoE** quando o servidor cria sessões de assinante) ou o servidor PPP (selo **PPP**).

O filtro Dono pede ao roteador só um tipo: com milhares de assinantes a lista é uma página (os 10 000 primeiros por endereço) e a contagem diz quantos são no total.",
    ),
    (
        "ip_pool.used.pool",
        "## Pool

O pool de onde veio o endereço. Uma concessão DHCP é do pool cujas faixas a contêm; uma sessão PPP, do pool de onde tirou o endereço (depois do `next_pool`, o que tinha vaga).",
    ),
    (
        "ip_pool.used.state",
        "## State (estado)

- **bound**: um cliente DHCP está com ele.
- **offered**: oferecido, esperando o REQUEST do cliente.
- **active**: uma sessão PPP ativa está com ele.
- **declined**: um cliente disse que o endereço já estava em uso (DHCPDECLINE).
- **conflict**: outro equipamento responde nele (ARP), ou uma concessão DHCP e uma sessão PPP estão com ele ao mesmo tempo. O segundo caso vem de um pool usado pelo servidor DHCP e por um perfil PPP: os dois entregam endereços sem ver um ao outro. Dê a cada um o seu pool (o pool mostra a verificação **DHCP + PPP**).",
    ),
    (
        "ip_pool.used_tab",
        "## Used Addresses (endereços em uso)

Todo endereço dos pools em uso, com quem o pegou: as concessões do servidor DHCP e as sessões PPP, como o `/ip pool used` do RouterOS. O pool é compartilhado, por isso a janela Pool fica direto em IP, e não dentro de DHCP.

Comando: `ip.pool.used.print` (`pool`, `owner`, `find` e `limit` filtram).",
    ),
];
