//! Portuguese labels and explanations of Interfaces › Bonding (G1.30m), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (
        "A Wi-Fi client cannot be a slave: the access point only passes its own MAC",
        "Cliente Wi-Fi não entra em bonding: o ponto de acesso só passa o MAC dele",
    ),
    ("Wi-Fi", "Wi-Fi"),
    (
        "Wi-Fi links have different, changing rates: balance-rr reorders TCP and a flow goes no faster than the slowest. balance-xor (one link per flow) or active-backup suit Wi-Fi better.",
        "Enlaces Wi-Fi têm taxas diferentes e que mudam: o balance-rr reordena o TCP e um fluxo não passa do mais lento. balance-xor (um enlace por fluxo) ou active-backup combinam melhor com Wi-Fi.",
    ),
    ("Wi-Fi ports", "Portas Wi-Fi"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "bonding.wifi_slave",
    "## Portas Wi-Fi no bonding

Cliente Wi-Fi comum (modo `station`) não entra em bonding nem em bridge.

- O quadro dele leva três endereços: o ponto de acesso só passa o que sai do MAC do próprio cliente.
- O bonding troca o MAC das portas, e a bridge encaminha quadros de outras máquinas: o ponto de acesso descartaria os dois.
- O kernel também recusa o cliente numa bridge (`IFF_DONT_BRIDGE`).

**Entre dois CoreRouters**, use **station-bridge** (G1.30m): o enlace leva quatro endereços (Multi-AP, ou WDS para falar com o OpenWrt). Um rádio em modo `station-bridge` e, no outro roteador, o enlace do par dele (Interfaces › Wi-Fi › Peers) aparecem entre as portas acima, como portas.

- **active-backup** ou **balance-xor** (cada fluxo num enlace) combinam com Wi-Fi; **balance-rr** reordena o TCP em enlaces de taxas diferentes.
- **802.3ad** (LACP), **balance-tlb** e **balance-alb** são recusados: o kernel precisa da velocidade e do duplex de cada porta, e o enlace Wi-Fi não os informa.
- O bonding dá o MAC dele às portas: do lado das estações, cadastre o MAC do bonding como o MAC dos pares nos pontos de acesso da outra ponta.

Cliente Wi-Fi comum: roteie por ele (com NAT de origem se a rede atrás do ponto de acesso não tem rota de volta).",
)];
