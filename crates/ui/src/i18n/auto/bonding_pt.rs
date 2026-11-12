//! Portuguese labels and explanations of Interfaces › Bonding (G1.30m), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (
        "A Wi-Fi client cannot be a slave: the access point only passes its own MAC",
        "Cliente Wi-Fi não entra em bonding: o ponto de acesso só passa o MAC dele",
    ),
    ("Wi-Fi", "Wi-Fi"),
    (
        "Wi-Fi links have different, changing rates: balance-rr reorders TCP and a flow goes no faster than the slowest. 802.3ad or active-backup suit Wi-Fi better.",
        "Enlaces Wi-Fi têm taxas diferentes e que mudam: o balance-rr reordena o TCP e um fluxo não passa do mais lento. 802.3ad ou active-backup combinam melhor com Wi-Fi.",
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

- **802.3ad** (LACP; a outra ponta também) ou **active-backup** combinam com Wi-Fi; **balance-rr** reordena o TCP em enlaces de taxas diferentes.
- O bonding dá um MAC só às portas: do lado das estações, cadastre o MAC do bonding como o MAC dos pares no ponto de acesso; do lado do ponto de acesso, os APs dos pares de um mesmo bonding usam o mesmo MAC (o do primeiro).

Cliente Wi-Fi comum: roteie por ele (com NAT de origem se a rede atrás do ponto de acesso não tem rota de volta).",
)];
