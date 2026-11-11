//! Portuguese labels and explanations of Interfaces › Bonding (G1.30m), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (
        "A Wi-Fi client cannot be a slave: the access point only passes its own MAC",
        "Cliente Wi-Fi não entra em bonding: o ponto de acesso só passa o MAC dele",
    ),
    ("Wi-Fi", "Wi-Fi"),
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

**Entre dois CoreRouters**, use **station-bridge** (G1.30m, a caminho): o enlace leva quatro endereços (Multi-AP, ou WDS para falar com o OpenWrt), entra numa bridge e num bonding feito de vários desses enlaces.

Hoje: roteie pela porta Wi-Fi (com NAT de origem se a rede atrás do ponto de acesso não tem rota de volta).",
)];
