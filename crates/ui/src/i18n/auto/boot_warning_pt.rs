//! Portuguese labels and explanation of the boot warning (G1.3e), sorted
//! by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Config left out at boot", "Configuração de fora no boot"),
    (
        "The kernel refused these parts of the saved config at boot; the rest, management included, is up. Retried with a growing wait (up to 60 s).",
        "O kernel recusou estas partes da configuração salva no boot; o resto, gerência inclusive, está no ar. Nova tentativa com espera crescente (até 60 s).",
    ),
    ("Why this matters", "Por que importa"),
    ("boot", "boot"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "boot_warning.boot_apply",
    "## Configuração de fora no boot

Ao ligar, o roteador aplica a configuração salva inteira de uma vez. Se o kernel recusa alguma parte (uma regra de firewall que pede um módulo que não carregou, uma rota, uma entrada MPLS, um ajuste de placa), ele **não desfaz tudo**: sobe primeiro interfaces e endereços, para a gerência ficar acessível, e depois cada seção por cima. A seção recusada fica de fora, com o erro do kernel.

Seções: `ethernet` (velocidade/duplex), `routes`, `firewall` (filter, nat, mangle, raw, listas), `cgnat`, `fastpath`, `tuning`, `xdp`, `arp`, `mpls`. `core` quer dizer que nem interfaces e endereços entraram.

- O selo some quando tudo entra: o roteador tenta de novo sozinho, com espera crescente (1, 2, 4… até 60 s).
- **Corrija ou tire** o item recusado e faça commit: um commit que mexe na seção a aplica inteira (tudo ou nada, como sempre). Commits em outras partes funcionam normalmente e deixam a seção recusada como está.
- **Firewall: só a regra recusada fica de fora** (`firewall *5`, flag I na lista de regras, com o motivo do kernel); o resto do firewall entra. O roteador acha a regra só com checagens que não aplicam nada (como o `nft --check`) e aplica o firewall reduzido uma vez. Se, sem a regra, o firewall cortaria a gerência (por exemplo, a regra recusada é o `accept` da gerência e há um `drop` no fim), o **firewall inteiro fica de fora** e o aviso diz qual regra e por quê. Regra recusada sozinha é tentada de novo com espera de até 10 min; um commit que muda a regra tenta na hora.
- **Firewall inteiro de fora deixa o roteador sem filtro** até ser corrigido: trate como prioridade.

A mesma lista está na saúde (`boot.apply`), no log do roteador, no `state.inspect` (`storage.boot_apply_failed`) e no aviso da CLI e do MCP.",
)];
