//! Portuguese labels and explanations of the first-login warning (G0.3b,
//! G0.3d), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Account without a password", "Conta sem senha"),
    (
        "Anyone who reaches the router, from this machine or the network, logs in as this user with an empty password.",
        "Qualquer um que alcance o roteador, desta máquina ou pela rede, entra como este usuário com a senha vazia.",
    ),
    ("Set password", "Definir senha"),
    (
        "This account has no password: anyone who reaches the router, from this machine or the network, logs in with an empty password. You can keep it so (Not now); the warning stays in the top bar until it has one.",
        "Esta conta não tem senha: qualquer um que alcance o roteador, desta máquina ou pela rede, entra com a senha vazia. Dá para manter assim (Not now); o aviso fica na barra de cima até haver senha.",
    ),
    ("Why this matters", "Por que importa"),
    ("no password", "sem senha"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "first_login.no_password",
    "## Conta sem senha

Esta conta do grupo **full** não tem senha. Como no RouterOS CHR, o roteador aceita então a **senha vazia vinda de qualquer rede** (sempre com TLS): quem alcançar o roteador primeiro entra e o controla.

Manter assim é escolha sua; nada é forçado nem limitado. O aviso fica na barra de cima, nas verificações de saúde e em todo cliente (CLI, MCP, terminal) até a conta ter senha. Cada login sem senha fica no log do roteador com o endereço de origem.

Defina em **Definir senha**, com `/user set admin password=…` no terminal ou `user.set`. O `--reset-admin-password` do daemon volta a deixar a conta sem senha.",
)];
