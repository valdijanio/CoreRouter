//! Portuguese labels and explanations of the top bar's other-build chip
//! (G0.32), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Another build", "Outra build"),
    ("Control protocol differs", "Protocolo de controle diferente"),
    (
        "The router's daemon is another build than this GUI: fixes may be missing on one side.",
        "O daemon do roteador é outra build que esta GUI: correções podem faltar de um dos lados.",
    ),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "version.other_build",
    "## Daemon e GUI de builds diferentes

A barra mostra a versão do daemon do roteador e a desta GUI quando elas não são a mesma build (G0.32). Numa release a versão é `0.1.0`; fora dela é `0.1.0-dev.<N>`, em que N conta os commits até a build: cada PR integrado soma 1, então `dev.498` contra `dev.500` são dois PRs de diferença. Quando só o commit muda, as duas aparecem completas (`0.1.0-dev.500+320cb9d`); `.dirty` quer dizer compilada com alterações sem commit. Passe o mouse para ver as duas builds com a data do commit.

- **Âmbar:** só a build difere. Tudo funciona, mas uma correção pode existir de um lado só. Feche e abra a GUI depois de compilar, ou atualize o roteador em **System › Packages**.
- **Vermelho:** o protocolo de controle mudou. Comandos podem ser lidos errado ou recusados: atualize o lado mais antigo antes de mexer na configuração.

Como no WinBox, que avisa quando a versão dele não bate com a do RouterOS.",
)];
