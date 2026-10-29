//! Portuguese labels and explanations of the connect screen's certificate
//! modal (G0.3d), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Cancel", "Cancelar"),
    ("Connect once", "Conectar só desta vez"),
    (
        "Connect with this certificate now; known_hosts keeps what it had.",
        "Conecta com este certificado agora; o known_hosts fica como estava.",
    ),
    (
        "Expected after a reinstall or a new certificate: compare the new fingerprint with the one the router prints at start-up (corerouter-daemon log, console). If you did not change anything, someone may be intercepting the connection: cancel.",
        "Esperado depois de reinstalar o roteador ou trocar o certificado: compare o fingerprint novo com o que o roteador imprime ao iniciar (log do corerouter-daemon, console). Se você não mudou nada, alguém pode estar interceptando a conexão: cancele.",
    ),
    (
        "First connection to this router. Compare the fingerprint with the one the router prints at start-up (corerouter-daemon log, console) before trusting it.",
        "Primeira conexão com este roteador. Compare o fingerprint com o que o roteador imprime ao iniciar (log do corerouter-daemon, console) antes de confiar.",
    ),
    ("Now", "Agora"),
    ("Remember this certificate (known_hosts, with today's date) and connect.", "Guarda este certificado (known_hosts, com a data de hoje) e conecta."),
    ("Remembered", "Guardado"),
    ("Router certificate CHANGED", "Certificado do roteador MUDOU"),
    ("Router:", "Roteador:"),
    (
        "The router shows another TLS certificate than the one remembered. Nothing was sent to it.",
        "O roteador mostra um certificado TLS diferente do guardado. Nada foi enviado a ele.",
    ),
    ("Trust and connect", "Confiar e conectar"),
    ("Trust and update", "Confiar e atualizar"),
    ("Unknown router certificate", "Certificado de roteador desconhecido"),
    ("What to check", "O que conferir"),
    ("accepted", "aceito em"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "connect.certificate",
    "## Certificado do roteador

Pela rede a GUI só fala com o roteador por TLS. Não há autoridade certificadora: na primeira vez você compara o fingerprint com o que o roteador imprime ao iniciar, e a GUI o guarda (`known_hosts`). As conexões seguintes conferem antes de enviar qualquer coisa.

**Mudou?** É o esperado depois de reinstalar o roteador ou trocar o certificado. Fora isso, alguém entre você e o roteador pode estar interceptando a conexão (homem no meio).

- **Cancel** (padrão; Enter e Esc cancelam): nada é enviado.
- **Connect once**: conecta com o certificado novo agora; o `known_hosts` continua com o antigo e a próxima conexão pergunta de novo.
- **Trust and update**: troca a linha no `known_hosts` (com a data de hoje) e conecta.

É o mesmo fluxo do PuTTY. CLI e MCP: num terminal perguntam o mesmo; sem terminal recusam e indicam `--accept-new-cert`.",
)];
