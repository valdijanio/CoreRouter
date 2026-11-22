//! Portuguese labels and explanations of the connect screen: the certificate modal
//! (G0.3d) and the saved password (G0.3e), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("A password is saved for this router and Login, but Connect sends what the field holds now (empty: no password).", "Há uma senha salva para este roteador e Login, mas o Connect manda o que está no campo agora (vazio: sem senha)."),
    ("A reinstalled router has a new admin (without a password until one is set): the password saved for the old one would be refused. Applies to Trust and update.", "Um roteador reinstalado tem um admin novo (sem senha até definirem uma): a senha salva para o antigo seria recusada. Vale para Confiar e atualizar."),
    ("Also forget the saved password of", "Esquecer também a senha salva de"),
    ("Cancel", "Cancelar"),
    ("Connect once", "Conectar só desta vez"),
    ("Connect with this certificate now; known_hosts keeps what it had.", "Conecta com este certificado agora; o known_hosts fica como estava."),
    ("Expected after a reinstall or a new certificate: compare the new fingerprint with the one the router prints at start-up (corerouter-daemon log, console). If you did not change anything, someone may be intercepting the connection: cancel.", "Esperado depois de reinstalar o roteador ou trocar o certificado: compare o fingerprint novo com o que o roteador imprime ao iniciar (log do corerouter-daemon, console). Se você não mudou nada, alguém pode estar interceptando a conexão: cancele."),
    ("First connection to this router. Compare the fingerprint with the one the router prints at start-up (corerouter-daemon log, console) before trusting it.", "Primeira conexão com este roteador. Compare o fingerprint com o que o roteador imprime ao iniciar (log do corerouter-daemon, console) antes de confiar."),
    ("Forget", "Esquecer"),
    ("Forget saved password", "Esquecer senha salva"),
    ("Forget saved password: delete it from the secure store of this computer; the router is not touched.", "Esquecer senha salva: apaga do cofre de senhas deste computador; o roteador não é alterado."),
    ("Now", "Agora"),
    ("Remember this certificate (known_hosts, with today's date) and connect.", "Guarda este certificado (known_hosts, com a data de hoje) e conecta."),
    ("Remembered", "Guardado"),
    ("Router certificate CHANGED", "Certificado do roteador MUDOU"),
    ("Router:", "Roteador:"),
    ("Saved password", "Senha salva"),
    ("The Password field holds the password saved for this router and Login. Clear it to connect with an empty password.", "O campo Password está com a senha salva para este roteador e Login. Apague-o para conectar com a senha vazia."),
    ("The router shows another TLS certificate than the one remembered. Nothing was sent to it.", "O roteador mostra um certificado TLS diferente do guardado. Nada foi enviado a ele."),
    ("Trust and connect", "Confiar e conectar"),
    ("Trust and update", "Confiar e atualizar"),
    ("Unknown router certificate", "Certificado de roteador desconhecido"),
    ("What to check", "O que conferir"),
    ("accepted", "aceito em"),
    ("saved password", "senha salva"),
    ("saved password unused", "senha salva sem uso"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
    "connect.certificate",
    "## Certificado do roteador

Pela rede a GUI só fala com o roteador por TLS. Não há autoridade certificadora: na primeira vez você compara o fingerprint com o que o roteador imprime ao iniciar, e a GUI o guarda (`known_hosts`). As conexões seguintes conferem antes de enviar qualquer coisa.

**Mudou?** É o esperado depois de reinstalar o roteador ou trocar o certificado. Fora isso, alguém entre você e o roteador pode estar interceptando a conexão (homem no meio).

- **Cancel** (padrão; Enter e Esc cancelam): nada é enviado.
- **Connect once**: conecta com o certificado novo agora; o `known_hosts` continua com o antigo e a próxima conexão pergunta de novo.
- **Trust and update**: troca a linha no `known_hosts` (com a data de hoje) e conecta.

É o mesmo fluxo do PuTTY. CLI e MCP: num terminal perguntam o mesmo; sem terminal recusam e indicam `--accept-new-cert`.",
),
    (
        "connect.saved_password",
        "## Senha salva

Com **Remember password** marcado, a GUI guarda a senha no cofre de senhas do sistema (chaveiro), por endereço e Login, nunca num arquivo dela.

- Quando há senha salva para o endereço e o Login na tela, ela aparece **no campo Password** (mascarada) com o selo `saved password`. Nada é usado escondido: o que o campo tem é o que vai para o roteador.
- **Apague o campo** para conectar com a senha vazia (o `admin` de um roteador novo ou reinstalado não tem senha). O selo vira `saved password unused`.
- **Forget** (ao lado do selo) apaga a senha do cofre deste computador; o roteador não muda.
- Se o roteador recusar a senha salva, a mensagem diz isso e oferece apagá-la.
- Certificado trocado (roteador reinstalado): **Trust and update** também esquece a senha salva, se a caixa estiver marcada (padrão).",
    ),
];
