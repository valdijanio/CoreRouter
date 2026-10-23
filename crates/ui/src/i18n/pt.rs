//! Portuguese labels (by their English text) and explanations (by key),
//! each sorted by key.

pub(super) const LABELS: &[(&str, &str)] = &[
    ("Close", "Fechar"),
    ("Explanations", "Explicações"),
    ("Labels", "Rótulos"),
    ("Language", "Idioma"),
    ("No explanation yet.", "Ainda sem explicação."),
    ("Settings", "Configurações"),
    (
        "Stored on this computer, not on the router.",
        "Guardado neste computador, não no roteador.",
    ),
];

pub(super) const HELP: &[(&str, &str)] = &[
    (
        "settings.help_lang",
        "## O que faz\n\
         O idioma das explicações: as janelas do botão redondo “i” e o texto de \
         ajuda de cada parâmetro.\n\n\
         Uma explicação que ainda não existe neste idioma aparece no idioma dos \
         rótulos e, depois, em inglês.",
    ),
    (
        "settings.labels_lang",
        "## O que faz\n\
         O idioma dos rótulos: menus, títulos de janela, colunas e botões.\n\n\
         Por enquanto a maior parte dos rótulos está só em inglês (os nomes do \
         RouterOS, que os manuais e o terminal também usam); rótulo sem \
         tradução aparece em inglês.\n\n\
         ## Onde fica guardado\n\
         Neste computador (ou neste navegador), não no roteador: cada operador \
         escolhe o seu.",
    ),
];
