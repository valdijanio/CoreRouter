//! Portuguese labels and explanations of PPP › Secrets › Import from
//! MikroTik (G4.3n), scope `ppp_import`, sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("(create from the file)", "(criar a partir do arquivo)"),
    ("/ppp secret export show-sensitive, or drop the .rsc file on this window", "/ppp secret export show-sensitive, ou arraste o .rsc para esta janela"),
    ("Enter Safe Mode", "Entrar no Safe Mode"),
    ("File", "Arquivo"),
    ("Forget", "Esquecer"),
    ("Here", "Aqui"),
    ("Import", "Importar"),
    ("Import from MikroTik", "Importar do MikroTik"),
    ("Load", "Carregar"),
    ("Loaded", "Carregado"),
    ("MikroTik profile", "Perfil no MikroTik"),
    ("Name already here", "Nome que já existe"),
    ("Not imported (no such field here)", "Não importado (campo que não existe aqui)"),
    ("Now delete the export file (and its copies): it holds every password.", "Agora apague o arquivo do export (e as cópias): ele tem todas as senhas."),
    ("Preview", "Pré-visualizar"),
    ("Profile mapping", "Mapeamento de perfis"),
    ("Safe Mode is on: losing the router undoes the import.", "Safe Mode ligado: se você perder o acesso ao roteador, a importação é desfeita."),
    ("Secrets", "Secrets"),
    ("The export holds every subscriber's password in clear. Read it here, then delete the file and its copies.", "O export tem a senha de todos os assinantes em texto claro. Leia-o aqui e depois apague o arquivo e as cópias."),
    ("The import is one change (one revision).", "A importação é uma mudança só (uma revisão)."),
    ("already here", "já existem"),
    ("errors", "erros"),
    ("import renamed (-2)", "importar renomeado (-2)"),
    ("imported", "importados"),
    ("missing profiles", "perfis ausentes"),
    ("or paste it", "ou cole aqui"),
    ("replace ours", "substituir o nosso"),
    ("replaced", "substituídos"),
    ("skip (keep ours)", "pular (fica o nosso)"),
    ("skipped", "pulados"),
    ("with password", "com senha"),
    ("without password", "sem senha"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("ppp_import.file", "## Arquivo\n\nO caminho do export do RouterOS neste computador (`~/` é a sua pasta). Gere-o no MikroTik com `/ppp secret export show-sensitive file=secrets` (ou `/export show-sensitive`): **sem `show-sensitive` o RouterOS omite as senhas sem avisar**, e a pré-visualização mostra quantos vieram sem senha. Também dá para arrastar o `.rsc` para esta janela.\n\nO arquivo tem a senha de todos os assinantes em texto claro: apague-o (e as cópias) depois de importar."),
    ("ppp_import.map", "## Mapeamento de perfis\n\nCada perfil que os secrets do arquivo usam e para onde eles vão aqui. Um perfil com o mesmo nome aqui é usado direto; um que o arquivo define (`/ppp profile add`) e não existe aqui é criado a partir dele; os outros (em vermelho) precisam ser mapeados para um perfil nosso, senão nada é importado.\n\nCampos de perfil sem equivalente aqui (scripts on-up, use-encryption, filas) aparecem em \"Não importado\"."),
    ("ppp_import.on_conflict", "## Nome que já existe\n\nO que fazer com um secret do arquivo cujo nome já existe aqui: **pular** (o nosso fica como está), **substituir** (o do arquivo toma o lugar e mantém o id) ou **importar renomeado** (`nome-2`, `nome-3`… — o assinante só entra com o nome novo)."),
    ("ppp_import.paste", "## Colar\n\nCole aqui o texto do export (o resultado de `/ppp secret export show-sensitive` no terminal do MikroTik). O texto não é mostrado: vai direto para a importação e é esquecido ao importar ou ao fechar a janela."),
];
