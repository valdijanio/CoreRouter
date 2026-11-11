id: fix-version-tree

A barra da GUI acusava "daemon … ≠ GUI …" entre duas builds do mesmo código: o pacote compilado
na branch de um PR e a imagem compilada da `main` depois do squash têm commits (e contagens
`dev.N`) diferentes e os mesmos arquivos. Visto no notebook: daemon `0.1.0-dev.583` (`a9c22459`,
o squash da G1.30g) contra a GUI `0.1.0-dev.585` (`386c56b`, a ponta da branch), com `git diff`
vazio entre os dois. O `corerouter-buildinfo` grava agora a árvore do git do commit (`TREE`), o
`server.info` a envia (`tree`) e a GUI não acusa nada quando as árvores batem e nenhum lado tem
`.dirty` (com alterações sem commit a árvore não diz o que foi compilado, e o aviso continua).
Daemon antigo, sem `tree`, segue comparado pelo commit. Teste: `same_files` no buildinfo e o caso
novo em `a_daemon_built_from_another_commit_is_flagged_in_the_top_bar`.
