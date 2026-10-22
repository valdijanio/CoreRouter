id: processo
history: processo: arquivos de mudança por PR (`docs/changes/`) e fila de entrada; o status das gaps passa a vir do fold

Fila de entrada e arquivos de mudança por PR, no lugar do merge automático + `pr-sync`. Cada PR
grava `docs/changes/<id>.md` (log, status da gap, histórico, gaps novas) em vez de editar
`docs/log.md`, `docs/gaps-history.md` e a coluna Status de `docs/gaps.md`; `cargo xtask docs`
confere o formato no CI e `cargo xtask docs fold` consolida. As sessões não ligam mais o
auto-merge: a sessão principal pergunta ao usuário por lote ("N features prontas — subir?") e
roda `scripts/land.sh`, que integra um PR por vez (traz a `main`, faz o fold, envia, espera o CI
do PR e faz o squash). A proteção da `main` volta a exigir branch atualizada, então o CI de cada
PR roda sobre a `main` em que ele vai entrar: "sozinho passa, junto quebra" (como o `from_pool` e
o `Head.parent` em 2026-10-22) para no PR, não na `main`. Saem o workflow `pr-sync` e o
`scripts/pr-sync.sh`; o #46 foi fechado sem merge. Números do dia (**medido**): 46 PRs, 86 runs
de CI nos PRs e 46 na `main`.
