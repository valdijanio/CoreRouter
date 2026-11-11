id: processo-fold-conta-md

A fila de entrada (`scripts/land.sh`) voltou a consolidar os `docs/changes/` só de tempos em
tempos. A conta dos pendentes somava as pastas `<id>-screenshots`, que ficam em `docs/changes/`
depois do fold: com 37 pastas (**medido**, `origin/main` em 2026-11-11) a conta nunca ficava
abaixo de `FOLD_MIN` (10) e cada lote ganhava um PR de fold só seu (#584, #587 e #589 na mesma
noite, cada um com o título "38 arquivos" e um arquivo consolidado). Agora contam só os `.md`
que não são o `README.md`: na `origin/main` a conta passa de 37 para 0 (**medido**).

Como testar: `git ls-tree --name-only origin/main docs/changes/ | grep '\.md$' | grep -vc
'/README\.md$'` dá o número de arquivos pendentes; com menos de 10 a fila escreve "fold adiado:
N arquivo(s)" no fim do lote, e `scripts/land.sh --fold` consolida na hora.
