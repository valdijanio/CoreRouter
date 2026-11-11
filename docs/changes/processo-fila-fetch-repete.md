id: processo-fila-fetch-repete

Fila de entrada: `git fetch` com nova tentativa (`scripts/land.sh`, função `fetch`). Depois do
#594 a fila escreveu `cannot lock ref 'refs/remotes/origin/main': is at a3494e8e… but expected
895e5fa0…` e "checkout não avançou para a main (ff): não recompila": o checkout principal
ficou um commit atrás e com os binários velhos. Causa: as worktrees das sessões dividem os refs
do repositório; quando outra sessão faz `git fetch` no mesmo instante, um dos dois perde a
trava do ref e sai com erro, embora o ref já esteja atualizado. Nos outros fetches da fila, que
não estão dentro de um `if`, o mesmo erro encerrava a fila (`set -e`).

Agora todo fetch da fila passa por `fetch`, que repete até três vezes (espera de 1, 2 e 3 s) e
só mostra o erro da última tentativa. **Medido** (repositório de teste, dois fetches
simultâneos logo depois de um push, 2026-11-11): sem repetir, 199 de 200 rodadas têm um fetch
com erro; com a repetição, 0 de 200, e o ref fica no commit novo em todas.

Vale só depois de religar a fila (ela roda o script com que começou).
