id: processo

Fila contínua (`scripts/land.sh --watch`): pega sozinha os PRs com o rótulo `fila` (as
sessões o põem no `gh pr create`), sem esperar a sessão principal reagir; e lote especulativo:
enquanto um lote roda o CI, os PRs que ficam prontos são testados num lote montado em cima
dele; verde, entram logo depois, sem outro CI; vermelho, o especulativo é descartado e o lote
passa pela bisseção. PR que ficou de fora volta sozinho quando a branch muda. Simulado: lote
verde com um PR chegando no meio entra um passo depois; lote vermelho cai na bisseção.
