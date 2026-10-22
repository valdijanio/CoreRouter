id: processo

Fila de entrada em lote (`scripts/land.sh --batch`), a pedido do usuário: um CI para a
combinação de todos os PRs prontos, não um por PR. A fila junta a `main` e os PRs numa branch
temporária, faz o fold e roda o CI (`workflow_dispatch`); verde, faz o squash de cada PR em
ordem sem esperar mais CI (a `main` termina igual à combinação testada) e um PR do fold;
vermelho, cai no modo um por um para achar o culpado; um PR que conflita com o lote fica de
fora. A proteção da `main` deixa de exigir branch atualizada (o lote testa a combinação). Com 7
PRs: ~2,5 min de CI em vez de ~17 min (7 × ~2,5 min, **estimado** pela bateria).
