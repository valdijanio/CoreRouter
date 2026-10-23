id: processo

Fila de entrada: o PR pai de um PR empilhado é reconhecido por **qualquer** commit dele que esteja
na branch do filho, não só pelo último. A fila manda merges da `main` na branch do pai antes do
squash, e esse último commit não está na branch do filho; a resolução automática não reconhecia o
pai e devolvia o PR à sessão (#177 e #186, 2026-10-23). Testado no #186 real: os 4 arquivos do
conflito resolvidos sozinhos.
