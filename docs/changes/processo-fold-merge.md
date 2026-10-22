id: processo

Fila de entrada: o merge do fold não para mais a fila quando o GitHub já apagou a branch. O
`gh pr merge --delete-branch` saía com erro (404 ao apagar a branch que o GitHub apaga sozinho no
merge) depois de um merge que tinha dado certo, e a fila parou em #120. Agora o merge é feito sem
`--delete-branch`, o estado do PR decide se houve falha, e a branch é apagada à parte, sem erro.
