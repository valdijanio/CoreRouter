id: processo

Fila de entrada: um PR que conflita só com outro PR do lote (ou do lote especulativo) não fica
mais marcado até a branch mudar. O conflito é com o vizinho, não com a `main`: quando o vizinho
entra, ele pode mesclar limpo. O #144 ficou parado assim (2026-10-23). Agora ele volta na rodada
seguinte; só o conflito com a própria `main` e o CI vermelho seguem marcando o PR.
