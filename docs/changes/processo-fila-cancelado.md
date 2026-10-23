id: processo

Fila de entrada: um CI cancelado não trava mais o lote por 30 minutos. Quando a sessão dona envia
um push novo, o GitHub cancela o CI do commit anterior; a fila, que tinha montado o lote com esse
commit, esperava um verde que nunca vinha até o prazo de 30 min (lote do #144, 2026-10-23). Agora
um run cancelado sem outro verde no mesmo commit tira o PR do lote na hora, e ele volta com o head
novo na rodada seguinte.
