id: processo

Teste instável `corerouter-control conn::tests::deadline_bounds_the_total_not_each_read`: o limite
de 900 ms estourou num runner do CI carregado (2026-10-24, branch da G2.5b, TRY 2 FAIL). Agora o
limite é 1600 ms, ainda bem abaixo dos 2 s em que o alimentador mantém cada leitura viva, então o
teste continua provando que o prazo vale para o total, não para cada leitura.
