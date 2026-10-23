id: fix

i18n: a mesma chave em duas tabelas de rótulos passa no teste quando o texto é igual (só reprova
se a tradução divergir). Sessões em paralelo registravam a mesma palavra ("changed", "of") em
catálogos diferentes, e cada combinação quebrava o lote da fila (#159, #165, 2026-10-23) sem
nenhum erro de verdade: o `lookup` pega a primeira, e com o mesmo texto não há diferença na tela.
