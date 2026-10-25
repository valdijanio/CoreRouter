id: processo

`AGENTS.md`: análise de desempenho e paralelismo passa a ser **obrigatória** em toda feature,
correção e revisão (pedido do usuário, 2026-10-25). O PR responde onde está o trabalho por item,
se ele cresce com o total, se várias threads ou núcleos ajudam e por quê, e mede quando houver
dúvida. Ganho mensurável em caminho quente entra no mesmo trabalho, e não como gap. A revisão
procura sempre:
- custo O(n) escondido;
- trabalho preso num núcleo;
- lock disputado;
- fila sem limite.

Origem: o laboratório do BNG (G4.3g) mostrou o plano de controle PPPoE num núcleo a 98%.
