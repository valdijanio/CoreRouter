id: processo-regras-basicas

Regras básicas do dono do projeto no topo do `AGENTS.md`/`CLAUDE.md`, valendo antes das outras:

1. o projeto é do agente: reorganizar o que existe quando isso deixa o código mais simples;
2. não parar enquanto faltar algo do pedido, com uma lista única de paradas permitidas;
3. erro se resolve achando a causa, sem perguntar;
4. conferir no sistema rodando antes de dizer que terminou, dizendo o que não deu para conferir;
5. o relato começa pelo resultado, em frases curtas.

As regras que conflitavam foram ajustadas:

- "Pare e pergunte só para" aponta para a lista da regra 2.
- "Com o PR aberto, pare" pede o sistema conferido antes e deixa claro que o pedido só termina
  quando o PR entra.
- Os pontos quentes e os crates compartilhados admitem uma reorganização maior num PR próprio.
